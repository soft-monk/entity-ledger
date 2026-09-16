// entity-ledger · src/action.cc —— 动作状态机（ELG-ACT）
//
// 权威依据：
//   · ELG-ACT-01 动作集由规则声明（引擎内 MUST NOT 出现动作名；"watch" 等取值零命中）
//   · ELG-ACT-02 幂等：已执行动作的重复请求 MUST 表达"已执行"语义
//   · ELG-ACT-03 动作**只产出结构化状态变更**（StateChange[]），MUST NOT 产出自然语言文案；
//               `target.state` 事件负载为既有冻结字段（protocol.md §4.2）
//   · ELG-ACT-04 前置条件可声明（未满足 → 拒绝 + 逐条可读原因；**不短路**）
//   · ELG-ACT-05 动作落事件日志（可查、可复原）
//   · ELG-ACT-06 可撤销语义由规则声明（不可撤销动作的撤销请求被拒绝）
//
// ⚠ 冲突登记（需求专篇内部 vs 上游冻结契约，已写入实现报告"开放问题"）：
//   需求专篇 ELG-ACT-02 与其 §1.4 硬约束写"重复 `upgrade` MUST 返回 `code=1002 正在执行/已执行`"，
//   但 protocol.md §3.3 CTR-EC-01/02 与《冲突裁决.md》ADR-C15-01/02 冻结：
//     **幂等成功 MUST 用 `code=0` + `data.idempotent=true`；MUST NOT 为幂等成功发明非零 code**
//     （理由：`mapApp/frontend/src/api/client.ts` L38 对任何 `code != 0` 一律抛错，
//       返回 1002 会把"已执行"这个**成功**语义变成前端异常）。
//   本实现的落点：
//     · 重复请求同一动作 → `code=0`，`status="already-done"`，`data.idempotent=true`（C15 口径）
//     · 同一实体的动作**正在执行 / 已由他方执行** → `code=1002`，`data.conflict=true`（C16 口径）
//     · 前置条件未满足 → `code=1003` + `unmet[]`（ADR-C16-03）
//   即需求专篇的"已执行"语义**保留**（由 status 字段承载），但不再借用 1002 表达成功。
#include "internal.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>

namespace entity_ledger {

namespace {

using detail::Definition;
using detail::MissionState;
using detail::State;

bool validGateId(const std::string& id) {
    if (id.empty() || id.size() > 64) return false;
    if (id[0] < 'a' || id[0] > 'z') return false;
    for (char ch : id) {
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-';
        if (!ok) return false;
    }
    return true;
}

bool hasFlag(const EntityRecord& rec, const std::string& key) {
    return std::find(rec.flags.begin(), rec.flags.end(), key) != rec.flags.end();
}

bool inSequence(const MissionState& m, const std::string& id) {
    for (const auto& e : m.sequence) {
        if (e.entityId == id) return true;
    }
    return false;
}

/// 内建守卫（`$` 前缀；与 phase-engine 的 D-PHE-04 同惯例）。
/// 返回空串 = 通过；否则返回 unmet 的 reason。
std::string evalBuiltinGate(const Definition& def, const State& st, const MissionState& m,
                            const EntityRecord& rec, const ActionDef& act,
                            const std::string& gateId, std::string& detail) {
    const auto parts = detail::splitGate(gateId);
    const std::string& name = parts.first;
    const std::string& arg = parts.second;
    detail.clear();
    if (name == "$in-sequence") {
        if (!inSequence(m, rec.id)) {
            detail = "entityId=" + rec.id;
            return "entity is not in the engagement sequence";
        }
        return "";
    }
    if (name == "$flag") {
        if (!hasFlag(rec, arg)) {
            detail = arg;
            return "required flag is not held";
        }
        return "";
    }
    if (name == "$state") {
        if (rec.dynamicState != arg) {
            detail = rec.dynamicState;
            return "dynamic state does not match the required value";
        }
        return "";
    }
    if (name == "$action") {
        auto it = m.applied.find(rec.id);
        if (it == m.applied.end() || !it->second.count(arg)) {
            detail = arg;
            return "required prior action has not been applied";
        }
        return "";
    }
    if (name == "$not-action") {
        auto it = m.applied.find(rec.id);
        if (it != m.applied.end() && it->second.count(arg)) {
            detail = arg;
            return "action already applied and must not repeat";
        }
        return "";
    }
    if (name == "$confidence-min") {
        double want = 0.0;
        bool ok = false;
        try {
            want = std::stod(arg);
            ok = true;
        } catch (...) {
            ok = false;
        }
        if (!ok) {
            detail = arg;
            return "invalid gate argument";
        }
        if (rec.confidence + 1e-9 < want) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%.6f", rec.confidence);
            detail = buf;
            return "confidence below the required minimum";
        }
        return "";
    }
    if (name == "$reversible") {
        if (!act.reversible) {
            detail = act.key;
            return "action is not reversible by rules";
        }
        return "";
    }
    detail = gateId;
    (void)def;
    (void)st;
    return "unknown builtin gate";
}

}  // namespace

bool EntityLedger::registerActionGate(const std::string& gateId, ActionGateFn fn) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    if (!validGateId(gateId)) return false;  // `$` 前缀保留给引擎内建守卫
    if (st.actionGates.count(gateId)) return false;
    st.actionGates.emplace(gateId, std::move(fn));
    return true;
}

bool EntityLedger::unregisterActionGate(const std::string& gateId) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    return st.actionGates.erase(gateId) > 0;
}

ActionResult EntityLedger::applyAction(const ActionRequest& req) {
    State& st = impl_->st;
    ActionResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.entityId = req.entityId;
    res.actionKey = req.actionKey;

    // ①②入参（协议 §3.4 同序裁决）
    if (req.entityId.empty() || req.actionKey.empty()) {
        res.code = 1000;
        res.message = "entityId and actionKey are required";
        return res;
    }
    {
        std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
        if (!st.def.loaded) {
            res.code = 1005;
            res.message = "policies not loaded";
            return res;
        }
    }

    // ③动作集由规则声明：未声明的动作 MUST NOT 被内建（ELG-ACT-01）
    const ActionDef* actPtr = nullptr;
    {
        std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
        actPtr = st.def.findAction(req.actionKey);
    }
    if (!actPtr) {
        res.code = 1004;
        res.message = "unknown action: " + req.actionKey;
        return res;
    }
    const ActionDef act = *actPtr;

    // ④实体互斥闸门（try-lock 语义：拿不到立刻 1002，MUST NOT 阻塞等待）
    if (!st.tryAcquire(req.entityId)) {
        std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
        ++st.metrics.actionConflicts;
        res.code = 1002;
        res.message = "action already in progress for this entity";
        res.status = "conflict";
        res.conflict = true;
        return res;
    }
    struct Releaser {
        State* st;
        std::string key;
        ~Releaser() { st->release(key); }
    } releaser{&st, req.entityId};

    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    MissionState* mp = nullptr;
    EntityRecord* rec = nullptr;
    for (auto& kv : st.missions) {
        auto it = kv.second.entities.find(req.entityId);
        if (it != kv.second.entities.end()) {
            mp = &kv.second;
            rec = &it->second;
            break;
        }
    }
    if (!mp || !rec) {
        res.code = 1004;
        res.message = "entity not found";
        return res;
    }
    MissionState& m = *mp;
    res.no = rec->no;
    res.missionId = m.missionId;

    if (rec->retired) {
        res.code = 1003;
        res.message = "entity is retired";
        res.status = "rejected";
        res.unmet.push_back(UnmetItem{"$retired", "entity is retired", rec->retireReason});
        ++st.metrics.actionRejected;
        return res;
    }

    // ⑤幂等：已执行过且规则声明 once → "已执行"语义（code=0 + idempotent，零状态副作用）
    auto appliedIt = m.applied.find(rec->id);
    const bool alreadyApplied =
        appliedIt != m.applied.end() && appliedIt->second.count(act.key) > 0;
    if (act.once && alreadyApplied) {
        ActionLogEntry entry;
        entry.at = now;
        entry.missionId = m.missionId;
        entry.entityId = rec->id;
        entry.no = rec->no;
        entry.actionKey = act.key;
        entry.actor = req.operatorId;
        entry.status = "already-done";
        entry.reversible = act.reversible;
        entry.reason = req.reason;
        m.actionLog.push_back(entry);
        ++st.metrics.actionIdempotent;
        res.code = 0;
        res.message = "already-done";
        res.status = "already-done";
        res.idempotent = true;
        res.state = *rec;
        return res;
    }

    // ⑥前置条件（**全部**求值，不短路）：内建 `$…` 守卫 + 宿主注册 gate
    for (const auto& gateId : act.requires) {
        if (detail::isBuiltinGate(gateId)) {
            std::string detailText;
            const std::string reason =
                evalBuiltinGate(st.def, st, m, *rec, act, gateId, detailText);
            if (!reason.empty()) res.unmet.push_back(UnmetItem{gateId, reason, detailText});
            continue;
        }
        auto git = st.actionGates.find(gateId);
        if (git == st.actionGates.end()) {
            // 未注册 → 放行但如实标注（与 phase-engine 的 Gate fail-open 同口径）
            res.skippedGates.push_back(gateId);
            continue;
        }
        UnmetItem item;
        try {
            item = git->second(ActionGateContext{*rec, act, req.params, now});
        } catch (...) {
            ++st.metrics.gateErrors;
            item = UnmetItem{gateId, "host gate threw", ""};
        }
        if (!item.gate.empty() && !item.reason.empty()) res.unmet.push_back(item);
    }
    if (!res.unmet.empty()) {
        ActionLogEntry entry;
        entry.at = now;
        entry.missionId = m.missionId;
        entry.entityId = rec->id;
        entry.no = rec->no;
        entry.actionKey = act.key;
        entry.actor = req.operatorId;
        entry.status = "rejected";
        entry.reversible = act.reversible;
        entry.reason = req.reason;
        m.actionLog.push_back(entry);
        ++st.metrics.actionRejected;
        res.code = 1003;
        res.message = "preconditions not satisfied";
        res.status = "rejected";
        return res;
    }

    // ⑦结构化状态变更（ELG-ACT-03：只有字段与前后值，没有文案）
    std::vector<StateChange> changes;
    std::vector<std::pair<std::string, bool>> flagOps;  // (flagKey, set?)
    for (const auto& f : act.setsFlags) {
        if (!hasFlag(*rec, f)) {
            // 唯一性旗标：已被他人持有 → 拒绝（ELG-ID-05）
            const FlagDef* fd = st.def.findFlag(f);
            if (fd && fd->unique) {
                const EntityRecord* holder = nullptr;
                for (const auto& id : m.order) {
                    auto it = m.entities.find(id);
                    if (it == m.entities.end()) continue;
                    if (it->second.id == rec->id) continue;
                    if (hasFlag(it->second, f)) holder = &it->second;
                }
                if (holder) {
                    res.code = 1003;
                    res.message = "unique flag already held in mission";
                    res.status = "rejected";
                    res.unmet.push_back(UnmetItem{"$flag-unique", "unique flag already held",
                                                  std::to_string(holder->no)});
                    ++st.metrics.actionRejected;
                    return res;
                }
            }
            flagOps.emplace_back(f, true);
        }
    }
    for (const auto& f : act.clearsFlags) {
        if (hasFlag(*rec, f)) flagOps.emplace_back(f, false);
    }
    if (!act.setsDynamicState.empty() && rec->dynamicState != act.setsDynamicState) {
        if (!st.def.transitionAllowed(rec->dynamicState, act.setsDynamicState)) {
            res.code = 1003;
            res.message = "illegal state transition";
            res.status = "rejected";
            res.unmet.push_back(UnmetItem{"$transition", "transition not declared by rules",
                                          rec->dynamicState + "->" + act.setsDynamicState});
            ++st.metrics.actionRejected;
            return res;
        }
        StateChange ch;
        ch.field = "dynamicState";
        ch.from = rec->dynamicState;
        ch.to = act.setsDynamicState;
        changes.push_back(ch);
    }
    if (act.setsPriority) {
        StateChange ch;
        ch.field = "priority";
        ch.from = std::to_string(rec->priority);
        ch.to = std::to_string(act.priorityValue);
        if (rec->priority != act.priorityValue || !rec->prioritySet) changes.push_back(ch);
    }

    // ⑧写前提交（失败 → 1005 且内存状态不变）
    const EntityRecord backup = *rec;
    for (const auto& op : flagOps) {
        if (op.second) rec->flags.push_back(op.first);
        else rec->flags.erase(std::remove(rec->flags.begin(), rec->flags.end(), op.first),
                              rec->flags.end());
        StateChange ch;
        ch.field = "flags";
        ch.from = op.second ? "" : op.first;
        ch.to = op.second ? op.first : "";
        changes.push_back(ch);
    }
    if (!act.setsDynamicState.empty() && rec->dynamicState != act.setsDynamicState) {
        rec->dynamicState = act.setsDynamicState;
    }
    if (act.setsPriority) {
        rec->priority = act.priorityValue;
        rec->prioritySet = true;
    }
    bool sequenceAdded = false;
    if (act.addsToSequence && !inSequence(m, rec->id)) {
        if (st.def.rank.sequenceLimit > 0 &&
            static_cast<int>(m.sequence.size()) >= st.def.rank.sequenceLimit) {
            *rec = backup;
            res.code = 1003;
            res.message = "sequence limit reached";
            res.status = "rejected";
            res.unmet.push_back(UnmetItem{"$sequence-limit", "sequence limit reached by rules",
                                          std::to_string(st.def.rank.sequenceLimit)});
            ++st.metrics.actionRejected;
            return res;
        }
        SequenceEntry entry;
        entry.entityId = rec->id;
        entry.no = rec->no;
        entry.position = static_cast<int>(m.sequence.size());
        entry.addedAt = now;
        entry.actor = req.operatorId;
        entry.reason = req.reason;
        m.sequence.push_back(entry);
        SequenceAuditEntry a;
        a.at = now;
        a.actor = req.operatorId;
        a.action = "add";
        a.entityId = rec->id;
        a.no = rec->no;
        a.position = entry.position;
        a.reason = req.reason;
        m.sequenceAudit.push_back(a);
        sequenceAdded = true;
        StateChange ch;
        ch.field = "sequence";
        ch.from = "";
        ch.to = std::to_string(entry.position);
        changes.push_back(ch);
    }
    rec->updatedAt = now;
    for (const auto& ch : changes) {
        EntityTrace t;
        t.at = now;
        t.field = ch.field;
        t.from = ch.from;
        t.to = ch.to;
        t.action = act.key;
        t.operatorId = req.operatorId;
        t.reason = req.reason;
        rec->trace.push_back(t);
    }
    m.applied[rec->id].insert(act.key);

    ActionLogEntry entry;
    entry.at = now;
    entry.missionId = m.missionId;
    entry.entityId = rec->id;
    entry.no = rec->no;
    entry.actionKey = act.key;
    entry.actor = req.operatorId;
    entry.status = "ok";
    entry.reversible = act.reversible;
    entry.changes = changes;
    entry.reason = req.reason;
    m.actionLog.push_back(entry);

    if (!st.persistLocked(m)) {
        *rec = backup;
        m.applied[rec->id].erase(act.key);
        m.actionLog.pop_back();
        if (sequenceAdded) {
            m.sequence.pop_back();
            m.sequenceAudit.pop_back();
        }
        res.code = 1005;
        res.message = "store save failed";
        return res;
    }

    ++st.metrics.actions;
    res.code = 0;
    res.message = "ok";
    res.status = "ok";
    res.idempotent = changes.empty();
    res.changes = changes;
    res.undoDeadline = act.undoWithinMs > 0 ? now + act.undoWithinMs : 0;
    EntityRecord out = *rec;
    detail::decorateEntity(st, m, out);
    res.state = out;
    st.emitEntityChanged(m.missionId, out, act.key, "", now);
    st.emitTargetState(out, now);
    AuditEntry au;
    au.at = now;
    au.actor = req.operatorId;
    au.action = act.key;
    au.target = rec->id;
    au.detail = "changes=" + std::to_string(changes.size());
    au.violation = false;
    st.audit(au);
    return res;
}

ActionResult EntityLedger::undoAction(const ActionRequest& req) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    ActionResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.entityId = req.entityId;
    res.actionKey = req.actionKey;
    if (req.entityId.empty() || req.actionKey.empty()) {
        res.code = 1000;
        res.message = "entityId and actionKey are required";
        return res;
    }
    const ActionDef* actPtr = st.def.findAction(req.actionKey);
    if (!actPtr) {
        res.code = 1004;
        res.message = "unknown action: " + req.actionKey;
        return res;
    }
    const ActionDef act = *actPtr;
    for (auto& kv : st.missions) {
        MissionState& m = kv.second;
        auto eit = m.entities.find(req.entityId);
        if (eit == m.entities.end()) continue;
        EntityRecord& rec = eit->second;
        res.no = rec.no;
        res.missionId = m.missionId;
        int last = -1;
        for (std::size_t i = 0; i < m.actionLog.size(); ++i) {
            const ActionLogEntry& e = m.actionLog[i];
            if (e.entityId == rec.id && e.actionKey == act.key && e.status == "ok" &&
                e.undoneAt == 0) {
                last = static_cast<int>(i);
            }
        }
        if (last < 0) {
            res.code = 0;
            res.message = "action not applied";
            res.status = "not-applied";
            res.idempotent = true;
            res.state = rec;
            return res;
        }
        if (!act.reversible) {
            res.code = 1003;
            res.message = "action is not reversible";
            res.status = "rejected";
            res.unmet.push_back(UnmetItem{"$irreversible", "action declared irreversible", act.key});
            ++st.metrics.actionRejected;
            return res;
        }
        const ActionLogEntry& log = m.actionLog[static_cast<std::size_t>(last)];
        if (act.undoWithinMs > 0 && now > log.at + act.undoWithinMs) {
            res.code = 1003;
            res.message = "undo window elapsed";
            res.status = "rejected";
            res.unmet.push_back(UnmetItem{"$undo-window", "undo window elapsed by rules",
                                          std::to_string(act.undoWithinMs)});
            ++st.metrics.actionRejected;
            return res;
        }
        MissionState backupMission = m;  // 整体备份（撤销会同时改动序列与日志）
        std::vector<StateChange> changes;
        for (const auto& ch : log.changes) {
            StateChange back;
            back.field = ch.field;
            back.from = ch.to;
            back.to = ch.from;
            if (ch.field == "dynamicState") {
                if (!ch.from.empty()) rec.dynamicState = ch.from;
            } else if (ch.field == "priority") {
                try {
                    rec.priority = std::stoi(ch.from);
                    rec.prioritySet = true;
                } catch (...) {
                }
            } else if (ch.field == "flags") {
                if (!ch.from.empty() && !hasFlag(rec, ch.from)) rec.flags.push_back(ch.from);
                if (!ch.to.empty()) {
                    rec.flags.erase(std::remove(rec.flags.begin(), rec.flags.end(), ch.to),
                                    rec.flags.end());
                }
            } else if (ch.field == "sequence") {
                for (std::size_t i = 0; i < m.sequence.size(); ++i) {
                    if (m.sequence[i].entityId == rec.id) {
                        m.sequence.erase(m.sequence.begin() + static_cast<long>(i));
                        break;
                    }
                }
            }
            changes.push_back(back);
        }
        m.applied[rec.id].erase(act.key);
        rec.updatedAt = now;
        if (!st.persistLocked(m)) {
            m = std::move(backupMission);
            res.code = 1005;
            res.message = "store save failed";
            return res;
        }
        m.actionLog[static_cast<std::size_t>(last)].undoneAt = now;
        m.actionLog[static_cast<std::size_t>(last)].undoneBy = req.operatorId;
        AuditEntry au;
        au.at = now;
        au.actor = req.operatorId;
        au.action = "undo:" + act.key;
        au.target = rec.id;
        au.detail = "changes=" + std::to_string(changes.size());
        st.audit(au);
        ++st.metrics.actions;
        EntityRecord out = rec;
        detail::decorateEntity(st, m, out);
        res.code = 0;
        res.message = "ok";
        res.status = "ok";
        res.changes = changes;
        res.state = out;
        st.emitEntityChanged(m.missionId, out, "undo:" + act.key, "", now);
        st.emitTargetState(out, now);
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

std::vector<ActionLogEntry> EntityLedger::actionLog(const ActionLogQuery& q) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    std::vector<ActionLogEntry> out;
    for (const auto& kv : st.missions) {
        if (!q.missionId.empty() && kv.first != q.missionId) continue;
        for (const auto& e : kv.second.actionLog) {
            if (!q.entityId.empty() && e.entityId != q.entityId) continue;
            if (!q.actionKey.empty() && e.actionKey != q.actionKey) continue;
            out.push_back(e);
        }
    }
    if (q.limit > 0 && static_cast<int>(out.size()) > q.limit) {
        out.erase(out.begin(), out.end() - q.limit);
    }
    return out;
}

}  // namespace entity_ledger
