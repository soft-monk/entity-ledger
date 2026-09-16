// entity-ledger · src/rank.cc —— 优先级与打击序列（ELG-RANK）
//
// 权威依据：
//   · ELG-RANK-01 排序规则可配（默认按优先级 + 威胁，**次级键稳定**：末位键恒为 no）
//   · ELG-RANK-02 优先级值可显式设置
//   · ELG-RANK-03 打击序列：加入/移出、序列内唯一、可排序；重复加入幂等
//   · ELG-RANK-04 序列变更可审计（谁在什么时候把谁加入了序列）
//
// 排序是**纯函数式比较**：逐键比较，键序与方向全部来自规则；`sortKeys[]` 回写逐键取值，
// 便于复现与人工核对。序列上限由规则声明（rank.sequenceLimit），超限 → 1003 + unmet[]。
#include "internal.h"

#include <algorithm>
#include <cmath>
#include <cstdio>

namespace entity_ledger {

namespace {

using detail::Definition;
using detail::MissionState;
using detail::RankKeyDef;
using detail::State;

/// 分档序号（规则 bands 已按 min 降序；序号越小威胁越高）
int bandRank(const Definition& def, const std::string& band) {
    for (std::size_t i = 0; i < def.bands.size(); ++i) {
        if (def.bands[i].key == band) return static_cast<int>(i);
    }
    return 1000;  // 未评级（无档）排最后
}

/// 单键取值（双精度承载；比较用相同刻度，确定性）
double keyValue(const Definition& def, const RankKeyDef& k, const EntityRecord& rec) {
    if (k.field == "priority") return static_cast<double>(rec.priority);
    if (k.field == "threatScore") return static_cast<double>(rec.threatScore);
    if (k.field == "threatBand") return static_cast<double>(bandRank(def, rec.threatBand));
    if (k.field == "confidence") return rec.confidence;
    if (k.field == "sourceCount") return static_cast<double>(rec.sources.size());
    if (k.field == "no") return static_cast<double>(rec.no);
    return 0.0;
}

std::string keyText(const Definition& def, const RankKeyDef& k, const EntityRecord& rec) {
    if (k.field == "threatBand") return rec.threatBand;
    const double v = keyValue(def, k, rec);
    if (k.field == "no" || k.field == "priority" || k.field == "threatScore" ||
        k.field == "sourceCount") {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(std::llround(v)));
        return std::string(buf);
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.6f", v);
    return std::string(buf);
}

/// 有效排序键：规则声明 + 恒定的末位键 no（稳定次级键，ELG-RANK-01）
std::vector<RankKeyDef> effectiveKeys(const Definition& def) {
    std::vector<RankKeyDef> keys = def.rank.keys;
    if (keys.empty()) {
        keys.push_back(RankKeyDef{"priority", "asc"});
        keys.push_back(RankKeyDef{"threatScore", "desc"});
    }
    bool hasNo = false;
    for (const auto& k : keys) {
        if (k.field == "no") hasNo = true;
    }
    if (!hasNo) keys.push_back(RankKeyDef{"no", "asc"});
    return keys;
}

bool lessThan(const Definition& def, const std::vector<RankKeyDef>& keys, const EntityRecord& a,
              const EntityRecord& b) {
    for (const auto& k : keys) {
        const double va = keyValue(def, k, a);
        const double vb = keyValue(def, k, b);
        if (va == vb) continue;
        const bool asc = (k.direction == "asc");
        return asc ? (va < vb) : (va > vb);
    }
    return false;
}

}  // namespace

std::vector<RankedEntity> EntityLedger::ranking(const RankQuery& q) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    std::vector<RankedEntity> out;
    auto mit = st.missions.find(q.missionId);
    if (mit == st.missions.end()) return out;
    const MissionState& m = mit->second;
    const std::vector<RankKeyDef> keys = effectiveKeys(st.def);

    // 视图限定（可选）：只排该视图可见集合（界面直接消费，避免各自过滤）
    std::set<std::string> allowed;
    bool restricted = false;
    if (!q.viewKey.empty()) {
        VisibleSetRequest vr;
        vr.missionId = q.missionId;
        vr.viewKey = q.viewKey;
        vr.includeExcluded = false;
        const VisibleSetResult vs = visibleSet(vr);
        if (vs.code != 0) return out;
        for (const auto& it : vs.items) allowed.insert(it.id);
        restricted = true;
    }

    std::vector<const EntityRecord*> recs;
    for (const auto& id : m.order) {
        auto it = m.entities.find(id);
        if (it == m.entities.end() || it->second.retired) continue;
        if (restricted && !allowed.count(id)) continue;
        recs.push_back(&it->second);
    }
    std::stable_sort(recs.begin(), recs.end(),
                     [&](const EntityRecord* a, const EntityRecord* b) {
                         return lessThan(st.def, keys, *a, *b);
                     });

    int rank = 0;
    for (const EntityRecord* rec : recs) {
        ++rank;
        RankedEntity r;
        r.rank = rank;
        r.id = rec->id;
        r.no = rec->no;
        r.typeKey = rec->typeKey;
        r.threatScore = rec->threatScore;
        r.threatBand = rec->threatBand;
        r.priority = rec->priority;
        r.prioritySet = rec->prioritySet;
        r.confidence = rec->confidence;
        r.sourceCount = static_cast<int>(rec->sources.size());
        for (const auto& k : keys) r.sortKeys.push_back(keyText(st.def, k, *rec));
        for (std::size_t i = 0; i < m.sequence.size(); ++i) {
            if (m.sequence[i].entityId == rec->id) r.sequenceIndex = static_cast<int>(i);
        }
        out.push_back(r);
        if (q.limit > 0 && static_cast<int>(out.size()) >= q.limit) break;
    }
    return out;
}

ActionResult EntityLedger::setPriority(const PriorityInput& in) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    ActionResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.entityId = in.entityId;
    res.actionKey = "priority-set";
    if (!st.def.loaded) {
        res.code = 1005;
        res.message = "policies not loaded";
        return res;
    }
    if (in.priority < 0) {
        res.code = 1000;
        res.message = "priority must be >= 0";
        return res;
    }
    for (auto& kv : st.missions) {
        MissionState& m = kv.second;
        auto eit = m.entities.find(in.entityId);
        if (eit == m.entities.end()) continue;
        EntityRecord& rec = eit->second;
        res.no = rec.no;
        res.missionId = kv.first;
        if (rec.prioritySet && rec.priority == in.priority) {
            res.code = 0;
            res.message = "priority unchanged";
            res.status = "already-done";
            res.idempotent = true;
            res.state = rec;
            return res;
        }
        const EntityRecord backup = rec;
        StateChange ch;
        ch.field = "priority";
        ch.from = std::to_string(rec.priority);
        ch.to = std::to_string(in.priority);
        rec.priority = in.priority;
        rec.prioritySet = true;
        rec.updatedAt = now;
        EntityTrace t;
        t.at = now;
        t.field = "priority";
        t.from = ch.from;
        t.to = ch.to;
        t.action = "priority-set";
        t.operatorId = in.operatorId;
        t.reason = in.reason;
        rec.trace.push_back(t);
        res.changes.push_back(ch);
        if (!st.persistLocked(m)) {
            rec = backup;
            res.code = 1005;
            res.message = "store save failed";
            return res;
        }
        ++st.metrics.actions;
        EntityRecord out = rec;
        detail::decorateEntity(st, m, out);
        res.code = 0;
        res.message = "ok";
        res.status = "ok";
        res.state = out;
        st.emitEntityChanged(kv.first, out, "priority-set", ch.to, now);
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

// ============================================================================
// 打击序列（ELG-RANK-03/04）
// ============================================================================

SequenceResult EntityLedger::addToSequence(const SequenceInput& in) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    SequenceResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.missionId = in.missionId;
    res.entityId = in.entityId;
    if (!st.def.loaded) {
        res.code = 1005;
        res.message = "policies not loaded";
        return res;
    }
    auto mit = st.missions.find(in.missionId);
    if (mit == st.missions.end()) {
        res.code = 1004;
        res.message = "mission not found";
        return res;
    }
    MissionState& m = mit->second;
    auto eit = m.entities.find(in.entityId);
    if (eit == m.entities.end()) {
        res.code = 1004;
        res.message = "entity not found";
        return res;
    }
    res.sequence = m.sequence;
    for (const auto& e : m.sequence) {
        if (e.entityId == in.entityId) {
            res.code = 0;
            res.message = "already in sequence";
            res.status = "already-in-sequence";
            res.idempotent = true;  // 幂等：重复加入不改变序列（ELG-RANK-03）
            ++st.metrics.actionIdempotent;
            return res;
        }
    }
    if (st.def.rank.sequenceLimit > 0 &&
        static_cast<int>(m.sequence.size()) >= st.def.rank.sequenceLimit) {
        res.code = 1003;
        res.message = "sequence limit reached";
        res.status = "rejected";
        res.unmet.push_back(UnmetItem{"$sequence-limit", "sequence limit reached by rules",
                                      std::to_string(st.def.rank.sequenceLimit)});
        ++st.metrics.actionRejected;
        return res;
    }
    MissionState backup = m;
    SequenceEntry entry;
    entry.entityId = eit->second.id;
    entry.no = eit->second.no;
    entry.addedAt = now;
    entry.actor = in.operatorId;
    entry.reason = in.reason;
    const int pos = (in.position >= 0 && in.position <= static_cast<int>(m.sequence.size()))
                        ? in.position
                        : static_cast<int>(m.sequence.size());
    m.sequence.insert(m.sequence.begin() + pos, entry);
    for (std::size_t i = 0; i < m.sequence.size(); ++i) {
        m.sequence[i].position = static_cast<int>(i);
    }
    SequenceAuditEntry a;
    a.at = now;
    a.actor = in.operatorId;
    a.action = "add";
    a.entityId = entry.entityId;
    a.no = entry.no;
    a.position = pos;
    a.reason = in.reason;
    m.sequenceAudit.push_back(a);
    if (!st.persistLocked(m)) {
        m = std::move(backup);
        res.code = 1005;
        res.message = "store save failed";
        return res;
    }
    ++st.metrics.actions;
    res.code = 0;
    res.message = "added";
    res.status = "added";
    res.sequence = m.sequence;
    st.emitEntityChanged(in.missionId, eit->second, "sequence-add", std::to_string(pos), now);
    AuditEntry au;
    au.at = now;
    au.actor = in.operatorId;
    au.action = "sequence-add";
    au.target = entry.entityId;
    au.detail = "position=" + std::to_string(pos);
    st.audit(au);
    return res;
}

SequenceResult EntityLedger::removeFromSequence(const SequenceInput& in) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    SequenceResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.missionId = in.missionId;
    res.entityId = in.entityId;
    auto mit = st.missions.find(in.missionId);
    if (mit == st.missions.end()) {
        res.code = 1004;
        res.message = "mission not found";
        return res;
    }
    MissionState& m = mit->second;
    res.sequence = m.sequence;
    int pos = -1;
    for (std::size_t i = 0; i < m.sequence.size(); ++i) {
        if (m.sequence[i].entityId == in.entityId) pos = static_cast<int>(i);
    }
    if (pos < 0) {
        res.code = 0;
        res.message = "not in sequence";
        res.status = "not-in-sequence";
        res.idempotent = true;  // 幂等：重复移出不改变序列
        ++st.metrics.actionIdempotent;
        return res;
    }
    MissionState backup = m;
    const int no = m.sequence[pos].no;
    m.sequence.erase(m.sequence.begin() + pos);
    for (std::size_t i = 0; i < m.sequence.size(); ++i) {
        m.sequence[i].position = static_cast<int>(i);  // 移出后序号键稳定（重新连续编号）
    }
    SequenceAuditEntry a;
    a.at = now;
    a.actor = in.operatorId;
    a.action = "remove";
    a.entityId = in.entityId;
    a.no = no;
    a.position = pos;
    a.reason = in.reason;
    m.sequenceAudit.push_back(a);
    if (!st.persistLocked(m)) {
        m = std::move(backup);
        res.code = 1005;
        res.message = "store save failed";
        return res;
    }
    ++st.metrics.actions;
    res.code = 0;
    res.message = "removed";
    res.status = "removed";
    res.sequence = m.sequence;
    AuditEntry au;
    au.at = now;
    au.actor = in.operatorId;
    au.action = "sequence-remove";
    au.target = in.entityId;
    au.detail = "position=" + std::to_string(pos);
    st.audit(au);
    return res;
}

std::vector<SequenceEntry> EntityLedger::sequence(const std::string& missionId) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    auto mit = st.missions.find(missionId);
    if (mit == st.missions.end()) return {};
    return mit->second.sequence;
}

std::vector<SequenceAuditEntry> EntityLedger::sequenceAudit(const std::string& missionId) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    auto mit = st.missions.find(missionId);
    if (mit == st.missions.end()) return {};
    return mit->second.sequenceAudit;
}

}  // namespace entity_ledger
