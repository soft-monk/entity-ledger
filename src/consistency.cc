// entity-ledger · src/consistency.cc —— 编号与一致性（ELG-ID）
//
// 这是初稿"待确认问题清单"第 12 项（同一场景内目标编号与类型在不同界面不一致）的**唯一收口点**：
//   · `visibleSet()`      —— protocol.md CTR-EN-06：某阶段应可见的实体集合 MUST 由本引擎提供，
//                            界面 MUST NOT 自行过滤（自行过滤正是"五个/六个/七个"的根因）
//   · `checkConsistency()`—— CTR-EN-08 / ELG-ID-02：逐条差异报告，可定位到**具体 no 与具体视图**
//   · CTR-EN-05：同一任务内 id ↔ no ↔ 类型 的映射 MUST 在全部阶段、全部视图下强一致
//   · CTR-EN-07 / ELG-ID-04：类型重判 MUST 走显式动作并留痕；无留痕的类型漂移 MUST 被检出
//
// 差异种类（机制 token，非业务词）：
//   presence/unknown   视图引用了台账里没有的实体
//   presence/missing   同一 no 在某视图缺席而在另一视图在场（"五个 vs 七个"）
//   presence/duplicate 同一视图内 no 重复
//   no/mismatch        同一 id 在两处编号不同
//   type/mismatch      类型与台账不一致（且台账无重判留痕可解释）
//   type/stale         视图渲染的是已被显式重判取代的旧类型（留痕在 reclassifications[]）
//   type/unknown       类型不在规则声明内
//   flag:<key>/missing | extra   旗标（如"高价值"）标记的持有者在视图间不一致（002 vs 003）
#include "internal.h"

#include <algorithm>
#include <cmath>

namespace entity_ledger {

namespace {

using detail::Definition;
using detail::MissionState;
using detail::PhaseFilterRule;
using detail::State;
using detail::ViewRule;

std::string labelOf(const ViewSnapshot& s) { return s.viewName.empty() ? s.viewKey : s.viewName; }

/// 视图过滤判定（ELG-ID-03：过滤口径来自规则，界面不再各自实现）
/// 返回空串 = 可见；否则返回机制 token 原因
std::string excludeReason(const EntityRecord& rec, const PhaseFilterRule* f, bool filterMatched) {
    if (rec.retired) return "retired";
    if (!filterMatched || f == nullptr) return "phase";
    if (!f->includeTypes.empty()) {
        if (std::find(f->includeTypes.begin(), f->includeTypes.end(), rec.typeKey) ==
            f->includeTypes.end()) {
            return "type";
        }
    }
    if (std::find(f->excludeTypes.begin(), f->excludeTypes.end(), rec.typeKey) !=
        f->excludeTypes.end()) {
        return "type";
    }
    if (f->minConfidence > 0.0 && rec.confidence < f->minConfidence) return "confidence";
    for (const auto& g : f->requireFlags) {
        if (std::find(rec.flags.begin(), rec.flags.end(), g) == rec.flags.end()) {
            return "flag-required";
        }
    }
    for (const auto& g : f->excludeFlags) {
        if (std::find(rec.flags.begin(), rec.flags.end(), g) != rec.flags.end()) {
            return "flag-excluded";
        }
    }
    return "";
}

VisibleItem makeVisibleItem(const Definition& def, const EntityRecord& rec) {
    VisibleItem it;
    it.id = rec.id;
    it.no = rec.no;
    it.typeKey = rec.typeKey;
    it.typeName = def.typeName(rec.typeKey);
    it.flags = rec.flags;
    it.dynamicState = rec.dynamicState;
    it.threatBand = rec.threatBand;
    it.status = rec.status;
    it.threatScore = rec.threatScore;
    it.confidence = rec.confidence;
    it.lng = rec.lng;
    it.lat = rec.lat;
    return it;
}

}  // namespace

// ============================================================================
// 阶段可见集合（ELG-ID-03 / CTR-EN-06）
// ============================================================================

VisibleSetResult EntityLedger::visibleSet(const VisibleSetRequest& req) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    VisibleSetResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.missionId = req.missionId;
    res.viewKey = req.viewKey;
    res.scenarioKey = req.scenarioKey;
    res.basis = "current-state";
    if (req.phase.has_value()) res.phaseKey = req.phase->phaseKey;

    if (!st.def.loaded) {
        res.code = 1005;
        res.message = "policies not loaded";
        return res;
    }
    const ViewRule* view = st.def.findView(req.viewKey);
    if (!view) {
        // 视图口径由规则声明；未声明即无法回答"应可见集合" → 拒绝而非静默返回全集
        res.code = 1000;
        res.message = "unknown view: " + req.viewKey;
        return res;
    }
    auto mit = st.missions.find(req.missionId);
    if (mit == st.missions.end()) {
        res.code = 1004;
        res.message = "mission not found";
        return res;
    }
    res.viewName = view->name;

    const PhaseFilterRule* f = st.def.filterFor(*view, res.phaseKey);
    const bool filterMatched = (f != nullptr);
    const MissionState& m = mit->second;
    for (const auto& id : m.order) {
        auto it = m.entities.find(id);
        if (it == m.entities.end()) continue;
        const EntityRecord& rec = it->second;
        const std::string why = excludeReason(rec, f, filterMatched);
        if (why.empty()) {
            res.items.push_back(makeVisibleItem(st.def, rec));
        } else if (req.includeExcluded) {
            ExcludedItem e;
            e.id = rec.id;
            e.no = rec.no;
            e.reason = why;
            res.excludedItems.push_back(e);
        }
    }
    std::stable_sort(res.items.begin(), res.items.end(),
                     [](const VisibleItem& a, const VisibleItem& b) { return a.no < b.no; });
    std::stable_sort(res.excludedItems.begin(), res.excludedItems.end(),
                     [](const ExcludedItem& a, const ExcludedItem& b) { return a.no < b.no; });
    res.total = static_cast<int>(res.items.size());
    res.excluded = static_cast<int>(res.excludedItems.size());
    res.code = 0;
    res.message = "ok";
    return res;
}

// ============================================================================
// 一致性检查（ELG-ID-02/04/05 / CTR-EN-08）
// ============================================================================

ConsistencyReport EntityLedger::checkConsistency(const ConsistencyRequest& req) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    ConsistencyReport rep;
    const int64_t now = st.nowLocked();
    rep.ts = now;
    rep.missionId = req.missionId;
    rep.checkedViews = static_cast<int>(req.views.size());
    if (req.phase.has_value()) rep.phaseKey = req.phase->phaseKey;

    if (!st.def.loaded) {
        rep.code = 1005;
        rep.message = "policies not loaded";
        return rep;
    }
    auto mit = st.missions.find(req.missionId);
    if (mit == st.missions.end()) {
        rep.code = 1004;
        rep.message = "mission not found";
        return rep;
    }
    const MissionState& m = mit->second;

    // 台账索引
    std::map<std::string, const EntityRecord*> byId;
    std::map<int, const EntityRecord*> byNo;
    for (const auto& id : m.order) {
        auto it = m.entities.find(id);
        if (it == m.entities.end()) continue;
        byId[it->second.id] = &it->second;
        if (!it->second.retired) byNo[it->second.no] = &it->second;
    }

    // 重判留痕（"允许并留痕"的证据面）
    for (const auto& id : m.order) {
        auto it = m.entities.find(id);
        if (it == m.entities.end()) continue;
        for (const auto& t : it->second.trace) {
            if (t.field == "type" && t.action == "reclassify") {
                ReclassifyRecord r;
                r.id = it->second.id;
                r.no = it->second.no;
                r.fromType = t.from;
                r.toType = t.to;
                r.at = t.at;
                r.operatorId = t.operatorId;
                r.reason = t.reason;
                rep.reclassifications.push_back(r);
            }
        }
    }

    std::vector<std::vector<int>> perNo(req.views.size());  // 视图下标 → 该视图内的 no
    std::map<int, std::vector<std::string>> nosToLabels;    // no → 出现过它的视图展示名

    for (std::size_t vi = 0; vi < req.views.size(); ++vi) {
        const ViewSnapshot& snap = req.views[vi];
        const std::string label = labelOf(snap);
        std::set<int> seenInView;
        for (const auto& item : snap.items) {
            ++rep.checkedItems;
            const EntityRecord* rec = nullptr;
            if (!item.id.empty()) {
                auto it = byId.find(item.id);
                if (it != byId.end()) rec = it->second;
            } else if (item.no > 0) {
                auto it = byNo.find(item.no);
                if (it != byNo.end()) rec = it->second;
            }

            if (!rec) {
                DiffItem d;
                d.no = item.no;
                d.field = "presence";
                d.views.push_back(label);
                d.kind = "unknown";
                d.id = item.id;
                d.expected = "known";
                d.actual = "unknown";
                d.phaseKey = snap.phaseKey;
                d.reason = "view references an entity absent from the ledger";
                rep.diffs.push_back(d);
                continue;
            }
            if (seenInView.count(rec->no)) {
                DiffItem d;
                d.no = rec->no;
                d.field = "presence";
                d.views.push_back(label);
                d.kind = "duplicate";
                d.id = rec->id;
                d.expected = "unique";
                d.actual = "duplicated";
                d.phaseKey = snap.phaseKey;
                d.reason = "same no appears twice in one view";
                rep.diffs.push_back(d);
            }
            seenInView.insert(rec->no);
            perNo[vi].push_back(rec->no);
            nosToLabels[rec->no].push_back(label);

            if (item.id.empty()) {
                DiffItem d;
                d.no = rec->no;
                d.field = "id";
                d.views.push_back(label);
                d.kind = "missing";
                d.id = rec->id;
                d.expected = "present";
                d.actual = "absent";
                d.phaseKey = snap.phaseKey;
                d.reason = "view item carries no id (protocol.md CTR-EN-02)";
                rep.diffs.push_back(d);
            } else if (item.no > 0 && item.no != rec->no) {
                DiffItem d;
                d.no = rec->no;
                d.field = "no";
                d.views.push_back(label);
                d.kind = "mismatch";
                d.id = rec->id;
                d.expected = std::to_string(rec->no);
                d.actual = std::to_string(item.no);
                d.phaseKey = snap.phaseKey;
                d.reason = "same id carries a different no";
                rep.diffs.push_back(d);
            }

            if (!item.typeKey.empty() && item.typeKey != rec->typeKey) {
                DiffItem d;
                d.no = rec->no;
                d.field = "type";
                d.views.push_back(label);
                d.kind = "mismatch";
                d.id = rec->id;
                d.expected = rec->typeKey;
                d.actual = item.typeKey;
                d.phaseKey = snap.phaseKey;
                if (!st.def.findType(item.typeKey)) {
                    d.kind = "unknown";
                    d.reason = "reported type is not declared by rules";
                } else {
                    bool superseded = false;
                    for (const auto& t : rec->trace) {
                        if (t.field == "type" && t.from == item.typeKey) superseded = true;
                    }
                    if (superseded) {
                        d.kind = "stale";
                        d.reason = "reported type was superseded by a reclassification";
                    } else {
                        d.reason = "reported type differs from the ledger (no reclassification trace)";
                    }
                }
                rep.diffs.push_back(d);
            }

            if (snap.flagsRendered) {
                // 旗标不一致 MUST 能定位到具体编号与**两个**视图：本视图 + 与台账一致的对侧视图
                const auto referenceLabelFor = [&](int no, const std::string& flagKey,
                                                   bool wantMarked) -> std::string {
                    for (const auto& other : req.views) {
                        if (labelOf(other) == label) continue;
                        if (!other.flagsRendered) continue;
                        for (const auto& oi : other.items) {
                            if (oi.no != no) continue;
                            const bool marked =
                                std::find(oi.flagKeys.begin(), oi.flagKeys.end(), flagKey) !=
                                oi.flagKeys.end();
                            if (marked == wantMarked) return labelOf(other);
                        }
                    }
                    return label;
                };
                for (const auto& g : rec->flags) {
                    if (std::find(item.flagKeys.begin(), item.flagKeys.end(), g) ==
                        item.flagKeys.end()) {
                        DiffItem d;
                        d.no = rec->no;
                        d.field = "flag:" + g;
                        d.views.push_back(label);
                        const std::string ref = referenceLabelFor(rec->no, g, true);
                        if (ref != label) d.views.push_back(ref);
                        d.kind = "missing";
                        d.id = rec->id;
                        d.expected = "present";
                        d.actual = "absent";
                        d.phaseKey = snap.phaseKey;
                        d.reason = "flag holder not marked in this view";
                        rep.diffs.push_back(d);
                    }
                }
                for (const auto& g : item.flagKeys) {
                    if (std::find(rec->flags.begin(), rec->flags.end(), g) == rec->flags.end()) {
                        DiffItem d;
                        d.no = rec->no;
                        d.field = "flag:" + g;
                        d.views.push_back(label);
                        const std::string ref = referenceLabelFor(rec->no, g, false);
                        if (ref != label) d.views.push_back(ref);
                        d.kind = "extra";
                        d.id = rec->id;
                        d.expected = "absent";
                        d.actual = "present";
                        d.phaseKey = snap.phaseKey;
                        d.reason = "flag marked on an entity that does not hold it";
                        rep.diffs.push_back(d);
                    }
                }
            }
        }
    }

    // ---- 跨视图存在性：同一 no 在一部分视图缺席（"五个 vs 七个"的定位）----
    if (req.views.size() > 1) {
        for (const auto& kv : nosToLabels) {
            const int no = kv.first;
            const std::vector<std::string>& labels = kv.second;
            if (labels.size() >= req.views.size()) continue;
            auto nit = byNo.find(no);
            const std::string refLabel = labels.front();
            for (const auto& snap : req.views) {
                const std::string label = labelOf(snap);
                if (std::find(labels.begin(), labels.end(), label) != labels.end()) continue;
                DiffItem d;
                d.no = no;
                d.field = "presence";
                d.views.push_back(label);
                d.views.push_back(refLabel);
                d.kind = "missing";
                d.id = nit == byNo.end() ? std::string() : nit->second->id;
                d.expected = "present";
                d.actual = "absent";
                d.phaseKey = snap.phaseKey;
                d.reason = "no present in the other view but absent here";
                rep.diffs.push_back(d);
            }
        }
    }

    // ---- 跨阶段集合变化（ELG-ID-03："跨阶段集合变化可解释"）----
    std::vector<std::string> phases;
    for (const auto& snap : req.views) {
        if (snap.phaseKey.empty()) continue;
        if (std::find(phases.begin(), phases.end(), snap.phaseKey) == phases.end()) {
            phases.push_back(snap.phaseKey);
        }
    }
    if (req.phase.has_value() && !req.phase->phaseKey.empty() &&
        std::find(phases.begin(), phases.end(), req.phase->phaseKey) == phases.end()) {
        phases.push_back(req.phase->phaseKey);
    }
    std::string viewKey = req.viewKey;
    if (viewKey.empty() && !req.views.empty()) viewKey = req.views.front().viewKey;
    if (!viewKey.empty()) {
        std::vector<int> base;
        bool hasBase = false;
        for (const auto& p : phases) {
            VisibleSetRequest vr;
            vr.missionId = req.missionId;
            vr.viewKey = viewKey;
            vr.scenarioKey = req.scenarioKey;
            PhaseContext pc;
            pc.phaseKey = p;
            pc.scenarioKey = req.scenarioKey;
            pc.missionId = req.missionId;
            vr.phase = pc;
            const VisibleSetResult vs = visibleSet(vr);
            PhaseDelta delta;
            delta.phaseKey = p;
            delta.basis = "current-state";
            delta.count = vs.total;
            std::vector<int> cur;
            for (const auto& it : vs.items) cur.push_back(it.no);
            if (!hasBase) {
                base = cur;
                hasBase = true;
            } else {
                for (int n : cur) {
                    if (std::find(base.begin(), base.end(), n) == base.end()) {
                        delta.addedNos.push_back(n);
                    }
                }
                for (int n : base) {
                    if (std::find(cur.begin(), cur.end(), n) == cur.end()) {
                        delta.removedNos.push_back(n);
                    }
                }
            }
            rep.phaseDeltas.push_back(delta);
        }
    }

    // ---- 与引擎"应可见集合"对账（界面 MUST NOT 自行过滤）----
    if (req.phase.has_value() && !viewKey.empty()) {
        VisibleSetRequest vr;
        vr.missionId = req.missionId;
        vr.viewKey = viewKey;
        vr.scenarioKey = req.scenarioKey;
        vr.phase = req.phase;
        vr.includeExcluded = false;
        const VisibleSetResult vs = visibleSet(vr);
        if (vs.code == 0) {
            for (const auto& it : vs.items) rep.expectedVisible.push_back(EntityRef{it.id, it.no});
            // 引擎期望可见但所有快照都没有 → 界面自行过滤的证据
            for (const auto& it : vs.items) {
                if (nosToLabels.count(it.no)) continue;
                DiffItem d;
                d.no = it.no;
                d.field = "presence";
                d.views.push_back(viewKey);
                d.kind = "missing";
                d.id = it.id;
                d.expected = "present";
                d.actual = "absent";
                d.phaseKey = req.phase->phaseKey;
                d.reason = "engine-expected visible entity absent from every snapshot";
                rep.diffs.push_back(d);
            }
        }
    }

    rep.consistent = rep.diffs.empty();
    rep.code = 0;
    rep.message = rep.consistent ? "consistent" : "differences-found";

    ++st.metrics.consistencyChecks;
    st.metrics.consistencyDiffs += static_cast<int64_t>(rep.diffs.size());

    if (st.sink) {
        ConsistencyEvent e;
        e.missionId = req.missionId;
        e.diffs = rep.diffs;
        e.consistent = rep.consistent;
        e.checkedViews = rep.checkedViews;
        e.phaseKey = rep.phaseKey;
        e.ts = now;
        try {
            st.sink->onConsistency(e);
        } catch (...) {
            ++st.metrics.sinkErrors;
        }
    }
    return rep;
}

}  // namespace entity_ledger
