// entity-ledger · src/engine.cc —— 引擎门面与实体登记（ELG-REG / ELG-ID 的登记侧）
//
// 权威依据：
//   · protocol.md §2 实体标识（CTR-EN-01..08）、§3 错误码、§5 规则包
//   · 需求专篇 ELG-REG-01..06（类型由规则声明 / 台账字段 / 任务内 no 唯一 / 多源去重 /
//     置信度融合 / 动态状态机）、ELG-ID-01/04/05（编号规则 / 类型重判留痕 / 旗标唯一性）
//   · ELG-NFR-01/02/03（零依赖 / 反向接口 / 确定性）
#include "internal.h"

#include <algorithm>
#include <cmath>
#include <fstream>

namespace entity_ledger {

namespace {

using detail::MissionState;
using detail::State;

/// 机制短语（ASCII；文案归规则包与宿主）
std::string reasonOf(const std::string& s) { return s; }

}  // namespace

// ============================================================================
// 构造 / 依赖注入
// ============================================================================

EntityLedger::EntityLedger() : impl_(new Impl()) {
    impl_->st.systemClock = std::make_shared<SystemClock>();
}

EntityLedger::EntityLedger(const EntityLedgerOptions& opts) : impl_(new Impl()) {
    impl_->st.systemClock = std::make_shared<SystemClock>();
    impl_->st.store = opts.store;
    impl_->st.clock = opts.clock;
    impl_->st.sink = opts.sink;
    impl_->st.log = opts.log;
}

EntityLedger::~EntityLedger() = default;
EntityLedger::EntityLedger(EntityLedger&& o) noexcept : impl_(std::move(o.impl_)) {}
EntityLedger& EntityLedger::operator=(EntityLedger&& o) noexcept {
    impl_ = std::move(o.impl_);
    return *this;
}

void EntityLedger::setStore(std::shared_ptr<IEntityStore> store) {
    std::lock_guard<std::recursive_mutex> lk(impl_->st.mtx);
    impl_->st.store = std::move(store);
}

void EntityLedger::setClock(std::shared_ptr<IClock> clock) {
    std::lock_guard<std::recursive_mutex> lk(impl_->st.mtx);
    impl_->st.clock = std::move(clock);
}

void EntityLedger::setSink(std::shared_ptr<IEntitySink> sink) {
    std::lock_guard<std::recursive_mutex> lk(impl_->st.mtx);
    impl_->st.sink = std::move(sink);
}

void EntityLedger::setLog(std::shared_ptr<ILogSink> log) {
    std::lock_guard<std::recursive_mutex> lk(impl_->st.mtx);
    impl_->st.log = std::move(log);
}

const char* EntityLedger::errorCodeName(int code) { return entity_ledger::errorCodeName(code); }

// ============================================================================
// 规则包装载
// ============================================================================

LoadResult EntityLedger::loadPolicies(const json& pkg) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    detail::ValidateOutcome out = detail::buildDefinition(st.def, pkg);
    LoadResult res;
    res.code = out.code;
    res.message = out.message;
    res.issues = out.issues;
    if (out.code == 0) {
        st.def = out.def;
        st.metrics.unknownFields = static_cast<int64_t>(st.def.unknownFields);
    }
    res.data = definitionInfo();
    return res;
}

LoadResult EntityLedger::loadPoliciesFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        LoadResult res;
        res.code = 1000;
        res.message = "cannot open policy file";
        res.issues.push_back(LoadIssue{path, "", "cannot open policy file"});
        res.data = definitionInfo();
        return res;
    }
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    json pkg;
    try {
        pkg = json::parse(text);
    } catch (const std::exception& ex) {
        LoadResult res;
        res.code = 1000;
        res.message = "invalid JSON in policy file";
        res.issues.push_back(LoadIssue{path, "", std::string("invalid JSON: ") + ex.what()});
        res.data = definitionInfo();
        return res;
    }
    return loadPolicies(pkg);
}

LoadResult EntityLedger::validatePolicies(const json& pkg) {
    detail::ValidateOutcome out = detail::buildDefinition(detail::Definition{}, pkg);
    LoadResult res;
    res.code = out.code;
    res.message = out.message;
    res.issues = out.issues;
    if (out.code == 0) {
        res.data.loaded = true;
        res.data.policiesNamespace = out.def.ns;
        res.data.schemaVersion = out.def.schemaVersion;
        res.data.definitionVersion = out.def.version;
        res.data.digest = out.def.digest;
        res.data.policiesMajor = out.def.major;
    }
    return res;
}

DefinitionInfo EntityLedger::definitionInfo() const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    const detail::Definition& d = st.def;
    DefinitionInfo info;
    info.loaded = d.loaded;
    info.policiesNamespace = d.ns;
    info.schemaVersion = d.schemaVersion;
    info.definitionVersion = d.version;
    info.digest = d.digest;
    info.policiesMajor = d.major;
    info.entityTypeCount = static_cast<int>(d.types.size());
    info.actionCount = static_cast<int>(d.actions.size());
    info.viewCount = static_cast<int>(d.views.size());
    info.factorCount = static_cast<int>(d.factors.size());
    info.bandCount = static_cast<int>(d.bands.size());
    info.flagCount = static_cast<int>(d.flags.size());
    info.relationKindCount = static_cast<int>(d.relations.kinds.size());
    info.dynamicStateCount = static_cast<int>(d.states.keys.size());
    info.entityTypeKeys = d.typeOrder;
    for (const auto& a : d.actions) info.actionKeys.push_back(a.key);
    for (const auto& v : d.views) info.viewKeys.push_back(v.key);
    for (const auto& b : d.bands) info.bandKeys.push_back(b.key);
    info.warnings = d.warnings;
    return info;
}

json EntityLedger::effectivePolicies() const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    json out = detail::definitionToJson(st.def);
    out["definitionVersion"] = st.def.version;
    out["digest"] = st.def.digest;
    return out;
}

std::vector<std::string> EntityLedger::entityTypeKeys() const {
    std::lock_guard<std::recursive_mutex> lk(impl_->st.mtx);
    return impl_->st.def.typeOrder;
}

std::vector<std::string> EntityLedger::actionKeys() const {
    std::lock_guard<std::recursive_mutex> lk(impl_->st.mtx);
    std::vector<std::string> out;
    for (const auto& a : impl_->st.def.actions) out.push_back(a.key);
    return out;
}

std::vector<std::string> EntityLedger::viewKeys() const {
    std::lock_guard<std::recursive_mutex> lk(impl_->st.mtx);
    std::vector<std::string> out;
    for (const auto& v : impl_->st.def.views) out.push_back(v.key);
    return out;
}

std::optional<EntityType> EntityLedger::entityType(const std::string& key) const {
    std::lock_guard<std::recursive_mutex> lk(impl_->st.mtx);
    const EntityType* t = impl_->st.def.findType(key);
    if (!t) return std::nullopt;
    return *t;
}

std::optional<ActionDef> EntityLedger::actionDef(const std::string& key) const {
    std::lock_guard<std::recursive_mutex> lk(impl_->st.mtx);
    const ActionDef* a = impl_->st.def.findAction(key);
    if (!a) return std::nullopt;
    return *a;
}

std::string EntityLedger::resolveViewName(const std::string& viewKey) const {
    std::lock_guard<std::recursive_mutex> lk(impl_->st.mtx);
    return impl_->st.def.viewName(viewKey);
}

std::string EntityLedger::resolveTypeName(const std::string& typeKey) const {
    std::lock_guard<std::recursive_mutex> lk(impl_->st.mtx);
    return impl_->st.def.typeName(typeKey);
}

// ============================================================================
// 登记：编号、去重、置信度融合
// ============================================================================

namespace {

/// 置信度融合（ELG-REG-05）：按规则权重加权，多源加成可配；输出逐项贡献（可复算）
double fuseConfidence(const detail::Definition& def, const std::vector<SourceRef>& sources,
                      std::vector<ConfidenceContribution>& out) {
    out.clear();
    if (sources.empty()) return 0.0;
    int64_t totalW = 0;
    int64_t acc = 0;
    for (const auto& s : sources) {
        const detail::SourceDef* sd = def.findSource(s.source);
        const int64_t w = sd ? sd->weightPpm : 1000000;
        totalW += w;
        const int64_t cppm = static_cast<int64_t>(std::llround(detail::clamp01(s.confidence) * 1000000.0));
        acc += w * cppm;
        ConfidenceContribution cc;
        cc.source = s.source;
        cc.value = s.confidence;
        cc.weightPpm = static_cast<int>(w);
        out.push_back(cc);
    }
    if (totalW <= 0) return 0.0;
    if (def.confidence.method == "max") {
        double best = 0.0;
        for (const auto& s : sources) best = std::max(best, detail::clamp01(s.confidence));
        for (auto& cc : out) {
            cc.contribution = static_cast<int>(
                std::llround(detail::clamp01(cc.value) * 1000000.0));
        }
        return best;
    }
    for (auto& cc : out) {
        const detail::SourceDef* sd = def.findSource(cc.source);
        const int64_t w = sd ? sd->weightPpm : 1000000;
        const int64_t cppm = static_cast<int64_t>(std::llround(detail::clamp01(cc.value) * 1000000.0));
        cc.contribution = static_cast<int>(detail::roundHalfUp(w * cppm, totalW));
    }
    double base = static_cast<double>(acc) / static_cast<double>(totalW);  // micro
    base /= 1000000.0;
    double bonus = 0.0;
    if (sources.size() > 1 && def.confidence.multiSourceBonus > 0.0) {
        bonus = def.confidence.multiSourceBonus * static_cast<double>(sources.size() - 1);
        if (def.confidence.maxBonus > 0.0) bonus = std::min(bonus, def.confidence.maxBonus);
    }
    return detail::clamp01(base + bonus);
}

/// 去重判定（ELG-REG-04 / R3：默认保守 —— 宁可标多源不合并）
struct DedupVerdict {
    const EntityRecord* target = nullptr;
    std::vector<MergeCandidate> candidates;
};

DedupVerdict dedupVerdict(const State& st, const MissionState& m, const RegisterInput& in,
                          const std::vector<SourceRef>& sources, int64_t now) {
    DedupVerdict v;
    const detail::Definition& def = st.def;
    if (def.dedup.mode == "off" || def.dedup.keys.empty()) return v;

    const auto hasKey = [&](const char* k) {
        return std::find(def.dedup.keys.begin(), def.dedup.keys.end(), std::string(k)) !=
               def.dedup.keys.end();
    };

    int64_t bestDist = -1;
    const EntityRecord* best = nullptr;
    const EntityRecord* bestPartial = nullptr;
    int bestPartialScore = 0;

    for (const auto& id : m.order) {
        auto it = m.entities.find(id);
        if (it == m.entities.end()) continue;
        const EntityRecord& e = it->second;
        if (e.retired) continue;
        std::vector<std::string> matched;
        std::vector<std::string> unmatched;
        int64_t dist = -1;
        if (def.dedup.spaceRadiusM > 0) {
            dist = static_cast<int64_t>(std::llround(
                detail::haversineM(in.lng, in.lat, e.lng, e.lat, def.earthRadiusM)));
        }
        for (const auto& k : def.dedup.keys) {
            bool ok = false;
            if (k == "obsKey") {
                if (!in.obsKey.empty()) {
                    auto oit = m.obsKeys.find(e.id);
                    if (oit != m.obsKeys.end() && oit->second.count(in.obsKey)) ok = true;
                }
            } else if (k == "typeKey") {
                ok = (e.typeKey == in.typeKey);
            } else if (k == "space") {
                ok = (def.dedup.spaceRadiusM > 0 && dist >= 0 && dist <= def.dedup.spaceRadiusM);
            } else if (k == "dynamicState") {
                ok = (!in.dynamicState.empty() && e.dynamicState == in.dynamicState);
            }
            if (ok) matched.push_back(k);
            else unmatched.push_back(k);
        }
        const bool all = unmatched.empty();
        const bool any = !matched.empty();
        const bool typeOk = !def.dedup.requireTypeMatch || e.typeKey == in.typeKey;

        if (dist >= 0 && (bestDist < 0 || dist < bestDist) && all && typeOk) {
            bestDist = dist;
            best = &e;
        }
        if (any && !all) {
            const int score = static_cast<int>(matched.size());
            if (score > bestPartialScore) {
                bestPartialScore = score;
                bestPartial = &e;
            }
            MergeCandidate cand;
            cand.id = e.id;
            cand.no = e.no;
            cand.typeKey = e.typeKey;
            cand.distanceM = std::max<int64_t>(0, dist);
            cand.matchedKeys = matched;
            cand.unmatchedKeys = unmatched;
            cand.confidence = e.confidence;
            v.candidates.push_back(cand);
        }
        if (all && typeOk && def.dedup.mode == "aggressive") {
            v.target = &e;
            return v;
        }
    }
    (void)now;
    if (def.dedup.mode == "conservative" && best) {
        v.target = best;
    } else if (def.dedup.mode == "aggressive" && bestPartial) {
        v.target = bestPartial;
    } else if (def.dedup.mode == "conservative" && !best && def.dedup.onAmbiguous == "merge" &&
               bestPartial) {
        v.target = bestPartial;
    }
    return v;
}

/// 编号分配（ELG-ID-01 / CTR-EN-03/04）
bool assignNumber(const detail::Definition& def, MissionState& m, int requested, int& outNo,
                  std::string& reason) {
    if (requested > 0) {
        if (m.usedNos.count(requested)) {
            reason = "duplicate no in mission";
            return false;
        }
        m.usedNos.insert(requested);
        m.nextNo = std::max(m.nextNo, requested + 1);
        outNo = requested;
        return true;
    }
    int n = m.nextNo > 0 ? m.nextNo : def.numbering.start;
    while (m.usedNos.count(n)) ++n;  // reuse=false：不复用；reuse=true 时 usedNos 已被释放
    m.usedNos.insert(n);
    m.nextNo = n + 1;
    outNo = n;
    return true;
}

std::string uniqueEntityId(const State& st, const MissionState& m, const std::string& missionId,
                           std::uint64_t startSerial) {
    std::uint64_t serial = startSerial;
    for (;;) {
        const std::string id = detail::makeEntityId(missionId, serial);
        bool taken = m.entities.count(id) > 0;
        if (!taken) {
            for (const auto& kv : st.missions) {
                if (kv.second.entities.count(id)) taken = true;
            }
        }
        if (!taken) return id;
        ++serial;
    }
}

void pushTrace(EntityRecord& rec, int64_t at, const std::string& field, const std::string& from,
               const std::string& to, const std::string& action, const std::string& operatorId,
               const std::string& reason) {
    EntityTrace t;
    t.at = at;
    t.field = field;
    t.from = from;
    t.to = to;
    t.action = action;
    t.operatorId = operatorId;
    t.reason = reason;
    rec.trace.push_back(t);
}

/// 评级写回（ELG-RATE：威胁等级是**算出来的**，不是读字段；与 assessThreat 同一条计算路径）
void applyAssessment(const State& st, const MissionState& m, EntityRecord& rec, int64_t now) {
    ThreatSnapshot snap = detail::snapshotOf(rec);
    bool refSet = false;
    double refLng = 0.0, refLat = 0.0;
    if (m.referenceSet) {
        refSet = true;
        refLng = m.referenceLng;
        refLat = m.referenceLat;
    }
    const ThreatAssessment a = computeAssessment(st.def, snap, refSet, refLng, refLat, now);
    rec.threatScore = a.score;
    rec.threatBand = a.band;
    rec.status = a.status;
    rec.assessed = true;
}

}  // namespace

RegisterResult EntityLedger::registerEntity(const RegisterInput& in) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    RegisterResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;

    if (!st.def.loaded) {
        res.code = 1005;
        res.message = "policies not loaded";
        return res;
    }
    if (in.missionId.empty()) {
        res.code = 1000;
        res.message = "missionId is required";
        return res;
    }
    if (in.typeKey.empty()) {
        res.code = 1000;
        res.message = "typeKey is required";
        return res;
    }
    if (!st.def.findType(in.typeKey)) {
        res.code = 1000;
        res.message = "unknown entity type: " + in.typeKey;
        return res;
    }
    for (std::size_t i = 0; i < in.flagKeys.size(); ++i) {
        if (!st.def.findFlag(in.flagKeys[i])) {
            res.code = 1000;
            res.message = "unknown flag: " + in.flagKeys[i];
            return res;
        }
    }

    MissionState& m = st.missionLocked(in.missionId);

    // 来源观测
    std::vector<SourceRef> sources;
    for (const auto& o : in.sources) {
        std::string key = o.source;
        if (key.empty()) key = st.def.confidence.defaultSource;
        if (key.empty() || !st.def.findSource(key)) {
            res.code = 1000;
            res.message = "unknown observation source: " + o.source;
            return res;
        }
        const detail::SourceDef* sd = st.def.findSource(key);
        bool merged = false;
        for (auto& s : sources) {
            if (s.source == key) {
                s.count += 1;
                s.confidence = o.confidence;
                s.lastAt = o.at != 0 ? o.at : now;
                if (s.firstAt == 0) s.firstAt = s.lastAt;
                merged = true;
            }
        }
        if (!merged) {
            SourceRef s;
            s.source = key;
            s.name = sd ? sd->name : key;
            s.confidence = o.confidence;
            s.count = 1;
            s.firstAt = o.at != 0 ? o.at : now;
            s.lastAt = s.firstAt;
            sources.push_back(s);
        }
    }
    if (sources.empty() && !st.def.confidence.defaultSource.empty()) {
        const detail::SourceDef* sd = st.def.findSource(st.def.confidence.defaultSource);
        SourceRef s;
        s.source = st.def.confidence.defaultSource;
        s.name = sd ? sd->name : s.source;
        s.confidence = detail::clamp01(in.confidence);
        s.count = 1;
        s.firstAt = now;
        s.lastAt = now;
        sources.push_back(s);
    }

    // 去重（保守默认：命中全部去重键才合并；部分命中 → 创建新实体并标注候选）
    const DedupVerdict verdict = dedupVerdict(st, m, in, sources, now);
    res.candidates = verdict.candidates;
    if (!res.candidates.empty()) {
        ++st.metrics.duplicatesFlagged;
    }

    std::string dynState = in.dynamicState;
    if (dynState.empty()) dynState = st.def.states.defaultState;
    if (!dynState.empty() && !st.def.hasState(dynState)) {
        res.code = 1000;
        res.message = "unknown dynamic state: " + dynState;
        return res;
    }

    if (verdict.target) {
        // ---- 合并到既有实体（同一实体的多来源观测；ELG-REG-04）----
        EntityRecord& rec = m.entities[verdict.target->id];
        const EntityRecord backup = rec;
        for (const auto& s : sources) {
            bool found = false;
            for (auto& cur : rec.sources) {
                if (cur.source == s.source) {
                    cur.count += s.count;
                    cur.confidence = s.confidence;
                    cur.lastAt = s.lastAt;
                    found = true;
                }
            }
            if (!found) rec.sources.push_back(s);
        }
        if (!in.obsKey.empty()) m.obsKeys[rec.id].insert(in.obsKey);
        rec.lng = in.lng;
        rec.lat = in.lat;
        if (in.alt != 0.0) rec.alt = in.alt;
        if (in.attributes.is_object() && !in.attributes.empty()) {
            for (auto it = in.attributes.begin(); it != in.attributes.end(); ++it) {
                rec.attributes[it.key()] = it.value();
            }
        }
        rec.confidence = in.sources.empty() && in.confidence > 0.0
                             ? detail::clamp01(in.confidence)
                             : fuseConfidence(st.def, rec.sources, res.contributions);
        if (!dynState.empty()) rec.dynamicState = dynState;
        rec.updatedAt = now;
        pushTrace(rec, now, "sources", "", std::to_string(rec.sources.size()), "obs-merge",
                  in.operatorId, "");
        applyAssessment(st, m, rec, now);
        if (!st.persistLocked(m)) {
            rec = backup;
            res.code = 1005;
            res.message = "store save failed";
            return res;
        }
        ++st.metrics.merges;
        ++st.metrics.updates;
        EntityRecord out = rec;
        detail::decorateEntity(st, m, out);
        res.code = 0;
        res.message = "merged";
        res.status = "merged";
        res.merged = true;
        res.data = out;
        st.emitEntityChanged(in.missionId, out, "obs-merge", "", now);
        st.emitTargetState(out, now);
        return res;
    }

    // ---- 新建实体 ----
    EntityRecord rec;
    int no = 0;
    std::string reason;
    MissionState backup = m;
    if (!assignNumber(st.def, m, in.no, no, reason)) {
        m = std::move(backup);
        res.code = 1000;
        res.message = reason.empty() ? "duplicate no in mission" : reason;
        return res;
    }
    rec.id = uniqueEntityId(st, m, in.missionId, static_cast<std::uint64_t>(no));
    rec.no = no;
    rec.missionId = in.missionId;
    rec.typeKey = in.typeKey;
    rec.typeName = st.def.typeName(in.typeKey);
    rec.lng = in.lng;
    rec.lat = in.lat;
    rec.alt = in.alt;
    rec.sources = sources;
    rec.confidence = in.sources.empty() && in.confidence > 0.0
                         ? detail::clamp01(in.confidence)
                         : fuseConfidence(st.def, rec.sources, res.contributions);
    rec.dynamicState = dynState;
    rec.attributes = in.attributes.is_object() ? in.attributes : json::object();
    rec.createdAt = now;
    rec.updatedAt = now;
    rec.priority = st.def.rank.defaultPriority;
    pushTrace(rec, now, "id", "", rec.id, "register", in.operatorId, "");

    for (const auto& f : in.flagKeys) {
        const FlagDef* fd = st.def.findFlag(f);
        if (fd && fd->unique) {
            bool taken = false;
            for (const auto& id : m.order) {
                auto it = m.entities.find(id);
                if (it == m.entities.end()) continue;
                const auto& fl = it->second.flags;
                if (std::find(fl.begin(), fl.end(), f) != fl.end()) taken = true;
            }
            if (taken) {
                res.code = 1003;
                res.message = "unique flag already held";
                res.unmet.push_back(UnmetItem{"$flag-unique", "flag already held in mission", f});
                return res;
            }
        }
        rec.flags.push_back(f);
    }

    applyAssessment(st, m, rec, now);

    m.order.push_back(rec.id);
    m.byNo[rec.no] = rec.id;
    if (!in.obsKey.empty()) m.obsKeys[rec.id].insert(in.obsKey);
    m.entities[rec.id] = rec;

    if (!st.persistLocked(m)) {
        m.entities.erase(rec.id);
        m.byNo.erase(rec.no);
        m.obsKeys.erase(rec.id);
        m.usedNos.erase(rec.no);
        m.order.pop_back();
        res.code = 1005;
        res.message = "store save failed";
        return res;
    }

    ++st.metrics.registrations;
    EntityRecord out = rec;
    detail::decorateEntity(st, m, out);
    res.code = 0;
    res.message = "created";
    res.status = "created";
    res.created = true;
    res.data = out;
    st.emitEntityChanged(in.missionId, out, "registered", "", now);
    st.emitTargetState(out, now);
    return res;
}

RegisterResult EntityLedger::updateObservation(const std::string& entityId, const SourceObs& obs) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    RegisterResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    if (!st.def.loaded) {
        res.code = 1005;
        res.message = "policies not loaded";
        return res;
    }
    std::string key = obs.source.empty() ? st.def.confidence.defaultSource : obs.source;
    if (key.empty() || !st.def.findSource(key)) {
        res.code = 1000;
        res.message = "unknown observation source: " + obs.source;
        return res;
    }
    for (auto& kv : st.missions) {
        MissionState& m = kv.second;
        auto eit = m.entities.find(entityId);
        if (eit == m.entities.end()) continue;
        EntityRecord& rec = eit->second;
        const EntityRecord backup = rec;
        const detail::SourceDef* sd = st.def.findSource(key);
        bool found = false;
        for (auto& s : rec.sources) {
            if (s.source == key) {
                s.count += 1;
                s.confidence = obs.confidence;
                s.lastAt = obs.at != 0 ? obs.at : now;
                found = true;
            }
        }
        if (!found) {
            SourceRef s;
            s.source = key;
            s.name = sd ? sd->name : key;
            s.confidence = obs.confidence;
            s.count = 1;
            s.firstAt = obs.at != 0 ? obs.at : now;
            s.lastAt = s.firstAt;
            rec.sources.push_back(s);
        }
        if (!obs.obsKey.empty()) m.obsKeys[rec.id].insert(obs.obsKey);
        rec.confidence = fuseConfidence(st.def, rec.sources, res.contributions);
        rec.updatedAt = now;
        pushTrace(rec, now, "confidence", "", std::to_string(rec.sources.size()), "obs-update",
                  "", "");
        applyAssessment(st, kv.second, rec, now);
        if (!st.persistLocked(m)) {
            rec = backup;
            res.code = 1005;
            res.message = "store save failed";
            return res;
        }
        ++st.metrics.updates;
        EntityRecord out = rec;
        detail::decorateEntity(st, m, out);
        res.code = 0;
        res.message = "updated";
        res.status = "updated";
        res.data = out;
        st.emitEntityChanged(kv.first, out, "obs-update", "", now);
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

std::optional<EntityRecord> EntityLedger::getEntity(const std::string& id) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    for (auto& kv : st.missions) {
        auto it = kv.second.entities.find(id);
        if (it == kv.second.entities.end()) continue;
        EntityRecord out = it->second;
        detail::decorateEntity(st, kv.second, out);
        return out;
    }
    return std::nullopt;
}

std::optional<EntityRecord> EntityLedger::getEntityByNo(const std::string& missionId,
                                                        int no) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    auto mit = st.missions.find(missionId);
    if (mit == st.missions.end()) return std::nullopt;
    auto it = mit->second.byNo.find(no);
    if (it == mit->second.byNo.end()) return std::nullopt;
    auto eit = mit->second.entities.find(it->second);
    if (eit == mit->second.entities.end()) return std::nullopt;
    EntityRecord out = eit->second;
    detail::decorateEntity(st, mit->second, out);
    return out;
}

std::vector<EntityRecord> EntityLedger::listEntities(const EntityQuery& q) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    std::vector<EntityRecord> out;
    auto mit = st.missions.find(q.missionId);
    if (mit == st.missions.end()) return out;
    const MissionState& m = mit->second;
    for (const auto& id : m.order) {
        auto it = m.entities.find(id);
        if (it == m.entities.end()) continue;
        const EntityRecord& rec = it->second;
        if (rec.retired && !q.includeRetired) continue;
        if (!q.typeKey.empty() && rec.typeKey != q.typeKey) continue;
        if (!q.dynamicState.empty() && rec.dynamicState != q.dynamicState) continue;
        if (!q.bandKey.empty() && rec.threatBand != q.bandKey) continue;
        if (!q.flagKey.empty() &&
            std::find(rec.flags.begin(), rec.flags.end(), q.flagKey) == rec.flags.end()) {
            continue;
        }
        if (q.minConfidence > 0.0 && rec.confidence < q.minConfidence) continue;
        EntityRecord copy = rec;
        detail::decorateEntity(st, m, copy);
        out.push_back(copy);
    }
    std::stable_sort(out.begin(), out.end(),
                     [](const EntityRecord& a, const EntityRecord& b) { return a.no < b.no; });
    if (q.offset > 0) {
        if (static_cast<std::size_t>(q.offset) >= out.size()) return {};
        out.erase(out.begin(), out.begin() + q.offset);
    }
    if (q.limit > 0 && static_cast<std::size_t>(q.limit) < out.size()) {
        out.resize(static_cast<std::size_t>(q.limit));
    }
    return out;
}

std::vector<MergeCandidate> EntityLedger::duplicateCandidates(const std::string& missionId) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    std::vector<MergeCandidate> out;
    auto mit = st.missions.find(missionId);
    if (mit == st.missions.end()) return out;
    const MissionState& m = mit->second;
    const detail::Definition& def = st.def;
    if (def.dedup.mode == "off" || def.dedup.spaceRadiusM <= 0) return out;
    const auto hasSpace = std::find(def.dedup.keys.begin(), def.dedup.keys.end(),
                                    std::string("space")) != def.dedup.keys.end();
    if (!hasSpace) return out;
    for (std::size_t i = 0; i < m.order.size(); ++i) {
        auto a = m.entities.find(m.order[i]);
        if (a == m.entities.end() || a->second.retired) continue;
        for (std::size_t j = i + 1; j < m.order.size(); ++j) {
            auto b = m.entities.find(m.order[j]);
            if (b == m.entities.end() || b->second.retired) continue;
            const int64_t d = static_cast<int64_t>(std::llround(detail::haversineM(
                a->second.lng, a->second.lat, b->second.lng, b->second.lat, def.earthRadiusM)));
            if (d > def.dedup.spaceRadiusM) continue;
            if (def.dedup.requireTypeMatch && a->second.typeKey != b->second.typeKey) continue;
            MergeCandidate c;
            c.id = b->second.id;
            c.no = b->second.no;
            c.typeKey = b->second.typeKey;
            c.distanceM = d;
            c.matchedKeys.push_back("space");
            if (a->second.typeKey == b->second.typeKey) c.matchedKeys.push_back("typeKey");
            else c.unmatchedKeys.push_back("typeKey");
            c.unmatchedKeys.push_back("obsKey");
            c.confidence = b->second.confidence;
            out.push_back(c);
        }
    }
    return out;
}

RegisterResult EntityLedger::mergeEntities(const std::string& primaryId,
                                           const std::vector<std::string>& otherIds,
                                           const std::string& operatorId) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    RegisterResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    for (auto& kv : st.missions) {
        MissionState& m = kv.second;
        auto pit = m.entities.find(primaryId);
        if (pit == m.entities.end()) continue;
        MissionState backup = m;
        EntityRecord& primary = pit->second;
        for (const auto& oid : otherIds) {
            if (oid == primaryId) continue;
            auto oit = m.entities.find(oid);
            if (oit == m.entities.end()) continue;
            EntityRecord& other = oit->second;
            for (const auto& s : other.sources) {
                bool found = false;
                for (auto& cur : primary.sources) {
                    if (cur.source == s.source) {
                        cur.count += s.count;
                        cur.confidence = std::max(cur.confidence, s.confidence);
                        cur.lastAt = std::max(cur.lastAt, s.lastAt);
                        found = true;
                    }
                }
                if (!found) primary.sources.push_back(s);
            }
            for (const auto& k : m.obsKeys[other.id]) m.obsKeys[primary.id].insert(k);
            for (const auto& f : other.flags) {
                if (std::find(primary.flags.begin(), primary.flags.end(), f) ==
                    primary.flags.end()) {
                    primary.flags.push_back(f);
                }
            }
            pushTrace(other, now, "merged", other.id, primary.id, "merge", operatorId, "");
            other.retired = true;
            other.retiredAt = now;
            other.retireReason = "merged";
            m.byNo.erase(other.no);
            if (st.def.numbering.reuse) m.usedNos.erase(other.no);
        }
        primary.confidence = fuseConfidence(st.def, primary.sources, res.contributions);
        primary.updatedAt = now;
        if (!st.persistLocked(m)) {
            m = std::move(backup);
            res.code = 1005;
            res.message = "store save failed";
            return res;
        }
        ++st.metrics.merges;
        EntityRecord out = primary;
        detail::decorateEntity(st, m, out);
        res.code = 0;
        res.message = "merged";
        res.status = "merged";
        res.merged = true;
        res.data = out;
        st.emitEntityChanged(kv.first, out, "merged", "", now);
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

RegisterResult EntityLedger::splitEntity(const std::string& entityId,
                                         const std::vector<std::string>& sourceKeys, double lng,
                                         double lat, const std::string& operatorId) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    RegisterResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    if (!st.def.loaded) {
        res.code = 1005;
        res.message = "policies not loaded";
        return res;
    }
    if (!st.def.dedup.allowManualSplit) {
        res.code = 1003;
        res.message = "manual split not allowed by rules";
        res.unmet.push_back(UnmetItem{"$manual-split", "manual split disabled by rules", ""});
        return res;
    }
    for (auto& kv : st.missions) {
        MissionState& m = kv.second;
        auto eit = m.entities.find(entityId);
        if (eit == m.entities.end()) continue;
        EntityRecord& rec = eit->second;
        MissionState backup = m;  // 源被移出后仍可整体回滚（ELG-REG-04 人工拆分）
        std::vector<SourceRef> moved;
        for (const auto& k : sourceKeys) {
            for (std::size_t i = 0; i < rec.sources.size(); ++i) {
                if (rec.sources[i].source == k) {
                    moved.push_back(rec.sources[i]);
                    rec.sources.erase(rec.sources.begin() + static_cast<long>(i));
                    break;
                }
            }
        }
        if (moved.empty()) {
            res.code = 1000;
            res.message = "no matching source to split";
            return res;
        }
        EntityRecord newRec;
        int no = 0;
        std::string reason;
        if (!assignNumber(st.def, m, 0, no, reason)) {
            m = std::move(backup);
            res.code = 1000;
            res.message = reason;
            return res;
        }
        newRec.id = uniqueEntityId(st, m, kv.first, static_cast<std::uint64_t>(no));
        newRec.no = no;
        newRec.missionId = kv.first;
        newRec.typeKey = rec.typeKey;
        newRec.lng = lng;
        newRec.lat = lat;
        newRec.sources = moved;
        newRec.dynamicState = rec.dynamicState;
        newRec.createdAt = now;
        newRec.updatedAt = now;
        newRec.priority = st.def.rank.defaultPriority;
        std::vector<ConfidenceContribution> dummy;
        newRec.confidence = fuseConfidence(st.def, newRec.sources, dummy);
        rec.confidence = fuseConfidence(st.def, rec.sources, res.contributions);
        rec.updatedAt = now;
        pushTrace(rec, now, "split", std::to_string(moved.size()), newRec.id, "split", operatorId,
                  "");
        applyAssessment(st, m, rec, now);
        applyAssessment(st, m, newRec, now);
        m.order.push_back(newRec.id);
        m.byNo[newRec.no] = newRec.id;
        m.entities[newRec.id] = newRec;
        if (!st.persistLocked(m)) {
            m = std::move(backup);
            res.code = 1005;
            res.message = "store save failed";
            return res;
        }
        ++st.metrics.splits;
        EntityRecord out = newRec;
        detail::decorateEntity(st, m, out);
        res.code = 0;
        res.message = "split";
        res.status = "created";
        res.created = true;
        res.data = out;
        st.emitEntityChanged(kv.first, out, "split", "", now);
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

ActionResult EntityLedger::setDynamicState(const std::string& entityId, const std::string& toState,
                                           const std::string& reason,
                                           const std::string& operatorId) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    ActionResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.entityId = entityId;
    res.actionKey = "set-state";
    if (!st.def.loaded) {
        res.code = 1005;
        res.message = "policies not loaded";
        return res;
    }
    if (!st.def.hasState(toState)) {
        res.code = 1000;
        res.message = "unknown dynamic state: " + toState;
        return res;
    }
    for (auto& kv : st.missions) {
        MissionState& m = kv.second;
        auto eit = m.entities.find(entityId);
        if (eit == m.entities.end()) continue;
        EntityRecord& rec = eit->second;
        res.no = rec.no;
        res.missionId = kv.first;
        if (rec.dynamicState == toState) {
            res.code = 0;
            res.message = "already in state";
            res.status = "already-done";
            res.idempotent = true;
            res.state = rec;
            ++st.metrics.actionIdempotent;
            return res;
        }
        if (!st.def.transitionAllowed(rec.dynamicState, toState)) {
            res.code = 1003;
            res.message = "illegal state transition";
            res.status = "rejected";
            res.unmet.push_back(UnmetItem{"$transition", "transition not declared by rules",
                                          rec.dynamicState + "->" + toState});
            ++st.metrics.actionRejected;
            return res;
        }
        const EntityRecord backup = rec;
        StateChange ch;
        ch.field = "dynamicState";
        ch.from = rec.dynamicState;
        ch.to = toState;
        rec.dynamicState = toState;
        rec.updatedAt = now;
        pushTrace(rec, now, "state", ch.from, ch.to, "state-change", operatorId, reason);
        applyAssessment(st, m, rec, now);
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
        st.emitEntityChanged(kv.first, out, "state-change", toState, now);
        st.emitTargetState(out, now);
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

ActionResult EntityLedger::retireEntity(const std::string& entityId, const std::string& reason,
                                        const std::string& operatorId) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    ActionResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.entityId = entityId;
    res.actionKey = "retire";
    for (auto& kv : st.missions) {
        MissionState& m = kv.second;
        auto eit = m.entities.find(entityId);
        if (eit == m.entities.end()) continue;
        EntityRecord& rec = eit->second;
        res.no = rec.no;
        res.missionId = kv.first;
        if (rec.retired) {
            res.code = 0;
            res.message = "already retired";
            res.status = "already-done";
            res.idempotent = true;
            res.state = rec;
            return res;
        }
        const EntityRecord backup = rec;
        rec.retired = true;
        rec.retiredAt = now;
        rec.retireReason = reason;
        rec.updatedAt = now;
        pushTrace(rec, now, "retired", "false", "true", "retire", operatorId, reason);
        m.byNo.erase(rec.no);
        if (st.def.numbering.reuse) m.usedNos.erase(rec.no);
        StateChange ch;
        ch.field = "retired";
        ch.from = "false";
        ch.to = "true";
        res.changes.push_back(ch);
        if (!st.persistLocked(m)) {
            rec = backup;
            m.byNo[backup.no] = backup.id;
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
        st.emitEntityChanged(kv.first, out, "retired", reasonOf(reason), now);
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

ActionResult EntityLedger::reclassifyType(const ReclassifyInput& in) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    ActionResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.entityId = in.entityId;
    res.actionKey = "type-reclassify";
    if (!st.def.loaded) {
        res.code = 1005;
        res.message = "policies not loaded";
        return res;
    }
    if (in.reason.empty()) {
        res.code = 1000;
        res.message = "reason is required for type reclassification";
        return res;
    }
    if (!st.def.findType(in.typeKey)) {
        res.code = 1000;
        res.message = "unknown entity type: " + in.typeKey;
        return res;
    }
    for (auto& kv : st.missions) {
        MissionState& m = kv.second;
        auto eit = m.entities.find(in.entityId);
        if (eit == m.entities.end()) continue;
        EntityRecord& rec = eit->second;
        res.no = rec.no;
        res.missionId = kv.first;
        if (rec.typeKey == in.typeKey) {
            res.code = 0;
            res.message = "type unchanged";
            res.status = "already-done";
            res.idempotent = true;
            res.state = rec;
            return res;
        }
        const EntityRecord backup = rec;
        StateChange ch;
        ch.field = "type";
        ch.from = rec.typeKey;
        ch.to = in.typeKey;
        rec.typeKey = in.typeKey;
        rec.typeName = st.def.typeName(in.typeKey);
        rec.updatedAt = now;
        pushTrace(rec, now, "type", ch.from, ch.to, "reclassify", in.operatorId, in.reason);
        applyAssessment(st, m, rec, now);
        res.changes.push_back(ch);
        if (!st.persistLocked(m)) {
            rec = backup;
            res.code = 1005;
            res.message = "store save failed";
            return res;
        }
        ++st.metrics.reclassifications;
        EntityRecord out = rec;
        detail::decorateEntity(st, m, out);
        res.code = 0;
        res.message = "ok";
        res.status = "ok";
        res.state = out;
        AuditEntry a;
        a.at = now;
        a.actor = in.operatorId;
        a.action = "type-reclassify";
        a.target = in.entityId;
        a.detail = ch.from + "->" + ch.to;
        a.violation = false;
        st.audit(a);
        st.emitEntityChanged(kv.first, out, "reclassified", in.reason, now);
        st.emitTargetState(out, now);
        return res;
    }
    res.code = 1004;
    res.message = "entity not found";
    return res;
}

// ============================================================================
// 旗标（ELG-ID-05：标记数量与去向可查；唯一性由规则声明）
// ============================================================================

std::vector<EntityRef> EntityLedger::flagHolders(const std::string& missionId,
                                                 const std::string& flagKey) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    std::vector<EntityRef> out;
    auto mit = st.missions.find(missionId);
    if (mit == st.missions.end()) return out;
    for (const auto& id : mit->second.order) {
        auto it = mit->second.entities.find(id);
        if (it == mit->second.entities.end()) continue;
        const auto& fl = it->second.flags;
        if (std::find(fl.begin(), fl.end(), flagKey) != fl.end()) {
            out.push_back(EntityRef{it->second.id, it->second.no});
        }
    }
    std::stable_sort(out.begin(), out.end(),
                     [](const EntityRef& a, const EntityRef& b) { return a.no < b.no; });
    return out;
}

ActionResult EntityLedger::setFlag(const FlagInput& in) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    ActionResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.entityId = in.entityId;
    res.actionKey = "flag-set";
    if (!st.def.loaded) {
        res.code = 1005;
        res.message = "policies not loaded";
        return res;
    }
    const FlagDef* fd = st.def.findFlag(in.flagKey);
    if (!fd) {
        res.code = 1000;
        res.message = "unknown flag: " + in.flagKey;
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
    EntityRecord& rec = eit->second;
    res.no = rec.no;
    res.missionId = in.missionId;
    if (std::find(rec.flags.begin(), rec.flags.end(), in.flagKey) != rec.flags.end()) {
        res.code = 0;
        res.message = "flag already held";
        res.status = "already-done";
        res.idempotent = true;
        res.state = rec;
        ++st.metrics.actionIdempotent;
        return res;
    }
    MissionState backup = m;
    EntityRecord* holder = nullptr;
    if (fd->unique) {
        for (const auto& id : m.order) {
            auto it = m.entities.find(id);
            if (it == m.entities.end()) continue;
            const auto& fl = it->second.flags;
            if (std::find(fl.begin(), fl.end(), in.flagKey) != fl.end()) holder = &it->second;
        }
    }
    if (holder && !in.transfer) {
        res.code = 1003;
        res.message = "unique flag already held in mission";
        res.status = "rejected";
        res.unmet.push_back(UnmetItem{"$flag-unique", "flag already held in mission",
                                      std::to_string(holder->no)});
        ++st.metrics.actionRejected;
        return res;
    }
    if (holder && in.transfer) {
        holder->flags.erase(std::remove(holder->flags.begin(), holder->flags.end(), in.flagKey),
                            holder->flags.end());
        holder->updatedAt = now;
        pushTrace(*holder, now, "flag", in.flagKey, "", "flag-transfer", in.operatorId, in.reason);
        StateChange ch;
        ch.field = "flags";
        ch.from = in.flagKey;
        ch.to = "";
        res.changes.push_back(ch);
    }
    rec.flags.push_back(in.flagKey);
    rec.updatedAt = now;
    pushTrace(rec, now, "flag", "", in.flagKey, "flag-set", in.operatorId, in.reason);
    {
        StateChange ch;
        ch.field = "flags";
        ch.from = "";
        ch.to = in.flagKey;
        res.changes.push_back(ch);
    }
    if (!st.persistLocked(m)) {
        m = std::move(backup);
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
    st.emitEntityChanged(in.missionId, out, "flag-set", in.flagKey, now);
    return res;
}

ActionResult EntityLedger::clearFlag(const FlagInput& in) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    ActionResult res;
    const int64_t now = st.nowLocked();
    res.ts = now;
    res.entityId = in.entityId;
    res.actionKey = "flag-clear";
    if (!st.def.loaded) {
        res.code = 1005;
        res.message = "policies not loaded";
        return res;
    }
    if (!st.def.findFlag(in.flagKey)) {
        res.code = 1000;
        res.message = "unknown flag: " + in.flagKey;
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
    EntityRecord& rec = eit->second;
    res.no = rec.no;
    res.missionId = in.missionId;
    if (std::find(rec.flags.begin(), rec.flags.end(), in.flagKey) == rec.flags.end()) {
        res.code = 0;
        res.message = "flag not held";
        res.status = "already-done";
        res.idempotent = true;
        res.state = rec;
        return res;
    }
    const EntityRecord backup = rec;
    rec.flags.erase(std::remove(rec.flags.begin(), rec.flags.end(), in.flagKey), rec.flags.end());
    rec.updatedAt = now;
    pushTrace(rec, now, "flag", in.flagKey, "", "flag-clear", in.operatorId, in.reason);
    StateChange ch;
    ch.field = "flags";
    ch.from = in.flagKey;
    ch.to = "";
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
    st.emitEntityChanged(in.missionId, out, "flag-clear", in.flagKey, now);
    return res;
}

// ============================================================================
// 任务基准点（距离因子的参照；宿主注入）
// ============================================================================

void EntityLedger::setMissionReference(const std::string& missionId, double lng, double lat) {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    MissionState& m = st.missionLocked(missionId);
    m.referenceSet = true;
    m.referenceLng = lng;
    m.referenceLat = lat;
    if (st.persistLocked(m)) return;
}

std::optional<std::pair<double, double>> EntityLedger::missionReference(
    const std::string& missionId) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    auto mit = st.missions.find(missionId);
    if (mit != st.missions.end() && mit->second.referenceSet) {
        return std::make_pair(mit->second.referenceLng, mit->second.referenceLat);
    }
    if (st.def.referenceSet) return std::make_pair(st.def.referenceLng, st.def.referenceLat);
    return std::nullopt;
}

// ============================================================================
// 自述与观测
// ============================================================================

Capabilities EntityLedger::capabilities() const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    Capabilities c;
    c.policiesLoaded = st.def.loaded;
    c.schemaVersion = st.def.schemaVersion;
    c.policiesMajor = st.def.major > 0 ? st.def.major : kSupportedPoliciesMajor;
    c.definitionVersion = st.def.version;
    c.persistent = static_cast<bool>(st.store);
    c.storeList = st.store ? st.store->supportsList() : false;
    c.clockInjected = static_cast<bool>(st.clock);
    c.sinkInjected = static_cast<bool>(st.sink);
    c.logInjected = static_cast<bool>(st.log);
    c.registeredActionGates = static_cast<int>(st.actionGates.size());
    c.missions = static_cast<int>(st.missions.size());
    int n = 0;
    for (const auto& kv : st.missions) n += static_cast<int>(kv.second.entities.size());
    c.entities = n;
    return c;
}

Metrics EntityLedger::metrics() const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    return st.metrics;
}

json EntityLedger::ledgerSnapshot(const std::string& missionId) const {
    State& st = impl_->st;
    std::lock_guard<std::recursive_mutex> lk(st.mtx);
    st.ensureStoreLoadedLocked();
    auto mit = st.missions.find(missionId);
    if (mit == st.missions.end()) return json(nullptr);
    return detail::missionToJson(mit->second);
}

// ============================================================================
// 自由函数：校验
// ============================================================================

LoadResult validatePolicies(const json& pkg) { return EntityLedger::validatePolicies(pkg); }

}  // namespace entity_ledger
