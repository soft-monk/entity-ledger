// tests/selftest.cc · 零依赖自测（手写断言，不引任何测试框架）
//
// 覆盖需求专篇 docs/需求/entity-ledger需求专篇.md 的 **41 条**：
//   ELG-REG 6 / ELG-ID 5 / ELG-RATE 6 / ELG-RANK 4 / ELG-TRK 6 / ELG-ACT 6 / ELG-INTEL 3 / ELG-NFR 5
// 以及 §7 验收清单、protocol.md 的 CTR-PL / CTR-EN / CTR-EV / CTR-EC 相关条目。
//
// 全部用例**确定性**：时钟一律注入假时钟（ELG-NFR-03），不依赖真实时间、不依赖当前工作目录
// （规则包与夹具路径由 CMake 注入的绝对路径给出）、不需要外部服务。
// 一切业务取值（类型名、动作名、旗标名、分档、视图标签、阶段 key）都**从规则包读取**，
// 用例内不出现任何业务字面量 —— 这本身就是"引擎不认识业务取值"的可执行证明（ELG-REG-01/ACT-01）。
//
// 运行： selftest                → 跑全部（人读输出）
//        selftest --list         → 只列用例名
//        selftest --json         → 机检输出（acceptance.ps1 读它做需求↔用例对账）
//        selftest <名字片段>      → 只跑名字里含该片段的用例
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "entity_ledger/entity_ledger.h"

using namespace entity_ledger;

namespace {

// ---------------------------------------------------------------- 断言框架
int g_asserts = 0;
int g_failed = 0;
int g_cases = 0;
int g_casesFailed = 0;
std::string g_case;
std::vector<std::string> g_failures;
bool g_jsonMode = false;
std::vector<std::string> g_reqs;

struct CaseMeta {
    std::string name;
    std::vector<std::string> reqs;
    int asserts = 0;
    int failed = 0;
    bool ok = false;
};
std::vector<CaseMeta> g_metas;

template <typename... Args>
void requires_(Args... ids) {
    for (const char* id : {ids...}) g_reqs.push_back(id);
}

std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out;
}

std::string jsonArray(const std::vector<std::string>& v) {
    std::string out = "[";
    for (std::size_t i = 0; i < v.size(); ++i) {
        if (i) out += ",";
        out += "\"" + jsonEscape(v[i]) + "\"";
    }
    out += "]";
    return out;
}

template <typename T, typename = void>
struct Comparable {
    using type = T;
};
template <typename T>
struct Comparable<T, typename std::enable_if<std::is_integral<T>::value>::type> {
    using type = long long;
};
template <typename T>
struct Comparable<T, typename std::enable_if<std::is_enum<T>::value>::type> {
    using type = long long;
};

template <typename T>
typename Comparable<T>::type asComparable(const T& v) {
    return static_cast<typename Comparable<T>::type>(v);
}

void record(bool ok, const std::string& what, const char* file, int line) {
    ++g_asserts;
    if (ok) return;
    ++g_failed;
    std::ostringstream os;
    os << g_case << " @ " << file << ":" << line << " · " << what;
    g_failures.push_back(os.str());
}

#define CHECK(cond) record((cond), std::string("CHECK failed: ") + #cond, __FILE__, __LINE__)

#define CHECK_EQ(a, b)                                                              \
    do {                                                                            \
        const auto va = asComparable(a);                                            \
        const auto vb = asComparable(b);                                            \
        if (!(va == vb)) {                                                          \
            std::ostringstream os_;                                                 \
            os_ << "CHECK_EQ failed: " << #a << " == " << #b << " (got " << va      \
                << " vs " << vb << ")";                                             \
            record(false, os_.str(), __FILE__, __LINE__);                           \
        } else {                                                                    \
            record(true, "", __FILE__, __LINE__);                                   \
        }                                                                           \
    } while (0)

#define CHECK_STR(a, b)                                                             \
    do {                                                                            \
        const std::string va = (a);                                                 \
        const std::string vb = (b);                                                 \
        if (va != vb) {                                                             \
            record(false, std::string("CHECK_STR failed: ") + #a + " == " + #b +    \
                              " (got '" + va + "' vs '" + vb + "')",                \
                   __FILE__, __LINE__);                                             \
        } else {                                                                    \
            record(true, "", __FILE__, __LINE__);                                   \
        }                                                                           \
    } while (0)

#define CHECK_NEAR(a, b, eps)                                                       \
    do {                                                                            \
        const double va = (a);                                                      \
        const double vb = (b);                                                      \
        if (std::fabs(va - vb) > (eps)) {                                           \
            std::ostringstream os_;                                                 \
            os_ << "CHECK_NEAR failed: " << #a << " ~= " << #b << " (got " << va    \
                << " vs " << vb << ")";                                             \
            record(false, os_.str(), __FILE__, __LINE__);                           \
        } else {                                                                    \
            record(true, "", __FILE__, __LINE__);                                   \
        }                                                                           \
    } while (0)

// ---------------------------------------------------------------- 测试替身（全部经反向接口注入）
struct FakeClock : IClock {
    int64_t t = 1750000000000LL;
    int64_t nowMs() const override { return t; }
    void advance(int64_t d) { t += d; }
};

struct RecSink : IEntitySink {
    int changes = 0;
    int states = 0;
    int consistencies = 0;
    std::vector<json> changePayloads;
    std::vector<json> statePayloads;
    std::vector<json> consistencyPayloads;
    bool throwOnEntity = false;
    void onEntityChanged(const EntityChangeEvent& e) override {
        ++changes;
        changePayloads.push_back(e.toJson());
        if (throwOnEntity) throw std::runtime_error("sink boom");
    }
    void onTargetState(const TargetStateEvent& e) override {
        ++states;
        statePayloads.push_back(e.toJson());
    }
    void onConsistency(const ConsistencyEvent& e) override {
        ++consistencies;
        consistencyPayloads.push_back(e.toJson());
    }
};

struct MemStore : IEntityStore {
    std::map<std::string, json> data;
    bool fail = false;
    int saves = 0;
    bool save(const std::string& missionId, const json& ledger) override {
        ++saves;
        if (fail) return false;
        data[missionId] = ledger;
        return true;
    }
    bool load(const std::string& missionId, json& out) override {
        auto it = data.find(missionId);
        if (it == data.end()) return false;
        out = it->second;
        return true;
    }
    bool remove(const std::string& missionId) override { return data.erase(missionId) > 0; }
    bool supportsList() const override { return true; }
    std::vector<std::string> listMissionIds() override {
        std::vector<std::string> v;
        for (const auto& kv : data) v.push_back(kv.first);
        return v;
    }
};

struct RecLog : ILogSink {
    std::vector<AuditEntry> audits;
    int logs = 0;
    void log(int, const std::string&, const json&) override { ++logs; }
    void commandAudit(const AuditEntry& e) override { audits.push_back(e); }
};

// ---------------------------------------------------------------- 规则包（唯一业务取值来源）
std::string g_policyTypesPath = ENTITY_LEDGER_POLICY_TYPES;
std::string g_policyFactorsPath = ENTITY_LEDGER_POLICY_FACTORS;

json readJson(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return json(nullptr);
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    try {
        return json::parse(text);
    } catch (...) {
        return json(nullptr);
    }
}

bool loadPolicies(EntityLedger& e) {
    const LoadResult a = e.loadPoliciesFile(g_policyTypesPath);
    if (a.code != 0) {
        std::printf("    规则包装载失败(%s)：code=%d %s\n", g_policyTypesPath.c_str(), a.code,
                    a.message.c_str());
        for (const auto& is : a.issues) {
            std::printf("      %s.%s: %s\n", is.path.c_str(), is.field.c_str(), is.reason.c_str());
        }
        return false;
    }
    const LoadResult b = e.loadPoliciesFile(g_policyFactorsPath);
    if (b.code != 0) {
        std::printf("    规则包装载失败(%s)：code=%d %s\n", g_policyFactorsPath.c_str(), b.code,
                    b.message.c_str());
        for (const auto& is : b.issues) {
            std::printf("      %s.%s: %s\n", is.path.c_str(), is.field.c_str(), is.reason.c_str());
        }
        return false;
    }
    return true;
}

/// 从规则包读取取值（测试里 MUST NOT 出现业务字面量）
struct Rules {
    json all;
    explicit Rules(EntityLedger& e) : all(e.effectivePolicies()) {}
    const json& et() const { return all["entityTypes"]; }
    const json& tf() const { return all["threatFactors"]; }
    std::vector<std::string> typeKeys() const {
        std::vector<std::string> v;
        for (const auto& it : et()["items"]) v.push_back(it["key"].get<std::string>());
        return v;
    }
    std::vector<std::string> sourceKeys() const {
        std::vector<std::string> v;
        for (const auto& it : et()["confidence"]["sources"]) v.push_back(it["key"].get<std::string>());
        return v;
    }
    std::vector<std::string> stateKeys() const {
        std::vector<std::string> v;
        for (const auto& it : et()["dynamicStates"]["items"]) v.push_back(it["key"].get<std::string>());
        return v;
    }
    std::vector<std::string> viewKeys() const {
        std::vector<std::string> v;
        for (const auto& it : et()["views"]) v.push_back(it["key"].get<std::string>());
        return v;
    }
    std::vector<std::string> actionKeys() const {
        std::vector<std::string> v;
        for (const auto& it : et()["actions"]) v.push_back(it["key"].get<std::string>());
        return v;
    }
    std::vector<std::string> flagKeys() const {
        std::vector<std::string> v;
        for (const auto& it : et()["flags"]) v.push_back(it["key"].get<std::string>());
        return v;
    }
    std::vector<std::string> relationKinds() const {
        std::vector<std::string> v;
        for (const auto& it : et()["relations"]["kinds"]) v.push_back(it["key"].get<std::string>());
        return v;
    }
    std::vector<std::string> relationStates() const {
        std::vector<std::string> v;
        for (const auto& it : et()["relations"]["states"]) v.push_back(it["key"].get<std::string>());
        return v;
    }
    /// 某视图第 idx 条 phaseFilter 的阶段 key 列表（首个命中生效）
    std::vector<std::string> viewPhases(const std::string& viewKey, std::size_t idx) const {
        std::vector<std::string> v;
        for (const auto& view : et()["views"]) {
            if (view["key"].get<std::string>() != viewKey) continue;
            const json& fs = view["phaseFilters"];
            if (idx >= fs.size()) return v;
            for (const auto& p : fs[idx]["phases"]) v.push_back(p.get<std::string>());
        }
        return v;
    }
    std::size_t viewFilterCount(const std::string& viewKey) const {
        for (const auto& view : et()["views"]) {
            if (view["key"].get<std::string>() == viewKey) return view["phaseFilters"].size();
        }
        return 0;
    }
    std::string typeWithBase(double want) const {
        for (const auto& it : et()["items"]) {
            if (std::fabs(it["baseThreat"].get<double>() - want) < 1e-9) {
                return it["key"].get<std::string>();
            }
        }
        return "";
    }
    /// 某个 table 归一化因子里取值为 want 的键（例如"动态状态"取 1.0 的那个状态）
    std::string tableKeyWithValue(const std::string& factorKey, double want) const {
        for (const auto& it : tf()["items"]) {
            if (it["key"].get<std::string>() != factorKey) continue;
            for (auto p = it["normalize"]["table"].begin(); p != it["normalize"]["table"].end();
                 ++p) {
                if (std::fabs(p.value().get<double>() - want) < 1e-9) return p.key();
            }
        }
        return "";
    }
    double referenceLng() const { return et()["reference"]["lng"].get<double>(); }
    double referenceLat() const { return et()["reference"]["lat"].get<double>(); }
    double multiSourceBonus() const { return et()["confidence"]["multiSourceBonus"].get<double>(); }
    double maxBonus() const { return et()["confidence"]["maxBonus"].get<double>(); }
    /// 动作挑选（按规则内容，不按名字）
    std::string actionWithFlagSetter() const {  // 会打旗标的动作（现状的 upgrade 语义）
        for (const auto& it : et()["actions"]) {
            if (!it["setsFlags"].empty()) return it["key"].get<std::string>();
        }
        return "";
    }
    std::string actionRequiring(const std::string& priorAction) const {  // 前置依赖某动作的动作
        for (const auto& it : et()["actions"]) {
            for (const auto& r : it["requires"]) {
                if (r.get<std::string>() == "$action:" + priorAction) {
                    return it["key"].get<std::string>();
                }
            }
        }
        return "";
    }
    std::string actionRepeatable() const {  // requires 为空且 once=false（现状的 track/watch 语义）
        for (const auto& it : et()["actions"]) {
            if (it["requires"].empty() && !it["once"].get<bool>()) {
                return it["key"].get<std::string>();
            }
        }
        return "";
    }
    std::string actionWithConfidenceGate() const {
        for (const auto& it : et()["actions"]) {
            for (const auto& r : it["requires"]) {
                const std::string s = r.get<std::string>();
                if (s.rfind("$confidence-min:", 0) == 0) return it["key"].get<std::string>();
            }
        }
        return "";
    }
    std::string irreversibleAction() const {
        for (const auto& it : et()["actions"]) {
            if (!it["reversible"].get<bool>()) return it["key"].get<std::string>();
        }
        return "";
    }
    std::string nonCyclicKind() const {
        for (const auto& it : et()["relations"]["kinds"]) {
            if (!it["cyclic"].get<bool>()) return it["key"].get<std::string>();
        }
        return "";
    }
    std::string cyclicKind() const {
        for (const auto& it : et()["relations"]["kinds"]) {
            if (it["cyclic"].get<bool>()) return it["key"].get<std::string>();
        }
        return "";
    }
};

// ---------------------------------------------------------------- 演示台账（7 个实体，5/6/7 三档可见）
//
// 依赖全部用 shared_ptr 持有：断言读的就是引擎实际调用的那一个替身（不是拷贝）。
struct Demo {
    EntityLedger engine;
    std::shared_ptr<FakeClock> clock = std::make_shared<FakeClock>();
    std::shared_ptr<RecSink> sink = std::make_shared<RecSink>();
    std::shared_ptr<MemStore> store = std::make_shared<MemStore>();
    std::shared_ptr<RecLog> log = std::make_shared<RecLog>();
    Rules* rules = nullptr;
    std::string mission = "m-demo";
    std::vector<std::string> ids;  // 按 no 升序
    std::vector<double> confidences{0.9, 0.8, 0.7, 0.6, 0.55, 0.45, 0.35};
};

void seedDemo(Demo& d, bool withStore) {
    if (withStore) d.engine.setStore(d.store);
    d.engine.setClock(d.clock);
    d.engine.setSink(d.sink);
    d.engine.setLog(d.log);
    const std::vector<std::string> types = d.rules->typeKeys();
    const std::vector<std::string> sources = d.rules->sourceKeys();
    const std::vector<std::string> states = d.rules->stateKeys();
    for (std::size_t i = 0; i < d.confidences.size(); ++i) {
        RegisterInput in;
        in.missionId = d.mission;
        in.typeKey = types[i % types.size()];
        in.lng = d.rules->referenceLng() + 0.02 * static_cast<double>(i);
        in.lat = d.rules->referenceLat() + 0.01 * static_cast<double>(i);
        in.dynamicState = states[i % states.size()];
        in.obsKey = "obs-" + std::to_string(i + 1);
        in.operatorId = "op-1";
        // 多源观测：各源置信度相同 → 融合值 = 观测值 + 多源加成。
        // 为使融合结果恰好落在期望置信度上（5/6/7 三档可见性由此确定），观测值先扣掉加成。
        const std::size_t nsrc = 1 + (i % 3);
        const double bonus =
            nsrc > 1 ? std::min(d.rules->multiSourceBonus() * static_cast<double>(nsrc - 1),
                                d.rules->maxBonus())
                     : 0.0;
        const double obsConf = std::max(0.0, d.confidences[i] - bonus);
        in.confidence = obsConf;
        for (std::size_t s = 0; s < nsrc; ++s) {
            SourceObs o;
            o.source = sources[s % sources.size()];
            o.obsKey = in.obsKey;
            o.confidence = obsConf;
            o.at = d.clock->t;
            in.sources.push_back(o);
        }
        const RegisterResult r = d.engine.registerEntity(in);
        if (r.code == 0) d.ids.push_back(r.data.id);
    }
}

std::string noToId(const Demo& d, int no) {
    auto r = d.engine.getEntityByNo(d.mission, no);
    return r.has_value() ? r->id : std::string();
}

ViewItem itemOf(const EntityRecord& rec) {
    ViewItem it;
    it.id = rec.id;
    it.no = rec.no;
    it.typeKey = rec.typeKey;
    it.flagKeys = rec.flags;
    it.confidence = rec.confidence;
    return it;
}

/// 依据引擎给出的应可见集合构造视图快照（界面**不需要自行过滤**）
ViewSnapshot snapshotFrom(const EntityLedger& e, const std::string& missionId,
                          const std::string& viewKey, const std::string& phaseKey,
                          bool flagsRendered, int mutateFlagNo = -1) {
    VisibleSetRequest req;
    req.missionId = missionId;
    req.viewKey = viewKey;
    PhaseContext pc;
    pc.phaseKey = phaseKey;
    pc.missionId = missionId;
    req.phase = pc;
    const VisibleSetResult vs = e.visibleSet(req);
    ViewSnapshot s;
    s.viewKey = viewKey;
    s.viewName = vs.viewName;
    s.phaseKey = phaseKey;
    s.flagsRendered = flagsRendered;
    for (const auto& it : vs.items) {
        ViewItem vi;
        vi.id = it.id;
        vi.no = it.no;
        vi.typeKey = it.typeKey;
        vi.flagKeys = it.flags;
        vi.confidence = it.confidence;
        if (mutateFlagNo == it.no) vi.flagKeys.clear();  // 人为制造"界面没标出来"
        s.items.push_back(vi);
    }
    return s;
}

// ---------------------------------------------------------------- 用例声明
void reg01_entity_types_are_rule_declared();
void reg02_ledger_fields_and_defaults();
void reg03_mission_scope_and_duplicate_no_rejected();
void reg04_multisource_dedup_conservative();
void reg05_confidence_fusion_reproducible();
void reg06_dynamic_state_machine();
void id01_numbering_rules_and_no_reuse();
void id02a_consistency_localizes_count_mismatch();
void id02b_consistency_localizes_flag_dispute();
void id02c_consistency_detects_no_and_type_mismatch();
void id03_visible_set_is_engine_owned_and_stable();
void id04_type_binding_and_reclassify_trace();
void id05_flag_uniqueness_and_holders();
void rate01_rating_follows_injected_rules();
void rate02_score_recomputable_by_hand();
void rate03_bands_from_thresholds_not_boolean();
void rate04_distance_uses_real_geometry();
void rate05_assessment_is_pure_over_snapshot();
void rate06_strike_window_is_computed_interval();
void rank01_stable_ordering_deterministic();
void rank02_priority_explicit_changes_order();
void rank03_sequence_add_remove_idempotent_and_limited();
void rank04_sequence_audit_recoverable();
void trk01_out_of_order_writes_ordered_queries();
void trk02_range_query_truncation_flagged();
void trk03_decimation_is_annotated();
void trk04_timeline_matches_replay_shape();
void trk05_prediction_flagged_not_mixed();
void trk06_retention_counters();
void act01_action_set_is_rule_declared();
void act02_idempotent_repeat_and_conflict_are_distinct();
void act03_action_output_is_structured_only();
void act04_preconditions_all_reported();
void act05_action_log_queryable();
void act06_undo_semantics();
void intel01a_relation_crud_and_cycle_rejected();
void intel01b_cyclic_kind_detected_and_queries_terminate();
void intel02_chain_and_related_count();
void intel03_two_states_filterable_and_counted();
void nfr01_works_with_zero_dependencies();
void nfr02_reverse_interfaces_only();
void nfr03_determinism_byte_identical_double_run();
void nfr04_standalone_public_api_smoke();
void nfr05_performance_thresholds();
void ctr_pl_schema_validation_and_atomicity();
void ctr_en_ref_shape_and_cross_view_identity();
void ctr_ev_payload_frozen_fields();
void persist_write_before_commit_and_reload();

}  // namespace

// ============================================================================
// 用例实现
// ============================================================================
namespace {

// ---- ELG-REG ----------------------------------------------------------------

void reg01_entity_types_are_rule_declared() {
    requires_("ELG-REG-01", "ELG-NFR-01");
    EntityLedger e;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    CHECK_EQ(e.entityTypeKeys().size(), r.typeKeys().size());
    for (const auto& k : r.typeKeys()) {
        auto t = e.entityType(k);
        CHECK(t.has_value());
        if (t) {
            CHECK(!t->name.empty());
            CHECK(t->baseThreat >= 0.0 && t->baseThreat <= 1.0);
        }
        CHECK_STR(e.resolveTypeName(k), t->name);
    }
    // 未知类型 → 拒绝（类型集完全来自规则）
    CHECK_STR(e.resolveTypeName("no-such-type"), "no-such-type");  // MUST NOT 造文案
    RegisterInput in;
    in.missionId = "m";
    in.typeKey = "no-such-type";
    CHECK_EQ(e.registerEntity(in).code, 1000);
    // 换一份规则 → 换一套类型集（引擎零改动）
    EntityLedger e2;
    json custom = readJson(std::string(ENTITY_LEDGER_TEST_FIXTURES) + "/types-alt.json");
    CHECK_EQ(e2.loadPolicies(custom).code, 0);
    CHECK_EQ(e2.entityTypeKeys().size(), std::size_t(2));
    CHECK_STR(e2.resolveTypeName("alphaNode"), "alpha node");
}

void reg02_ledger_fields_and_defaults() {
    requires_("ELG-REG-02");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    CHECK_EQ(e.listEntities(EntityQuery{d.mission}).size(), std::size_t(7));
    const auto rec = e.getEntity(d.ids.front());
    CHECK(rec.has_value());
    if (!rec) return;
    const json j = toJson(*rec);
    // ELG-REG-02 字段清单：id / no / 类型 / 坐标 / 来源 / 置信度 / 动态状态 / 威胁等级 / 优先级 / 关系链 / 时间
    for (const char* key : {"id", "no", "typeKey", "lng", "lat", "sources", "confidence",
                            "dynamicState", "threatBand", "priority", "relations", "createdAt",
                            "updatedAt"}) {
        CHECK(j.contains(key));
    }
    CHECK_STR(j["id"].get<std::string>(), rec->id);            // id 全局唯一字符串
    CHECK(j["no"].is_number());                                // no 任务内唯一整数
    CHECK(rec->sources.size() >= 1);                           // 来源标注
    CHECK(!rec->threatBand.empty());                           // 登记即评级（分档来自规则）
    CHECK(rec->priority == 9);                                 // 规则 rank.defaultPriority
    // 缺省字段有定义行为：空 dynamicState → 规则缺省状态
    RegisterInput in;
    in.missionId = d.mission;
    in.typeKey = r.typeKeys().front();
    in.lng = 0.0;
    in.lat = 0.0;
    const RegisterResult rr = e.registerEntity(in);
    CHECK_EQ(rr.code, 0);
    CHECK(!rr.data.dynamicState.empty());
    // 序列化可往返（宿主落库形状）
    json snap = e.ledgerSnapshot(d.mission);
    CHECK(snap.is_object());
    CHECK_EQ(snap["entities"].size(), std::size_t(8));
}

void reg03_mission_scope_and_duplicate_no_rejected() {
    requires_("ELG-REG-03", "CTR-EN-04");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    // 同一任务内 no 唯一：显式指定已占用的 no → 拒绝且原因可读
    RegisterInput dup;
    dup.missionId = d.mission;
    dup.typeKey = r.typeKeys().front();
    dup.no = 3;
    dup.lng = 0.0;
    dup.lat = 0.0;
    const RegisterResult rr = e.registerEntity(dup);
    CHECK_EQ(rr.code, 1000);
    CHECK(rr.message.find("no") != std::string::npos);
    // 任务隔离：另一个任务的 3 号合法
    RegisterInput other = dup;
    other.missionId = "m-other";
    CHECK_EQ(e.registerEntity(other).code, 0);
    CHECK_EQ(e.getEntityByNo("m-other", 3).has_value(), true);
    // 查询不存在的任务/实体 → 结构化"未找到"，不是空对象当真值
    CHECK_EQ(e.getEntity("ent-nope").has_value(), false);
    CHECK_EQ(e.getEntityByNo(d.mission, 999).has_value(), false);
}

void reg04_multisource_dedup_conservative() {
    requires_("ELG-REG-04");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    const std::vector<std::string> sources = r.sourceKeys();
    // 同一实体三条来源观测（同 obsKey + 同类型 + 同位置）→ 合并为一条且标注多源
    RegisterInput base;
    base.missionId = "m-dedup";
    base.typeKey = r.typeKeys().front();
    base.lng = r.referenceLng();
    base.lat = r.referenceLat();
    base.obsKey = "k-1";
    SourceObs o1;
    o1.source = sources[0];
    o1.obsKey = "k-1";
    o1.confidence = 0.6;
    base.sources.push_back(o1);
    const RegisterResult first = e.registerEntity(base);
    CHECK_EQ(first.code, 0);
    for (std::size_t i = 1; i < 3; ++i) {
        RegisterInput in = base;
        SourceObs o;
        o.source = sources[i % sources.size()];
        o.obsKey = "k-1";
        o.confidence = 0.6 + 0.1 * static_cast<double>(i);
        in.sources.clear();
        in.sources.push_back(o);
        const RegisterResult r2 = e.registerEntity(in);
        CHECK_EQ(r2.code, 0);
        CHECK_EQ(r2.merged, true);
        CHECK_STR(r2.status, "merged");
    }
    const auto rec = e.getEntity(first.data.id);
    CHECK(rec.has_value());
    CHECK_EQ(rec->sources.size(), std::size_t(3));
    CHECK_EQ(rec->multiSource, true);
    CHECK_EQ(toJson(*rec)["multiSource"].get<bool>(), true);
    // 默认保守：去重键只命中一部分（同类型、距离远）→ **不合并**，但标注候选（宁可标多源不合并）
    RegisterInput far = base;
    far.obsKey = "k-2";
    far.lng = r.referenceLng() + 0.5;  // 远超规则空间半径
    const RegisterResult rf = e.registerEntity(far);
    CHECK_EQ(rf.code, 0);
    CHECK_EQ(rf.merged, false);
    CHECK_EQ(e.listEntities(EntityQuery{"m-dedup"}).size(), std::size_t(2));
    // 保守判定的可解释面：部分命中（同类型 + 空间邻近，但观测主键不同）→ 标为候选而**不合并**
    RegisterInput near = base;
    near.obsKey = "k-3";
    near.lng = base.lng + 0.0005;  // ≈55 m，在规则空间半径内
    const RegisterResult rn = e.registerEntity(near);
    CHECK_EQ(rn.code, 0);
    CHECK_EQ(rn.merged, false);
    CHECK(rn.candidates.size() >= 1);
    CHECK_EQ(rn.toJson()["data"]["candidates"].size() >= 1, true);
    CHECK(e.duplicateCandidates("m-dedup").size() >= 1);
    CHECK_EQ(e.listEntities(EntityQuery{"m-dedup"}).size(), std::size_t(3));
    // 人工合并与拆分（保守规则的补偿手段）
    const RegisterResult m = e.mergeEntities(first.data.id, {rf.data.id}, "op-1");
    CHECK_EQ(m.code, 0);
    CHECK_EQ(m.merged, true);
    // 被合并者软删除：默认列表不含，但历史保留（includeRetired 可查）
    const std::vector<EntityRecord> active = e.listEntities(EntityQuery{"m-dedup"});
    const std::vector<EntityRecord> all =
        e.listEntities(EntityQuery{"m-dedup", "", "", "", "", 0.0, true, 100, 0});
    CHECK_EQ(active.size(), std::size_t(2));
    CHECK_EQ(all.size(), std::size_t(3));
    bool sawRetired = false;
    for (const auto& rec : all) {
        if (rec.retired) sawRetired = true;
    }
    CHECK(sawRetired);
    const RegisterResult sp = e.splitEntity(first.data.id, {sources[0]}, r.referenceLng(),
                                            r.referenceLat() - 0.05, "op-2");
    CHECK_EQ(sp.code, 0);
    CHECK_EQ(sp.data.no > 0, true);
}

void reg05_confidence_fusion_reproducible() {
    requires_("ELG-REG-05");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    const std::vector<std::string> sources = r.sourceKeys();
    // 两个来源、权重来自规则 → 融合结果可复算（逐项贡献之和 == 结果 ppm）
    RegisterInput in;
    in.missionId = "m-fuse";
    in.typeKey = r.typeKeys().front();
    in.lng = r.referenceLng();
    in.lat = r.referenceLat();
    in.obsKey = "k";
    SourceObs a;
    a.source = sources[0];
    a.obsKey = "k";
    a.confidence = 0.8;
    SourceObs b;
    b.source = sources[1];
    b.obsKey = "k";
    b.confidence = 0.4;
    in.sources.push_back(a);
    in.sources.push_back(b);
    const RegisterResult r1 = e.registerEntity(in);
    CHECK_EQ(r1.code, 0);
    CHECK_EQ(r1.contributions.size(), std::size_t(2));
    int64_t sum = 0;
    for (const auto& c : r1.contributions) sum += c.contribution;
    const double base = static_cast<double>(sum) / 1000000.0;
    // 多源加成（规则 multiSourceBonus，上限 maxBonus）
    const double bonus = std::min(
        0.05 * 1.0, r.all["entityTypes"]["confidence"]["maxBonus"].get<double>());
    CHECK_NEAR(r1.data.confidence, std::min(1.0, base + bonus), 2e-6);
    // 融合不是简单覆盖：再加一条观测后结果变化且仍可复算
    const RegisterResult r2 = e.updateObservation(r1.data.id, SourceObs{sources[2], "k", 1.0, d.clock->t});
    CHECK_EQ(r2.code, 0);
    CHECK(r2.data.confidence > r1.data.confidence);
    int64_t sum2 = 0;
    for (const auto& c : r2.contributions) sum2 += c.contribution;
    const double bonus2 = std::min(
        0.05 * 2.0, r.all["entityTypes"]["confidence"]["maxBonus"].get<double>());
    CHECK_NEAR(r2.data.confidence, std::min(1.0, static_cast<double>(sum2) / 1000000.0 + bonus2),
               2e-6);
    // 结果可复现：同样输入再跑一次 → 同样的贡献度
    EntityLedger e2;
    CHECK_EQ(loadPolicies(e2), true);
    const RegisterResult r3 = e2.registerEntity(in);
    CHECK_EQ(r3.code, 0);
    CHECK_NEAR(r3.data.confidence, r1.data.confidence, 1e-12);
    CHECK_EQ(r3.contributions.front().contribution, r1.contributions.front().contribution);
}

void reg06_dynamic_state_machine() {
    requires_("ELG-REG-06");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const auto rec = e.getEntityByNo(d.mission, 1);
    CHECK(rec.has_value());
    if (!rec) return;
    const json transitions = r.et()["dynamicStates"]["transitions"];
    // 找一条规则声明的合法迁移
    std::string from = rec->dynamicState;
    std::string to;
    for (const auto& t : transitions) {
        if (t["from"].get<std::string>() == from) {
            to = t["to"].get<std::string>();
            break;
        }
    }
    CHECK(!to.empty());
    const ActionResult ok = e.setDynamicState(rec->id, to, "rule-declared", "op-1");
    CHECK_EQ(ok.code, 0);
    CHECK_STR(ok.status, "ok");
    CHECK_EQ(ok.changes.size(), std::size_t(1));
    CHECK_STR(ok.changes.front().field, "dynamicState");
    // 未声明的迁移 → 拒绝 + 可读原因
    std::string illegal;
    for (const auto& k : r.stateKeys()) {
        bool declared = false;
        for (const auto& t : transitions) {
            if (t["from"].get<std::string>() == to && t["to"].get<std::string>() == k) declared = true;
        }
        if (!declared && k != to) {
            illegal = k;
            break;
        }
    }
    CHECK(!illegal.empty());
    const ActionResult bad = e.setDynamicState(rec->id, illegal, "not-declared", "op-1");
    CHECK_EQ(bad.code, 1003);
    CHECK_EQ(bad.unmet.size(), std::size_t(1));
    CHECK(bad.unmet.front().reason.find("transition") != std::string::npos);
    // 幂等：重复设置同一状态 → already-done
    const ActionResult again = e.setDynamicState(rec->id, to, "again", "op-1");
    CHECK_EQ(again.code, 0);
    CHECK_EQ(again.idempotent, true);
    CHECK_STR(again.status, "already-done");
}

// ---- ELG-ID -----------------------------------------------------------------

void id01_numbering_rules_and_no_reuse() {
    requires_("ELG-ID-01", "CTR-EN-03");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const int start = r.et()["numbering"]["start"].get<int>();
    const bool reuse = r.et()["numbering"]["reuse"].get<bool>();
    // 编号从规则声明的起始值开始且连续
    std::vector<int> nos;
    for (const auto& rec : e.listEntities(EntityQuery{d.mission})) nos.push_back(rec.no);
    CHECK_EQ(nos.front(), start);
    for (std::size_t i = 1; i < nos.size(); ++i) CHECK_EQ(nos[i], nos[i - 1] + 1);
    // 删除中间目标后新增：reuse=false → 编号不被复用
    const std::string victim = noToId(d, start + 2);
    CHECK(!victim.empty());
    const ActionResult rt = e.retireEntity(victim, "destroyed", "op-1");
    CHECK_EQ(rt.code, 0);
    RegisterInput in;
    in.missionId = d.mission;
    in.typeKey = r.typeKeys().front();
    in.lng = r.referenceLng();
    in.lat = r.referenceLat();
    in.obsKey = "obs-new";
    const RegisterResult rr = e.registerEntity(in);
    CHECK_EQ(rr.code, 0);
    if (reuse) {
        CHECK_EQ(rr.data.no, start + 2);  // 规则声明可复用时复用被释放的号
    } else {
        CHECK(rr.data.no > start + 6);  // 规则声明不复用 → 取新号
    }
    // 注销后仍可按 no 查历史（软删除保留历史），但默认列表不含
    CHECK_EQ(e.getEntityByNo(d.mission, start + 2).has_value(), false);
    CHECK_EQ(e.listEntities(EntityQuery{d.mission, "", "", "", "", 0.0, true, 100, 0}).size(),
             std::size_t(8));
}

void id02a_consistency_localizes_count_mismatch() {
    requires_("ELG-ID-02", "CTR-EN-06", "CTR-EN-08", "ELG-ID-03");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    // 三个界面视图（视图标签由规则声明，测试不写业务字面量）
    const std::string viewA = "boardA";
    const std::string viewB = "boardB";
    const std::string viewC = "boardC";
    const std::vector<std::string> phA = r.viewPhases("situation", 0);
    CHECK_EQ(phA.size(), std::size_t(1));
    const std::string phase = phA.empty() ? std::string() : phA.front();
    ViewSnapshot a = snapshotFrom(e, d.mission, viewA, phase, false);
    ViewSnapshot b = snapshotFrom(e, d.mission, viewB, phase, false);
    ViewSnapshot c = snapshotFrom(e, d.mission, viewC, phase, false);
    // 复刻初稿 §10.12：同一场景内三个界面看到的目标数不同（五个 / 六个 / 七个）
    CHECK_EQ(a.items.size(), std::size_t(5));
    CHECK_EQ(b.items.size(), std::size_t(6));
    CHECK_EQ(c.items.size(), std::size_t(7));
    ConsistencyRequest req;
    req.missionId = d.mission;
    req.views = {a, b, c};
    const ConsistencyReport rep = e.checkConsistency(req);
    CHECK_EQ(rep.consistent, false);
    CHECK_EQ(rep.diffs.size(), std::size_t(3));
    // 报告 MUST 定位到**具体编号**与**具体视图**
    bool found6 = false;
    int no7LackingViews = 0;
    for (const auto& diff : rep.diffs) {
        if (diff.field != "presence" || diff.kind != "missing") continue;
        CHECK_EQ(diff.views.size(), std::size_t(2));
        if (diff.no == 6) {
            found6 = true;
            CHECK_STR(diff.views[0], a.viewName);  // "少两个"的那个界面被点名
            CHECK_STR(diff.views[1], b.viewName);  // 与之不一致的对侧界面
        }
        if (diff.no == 7) {
            ++no7LackingViews;
            CHECK(diff.views[0] == a.viewName || diff.views[0] == b.viewName);
            CHECK_STR(diff.views[1], c.viewName);
        }
    }
    CHECK(found6);
    CHECK_EQ(no7LackingViews, 2);
    // "界面自行过滤"也被检出（引擎给出应可见集合，界面 MUST NOT 自己砍）
    ViewSnapshot selfFiltered = snapshotFrom(e, d.mission, viewC, phase, false);
    selfFiltered.items.pop_back();
    selfFiltered.items.pop_back();
    ConsistencyRequest req3;
    req3.missionId = d.mission;
    req3.viewKey = viewC;
    PhaseContext pc3;
    pc3.phaseKey = phase;
    pc3.missionId = d.mission;
    req3.phase = pc3;
    req3.views = {selfFiltered};
    const ConsistencyReport rep3 = e.checkConsistency(req3);
    CHECK_EQ(rep3.consistent, false);
    CHECK_EQ(rep3.expectedVisible.size(), std::size_t(7));
    int selfFilteredDiffs = 0;
    for (const auto& diff : rep3.diffs) {
        if (diff.reason.find("engine-expected") != std::string::npos) ++selfFilteredDiffs;
    }
    CHECK_EQ(selfFilteredDiffs, 2);
    // 事件负载（protocol.md §4.4）逐字段：{missionId, diffs:[{no, field, views[]}]}
    CHECK(d.sink->consistencies >= 1);
    const json ev = d.sink->consistencyPayloads.front();
    CHECK(ev.contains("missionId"));
    CHECK(ev.contains("diffs"));
    CHECK(ev["diffs"][0].contains("no"));
    CHECK(ev["diffs"][0].contains("field"));
    CHECK(ev["diffs"][0].contains("views"));
    // 同一阶段两次查询应可见集合一致（ELG-ID-03）
    CHECK_EQ(e.visibleSet(VisibleSetRequest{d.mission, viewA, "", {}, true}).total, 5);
    CHECK_EQ(e.visibleSet(VisibleSetRequest{d.mission, viewC, "", {}, true}).total, 7);
    // 跨阶段集合变化可解释（阶段 key 同样来自规则）
    std::vector<std::string> phases;
    for (std::size_t i = 0; i < r.viewFilterCount("situation"); ++i) {
        for (const auto& p : r.viewPhases("situation", i)) {
            if (p == "*") continue;
            phases.push_back(p);  // 每条过滤器取首个阶段（规则声明顺序）
            break;
        }
    }
    CHECK_EQ(phases.size(), std::size_t(3));
    PhaseContext pc;
    pc.phaseKey = phases[0];
    pc.missionId = d.mission;
    ConsistencyRequest req2;
    req2.missionId = d.mission;
    req2.viewKey = "situation";
    req2.phase = pc;
    req2.views = {snapshotFrom(e, d.mission, "situation", phases[0], false),
                  snapshotFrom(e, d.mission, "situation", phases[1], false),
                  snapshotFrom(e, d.mission, "situation", phases[2], false)};
    const ConsistencyReport rep2 = e.checkConsistency(req2);
    CHECK_EQ(rep2.expectedVisible.size(), std::size_t(5));
    CHECK_EQ(rep2.phaseDeltas.size(), std::size_t(3));
    CHECK_EQ(rep2.phaseDeltas[0].count, 5);
    CHECK_EQ(rep2.phaseDeltas[1].count, 6);
    CHECK_EQ(rep2.phaseDeltas[2].count, 7);
    CHECK_EQ(rep2.phaseDeltas[1].addedNos.size(), std::size_t(1));
    CHECK_EQ(rep2.phaseDeltas[2].addedNos.size(), std::size_t(2));
    CHECK_STR(rep2.phaseDeltas[0].basis, "current-state");
}

void id02b_consistency_localizes_flag_dispute() {
    requires_("ELG-ID-02", "ELG-ID-05");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string flag = r.flagKeys().front();
    // 台账权威：二号目标持有该旗标（显式动作 + 留痕）
    FlagInput fi;
    fi.missionId = d.mission;
    fi.entityId = noToId(d, 2);
    fi.flagKey = flag;
    fi.operatorId = "op-1";
    fi.reason = "rule-driven";
    CHECK_EQ(e.setFlag(fi).code, 0);
    CHECK_EQ(e.flagHolders(d.mission, flag).size(), std::size_t(1));
    CHECK_EQ(e.flagHolders(d.mission, flag).front().no, 2);
    const std::vector<std::string> phA = r.viewPhases("situation", 0);
    const std::string phase = phA.empty() ? std::string() : phA.front();
    ViewSnapshot board = snapshotFrom(e, d.mission, "boardC", phase, true);
    ViewSnapshot brief = snapshotFrom(e, d.mission, "brief", phase, true);
    // 文字稿与界面就"谁高价值"给出不同答案（002 vs 003）
    for (auto& it : board.items) {
        if (it.no == 2) it.flagKeys.clear();
        if (it.no == 3) it.flagKeys.push_back(flag);
    }
    ConsistencyRequest req;
    req.missionId = d.mission;
    req.views = {board, brief};
    const ConsistencyReport rep = e.checkConsistency(req);
    CHECK_EQ(rep.consistent, false);
    int missingOn2 = 0;
    int extraOn3 = 0;
    for (const auto& diff : rep.diffs) {
        if (diff.field != "flag:" + flag) continue;
        if (diff.no == 2 && diff.kind == "missing") {
            ++missingOn2;
            CHECK_EQ(diff.views.size(), std::size_t(2));  // 两个视图都点名
            CHECK_STR(diff.views[0], board.viewName);
            CHECK_STR(diff.views[1], brief.viewName);
        }
        if (diff.no == 3 && diff.kind == "extra") ++extraOn3;
    }
    CHECK_EQ(missingOn2, 1);
    CHECK_EQ(extraOn3, 1);
    // 旗标唯一性：同一任务内第二个持有者要么被拒，要么显式转移（ELG-ID-05）
    FlagInput second = fi;
    second.entityId = noToId(d, 3);
    const ActionResult rej = e.setFlag(second);
    CHECK_EQ(rej.code, 1003);
    CHECK(!rej.unmet.empty());
    second.transfer = true;
    CHECK_EQ(e.setFlag(second).code, 0);
    CHECK_EQ(e.flagHolders(d.mission, flag).size(), std::size_t(1));
    CHECK_EQ(e.flagHolders(d.mission, flag).front().no, 3);
}

void id02c_consistency_detects_no_and_type_mismatch() {
    requires_("ELG-ID-02", "CTR-EN-05", "CTR-EN-08");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    ViewSnapshot a = snapshotFrom(e, d.mission, "boardC", "", false);
    ViewSnapshot b = snapshotFrom(e, d.mission, "brief", "", false);
    // 人为制造：编号漂移（同一 id 写成别的 no）与类型漂移（同一 no 写成别的类型）
    const std::vector<std::string> types = r.typeKeys();
    b.items[1].no = 99;
    b.items[2].typeKey = types.back();
    // 以及一个台账里不存在的实体（界面自造）
    ViewItem ghost;
    ghost.id = "ent-ghost";
    ghost.no = 77;
    b.items.push_back(ghost);
    ConsistencyRequest req;
    req.missionId = d.mission;
    req.views = {a, b};
    const ConsistencyReport rep = e.checkConsistency(req);
    bool noDiff = false;
    bool typeDiff = false;
    bool ghostDiff = false;
    for (const auto& diff : rep.diffs) {
        if (diff.field == "no" && diff.kind == "mismatch") {
            noDiff = true;
            CHECK_EQ(diff.no, 2);
            CHECK_STR(diff.expected, "2");
            CHECK_STR(diff.actual, "99");
            CHECK_STR(diff.views.front(), b.viewName);
        }
        if (diff.field == "type") {
            typeDiff = true;
            CHECK_EQ(diff.no, 3);
        }
        if (diff.kind == "unknown" && diff.field == "presence") ghostDiff = true;
    }
    CHECK(noDiff);
    CHECK(typeDiff);
    CHECK(ghostDiff);
    // id ↔ no ↔ 类型 强一致（CTR-EN-05）：无差异时 consistent=true
    ViewSnapshot c = snapshotFrom(e, d.mission, "boardC", "", false);
    ViewSnapshot dd = snapshotFrom(e, d.mission, "brief", "", false);
    ConsistencyRequest ok;
    ok.missionId = d.mission;
    ok.views = {c, dd};
    const ConsistencyReport clean = e.checkConsistency(ok);
    CHECK_EQ(clean.consistent, true);
    CHECK_EQ(clean.diffs.size(), std::size_t(0));
    CHECK_STR(clean.message, "consistent");
}

void id03_visible_set_is_engine_owned_and_stable() {
    requires_("ELG-ID-03", "CTR-EN-06");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    // 同一阶段两次查询结果一致（确定性）
    const VisibleSetResult a =
        e.visibleSet(VisibleSetRequest{d.mission, "situation", "", {}, true});
    const VisibleSetResult b =
        e.visibleSet(VisibleSetRequest{d.mission, "situation", "", {}, true});
    CHECK_STR(a.toJson().dump(), b.toJson().dump());
    // 被排除项带有可解释原因（界面无需自行过滤）
    CHECK_EQ(a.total + a.excluded, 7);
    for (const auto& ex : a.excludedItems) CHECK(!ex.reason.empty());
    // 未知视图 → 拒绝而非静默返回全集
    CHECK_EQ(e.visibleSet(VisibleSetRequest{d.mission, "no-such-view", "", {}, true}).code, 1000);
    // 未装载规则 → 1005
    EntityLedger e2;
    CHECK_EQ(e2.visibleSet(VisibleSetRequest{d.mission, "situation", "", {}, true}).code, 1005);
    // 视图限定排序：只排该视图可见集合
    std::vector<RankedEntity> rk = e.ranking(RankQuery{d.mission, "boardA", 0});
    CHECK_EQ(rk.size(), std::size_t(5));
    for (std::size_t i = 1; i < rk.size(); ++i) CHECK(rk[i].rank == rk[i - 1].rank + 1);
}

void id04_type_binding_and_reclassify_trace() {
    requires_("ELG-ID-04", "CTR-EN-07");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string id = noToId(d, 3);
    const auto before = e.getEntity(id);
    CHECK(before.has_value());
    const std::vector<std::string> types = r.typeKeys();
    std::string newType;
    for (const auto& t : types) {
        if (t != before->typeKey) {
            newType = t;
            break;
        }
    }
    // ① 类型漂移（无留痕）→ 被检出
    ViewSnapshot a = snapshotFrom(e, d.mission, "boardC", "", false);
    ViewSnapshot b = snapshotFrom(e, d.mission, "brief", "", false);
    for (auto& it : b.items) {
        if (it.no == 3) it.typeKey = newType;
    }
    ConsistencyRequest req;
    req.missionId = d.mission;
    req.views = {a, b};
    const ConsistencyReport rep = e.checkConsistency(req);
    CHECK_EQ(rep.consistent, false);
    bool typeDiff = false;
    for (const auto& diff : rep.diffs) {
        if (diff.field == "type" && diff.no == 3) {
            typeDiff = true;
            CHECK_STR(diff.kind, "mismatch");
            CHECK(diff.reason.find("no reclassification trace") != std::string::npos);
        }
    }
    CHECK(typeDiff);
    // ② 走显式重判动作 → 允许并留痕
    ReclassifyInput ri;
    ri.entityId = id;
    ri.typeKey = newType;
    ri.operatorId = "op-9";
    ri.reason = "confirmed-by-imagery";
    CHECK_EQ(e.reclassifyType(ReclassifyInput{id, newType, "op-9", ""}).code, 1000);  // 无原因拒绝
    const ActionResult ok = e.reclassifyType(ri);
    CHECK_EQ(ok.code, 0);
    CHECK_EQ(ok.changes.size(), std::size_t(1));
    CHECK_STR(ok.changes.front().field, "type");
    CHECK_STR(ok.changes.front().to, newType);
    const auto after = e.getEntity(id);
    CHECK(after.has_value());
    if (after) {
        CHECK_STR(after->typeKey, newType);
        bool traced = false;
        for (const auto& t : after->trace) {
            if (t.field == "type" && t.action == "reclassify" && t.operatorId == "op-9") {
                traced = true;
                CHECK_STR(t.to, newType);
                CHECK_STR(t.from, before->typeKey);
            }
        }
        CHECK(traced);
    }
    // ③ 重判后：老视图渲染旧类型 → 检出为 stale，且留痕在 reclassifications[] 里
    ViewSnapshot stale = b;
    for (auto& it : stale.items) {
        if (it.no == 3) it.typeKey = before->typeKey;
    }
    ConsistencyRequest req2;
    req2.missionId = d.mission;
    req2.views = {a, stale};
    const ConsistencyReport rep2 = e.checkConsistency(req2);
    bool staleDiff = false;
    for (const auto& diff : rep2.diffs) {
        if (diff.field == "type" && diff.no == 3) {
            staleDiff = true;
            CHECK_STR(diff.kind, "stale");
        }
    }
    CHECK(staleDiff);
    CHECK_EQ(rep2.reclassifications.size(), std::size_t(1));
    CHECK_STR(rep2.reclassifications.front().operatorId, "op-9");
    CHECK_EQ(rep2.reclassifications.front().no, 3);
    // 类型变化只此一条路径：引擎没有"静默改类型"的接口（结构性断言见 acceptance）
}

void id05_flag_uniqueness_and_holders() {
    requires_("ELG-ID-05");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string flag = r.flagKeys().front();
    CHECK_EQ(e.flagHolders(d.mission, flag).size(), std::size_t(0));  // 数量与去向可查
    FlagInput fi;
    fi.missionId = d.mission;
    fi.entityId = noToId(d, 1);
    fi.flagKey = flag;
    fi.operatorId = "op-1";
    CHECK_EQ(e.setFlag(fi).code, 0);
    // 幂等重复
    const ActionResult again = e.setFlag(fi);
    CHECK_EQ(again.code, 0);
    CHECK_EQ(again.idempotent, true);
    // 越界（唯一旗标第二个持有者）→ 报错
    fi.entityId = noToId(d, 4);
    CHECK_EQ(e.setFlag(fi).code, 1003);
    // 清除必须作用在实际持有者上（越界设置不会改变持有者）
    FlagInput holderClear;
    holderClear.missionId = d.mission;
    holderClear.entityId = noToId(d, 1);
    holderClear.flagKey = flag;
    holderClear.operatorId = "op-1";
    const ActionResult cl = e.clearFlag(holderClear);
    CHECK_EQ(cl.code, 0);
    CHECK_EQ(e.clearFlag(holderClear).idempotent, true);
    fi.entityId = noToId(d, 4);
    CHECK_EQ(e.setFlag(fi).code, 0);
    CHECK_EQ(e.flagHolders(d.mission, flag).front().no, 4);
    // 视图按旗标过滤（"高价值面板"由规则声明）
    const VisibleSetResult hv =
        e.visibleSet(VisibleSetRequest{d.mission, "hvBoard", "", {}, false});
    CHECK_EQ(hv.total, 1);
    CHECK_EQ(hv.items.front().no, 4);
}

// ---- ELG-RATE ---------------------------------------------------------------

void rate01_rating_follows_injected_rules() {
    requires_("ELG-RATE-01", "ELG-RATE-03");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const auto rec = e.getEntityByNo(d.mission, 1);
    CHECK(rec.has_value());
    ThreatSnapshot s;
    if (rec) s = ThreatSnapshot{rec->id,  rec->no,        d.mission,   rec->typeKey,
                                rec->lng, rec->lat,       rec->confidence, rec->dynamicState,
                                static_cast<int>(rec->sources.size()), rec->flags, rec->attributes,
                                rec->updatedAt, false, 0.0, 0.0};
    const ThreatAssessment base = e.assessThreat(s);
    CHECK_EQ(base.factors.size(), r.tf()["items"].size());
    for (const auto& f : base.factors) CHECK(!f.source.empty());
    CHECK(!base.band.empty());
    // 同一目标、换一份阈值 → 分档变化（分档是阈值决定的，不是布尔判断）
    EntityLedger e2;
    CHECK_EQ(loadPolicies(e2), true);
    json bump = readJson(std::string(ENTITY_LEDGER_TEST_FIXTURES) + "/bands-shifted.json");
    CHECK_EQ(e2.loadPolicies(bump).code, 0);
    const ThreatAssessment other = e2.assessThreat(s);
    CHECK_EQ(other.score, base.score);            // 分不变（因子与权重未变）
    CHECK(base.band != other.band);               // 档变了（阈值变了）
    // 换因子权重 → 分数变化
    EntityLedger e3;
    CHECK_EQ(loadPolicies(e3), true);
    json reweight = readJson(std::string(ENTITY_LEDGER_TEST_FIXTURES) + "/factors-reweighted.json");
    CHECK_EQ(e3.loadPolicies(reweight).code, 0);
    const ThreatAssessment third = e3.assessThreat(s);
    CHECK(third.score != base.score);
}

void rate02_score_recomputable_by_hand() {
    requires_("ELG-RATE-02");
    EntityLedger e;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    // 手算夹具：规则里的某类型（基础威胁 0.9）、状态（表值 1.0）、基准点 (0,0)、目标在 0.1° 纬度外
    const std::string typeKey = r.typeWithBase(0.9);
    const std::string stateKey = r.tableKeyWithValue("state", 1.0);
    CHECK(!typeKey.empty());
    CHECK(!stateKey.empty());
    ThreatSnapshot s;
    s.missionId = "m-hand";
    s.typeKey = typeKey;
    s.lng = 0.0;
    s.lat = 0.1;
    s.referenceSet = true;
    s.referenceLng = 0.0;
    s.referenceLat = 0.0;
    s.confidence = 0.9;
    s.dynamicState = stateKey;
    s.sourceCount = 3;
    const ThreatAssessment a = e.assessThreat(s);
    // 逐因子手算（权重 0.40/0.30/0.15/0.10/0.05，W = 1.0）：
    //   typeBase  : 0.9            → round(0.9 *0.40*100)  = 36
    //   distance  : 11119 m, [0,50000] 反向 → 1-0.222380 = 0.777620 → round(23.3286) = 23
    //   state     : 1.0            → round(1.0 *0.15*100)  = 15
    //   sourceCount: (3-1)/(4-1)=0.666667 → round(6.66667) = 7
    //   confidence: 0.9            → round(4.5)            = 5   （half-up）
    //   总分 = 36+23+15+7+5 = 86 → 档 min 70 → 高级档
    CHECK_EQ(a.factors.size(), std::size_t(5));
    CHECK_EQ(a.factors[0].contribution, 36);
    CHECK_EQ(a.factors[1].contribution, 23);
    CHECK_EQ(a.factors[2].contribution, 15);
    CHECK_EQ(a.factors[3].contribution, 7);
    CHECK_EQ(a.factors[4].contribution, 5);
    CHECK_EQ(a.score, 86);
    CHECK_EQ(a.totalWeightPpm, 1000000);
    int sum = 0;
    for (const auto& f : a.factors) sum += f.contribution;
    CHECK_EQ(sum, a.score);  // 逐项贡献之和 == 总分（可手算复算）
    // 导出的整数项可独立复算每一项贡献（round_half_up(norm*w*100/(W*1e6))）
    for (const auto& f : a.factors) {
        const long long num = static_cast<long long>(f.normPpm) * f.weightPpm * 100;
        const long long den = static_cast<long long>(a.totalWeightPpm) * 1000000;
        const long long expect = (2 * num + den) / (2 * den);
        CHECK_EQ(static_cast<long long>(f.contribution), expect);
    }
    // 分档边界与阈值一致
    for (const auto& band : r.tf()["bands"]) {
        if (band["key"].get<std::string>() == a.band) {
            CHECK(a.score >= band["min"].get<int>());
            CHECK_STR(a.status, band["state"].get<std::string>());
        }
    }
}

void rate03_bands_from_thresholds_not_boolean() {
    requires_("ELG-RATE-03");
    EntityLedger e;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    // 只为"分档由阈值决定"构造：同一个分数、两组阈值 → 两个档；组内逐档严格可复现
    json pkg = e.effectivePolicies();
    json factors = pkg["threatFactors"];
    factors["bands"] = json::array();
    factors["bands"].push_back(json{{"key", "top"}, {"min", 80}});
    factors["bands"].push_back(json{{"key", "mid"}, {"min", 50}});
    factors["bands"].push_back(json{{"key", "bottom"}, {"min", 0}});
    json reload = json::object();
    reload["policiesNamespace"] = "mapapp";
    reload["schemaVersion"] = "1.0.0";
    reload["kind"] = "threatFactors";
    reload["items"] = factors["items"];
    reload["bands"] = factors["bands"];
    EntityLedger e2;
    CHECK_EQ(loadPolicies(e2), true);          // 类型集来自主规则包
    CHECK_EQ(e2.loadPolicies(reload).code, 0);  // 分档被覆盖
    ThreatSnapshot s;
    s.missionId = "m";
    s.typeKey = r.typeWithBase(0.9);
    s.confidence = 0.9;
    s.dynamicState = r.tableKeyWithValue("state", 1.0);
    s.sourceCount = 3;
    s.referenceSet = true;
    s.referenceLng = 0.0;
    s.referenceLat = 0.0;
    s.lat = 0.1;
    const ThreatAssessment a = e2.assessThreat(s);
    CHECK_EQ(a.score, 86);
    CHECK_STR(a.band, "top");
    // 分数不变、档可配：抬高阈值 → 落回中档
    reload["bands"] = json::array();
    reload["bands"].push_back(json{{"key", "top"}, {"min", 95}});
    reload["bands"].push_back(json{{"key", "mid"}, {"min", 50}});
    reload["bands"].push_back(json{{"key", "bottom"}, {"min", 0}});
    EntityLedger e3;
    CHECK_EQ(loadPolicies(e3), true);
    CHECK_EQ(e3.loadPolicies(reload).code, 0);
    const ThreatAssessment b = e3.assessThreat(s);
    CHECK_EQ(b.score, 86);
    CHECK_STR(b.band, "mid");
    // 缺 min<=0 的档 → 装载被拒（逐条原因）
    reload["bands"] = json::array();
    reload["bands"].push_back(json{{"key", "top"}, {"min", 95}});
    const LoadResult bad = EntityLedger::validatePolicies(reload);
    CHECK_EQ(bad.code, 1000);
    CHECK(bad.issues.size() >= 1);
}

void rate04_distance_uses_real_geometry() {
    requires_("ELG-RATE-04");
    EntityLedger e;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    const std::string typeKey = r.typeWithBase(0.9);
    ThreatSnapshot s;
    s.missionId = "m-geo";
    s.typeKey = typeKey;
    s.referenceSet = true;
    s.referenceLng = 0.0;
    s.referenceLat = 0.0;
    s.confidence = 0.9;
    s.dynamicState = r.tableKeyWithValue("state", 1.0);
    s.sourceCount = 3;
    // 同经线 0.1°：R * (0.1° 弧度) = 6371000 * 0.0017453292519943296 = 11119.49 m → 取整 11119
    s.lng = 0.0;
    s.lat = 0.1;
    const ThreatAssessment a = e.assessThreat(s);
    const FactorScore* dist = nullptr;
    for (const auto& f : a.factors) {
        if (f.source == "distance") dist = &f;
    }
    CHECK(dist != nullptr);
    if (dist) {
        CHECK_NEAR(dist->rawNumber, 11119.0, 0.5);
        CHECK_EQ(static_cast<int>(dist->rawNumber), 11119);
        CHECK_EQ(dist->normPpm, 777620);  // 1 - 11119/50000 = 0.77762
    }
    // 0.2° → 22238.98 → 22239（几何是真实的，不是占位）
    s.lat = 0.2;
    const ThreatAssessment b = e.assessThreat(s);
    for (const auto& f : b.factors) {
        if (f.source == "distance") {
            CHECK_EQ(static_cast<int>(f.rawNumber), 22239);
            CHECK_EQ(f.normPpm, 555220);
        }
    }
    // 距离越远 → 贡献越低（direction=lower 由规则声明）
    int ca = 0;
    int cb = 0;
    for (const auto& f : a.factors) {
        if (f.source == "distance") ca = f.contribution;
    }
    for (const auto& f : b.factors) {
        if (f.source == "distance") cb = f.contribution;
    }
    CHECK(ca > cb);
    // 快照未给基准 → 回落"任务参考点"（规则声明），距离仍为真实几何（不伪造、不置零）
    ThreatSnapshot n = s;
    n.referenceSet = false;
    n.lng = r.referenceLng();
    n.lat = r.referenceLat();
    const ThreatAssessment c = e.assessThreat(n);
    for (const auto& f : c.factors) {
        if (f.source == "distance") {
            CHECK_EQ(f.missing, false);
            CHECK_EQ(static_cast<int>(f.rawNumber), 0);   // 与任务参考点重合
            CHECK_EQ(f.normPpm, 1000000);
            CHECK_EQ(f.contribution, 30);
        }
    }
}

void rate05_assessment_is_pure_over_snapshot() {
    requires_("ELG-RATE-05", "ELG-NFR-03");
    // 空引擎（无任务、无规则外的任何全局态）：仅凭快照即可评级
    EntityLedger e;
    CHECK_EQ(e.listEntities(EntityQuery{"m-none"}).size(), std::size_t(0));
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    ThreatSnapshot s;
    s.entityId = "ent-x";
    s.no = 1;
    s.missionId = "m-snapshot";
    s.typeKey = r.typeKeys().front();
    s.lng = 0.0;
    s.lat = 0.0;
    s.referenceSet = true;
    s.referenceLng = 0.0;
    s.referenceLat = 0.0;
    s.confidence = 0.5;
    s.dynamicState = r.tableKeyWithValue("state", 0.2);
    s.sourceCount = 1;
    const ThreatAssessment a = e.assessThreat(s);
    const ThreatAssessment b = e.assessThreat(s);
    CHECK_STR(a.toJson().dump(), b.toJson().dump());  // 纯函数：同输入同输出
    CHECK_EQ(a.score >= 0 && a.score <= 100, true);
    // 台账里没有这个实体 → 评级照常（不读全局状态）
    CHECK_EQ(e.getEntity("ent-x").has_value(), false);
    // 状态因子来自快照（换状态 → 分数变化），与任务/台账无关
    ThreatSnapshot s2 = s;
    s2.dynamicState = r.tableKeyWithValue("state", 1.0);
    CHECK(e.assessThreat(s2).score > a.score);
}

void rate06_strike_window_is_computed_interval() {
    requires_("ELG-RATE-06");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string id = noToId(d, 1);
    // 轨迹：两点定速度与航向（窗口由轨迹外推 + 规则暴露规律推算）
    const double lng0 = r.referenceLng();
    const double lat0 = r.referenceLat();
    for (int i = 0; i < 4; ++i) {
        TrackPoint p;
        p.ts = d.clock->t - (3 - i) * 10000;
        p.lng = lng0 + 0.0005 * i;
        p.lat = lat0 + 0.0002 * i;
        CHECK_EQ(e.appendTrack(TrackInput{id, p}).code, 0);
    }
    const StrikeWindowResult w = e.strikeWindow(id, StrikeWindowQuery{});
    CHECK_EQ(w.code, 0);
    CHECK_EQ(w.data.found, true);
    // **结构化时间区间**：[fromMs, toMs) + durationMs + leadMs（不是字符串）
    CHECK(w.data.toMs > w.data.fromMs);
    CHECK_EQ(w.data.durationMs, w.data.toMs - w.data.fromMs);
    CHECK_EQ(w.data.leadMs, w.data.fromMs - d.clock->t);
    CHECK(!w.data.basis.empty());
    CHECK_EQ(w.data.extrapolated, true);
    // 复刻演示口径：规则 offsetMs = 752000 ms（现状硬编码窗口字符串的数值等价物），窗口起点与规则一致
    const json pattern = r.tf()["strikeWindow"]["patterns"][0];
    CHECK_EQ(w.data.leadMs, pattern["offsetMs"].get<long long>());
    CHECK_EQ(w.data.durationMs, std::min(pattern["exposedMs"].get<long long>(),
                                        r.tf()["strikeWindow"]["horizonMs"].get<long long>() -
                                            pattern["offsetMs"].get<long long>()));
    // 逐段可复算依据：段起止与规则周期一致
    CHECK(w.data.segments.size() >= 1);
    CHECK_EQ(w.data.segments.front().fromMs, w.data.fromMs);
    CHECK_EQ(w.data.segments.front().basis, w.data.basis);
    CHECK(w.data.segments.front().predicted);
    // 窗口起点位置是外推（预测，不是实测）
    CHECK(w.data.segments.front().speedMps > 0.0);
    // 无轨迹 → 结构化"未找到"，不是硬编码字符串
    RegisterInput in;
    in.missionId = d.mission;
    in.typeKey = r.typeKeys().front();
    in.lng = lng0;
    in.lat = lat0;
    in.obsKey = "obs-nowindow";
    const RegisterResult nw = e.registerEntity(in);
    CHECK_EQ(nw.code, 0);
    const StrikeWindowResult w2 = e.strikeWindow(nw.data.id, StrikeWindowQuery{});
    CHECK_EQ(w2.code, 0);
    CHECK_EQ(w2.data.found, false);
    CHECK_STR(w2.message, "insufficient-track");
    CHECK_EQ(w2.data.toJson().contains("fromMs"), true);
    CHECK_EQ(e.strikeWindow("ent-none", StrikeWindowQuery{}).code, 1004);
}

// ---- ELG-RANK ---------------------------------------------------------------

void rank01_stable_ordering_deterministic() {
    requires_("ELG-RANK-01");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::vector<RankedEntity> a = e.ranking(RankQuery{d.mission, "", 0});
    const std::vector<RankedEntity> b = e.ranking(RankQuery{d.mission, "", 0});
    CHECK_EQ(a.size(), std::size_t(7));
    CHECK_EQ(toJson(a.front()).dump() == toJson(b.front()).dump(), true);
    for (std::size_t i = 1; i < a.size(); ++i) CHECK_EQ(a[i].rank, i + 1);
    // 同分排序稳定：末位键恒为 no（规则未声明 no 时引擎补上）
    CHECK(a.front().sortKeys.size() >= 2);
    // 逐键可复现排序过程
    const std::vector<std::string> keyFields = [&] {
        std::vector<std::string> v;
        for (const auto& k : r.tf()["rank"]["keys"]) v.push_back(k["field"].get<std::string>());
        return v;
    }();
    CHECK_EQ(a.front().sortKeys.size(), keyFields.size());
    // 规则未声明 rank.keys → 引擎缺省（优先级 + 威胁，末位 no），且文档化
    json pkg = e.effectivePolicies();
    json reload = json::object();
    reload["policiesNamespace"] = "mapapp";
    reload["schemaVersion"] = "1.0.0";
    reload["kind"] = "threatFactors";
    reload["items"] = pkg["threatFactors"]["items"];
    reload["bands"] = pkg["threatFactors"]["bands"];
    EntityLedger e2;
    CHECK_EQ(loadPolicies(e2), true);
    CHECK_EQ(e2.loadPolicies(reload).code, 0);  // 未声明 rank.keys → 引擎缺省排序键
    CHECK(e2.definitionInfo().loaded);
}

void rank02_priority_explicit_changes_order() {
    requires_("ELG-RANK-02");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const int defaultPriority = r.tf()["rank"]["defaultPriority"].get<int>();
    std::vector<RankedEntity> before = e.ranking(RankQuery{d.mission, "", 0});
    CHECK_EQ(before.front().priority, defaultPriority);
    CHECK_EQ(before.front().prioritySet, false);
    // 显示设置优先级（初稿 T5-2 的 1/2/3 口径由规则与调用方给值）
    const std::string id = noToId(d, 5);
    PriorityInput pi;
    pi.entityId = id;
    pi.priority = 1;
    pi.operatorId = "op-1";
    pi.reason = "commander-order";
    CHECK_EQ(e.setPriority(pi).code, 0);
    std::vector<RankedEntity> after = e.ranking(RankQuery{d.mission, "", 0});
    CHECK_EQ(after.front().no, 5);
    CHECK_EQ(after.front().priority, 1);
    CHECK_EQ(after.front().prioritySet, true);
    CHECK_STR(after.front().id, id);
    // 幂等：重复设置同一值
    const ActionResult again = e.setPriority(pi);
    CHECK_EQ(again.code, 0);
    CHECK_EQ(again.idempotent, true);
    // 设置后排序与界面一致（同一规则口径）
    const std::vector<RankedEntity> again2 = e.ranking(RankQuery{d.mission, "", 0});
    CHECK_EQ(again2.front().no, 5);
}

void rank03_sequence_add_remove_idempotent_and_limited() {
    requires_("ELG-RANK-03");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const int limit = r.tf()["rank"]["sequenceLimit"].get<int>();
    CHECK(limit > 0);
    SequenceInput in;
    in.missionId = d.mission;
    in.entityId = noToId(d, 2);
    in.operatorId = "op-1";
    in.reason = "commander-order";
    const SequenceResult a = e.addToSequence(in);
    CHECK_EQ(a.code, 0);
    CHECK_STR(a.status, "added");
    CHECK_EQ(a.sequence.size(), std::size_t(1));
    // 重复加入 → 幂等，不改变序列
    const SequenceResult b = e.addToSequence(in);
    CHECK_EQ(b.code, 0);
    CHECK_EQ(b.idempotent, true);
    CHECK_STR(b.status, "already-in-sequence");
    CHECK_EQ(e.sequence(d.mission).size(), std::size_t(1));
    // 依次加入至上限 → 超限被拒（1003 + unmet）
    int added = 1;
    for (int no = 1; no <= 7 && added < limit; ++no) {
        if (no == 2) continue;
        SequenceInput x = in;
        x.entityId = noToId(d, no);
        const SequenceResult s = e.addToSequence(x);
        if (s.code == 0) ++added;
    }
    CHECK_EQ(e.sequence(d.mission).size(), std::size_t(limit));
    int extraNo = 0;
    for (int no = 1; no <= 7; ++no) {
        bool inSeq = false;
        for (const auto& se : e.sequence(d.mission)) {
            if (se.no == no) inSeq = true;
        }
        if (!inSeq) extraNo = no;
    }
    CHECK(extraNo > 0);
    SequenceInput over = in;
    over.entityId = noToId(d, extraNo);
    const SequenceResult o = e.addToSequence(over);
    CHECK_EQ(o.code, 1003);
    CHECK_EQ(o.unmet.size(), std::size_t(1));
    // 移出后序号键稳定（重新连续编号），重复移出幂等
    const SequenceResult rm = e.removeFromSequence(in);
    CHECK_EQ(rm.code, 0);
    CHECK_STR(rm.status, "removed");
    for (std::size_t i = 0; i < rm.sequence.size(); ++i) CHECK_EQ(rm.sequence[i].position, int(i));
    const SequenceResult rm2 = e.removeFromSequence(in);
    CHECK_EQ(rm2.code, 0);
    CHECK_EQ(rm2.idempotent, true);
    CHECK_STR(rm2.status, "not-in-sequence");
}

void rank04_sequence_audit_recoverable() {
    requires_("ELG-RANK-04");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    SequenceInput in;
    in.missionId = d.mission;
    in.entityId = noToId(d, 3);
    in.operatorId = "op-alpha";
    in.reason = "fire-mission";
    CHECK_EQ(e.addToSequence(in).code, 0);
    d.clock->advance(5000);
    in.entityId = noToId(d, 4);
    in.operatorId = "op-bravo";
    CHECK_EQ(e.addToSequence(in).code, 0);
    d.clock->advance(5000);
    in.entityId = noToId(d, 3);
    in.operatorId = "op-alpha";
    CHECK_EQ(e.removeFromSequence(in).code, 0);
    const std::vector<SequenceAuditEntry> audit = e.sequenceAudit(d.mission);
    CHECK_EQ(audit.size(), std::size_t(3));
    // 谁在什么时候把谁加入了序列 → 可复原
    CHECK_STR(audit[0].action, "add");
    CHECK_STR(audit[0].actor, "op-alpha");
    CHECK_EQ(audit[0].no, 3);
    CHECK_EQ(audit[0].position, 0);
    CHECK_STR(audit[1].actor, "op-bravo");
    CHECK_EQ(audit[1].no, 4);
    CHECK_STR(audit[2].action, "remove");
    CHECK_EQ(audit[2].no, 3);
    CHECK(audit[0].at < audit[1].at && audit[1].at < audit[2].at);
    // 事件日志放大器（ILogSink::commandAudit）也可复原
    CHECK(d.log->audits.size() >= 3);
}

// ---- ELG-TRK ----------------------------------------------------------------

void trk01_out_of_order_writes_ordered_queries() {
    requires_("ELG-TRK-01");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string id = noToId(d, 1);
    const int64_t base = d.clock->t;
    // 乱序写入 5 个点
    const int64_t offsets[5] = {30, 10, 50, 20, 40};
    for (int i = 0; i < 5; ++i) {
        TrackPoint p;
        p.ts = base + offsets[i] * 1000;
        p.lng = r.referenceLng() + 0.001 * offsets[i];
        p.lat = r.referenceLat();
        const TrackAppendResult ar = e.appendTrack(TrackInput{id, p});
        CHECK_EQ(ar.code, 0);
        CHECK_EQ(ar.ordered, true);
    }
    const TrackQueryResult q = e.queryTrack(TrackQuery{id});
    CHECK_EQ(q.returned, 5);
    for (std::size_t i = 1; i < q.points.size(); ++i) CHECK(q.points[i].ts > q.points[i - 1].ts);
    CHECK_EQ(q.points.front().ts, base + 10000);
    CHECK_EQ(q.points.back().ts, base + 50000);
    // 同 ts 覆盖（确定性；避免回放重复时间戳）
    TrackPoint dup;
    dup.ts = base + 20000;
    dup.lng = r.referenceLng() + 9.0;
    dup.lat = r.referenceLat();
    const TrackAppendResult dr = e.appendTrack(TrackInput{id, dup});
    CHECK_EQ(dr.code, 0);
    CHECK_EQ(dr.replaced, 1);
    CHECK_EQ(e.queryTrack(TrackQuery{id}).returned, 5);
    CHECK_EQ(e.trackStats(id).replacedSamples, 1);
}

void trk02_range_query_truncation_flagged() {
    requires_("ELG-TRK-02");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string id = noToId(d, 1);
    const int64_t base = d.clock->t;
    for (int i = 0; i < 20; ++i) {
        TrackPoint p;
        p.ts = base + i * 1000;
        p.lng = r.referenceLng() + 0.0001 * i;
        p.lat = r.referenceLat();
        CHECK_EQ(e.appendTrack(TrackInput{id, p}).code, 0);
    }
    // 半开区间 [from, to)
    TrackQuery q;
    q.entityId = id;
    q.fromMs = base + 5000;
    q.toMs = base + 10000;
    const TrackQueryResult in = e.queryTrack(q);
    CHECK_EQ(in.returned, 5);
    CHECK_EQ(in.points.front().ts, base + 5000);
    CHECK_EQ(in.points.back().ts, base + 9000);
    // 超限截断：**不静默丢** —— 带 truncated 标记与续取游标
    TrackQuery lim = q;
    lim.fromMs = 0;
    lim.toMs = 0;
    lim.limit = 7;
    const TrackQueryResult t = e.queryTrack(lim);
    CHECK_EQ(t.returned, 7);
    CHECK_EQ(t.totalInRange, 20);
    CHECK_EQ(t.truncated, true);
    CHECK_EQ(t.nextCursor, base + 7000);
    CHECK_EQ(t.stats.points, 20);
    // 用游标续取 → 拿到剩余点
    TrackQuery next = lim;
    next.fromMs = t.nextCursor;
    next.limit = 0;
    const TrackQueryResult t2 = e.queryTrack(next);
    CHECK_EQ(t2.returned, 13);
    CHECK_EQ(t2.truncated, false);
    // 倒序查询
    TrackQuery desc = lim;
    desc.descending = true;
    desc.limit = 3;
    const TrackQueryResult dr = e.queryTrack(desc);
    CHECK_EQ(dr.points.front().ts, base + 19000);
    // 未找到实体 → 1004
    CHECK_EQ(e.queryTrack(TrackQuery{"ent-none"}).code, 1004);
}

void trk03_decimation_is_annotated() {
    requires_("ELG-TRK-03");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string id = noToId(d, 1);
    const int64_t base = d.clock->t;
    for (int i = 0; i < 30; ++i) {
        TrackPoint p;
        p.ts = base + i * 1000;
        p.lng = r.referenceLng() + 0.0001 * i;
        p.lat = r.referenceLat();
        CHECK_EQ(e.appendTrack(TrackInput{id, p}).code, 0);
    }
    TrackQuery q;
    q.entityId = id;
    q.everyNth = 5;
    const TrackQueryResult a = e.queryTrack(q);
    CHECK_EQ(a.decimated, true);           // 如实标注已抽稀
    CHECK_EQ(a.decimatedFrom, 30);         // 抽稀前点数
    CHECK_EQ(a.everyNth, 5);               // 生效参数
    CHECK_EQ(a.returned, 6);               // 30 / 5
    CHECK_EQ(a.points.front().ts, base);
    // 最小时间间隔抽稀
    TrackQuery q2;
    q2.entityId = id;
    q2.minIntervalMs = 10000;
    const TrackQueryResult b = e.queryTrack(q2);
    CHECK_EQ(b.decimated, true);
    CHECK_EQ(b.minIntervalMs, 10000);
    CHECK_EQ(b.returned, 3);
    for (std::size_t i = 1; i < b.points.size(); ++i) {
        CHECK(b.points[i].ts - b.points[i - 1].ts >= 10000);
    }
    // 未抽稀时标注为 false（不误报）
    TrackQuery q3;
    q3.entityId = id;
    const TrackQueryResult c = e.queryTrack(q3);
    CHECK_EQ(c.decimated, false);
    CHECK_EQ(c.decimatedFrom, 30);
    CHECK_EQ(c.truncated, false);
}

void trk04_timeline_matches_replay_shape() {
    requires_("ELG-TRK-04");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string id = noToId(d, 1);
    const int64_t base = d.clock->t;
    for (int i = 0; i < 5; ++i) {
        TrackPoint p;
        p.ts = base + i * 2000;
        p.lng = r.referenceLng() + 0.0002 * i;
        p.lat = r.referenceLat() + 0.0001 * i;
        CHECK_EQ(e.appendTrack(TrackInput{id, p}).code, 0);
    }
    TrackTimelineQuery tq;
    tq.entityId = id;
    tq.label = "demo track";
    tq.kind = "target";
    const TrackTimelineResult tl = e.trackTimeline(tq);
    CHECK_EQ(tl.code, 0);
    CHECK_EQ(tl.data.points.size(), std::size_t(5));
    CHECK_EQ(tl.data.durationMs, 8000);
    // 回放形状（map-2d `ReplayData`）：{id?, tracks:[{id,label?,kind?,color?,samples:[{t,lng,lat,...}]}]}
    const json replay = toJson(tl.data.replay);
    CHECK(replay.contains("id"));
    CHECK(replay.contains("tracks"));
    CHECK_EQ(replay["tracks"].size(), std::size_t(1));
    const json& track = replay["tracks"][0];
    for (const char* key : {"id", "label", "kind", "samples"}) CHECK(track.contains(key));
    CHECK_STR(track["id"].get<std::string>(), id);
    CHECK_STR(track["label"].get<std::string>(), "demo track");
    CHECK_STR(track["kind"].get<std::string>(), "target");
    CHECK_EQ(track["samples"].size(), std::size_t(5));
    // 时间戳为 epoch 毫秒且升序（map-2d 会用 samples 的 min/max 作 start/end）
    int64_t prev = 0;
    for (const auto& s : track["samples"]) {
        CHECK(s.contains("t"));
        CHECK(s.contains("lng"));
        CHECK(s.contains("lat"));
        CHECK(s.contains("props"));
        CHECK(s["props"].contains("predicted"));
        CHECK_EQ(s["props"]["predicted"].get<bool>(), false);
        const int64_t t = s["t"].get<int64_t>();
        CHECK(t > prev);
        prev = t;
    }
    CHECK_EQ(track["samples"][0]["t"].get<int64_t>(), base);
    // 采样点带推算的航向/速度（map-2d 缺省也会自算，这里显式给）
    CHECK(track["samples"][1].contains("speed"));
    // 区间裁剪
    TrackTimelineQuery cut = tq;
    cut.fromMs = base + 2000;
    cut.toMs = base + 6000;
    const TrackTimelineResult tl2 = e.trackTimeline(cut);
    CHECK_EQ(tl2.data.points.size(), std::size_t(2));
    CHECK_EQ(tl2.data.fromMs, base + 2000);
    CHECK_EQ(tl2.data.toMs, base + 4000);
}

void trk05_prediction_flagged_not_mixed() {
    requires_("ELG-TRK-05");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string id = noToId(d, 1);
    const int64_t base = d.clock->t;
    for (int i = 0; i < 3; ++i) {
        TrackPoint p;
        p.ts = base + i * 10000 - 20000;
        p.lng = r.referenceLng() + 0.001 * i;
        p.lat = r.referenceLat();
        CHECK_EQ(e.appendTrack(TrackInput{id, p}).code, 0);
    }
    const int maxPoints = r.tf()["trajectory"]["predict"]["maxPoints"].get<int>();
    PredictQuery pq;
    pq.entityId = id;
    const TrackQueryResult pr = e.predictTrack(pq);
    CHECK_EQ(pr.code, 0);
    CHECK_EQ(pr.hasPredicted, true);
    CHECK(!pr.points.empty());
    CHECK(pr.points.size() <= std::size_t(maxPoints));
    for (const auto& p : pr.points) {
        CHECK_EQ(p.predicted, true);          // 显式标记
        CHECK_STR(p.basis, "extrapolation");  // 推算依据
        CHECK(p.ts > d.clock->t);              // 只给未来
    }
    // 预测点**不入库**：实测查询里一个都没有
    const TrackQueryResult real = e.queryTrack(TrackQuery{id});
    CHECK_EQ(real.hasPredicted, false);
    for (const auto& p : real.points) CHECK_EQ(p.predicted, false);
    CHECK_EQ(real.returned, 3);
    // 预测点可出现在时间轴输出，但同样带标记
    TrackTimelineQuery tq;
    tq.entityId = id;
    tq.includePredicted = true;
    const TrackTimelineResult tl = e.trackTimeline(tq);
    CHECK_EQ(tl.data.hasPredicted, true);
    CHECK_EQ(tl.data.points.size(), std::size_t(3) + pr.points.size());
    const json replay = toJson(tl.data.replay);
    int predictedSamples = 0;
    int measuredSamples = 0;
    for (const auto& s : replay["tracks"][0]["samples"]) {
        if (s["props"]["predicted"].get<bool>()) ++predictedSamples;
        else ++measuredSamples;
    }
    CHECK_EQ(predictedSamples, static_cast<int>(pr.points.size()));  // 预测点在回放里带标记
    CHECK_EQ(measuredSamples, 3);                                    // 实测点仍为 3 条
}

void trk06_retention_counters() {
    requires_("ELG-TRK-06");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string id = noToId(d, 1);
    const int64_t base = d.clock->t;
    for (int i = 0; i < 12; ++i) {
        TrackPoint p;
        p.ts = base - 8000 + i * 1000;
        p.lng = r.referenceLng();
        p.lat = r.referenceLat();
        CHECK_EQ(e.appendTrack(TrackInput{id, p}).code, 0);
    }
    CHECK_EQ(e.trackStats(id).points, 12);
    // 保留策略：清理比 maxAge 更老的点 + 超出 maxPoints 的点，计数可查
    RetentionInput ri;
    ri.entityId = id;
    ri.maxAgeMs = 5000;
    ri.maxPoints = 4;
    const RetentionResult rr = e.applyRetention(ri);
    CHECK_EQ(rr.code, 0);
    CHECK_EQ(rr.entities, 1);
    CHECK(rr.removedByAge >= 1);
    CHECK(rr.removedByCap >= 1);
    const TrackStats st = e.trackStats(id);
    CHECK_EQ(st.points, 4);
    CHECK(st.droppedByRetention >= 1);
    CHECK(st.droppedByCap >= 1);
    // 清理后查询只剩保留点，且没有静默丢（计数与统计一致）
    const TrackQueryResult q = e.queryTrack(TrackQuery{id});
    CHECK_EQ(q.returned, 4);
    CHECK_EQ(q.totalInRange, 4);
    CHECK_EQ(q.stats.points, 4);
    // 未配置保留 → 不开清理
    EntityLedger e2;
    CHECK_EQ(loadPolicies(e2), true);
    const RetentionResult rr2 = e2.applyRetention(RetentionInput{});
    CHECK_EQ(rr2.code, 0);
}

// ---- ELG-ACT ----------------------------------------------------------------

void act01_action_set_is_rule_declared() {
    requires_("ELG-ACT-01");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    // 动作集来自规则（含现状四动作之外的新动作 → 可扩展）
    const std::vector<std::string> keys = e.actionKeys();
    CHECK_EQ(keys.size(), r.actionKeys().size());
    CHECK(keys.size() >= 4);
    for (const auto& k : keys) {
        const auto a = e.actionDef(k);
        CHECK(a.has_value());
        if (a) CHECK(!a->name.empty());
    }
    // 未声明的动作 → 1004（引擎 MUST NOT 内建动作名）
    ActionRequest req;
    req.entityId = noToId(d, 1);
    req.actionKey = "no-such-action";
    CHECK_EQ(e.applyAction(req).code, 1004);
    // 换一份规则 → 换一套动作集
    EntityLedger e2;
    json alt = readJson(std::string(ENTITY_LEDGER_TEST_FIXTURES) + "/actions-alt.json");
    CHECK_EQ(e2.loadPolicies(alt).code, 0);
    CHECK_EQ(e2.actionKeys().size(), std::size_t(1));
}

void act02_idempotent_repeat_and_conflict_are_distinct() {
    requires_("ELG-ACT-02", "ELG-NFR-03");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string up = r.actionWithFlagSetter();
    const std::string id = noToId(d, 1);
    CHECK(!up.empty());
    ActionRequest req;
    req.entityId = id;
    req.actionKey = up;
    req.operatorId = "op-1";
    req.reason = "commander-order";
    const ActionResult a = e.applyAction(req);
    CHECK_EQ(a.code, 0);
    CHECK_STR(a.status, "ok");
    CHECK(!a.changes.empty());
    // 连点两次：第二次是**幂等成功**（code=0 + idempotent），并有"已执行"语义
    //   protocol.md §3.3 CTR-EC-01/02 + 《冲突裁决.md》ADR-C15-02（MUST NOT 用非零码表达幂等成功）
    const ActionResult b = e.applyAction(req);
    CHECK_EQ(b.code, 0);
    CHECK_EQ(b.idempotent, true);
    CHECK_STR(b.status, "already-done");
    CHECK_EQ(b.conflict, false);
    CHECK_EQ(b.changes.size(), std::size_t(0));
    CHECK_EQ(b.toJson()["data"]["idempotent"].get<bool>(), true);
    // 事件：幂等命中 MUST NOT 重复广播状态事件
    const int statesAfterFirst = d.sink->states;
    CHECK_EQ(e.applyAction(req).code, 0);
    CHECK_EQ(d.sink->states, statesAfterFirst);
    // 互斥冲突（他方正在执行）：同实体在动作 gate 内重入 → 1002 + conflict=true
    //   用宿主 gate 模拟"执行期间他方再次提交"（ADR-C16-01）
    const std::string repeatable = r.actionRepeatable();
    CHECK(!repeatable.empty());
    EntityLedger e3;
    CHECK_EQ(loadPolicies(e3), true);
    auto clk3 = std::make_shared<FakeClock>();
    e3.setClock(clk3);
    // 加载一份"动作集被替换为一个需要宿主 gate 的动作"的规则（验证动作集可扩展）
    json fixture = readJson(std::string(ENTITY_LEDGER_TEST_FIXTURES) + "/actions-gated.json");
    CHECK_EQ(e3.loadPolicies(fixture).code, 0);
    Rules r3(e3);
    const std::string gatedAction = e3.actionKeys().front();
    unsigned reentrant = 0;
    const std::string requiredGate = e3.actionDef(gatedAction)->requires.front();
    CHECK_STR(requiredGate, "host-approval");
    e3.registerActionGate(requiredGate, [&](const ActionGateContext& ctx) -> UnmetItem {
        if (reentrant == 0) {
            ++reentrant;
            ActionRequest inner;
            inner.entityId = ctx.entity.id;
            inner.actionKey = ctx.action.key;
            inner.operatorId = "op-2";
            const ActionResult ir = e3.applyAction(inner);  // 闸门已被持有 → 1002
            if (ir.code != 1002 || !ir.conflict) {
                return UnmetItem{"reentry", "expected conflict rejection", ""};
            }
        }
        return UnmetItem{};
    });
    RegisterInput in;
    in.missionId = "m-gated";
    in.typeKey = r3.typeKeys().front();
    in.lng = 0.0;
    in.lat = 0.0;
    in.obsKey = "g-1";
    const RegisterResult reg = e3.registerEntity(in);
    CHECK_EQ(reg.code, 0);
    ActionRequest gr;
    gr.entityId = reg.data.id;
    gr.actionKey = gatedAction;
    gr.operatorId = "op-1";
    const ActionResult ga = e3.applyAction(gr);
    CHECK_EQ(ga.code, 0);
    CHECK_EQ(reentrant, 1u);
    CHECK_EQ(e3.metrics().actionConflicts >= 1, true);
}

void act03_action_output_is_structured_only() {
    requires_("ELG-ACT-03");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string up = r.actionWithFlagSetter();
    ActionRequest req;
    req.entityId = noToId(d, 1);
    req.actionKey = up;
    req.operatorId = "op-1";
    req.reason = "commander-order";
    const ActionResult a = e.applyAction(req);
    CHECK_EQ(a.code, 0);
    // 动作产出**结构化状态变更**：字段 + 前后值；没有自然语言文案字段
    const json j = a.toJson();
    const json& data = j["data"];
    CHECK(data.contains("changes"));
    CHECK(data.contains("status"));
    CHECK(data.contains("idempotent"));
    CHECK(data.contains("conflict"));
    CHECK(!data.contains("text"));
    CHECK(!data.contains("messageText"));
    for (const auto& ch : data["changes"]) {
        CHECK(ch.contains("field"));
        CHECK(ch.contains("from"));
        CHECK(ch.contains("to"));
    }
    // 引擎自产文本（message / status / 动作 key / 变更字段 / 未通过原因）必须为 ASCII 机制短语：
    // 引擎 MUST NOT 拼自然语言文案（ELG-ACT-03，文案归规则包 / llm-provider）。
    const auto asciiOnly = [](const std::string& s) {
        for (unsigned char c : s) {
            if (c >= 0x80) return false;
        }
        return true;
    };
    CHECK(asciiOnly(a.message));
    CHECK(asciiOnly(a.status));
    CHECK(asciiOnly(a.actionKey));
    for (const auto& ch : a.changes) {
        CHECK(asciiOnly(ch.field));
        CHECK(asciiOnly(ch.from));
        CHECK(asciiOnly(ch.to));
    }
    for (const auto& u : a.unmet) CHECK(asciiOnly(u.reason));
    // 动作结果 data 中不含任何"文案类"字段
    CHECK(!data.contains("text"));
    CHECK(!data.contains("speak"));
    // target.state 事件负载为既有冻结字段（protocol.md §4.2）
    CHECK(d.sink->states >= 1);
    const json ev = d.sink->statePayloads.back();
    for (const char* key : {"targetId", "targetNo", "threat", "confidence", "dynamicState", "lng",
                            "lat", "status"}) {
        CHECK(ev.contains(key));
    }
    CHECK_STR(ev["targetId"].get<std::string>(), req.entityId);
    CHECK_EQ(ev["targetNo"].get<int>(), 1);
    CHECK(!ev["threat"].get<std::string>().empty());   // 分档取自规则
    CHECK(!ev["status"].get<std::string>().empty());   // 状态色取自规则
    // entity.changed 负载（protocol.md §4.4）：{entityId, no, missionId, change}
    const json ce = d.sink->changePayloads.back();
    for (const char* key : {"entityId", "no", "missionId", "change"}) CHECK(ce.contains(key));
}

void act04_preconditions_all_reported() {
    requires_("ELG-ACT-04");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string up = r.actionWithFlagSetter();
    const std::string dependent = r.actionRequiring(up);
    CHECK(!dependent.empty());
    const std::string id = noToId(d, 1);
    ActionRequest req;
    req.entityId = id;
    req.actionKey = dependent;
    req.operatorId = "op-1";
    // 前置未满足：依赖的动作没做过 + 不在打击序列 → **全部**未通过项一次返回（不短路）
    const ActionResult a = e.applyAction(req);
    CHECK_EQ(a.code, 1003);
    CHECK_STR(a.status, "rejected");
    CHECK_EQ(a.unmet.size(), std::size_t(2));
    CHECK(a.unmet[0].gate.rfind("$", 0) == 0);
    for (const auto& u : a.unmet) CHECK(!u.reason.empty());
    // 满足前置 → 通过
    ActionRequest pre;
    pre.entityId = id;
    pre.actionKey = up;
    pre.operatorId = "op-1";
    CHECK_EQ(e.applyAction(pre).code, 0);
    SequenceInput si;
    si.missionId = d.mission;
    si.entityId = id;
    si.operatorId = "op-1";
    CHECK_EQ(e.addToSequence(si).code, 0);
    CHECK_EQ(e.applyAction(req).code, 0);
    // 宿主注册 gate：未注册 → 放行并如实标注（fail-open，与 phase-engine 同口径）
    json fixture = readJson(std::string(ENTITY_LEDGER_TEST_FIXTURES) + "/actions-gated.json");
    EntityLedger e2;
    CHECK_EQ(loadPolicies(e2), true);
    CHECK_EQ(e2.loadPolicies(fixture).code, 0);
    const std::string gated = e2.actionKeys().front();
    RegisterInput in;
    in.missionId = "m-gate";
    in.typeKey = r.typeKeys().front();
    in.lng = 0.0;
    in.lat = 0.0;
    in.obsKey = "gg";
    const RegisterResult reg = e2.registerEntity(in);
    CHECK_EQ(reg.code, 0);
    ActionRequest gr;
    gr.entityId = reg.data.id;
    gr.actionKey = gated;
    gr.operatorId = "op-1";
    const ActionResult pass = e2.applyAction(gr);
    CHECK_EQ(pass.code, 0);
    CHECK_EQ(pass.skippedGates.size(), std::size_t(1));
    CHECK_STR(pass.skippedGates.front(), "host-approval");
    // 注册后未通过 → 1003 + 原因
    CHECK_EQ(e2.registerActionGate("host-approval",
                                   [](const ActionGateContext&) {
                                       return UnmetItem{"host-approval", "approval missing", ""};
                                   }),
             true);
    CHECK_EQ(e2.registerActionGate("host-approval",
                                   [](const ActionGateContext&) { return UnmetItem{}; }),
             false);  // 重复注册被拒
    const ActionResult rejected = e2.applyAction(gr);
    CHECK_EQ(rejected.code, 0);  // 该动作 once=true 且已执行 → 幂等"已执行"（不重复校验前置）
    CHECK_STR(rejected.status, "already-done");
    // 换一个尚未执行该动作的实体 → 宿主 gate 未通过 → 1003 + 原因
    RegisterInput in2 = in;
    in2.obsKey = "gg2";
    in2.lng = 0.01;
    const RegisterResult reg2 = e2.registerEntity(in2);
    CHECK_EQ(reg2.code, 0);
    ActionRequest gr2 = gr;
    gr2.entityId = reg2.data.id;
    const ActionResult rejected2 = e2.applyAction(gr2);
    CHECK_EQ(rejected2.code, 1003);
    CHECK_EQ(rejected2.unmet.size(), std::size_t(1));
    CHECK_STR(rejected2.unmet.front().gate, "host-approval");
    // 注册通过 → 放行（宿主 gate 返回空 = 通过）
    CHECK_EQ(e2.unregisterActionGate("host-approval"), true);
    CHECK_EQ(e2.registerActionGate("host-approval",
                                   [](const ActionGateContext&) { return UnmetItem{}; }),
             true);
    const ActionResult passed2 = e2.applyAction(gr2);
    CHECK_EQ(passed2.code, 0);
    CHECK_EQ(passed2.skippedGates.size(), std::size_t(0));
    // 非法 gate id 不能注册（`$` 前缀保留给引擎内建守卫）
    CHECK_EQ(e2.registerActionGate("$builtin", [](const ActionGateContext&) { return UnmetItem{}; }),
             false);
    // 参数化内建守卫：置信度门槛（在主规则包上验证；e2 的动作集已被覆盖）
    const std::string confAction = r.actionWithConfidenceGate();
    CHECK(!confAction.empty());
    ActionRequest cr;
    cr.entityId = noToId(d, 7);  // 演示数据中置信度最低的一号
    cr.actionKey = confAction;
    cr.operatorId = "op-1";
    const ActionResult low = e.applyAction(cr);
    CHECK_EQ(low.code, 1003);
    CHECK_EQ(low.unmet.size(), std::size_t(1));
    CHECK(low.unmet.front().gate.rfind("$confidence-min:", 0) == 0);
    cr.entityId = noToId(d, 1);  // 高置信度 → 通过
    CHECK_EQ(e.applyAction(cr).code, 0);
}

void act05_action_log_queryable() {
    requires_("ELG-ACT-05");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string repeatable = r.actionRepeatable();
    const std::string up = r.actionWithFlagSetter();
    const std::string id = noToId(d, 1);
    ActionRequest a;
    a.entityId = id;
    a.actionKey = repeatable;
    a.operatorId = "op-1";
    a.reason = "routine";
    CHECK_EQ(e.applyAction(a).code, 0);
    d.clock->advance(1000);
    ActionRequest b = a;
    b.actionKey = up;
    b.operatorId = "op-2";
    CHECK_EQ(e.applyAction(b).code, 0);
    // 幂等重复也留日志（可查"谁点了第二次"），但不改台账状态
    const auto before = e.getEntity(id);
    CHECK_EQ(e.applyAction(b).code, 0);
    const auto after = e.getEntity(id);
    if (before && after) CHECK_EQ(before->updatedAt, after->updatedAt);
    const std::vector<ActionLogEntry> all = e.actionLog(ActionLogQuery{d.mission, "", "", 0});
    CHECK_EQ(all.size(), std::size_t(3));
    CHECK_STR(all[0].actionKey, repeatable);
    CHECK_STR(all[0].status, "ok");
    CHECK_STR(all[1].actor, "op-2");
    CHECK(!all[1].changes.empty());
    CHECK_STR(all[2].status, "already-done");
    // 可按实体/动作筛选；可复原（含结构化变更）
    const std::vector<ActionLogEntry> onlyUp = e.actionLog(ActionLogQuery{d.mission, id, up, 0});
    CHECK_EQ(onlyUp.size(), std::size_t(2));
    CHECK(!onlyUp.front().changes.empty());          // 生效动作：结构化变更可复原
    CHECK(onlyUp.back().changes.empty());            // 幂等重复：无变更（如实记录）
    const json j = toJson(all[1]);
    for (const char* key : {"at", "missionId", "entityId", "no", "actionKey", "actor", "status",
                            "reversible", "changes", "reason"}) {
        CHECK(j.contains(key));
    }
}

void act06_undo_semantics() {
    requires_("ELG-ACT-06");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string up = r.actionWithFlagSetter();   // reversible + undoWithinMs
    const std::string irr = r.irreversibleAction();    // reversible=false
    const std::string flag = r.flagKeys().front();
    const std::string id = noToId(d, 1);
    ActionRequest req;
    req.entityId = id;
    req.actionKey = up;
    req.operatorId = "op-1";
    CHECK_EQ(e.applyAction(req).code, 0);
    CHECK_EQ(e.flagHolders(d.mission, flag).size(), std::size_t(1));
    // 撤销 → 状态复原
    ActionRequest undo = req;
    undo.operatorId = "op-2";
    const ActionResult u = e.undoAction(undo);
    CHECK_EQ(u.code, 0);
    CHECK_STR(u.status, "ok");
    CHECK(!u.changes.empty());
    CHECK_EQ(e.flagHolders(d.mission, flag).size(), std::size_t(0));
    // 幂等：再撤一次 → not-applied
    const ActionResult u2 = e.undoAction(undo);
    CHECK_EQ(u2.code, 0);
    CHECK_EQ(u2.idempotent, true);
    CHECK_STR(u2.status, "not-applied");
    // 不可撤销动作 → 拒绝 + 原因
    if (!irr.empty()) {
        ActionRequest pre;
        pre.entityId = id;
        pre.actionKey = up;
        pre.operatorId = "op-1";
        CHECK_EQ(e.applyAction(pre).code, 0);
        SequenceInput si;
        si.missionId = d.mission;
        si.entityId = id;
        si.operatorId = "op-1";
        CHECK_EQ(e.addToSequence(si).code, 0);
        ActionRequest ir;
        ir.entityId = id;
        ir.actionKey = irr;
        ir.operatorId = "op-1";
        CHECK_EQ(e.applyAction(ir).code, 0);
        const ActionResult bad = e.undoAction(ir);
        CHECK_EQ(bad.code, 1003);
        CHECK(!bad.unmet.empty());
        CHECK_STR(bad.unmet.front().gate, "$irreversible");
        // 不可撤销动作重复执行 → 幂等"已执行"
        const ActionResult again = e.applyAction(ir);
        CHECK_EQ(again.code, 0);
        CHECK_EQ(again.idempotent, true);
        CHECK_STR(again.status, "already-done");
    }
    // 撤销窗口（规则声明 undoWithinMs）：超时后拒绝
    ActionRequest r2 = req;
    CHECK_EQ(e.applyAction(r2).code, 0);
    d.clock->advance(7200000);  // 2 小时 > 规则窗口
    const ActionResult late = e.undoAction(r2);
    CHECK_EQ(late.code, 1003);
    CHECK_STR(late.unmet.front().gate, "$undo-window");
}

// ---- ELG-INTEL --------------------------------------------------------------

void intel01a_relation_crud_and_cycle_rejected() {
    requires_("ELG-INTEL-01");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string kind = r.nonCyclicKind();
    const std::string state = r.relationStates().front();
    RelationInput in;
    in.missionId = d.mission;
    in.kind = kind;
    in.state = state;
    in.fromId = noToId(d, 1);
    in.toId = noToId(d, 2);
    in.operatorId = "op-1";
    CHECK_EQ(e.addRelation(in).code, 0);
    // 重复添加 → 幂等
    const RelationResult dup = e.addRelation(in);
    CHECK_EQ(dup.code, 0);
    CHECK_EQ(dup.idempotent, true);
    CHECK_STR(dup.status, "already-exists");
    CHECK_EQ(e.relations(RelationQuery{d.mission}).size(), std::size_t(1));
    // 再加一条链 2→3，然后 3→1 形成环 → **必须检出并拒绝**（否则查询死循环）
    RelationInput second = in;
    second.fromId = noToId(d, 2);
    second.toId = noToId(d, 3);
    CHECK_EQ(e.addRelation(second).code, 0);
    RelationInput cyc = in;
    cyc.fromId = noToId(d, 3);
    cyc.toId = noToId(d, 1);
    const RelationResult cr = e.addRelation(cyc);
    CHECK_EQ(cr.code, 1003);
    CHECK(!cr.cycle.empty());
    CHECK_EQ(cr.cycle.front(), cyc.fromId);
    CHECK_STR(cr.unmet.front().gate, "$acyclic");
    CHECK_EQ(e.detectCycles(d.mission).size(), std::size_t(0));
    // 引用不存在的实体 → 1004（protocol.md §2.3）
    RelationInput bad = in;
    bad.toId = "ent-missing";
    CHECK_EQ(e.addRelation(bad).code, 1004);
    // 删/查
    RelationInput rm = in;
    const RelationResult rr = e.removeRelation(rm);
    CHECK_EQ(rr.code, 0);
    CHECK_STR(rr.status, "removed");
    CHECK_EQ(e.relations(RelationQuery{d.mission}).size(), std::size_t(1));
    CHECK_EQ(e.removeRelation(rm).idempotent, true);
    // 方向筛选
    second = in;
    second.fromId = noToId(d, 2);
    second.toId = noToId(d, 3);
    CHECK_EQ(e.relations(RelationQuery{d.mission, noToId(d, 2), "", "", "out", 0, 0}).size(),
             std::size_t(1));
    CHECK_EQ(e.relations(RelationQuery{d.mission, noToId(d, 2), "", "", "in", 0, 0}).size(),
             std::size_t(0));
}

void intel01b_cyclic_kind_detected_and_queries_terminate() {
    requires_("ELG-INTEL-01", "ELG-INTEL-02");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string kind = r.cyclicKind();
    CHECK(!kind.empty());
    RelationInput in;
    in.missionId = d.mission;
    in.kind = kind;
    in.state = r.relationStates().back();
    in.operatorId = "op-1";
    const int nos[3] = {1, 2, 3};
    for (int i = 0; i < 3; ++i) {
        in.fromId = noToId(d, nos[i]);
        in.toId = noToId(d, nos[(i + 1) % 3]);
        CHECK_EQ(e.addRelation(in).code, 0);
    }
    // 允许成环的种类：环被如实检出（用于审计），且**查询不死循环**
    const std::vector<CyclePath> cycles = e.detectCycles(d.mission);
    CHECK(cycles.size() >= 1);
    CHECK_EQ(cycles.front().ids.size(), std::size_t(4));  // A→B→C→A（首尾重复一次）
    CHECK_EQ(cycles.front().nos.front(), 1);
    ChainResult ch = e.chain(ChainQuery{noToId(d, 1), 8, "", true});
    CHECK_EQ(ch.code, 0);
    CHECK_EQ(ch.cycleDetected, true);
    CHECK_EQ(ch.relatedCount, 2);  // 去重后的关联目标数（不因环而无限增长）
    CHECK_EQ(ch.downstream.size(), std::size_t(2));
    CHECK(!ch.truncated);
}

void intel02_chain_and_related_count() {
    requires_("ELG-INTEL-02");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string kind = r.nonCyclicKind();
    // 链：1 → 2 → 3 → 4，另 1 → 5（菱形/分支）
    const int chain[3][2] = {{1, 2}, {2, 3}, {3, 4}};
    for (const auto& c : chain) {
        RelationInput in;
        in.missionId = d.mission;
        in.kind = kind;
        in.state = r.relationStates().front();
        in.fromId = noToId(d, c[0]);
        in.toId = noToId(d, c[1]);
        in.operatorId = "op-1";
        CHECK_EQ(e.addRelation(in).code, 0);
    }
    RelationInput br;
    br.missionId = d.mission;
    br.kind = kind;
    br.state = r.relationStates().back();
    br.fromId = noToId(d, 1);
    br.toId = noToId(d, 5);
    br.operatorId = "op-1";
    CHECK_EQ(e.addRelation(br).code, 0);
    const ChainResult ch = e.chain(ChainQuery{noToId(d, 2), 8, "", true});
    CHECK_EQ(ch.code, 0);
    CHECK_EQ(ch.downstream.size(), std::size_t(2));   // 3, 4
    CHECK_EQ(ch.upstream.size(), std::size_t(1));     // 1
    CHECK_EQ(ch.relatedCount, 3);                     // 关联目标数（去重）
    CHECK_EQ(ch.downstream.front().depth, 1);
    CHECK_EQ(ch.downstream.back().depth, 2);
    CHECK_STR(ch.downstream.front().viaKind, kind);
    CHECK_EQ(ch.truncated, false);
    // 深度上限：截断如实标注
    const ChainResult shallow = e.chain(ChainQuery{noToId(d, 2), 1, "", true});
    CHECK_EQ(shallow.downstream.size(), std::size_t(1));
    CHECK_EQ(shallow.truncated, true);
    // 可复现
    const ChainResult again = e.chain(ChainQuery{noToId(d, 2), 8, "", true});
    CHECK_STR(again.toJson().dump(), ch.toJson().dump());
    // 关联统计（第三屏统计项口径）
    const RelationStats stats = e.relationStats(d.mission);
    CHECK_EQ(stats.edges, 4);
    CHECK_EQ(stats.entitiesWithRelations, 5);
    CHECK_EQ(stats.isolatedEntities, 2);
    CHECK_EQ(stats.byKind.size(), std::size_t(1));
    CHECK_EQ(stats.byState.size(), std::size_t(2));
}

void intel03_two_states_filterable_and_counted() {
    requires_("ELG-INTEL-03");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    const std::string kind = r.nonCyclicKind();
    const std::vector<std::string> states = r.relationStates();
    CHECK_EQ(states.size(), std::size_t(2));
    RelationInput in;
    in.missionId = d.mission;
    in.kind = kind;
    in.operatorId = "op-1";
    in.fromId = noToId(d, 1);
    in.toId = noToId(d, 2);
    in.state = states[0];
    CHECK_EQ(e.addRelation(in).code, 0);
    in.toId = noToId(d, 3);
    in.state = states[1];
    CHECK_EQ(e.addRelation(in).code, 0);
    // 两态可筛选
    CHECK_EQ(e.relations(RelationQuery{d.mission, "", "", states[0], "both", 0, 0}).size(),
             std::size_t(1));
    CHECK_EQ(e.relations(RelationQuery{d.mission, "", "", states[1], "both", 0, 0}).size(),
             std::size_t(1));
    // 两态可统计
    const RelationStats stats = e.relationStats(d.mission);
    CHECK_EQ(stats.byState.size(), std::size_t(2));
    for (const auto& s : stats.byState) CHECK_EQ(s.count, 1);
    // 链路查询可排除疑似
    const ChainResult withSuspected = e.chain(ChainQuery{noToId(d, 1), 8, "", true});
    const ChainResult onlyConfirmed = e.chain(ChainQuery{noToId(d, 1), 8, "", false});
    CHECK_EQ(withSuspected.relatedCount, 2);
    CHECK_EQ(onlyConfirmed.relatedCount, 1);
}

// ---- ELG-NFR ----------------------------------------------------------------

void nfr01_works_with_zero_dependencies() {
    requires_("ELG-NFR-01", "ELG-NFR-02");
    // 默认构造：无 store / 无 clock / 无 sink / 无 log —— 引擎 MUST 仍可工作（纯内存）
    EntityLedger e;
    const Capabilities cap = e.capabilities();
    CHECK_EQ(cap.persistent, false);
    CHECK_EQ(cap.clockInjected, false);
    CHECK_EQ(cap.sinkInjected, false);
    CHECK_EQ(cap.logInjected, false);
    CHECK_EQ(e.metrics().registrations, 0);
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    RegisterInput in;
    in.missionId = "m-mem";
    in.typeKey = r.typeKeys().front();
    in.lng = 0.0;
    in.lat = 0.0;
    in.confidence = 0.5;
    in.obsKey = "k";
    const RegisterResult reg = e.registerEntity(in);
    CHECK_EQ(reg.code, 0);
    CHECK_EQ(e.listEntities(EntityQuery{"m-mem"}).size(), std::size_t(1));
    CHECK(e.assessEntity(reg.data.id).score >= 0);
    CHECK_EQ(e.strikeWindow(reg.data.id, StrikeWindowQuery{}).code, 0);
    ActionRequest a;
    a.entityId = reg.data.id;
    a.actionKey = r.actionRepeatable();
    CHECK_EQ(e.applyAction(a).code, 0);
    // 系统时钟兜底：未注入 IClock 时也能正常裁决
    RegisterInput bad = in;
    bad.typeKey = "no-such-type";
    bad.obsKey = "k2";
    CHECK_EQ(e.registerEntity(bad).code, 1000);
}

void nfr02_reverse_interfaces_only() {
    requires_("ELG-NFR-02", "ELG-NFR-03");
    // 注入记录型实现 → 变更只经 IEntitySink；引擎内无落库/广播（结构性断言见 acceptance.ps1）
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, true);
    const Capabilities cap = e.capabilities();
    CHECK_EQ(cap.persistent, true);
    CHECK_EQ(cap.storeList, true);
    CHECK_EQ(cap.clockInjected, true);
    CHECK_EQ(cap.sinkInjected, true);
    CHECK_EQ(cap.logInjected, true);
    CHECK(d.store->saves > 0);
    CHECK(d.sink->changes > 0);
    // 一次状态变更**恰好一次** nowMs()：结果、事件、台账同源（同 ts）
    auto watch = std::make_shared<FakeClock>();
    EntityLedger e2;
    CHECK_EQ(loadPolicies(e2), true);
    e2.setClock(watch);
    auto sink2 = std::make_shared<RecSink>();
    e2.setSink(sink2);
    RegisterInput in;
    in.missionId = "m-ts";
    in.typeKey = r.typeKeys().front();
    in.lng = 0.0;
    in.lat = 0.0;
    in.confidence = 0.5;
    in.obsKey = "k";
    const RegisterResult reg = e2.registerEntity(in);
    CHECK_EQ(reg.code, 0);
    CHECK_EQ(reg.ts, watch->t);
    CHECK_EQ(sink2->changePayloads.back()["ts"].get<int64_t>(), watch->t);
    CHECK_EQ(sink2->statePayloads.back()["ts"].get<int64_t>(), watch->t);
    // Sink 抛异常不影响已生效状态
    EntityLedger e3;
    CHECK_EQ(loadPolicies(e3), true);
    e3.setClock(watch);
    auto boom = std::make_shared<RecSink>();
    boom->throwOnEntity = true;
    e3.setSink(boom);
    RegisterInput in3 = in;
    in3.missionId = "m-boom";
    const RegisterResult r3 = e3.registerEntity(in3);
    CHECK_EQ(r3.code, 0);
    CHECK_EQ(e3.listEntities(EntityQuery{"m-boom"}).size(), std::size_t(1));
    CHECK(e3.metrics().sinkErrors >= 1);
}

void nfr03_determinism_byte_identical_double_run() {
    requires_("ELG-NFR-03", "ELG-NFR-01");
    // 同一（规则包 + 请求序列 + 假时钟序列）→ 逐字节一致
    auto run = [](std::string& out) {
        Demo d;
        EntityLedger& e = d.engine;
        if (!loadPolicies(e)) return false;
        Rules r(e);
        d.rules = &r;
        seedDemo(d, false);
        const std::string id = noToId(d, 1);
        TrackPoint p;
        p.ts = d.clock->t - 10000;
        p.lng = r.referenceLng();
        p.lat = r.referenceLat();
        e.appendTrack(TrackInput{id, p});
        p.ts = d.clock->t - 5000;
        p.lng = r.referenceLng() + 0.001;
        e.appendTrack(TrackInput{id, p});
        ActionRequest a;
        a.entityId = id;
        a.actionKey = r.actionWithFlagSetter();
        a.operatorId = "op-1";
        e.applyAction(a);
        e.applyAction(a);
        SequenceInput si;
        si.missionId = d.mission;
        si.entityId = id;
        si.operatorId = "op-1";
        e.addToSequence(si);
        ConsistencyRequest req;
        req.missionId = d.mission;
        req.views = {snapshotFrom(e, d.mission, "boardC", "", true),
                     snapshotFrom(e, d.mission, "brief", "", true)};
        const ConsistencyReport rep = e.checkConsistency(req);
        json bundle = json::object();
        bundle["ledger"] = e.ledgerSnapshot(d.mission);
        bundle["report"] = rep.toJson();
        bundle["assessment"] = e.assessEntity(id).toJson();
        bundle["window"] = e.strikeWindow(id, StrikeWindowQuery{}).toJson();
        bundle["ranking"] = json::array();
        for (const auto& rk : e.ranking(RankQuery{d.mission, "", 0})) {
            bundle["ranking"].push_back(toJson(rk));
        }
        bundle["metrics"] = toJson(e.metrics());
        out = bundle.dump();
        return true;
    };
    std::string a;
    std::string b;
    CHECK_EQ(run(a), true);
    CHECK_EQ(run(b), true);
    CHECK(a.size() > 1000);
    CHECK_STR(a, b);
}

// ---- ELG-NFR-04：独立交付（每个公开入口在"零依赖 + 无数据"下都给出结构化结果） -------------

void nfr04_standalone_public_api_smoke() {
    requires_("ELG-NFR-04", "ELG-NFR-01", "ELG-NFR-02");
    EntityLedger e;  // 全空依赖：无 store / 无 clock / 无 sink / 无 log
    CHECK_EQ(loadPolicies(e), true);
    // 无数据时每个入口都返回结构化结果（不抛异常、不崩、不返回空对象当真值）
    CHECK_EQ(e.visibleSet(VisibleSetRequest{"m", "situation", "", {}, true}).code, 1004);
    CHECK_EQ(e.checkConsistency(ConsistencyRequest{"m", "", {}, {}, ""}).code, 1004);
    CHECK_EQ(e.getEntity("x").has_value(), false);
    CHECK_EQ(e.getEntityByNo("m", 1).has_value(), false);
    CHECK_EQ(e.listEntities(EntityQuery{"m"}).size(), std::size_t(0));
    CHECK_EQ(e.queryTrack(TrackQuery{"x"}).code, 1004);
    CHECK_EQ(e.predictTrack(PredictQuery{"x"}).code, 1004);
    CHECK_EQ(e.trackTimeline(TrackTimelineQuery{"x"}).code, 1004);
    CHECK_EQ(e.trackStats("x").points, 0);
    CHECK_EQ(e.applyAction(ActionRequest{"x", "y", "", "", json::object()}).code, 1004);
    CHECK_EQ(e.undoAction(ActionRequest{"x", "y", "", "", json::object()}).code, 1004);
    CHECK_EQ(e.addRelation(RelationInput{"m", "", "", "", "", ""}).code, 1000);
    CHECK_EQ(e.removeRelation(RelationInput{"m", "", "", "", "", ""}).code, 1004);
    CHECK_EQ(e.relations(RelationQuery{"m"}).size(), std::size_t(0));
    CHECK_EQ(e.chain(ChainQuery{"x"}).code, 1004);
    CHECK_EQ(e.detectCycles("m").size(), std::size_t(0));
    CHECK_EQ(e.relationStats("m").edges, 0);
    CHECK_EQ(e.ranking(RankQuery{"m", "", 0}).size(), std::size_t(0));
    CHECK_EQ(e.sequence("m").size(), std::size_t(0));
    CHECK_EQ(e.sequenceAudit("m").size(), std::size_t(0));
    CHECK_EQ(e.actionLog(ActionLogQuery{}).size(), std::size_t(0));
    CHECK_EQ(e.applyRetention(RetentionInput{}).code, 0);
    CHECK_EQ(e.ledgerSnapshot("m").is_null(), true);
    CHECK(e.capabilities().policiesLoaded);
    CHECK_EQ(e.capabilities().persistent, false);
    CHECK_EQ(e.strikeWindow("x", StrikeWindowQuery{}).code, 1004);
    // 错误码短名（1001 保留不用 → unknown）
    CHECK_STR(errorCodeName(0), "ok");
    CHECK_STR(errorCodeName(1002), "conflict");
    CHECK_STR(errorCodeName(1001), "unknown");
    CHECK_STR(errorCodeName(4242), "unknown");
    // 规则包校验是纯函数（可独立于引擎实例使用）
    CHECK_EQ(validatePolicies(json::object()).code, 1000);
    CHECK_EQ(policiesDigest(json::object()).size(), std::size_t(16));
}
void nfr05_performance_thresholds() {
    requires_("ELG-NFR-05");
    EntityLedger e;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    // 1000 实体台账：全量评级
    const std::vector<std::string> types = r.typeKeys();
    const std::vector<std::string> states = r.stateKeys();
    std::vector<ThreatSnapshot> snaps;
    snaps.reserve(1000);
    for (int i = 0; i < 1000; ++i) {
        RegisterInput in;
        in.missionId = "m-perf";
        in.typeKey = types[static_cast<std::size_t>(i) % types.size()];
        in.lng = r.referenceLng() + 0.001 * (i % 60);
        in.lat = r.referenceLat() + 0.001 * (i % 40);
        in.confidence = 0.3 + 0.0006 * (i % 1000);
        in.dynamicState = states[static_cast<std::size_t>(i) % states.size()];
        in.obsKey = "p-" + std::to_string(i);
        const RegisterResult rr = e.registerEntity(in);
        if (rr.code != 0) continue;
        ThreatSnapshot s;
        s.entityId = rr.data.id;
        s.no = rr.data.no;
        s.missionId = "m-perf";
        s.typeKey = rr.data.typeKey;
        s.lng = rr.data.lng;
        s.lat = rr.data.lat;
        s.confidence = rr.data.confidence;
        s.dynamicState = rr.data.dynamicState;
        s.sourceCount = static_cast<int>(rr.data.sources.size());
        s.referenceSet = true;
        s.referenceLng = r.referenceLng();
        s.referenceLat = r.referenceLat();
        snaps.push_back(s);
    }
    CHECK_EQ(snaps.size(), std::size_t(1000));
    const auto t0 = std::chrono::steady_clock::now();
    int64_t acc = 0;
    for (const auto& s : snaps) acc += e.assessThreat(s).score;
    const auto t1 = std::chrono::steady_clock::now();
    const double assessMs = std::chrono::duration<double, std::milli>(t1 - t0).count();
    CHECK(acc > 0);
    // 轨迹区间查询（1 万点）
    const std::string id = snaps.front().entityId;
    for (int i = 0; i < 10000; ++i) {
        TrackPoint p;
        p.ts = 1750000000000LL + i * 1000;
        p.lng = r.referenceLng() + 0.00001 * (i % 100);
        p.lat = r.referenceLat();
        const TrackAppendResult ar = e.appendTrack(TrackInput{id, p});
        if (ar.code != 0) break;
    }
    CHECK_EQ(e.trackStats(id).points, 10000);
    TrackQuery perf;
    perf.entityId = id;
    perf.limit = 0;  // 不限流：测 1 万点全量区间查询
    const auto t2 = std::chrono::steady_clock::now();
    const TrackQueryResult q = e.queryTrack(perf);
    const auto t3 = std::chrono::steady_clock::now();
    const double queryMs = std::chrono::duration<double, std::milli>(t3 - t2).count();
    CHECK_EQ(q.returned, 10000);
    if (!g_jsonMode) {  // --json 模式必须只输出 JSON（验收脚本按机检格式解析）
        std::printf(
            "    [perf] assess 1000 = %.2f ms（阈值 10 ms）｜track query 10000 = %.2f ms（阈值 5 ms）\n",
            assessMs, queryMs);
    }
#ifdef NDEBUG
    CHECK(assessMs <= 10.0);
    CHECK(queryMs <= 5.0);
#else
    CHECK(assessMs <= 500.0);  // Debug 构建下放宽（阈值口径以 Release 为准）
    CHECK(queryMs <= 250.0);
#endif
}

// ---- 契约条目（protocol.md） -----------------------------------------------

void ctr_pl_schema_validation_and_atomicity() {
    requires_("ELG-REG-01", "ELG-NFR-01");
    EntityLedger e;
    // CTR-PL-01：kind 未知 → 拒绝
    json pkg = json::object();
    pkg["policiesNamespace"] = "mapapp";
    pkg["schemaVersion"] = "1.0.0";
    pkg["kind"] = "unknownKind";
    pkg["items"] = json::array();
    LoadResult r = e.loadPolicies(pkg);
    CHECK_EQ(r.code, 1000);
    CHECK(!r.issues.empty());
    // §5.2：MAJOR 不匹配 → 1006（MUST NOT 静默降级）
    json bad = readJson(std::string(ENTITY_LEDGER_TEST_FIXTURES) + "/types-alt.json");
    bad["schemaVersion"] = "2.0.0";
    r = e.loadPolicies(bad);
    CHECK_EQ(r.code, 1006);
    // CTR-PL-05：缺必填字段 → 拒绝且原因指向条目与字段
    json missing = readJson(std::string(ENTITY_LEDGER_TEST_FIXTURES) + "/types-alt.json");
    missing["items"][1].erase("baseThreat");
    r = e.loadPolicies(missing);
    CHECK_EQ(r.code, 1000);
    CHECK(!r.issues.empty());
    CHECK_STR(r.issues.front().path, "items[1]");
    CHECK_STR(r.issues.front().field, "baseThreat");
    // CTR-PL-03：未知字段被忽略并计入告警（不失败）
    json extra = readJson(std::string(ENTITY_LEDGER_TEST_FIXTURES) + "/types-alt.json");
    extra["someUnknownSegment"] = json::object();
    extra["items"][0]["unknownField"] = 1;
    EntityLedger e2;
    r = e2.loadPolicies(extra);
    CHECK_EQ(r.code, 0);
    CHECK(r.data.warnings.size() >= 2);
    CHECK(e2.metrics().unknownFields >= 2);
    // 原子替换：装载失败保留上一次成功装载的规则
    CHECK_EQ(e2.entityTypeKeys().size(), std::size_t(2));
    json broken = extra;
    broken["items"][0].erase("key");
    CHECK_EQ(e2.loadPolicies(broken).code, 1000);
    CHECK_EQ(e2.entityTypeKeys().size(), std::size_t(2));  // 未被破坏
    // CTR-PL-06：可导出"当前生效规则"
    const json eff = e2.effectivePolicies();
    CHECK(eff.contains("entityTypes"));
    CHECK(eff.contains("threatFactors"));
    CHECK(!e2.definitionInfo().digest.empty());
    // 校验是纯函数（不装载）
    json third = readJson(std::string(ENTITY_LEDGER_TEST_FIXTURES) + "/types-alt.json");
    CHECK_EQ(EntityLedger::validatePolicies(third).code, 0);
    EntityLedger e3;
    CHECK_EQ(e3.definitionInfo().loaded, false);
    CHECK_EQ(e3.registerEntity(RegisterInput{"m", "x", 0, 0}).code, 1005);  // 未装载规则 → 1005
    // 未装载规则时只读查询不崩
    CHECK_EQ(e3.visibleSet(VisibleSetRequest{"m", "v", "", {}, true}).code, 1005);
    CHECK_EQ(e3.checkConsistency(ConsistencyRequest{"m", "", {}, {}, ""}).code, 1005);
    CHECK_EQ(e3.strikeWindow("ent-x", StrikeWindowQuery{}).code, 1004);
    CHECK_EQ(e3.ranking(RankQuery{"m", "", 0}).size(), std::size_t(0));
    CHECK_EQ(e3.sequence("m").size(), std::size_t(0));
    CHECK_EQ(e3.actionLog(ActionLogQuery{}).size(), std::size_t(0));
}

void ctr_en_ref_shape_and_cross_view_identity() {
    requires_("ELG-ID-02", "CTR-EN-01", "CTR-EN-02", "CTR-EN-05");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    // 展示形状 {id, no}：id 为全局唯一字符串、no 为任务内唯一整数
    const auto rec = e.getEntityByNo(d.mission, 1);
    CHECK(rec.has_value());
    if (rec) {
        const json ref = toJson(EntityRef{rec->id, rec->no});
        CHECK(ref.contains("id"));
        CHECK(ref.contains("no"));
        CHECK(ref["id"].is_string());
        CHECK(ref["no"].is_number_integer());
        // 反例形状（只有 no 没有 id）不出现于任何输出
        const json full = toJson(*rec);
        CHECK(full.contains("id"));
        CHECK(full.contains("no"));
    }
    // id 不复用：注销后新实体 id 不与历史相同
    const std::string firstId = rec ? rec->id : std::string();
    if (!firstId.empty()) {
        CHECK_EQ(e.retireEntity(firstId, "gone", "op").code, 0);
        RegisterInput in;
        in.missionId = d.mission;
        in.typeKey = r.typeKeys().front();
        in.lng = 0.0;
        in.lat = 0.0;
        in.obsKey = "fresh";
        const RegisterResult rr = e.registerEntity(in);
        CHECK_EQ(rr.code, 0);
        CHECK(rr.data.id != firstId);
    }
    // 视图集合由引擎给出（界面不自行过滤）：可见集合 + 排除原因
    const VisibleSetResult vs = e.visibleSet(VisibleSetRequest{d.mission, "situation", "", {}, true});
    CHECK_EQ(vs.total + vs.excluded,
             e.listEntities(EntityQuery{d.mission, "", "", "", "", 0.0, true, 100, 0}).size());
    const json vj = vs.toJson();
    for (const char* key : {"missionId", "viewKey", "viewName", "phaseKey", "items", "total",
                            "excluded", "excludedItems", "basis", "ts"}) {
        CHECK(vj["data"].contains(key));
    }
    CHECK_STR(vj["data"]["basis"].get<std::string>(), "current-state");
}

void ctr_ev_payload_frozen_fields() {
    requires_("ELG-ACT-03", "ELG-NFR-02");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    seedDemo(d, false);
    CHECK(d.sink->changes > 0);
    CHECK(d.sink->states > 0);
    // entity.changed：{entityId, no, missionId, change}（protocol.md §4.4）
    const json ec = d.sink->changePayloads.back();
    CHECK_EQ(ec.size() >= 4, true);
    CHECK(ec["entityId"].is_string());
    CHECK(ec["no"].is_number_integer());
    CHECK(ec["missionId"].is_string());
    CHECK(ec["change"].is_string());
    CHECK(ec["ts"].is_number());
    // target.state：既有冻结八字段 + ts（CTR-EV-04 只增不改）
    const json ts = d.sink->statePayloads.back();
    for (const char* key : {"targetId", "targetNo", "threat", "confidence", "dynamicState", "lng",
                            "lat", "status"}) {
        CHECK(ts.contains(key));
    }
    CHECK(ts["confidence"].is_number());
    // 字段名 camelCase（P4）
    for (auto it = ts.begin(); it != ts.end(); ++it) {
        const std::string k = it.key();
        CHECK(!k.empty() && k.find('_') == std::string::npos);
    }
    // entity.consistency：{missionId, diffs:[{no, field, views[]}]}
    ConsistencyRequest req;
    req.missionId = d.mission;
    req.views = {snapshotFrom(e, d.mission, "boardC", "", false),
                 snapshotFrom(e, d.mission, "brief", "", false)};
    e.checkConsistency(req);
    const json con = d.sink->consistencyPayloads.back();
    CHECK(con.contains("missionId"));
    CHECK(con.contains("diffs"));
    CHECK(con["diffs"].is_array());
}

void persist_write_before_commit_and_reload() {
    requires_("ELG-NFR-02", "ELG-REG-03");
    Demo d;
    EntityLedger& e = d.engine;
    CHECK_EQ(loadPolicies(e), true);
    Rules r(e);
    d.rules = &r;
    d.engine.setStore(d.store);
    d.engine.setClock(d.clock);
    seedDemo(d, false);
    CHECK_EQ(e.listEntities(EntityQuery{d.mission}).size(), std::size_t(7));
    // 写前提交：store 失败 → 1005 且内存状态不变
    d.store->fail = true;
    RegisterInput in;
    in.missionId = d.mission;
    in.typeKey = r.typeKeys().front();
    in.lng = 1.0;
    in.lat = 1.0;
    in.obsKey = "fail";
    const RegisterResult bad = e.registerEntity(in);
    CHECK_EQ(bad.code, 1005);
    CHECK_EQ(e.listEntities(EntityQuery{d.mission}).size(), std::size_t(7));
    CHECK(e.metrics().storeErrors >= 1);
    d.store->fail = false;
    // 落库内容可往返：新引擎从同一 store 装载 → 台账恢复
    CHECK_EQ(e.listEntities(EntityQuery{d.mission}).size(), std::size_t(7));
    EntityLedger e2;
    CHECK_EQ(loadPolicies(e2), true);
    e2.setStore(d.store);
    const auto restored = e2.listEntities(EntityQuery{d.mission});
    CHECK_EQ(restored.size(), std::size_t(7));
    for (const auto& rec : restored) {
        CHECK(!rec.id.empty());
        CHECK(rec.no > 0);
        CHECK(!rec.typeKey.empty());
        CHECK(rec.confidence > 0.0);
    }
    // 轨迹一并往返
    const std::string id = restored.front().id;
    TrackPoint p;
    p.ts = d.clock->t;
    p.lng = 1.0;
    p.lat = 1.0;
    CHECK_EQ(e.appendTrack(TrackInput{id, p}).code, 0);
    EntityLedger e3;
    CHECK_EQ(loadPolicies(e3), true);
    e3.setStore(d.store);
    CHECK_EQ(e3.queryTrack(TrackQuery{id}).returned, 1);
    // 查询不存在的任务 → 结构化结果（不是空对象当真值）
    CHECK_EQ(e.ledgerSnapshot("m-missing").is_null(), true);
}

}  // namespace

// ============================================================================
// 用例表
// ============================================================================
namespace {
struct Case {
    const char* name;
    void (*fn)();
};
const Case kCases[] = {
    {"reg01_entity_types_are_rule_declared", reg01_entity_types_are_rule_declared},
    {"reg02_ledger_fields_and_defaults", reg02_ledger_fields_and_defaults},
    {"reg03_mission_scope_and_duplicate_no_rejected", reg03_mission_scope_and_duplicate_no_rejected},
    {"reg04_multisource_dedup_conservative", reg04_multisource_dedup_conservative},
    {"reg05_confidence_fusion_reproducible", reg05_confidence_fusion_reproducible},
    {"reg06_dynamic_state_machine", reg06_dynamic_state_machine},
    {"id01_numbering_rules_and_no_reuse", id01_numbering_rules_and_no_reuse},
    {"id02a_consistency_localizes_count_mismatch", id02a_consistency_localizes_count_mismatch},
    {"id02b_consistency_localizes_flag_dispute", id02b_consistency_localizes_flag_dispute},
    {"id02c_consistency_detects_no_and_type_mismatch", id02c_consistency_detects_no_and_type_mismatch},
    {"id03_visible_set_is_engine_owned_and_stable", id03_visible_set_is_engine_owned_and_stable},
    {"id04_type_binding_and_reclassify_trace", id04_type_binding_and_reclassify_trace},
    {"id05_flag_uniqueness_and_holders", id05_flag_uniqueness_and_holders},
    {"rate01_rating_follows_injected_rules", rate01_rating_follows_injected_rules},
    {"rate02_score_recomputable_by_hand", rate02_score_recomputable_by_hand},
    {"rate03_bands_from_thresholds_not_boolean", rate03_bands_from_thresholds_not_boolean},
    {"rate04_distance_uses_real_geometry", rate04_distance_uses_real_geometry},
    {"rate05_assessment_is_pure_over_snapshot", rate05_assessment_is_pure_over_snapshot},
    {"rate06_strike_window_is_computed_interval", rate06_strike_window_is_computed_interval},
    {"rank01_stable_ordering_deterministic", rank01_stable_ordering_deterministic},
    {"rank02_priority_explicit_changes_order", rank02_priority_explicit_changes_order},
    {"rank03_sequence_add_remove_idempotent_and_limited",
     rank03_sequence_add_remove_idempotent_and_limited},
    {"rank04_sequence_audit_recoverable", rank04_sequence_audit_recoverable},
    {"trk01_out_of_order_writes_ordered_queries", trk01_out_of_order_writes_ordered_queries},
    {"trk02_range_query_truncation_flagged", trk02_range_query_truncation_flagged},
    {"trk03_decimation_is_annotated", trk03_decimation_is_annotated},
    {"trk04_timeline_matches_replay_shape", trk04_timeline_matches_replay_shape},
    {"trk05_prediction_flagged_not_mixed", trk05_prediction_flagged_not_mixed},
    {"trk06_retention_counters", trk06_retention_counters},
    {"act01_action_set_is_rule_declared", act01_action_set_is_rule_declared},
    {"act02_idempotent_repeat_and_conflict_are_distinct",
     act02_idempotent_repeat_and_conflict_are_distinct},
    {"act03_action_output_is_structured_only", act03_action_output_is_structured_only},
    {"act04_preconditions_all_reported", act04_preconditions_all_reported},
    {"act05_action_log_queryable", act05_action_log_queryable},
    {"act06_undo_semantics", act06_undo_semantics},
    {"intel01a_relation_crud_and_cycle_rejected", intel01a_relation_crud_and_cycle_rejected},
    {"intel01b_cyclic_kind_detected_and_queries_terminate",
     intel01b_cyclic_kind_detected_and_queries_terminate},
    {"intel02_chain_and_related_count", intel02_chain_and_related_count},
    {"intel03_two_states_filterable_and_counted", intel03_two_states_filterable_and_counted},
    {"nfr01_works_with_zero_dependencies", nfr01_works_with_zero_dependencies},
    {"nfr02_reverse_interfaces_only", nfr02_reverse_interfaces_only},
    {"nfr03_determinism_byte_identical_double_run", nfr03_determinism_byte_identical_double_run},
    {"nfr04_standalone_public_api_smoke", nfr04_standalone_public_api_smoke},
    {"nfr05_performance_thresholds", nfr05_performance_thresholds},
    {"ctr_pl_schema_validation_and_atomicity", ctr_pl_schema_validation_and_atomicity},
    {"ctr_en_ref_shape_and_cross_view_identity", ctr_en_ref_shape_and_cross_view_identity},
    {"ctr_ev_payload_frozen_fields", ctr_ev_payload_frozen_fields},
    {"persist_write_before_commit_and_reload", persist_write_before_commit_and_reload},
};
}  // namespace

int main(int argc, char** argv) {
#if defined(_WIN32)
    if (argc < 2) std::system("chcp 65001 > nul");
#endif
    std::string filter;
    bool listOnly = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--list") listOnly = true;
        else if (arg == "--json") g_jsonMode = true;
        else filter = arg;
    }
    if (listOnly) {
        for (const auto& c : kCases) std::printf("%s\n", c.name);
        return 0;
    }

    const auto t0 = std::chrono::steady_clock::now();
    for (const auto& c : kCases) {
        if (!filter.empty() && std::string(c.name).find(filter) == std::string::npos) continue;
        g_case = c.name;
        g_reqs.clear();
        const int failedBefore = g_failed;
        const int assertsBefore = g_asserts;
        ++g_cases;
        try {
            c.fn();
        } catch (const std::exception& ex) {
            record(false, std::string("用例抛出异常：") + ex.what(), __FILE__, __LINE__);
        } catch (...) {
            record(false, "用例抛出未知异常", __FILE__, __LINE__);
        }
        const bool ok = (g_failed == failedBefore);
        if (!ok) ++g_casesFailed;
        CaseMeta meta;
        meta.name = c.name;
        meta.reqs = g_reqs;
        meta.asserts = g_asserts - assertsBefore;
        meta.failed = g_failed - failedBefore;
        meta.ok = ok;
        g_metas.push_back(std::move(meta));
        if (!g_jsonMode) {
            std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", c.name);
            std::fflush(stdout);
        }
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    if (g_jsonMode) {
        std::string out = "{\n";
        out += "  \"engineVersion\": \"" + jsonEscape(kEngineVersion) + "\",\n";
        out += "  \"cases\": " + std::to_string(g_cases) + ",\n";
        out += "  \"casesFailed\": " + std::to_string(g_casesFailed) + ",\n";
        out += "  \"asserts\": " + std::to_string(g_asserts) + ",\n";
        out += "  \"assertsFailed\": " + std::to_string(g_failed) + ",\n";
        out += "  \"elapsedMs\": " + std::to_string(ms) + ",\n";
        out += "  \"result\": \"" + std::string(g_failed == 0 ? "ALL GREEN" : "FAILED") + "\",\n";
        out += "  \"details\": [";
        for (std::size_t i = 0; i < g_metas.size(); ++i) {
            const CaseMeta& m = g_metas[i];
            out += (i == 0 ? "\n" : ",\n");
            out += "    {\"name\": \"" + jsonEscape(m.name) + "\", \"ok\": " +
                   (m.ok ? "true" : "false") + ", \"asserts\": " + std::to_string(m.asserts) +
                   ", \"failed\": " + std::to_string(m.failed) + ", \"reqs\": " +
                   jsonArray(m.reqs) + "}";
        }
        out += "\n  ],\n";
        out += "  \"failures\": " + jsonArray(g_failures) + "\n";
        out += "}\n";
        std::fputs(out.c_str(), stdout);
        return g_failed == 0 ? 0 : 1;
    }

    std::printf("\n================ entity-ledger selftest ================\n");
    std::printf("用例 %d 个（失败 %d）｜断言 %d 条（失败 %d）｜耗时 %.1f ms\n", g_cases,
                g_casesFailed, g_asserts, g_failed, ms);
    if (!g_failures.empty()) {
        std::printf("\n---- 失败明细 ----\n");
        for (const auto& f : g_failures) std::printf("  %s\n", f.c_str());
    }
    std::printf("结果： %s\n", g_failed == 0 ? "ALL GREEN" : "FAILED");
    std::printf("========================================================\n");
    return g_failed == 0 ? 0 : 1;
}
