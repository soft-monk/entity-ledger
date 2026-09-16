// examples/minimal/main.cc —— 最小可跑示例（ELG-NFR-04：独立示例、独立退出码）
//
// 演示三件事：
//   ① 规则包（kind: entityTypes / threatFactors）**外部注入**，引擎内不认识任何业务取值
//   ② 实体登记 → 评级（逐因子得分可手算）→ 打击窗口（结构化时间区间）
//   ③ 出口全部走注入的反向接口（本示例只注入假时钟 + 记录型 Sink）
//
// 运行：  example_minimal [entityTypes.json] [threatFactors.json]
// 退出码：0 = 全部演示点成立；1 = 有断言不成立
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "entity_ledger/entity_ledger.h"

using namespace entity_ledger;

namespace {

int g_failed = 0;

void check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "ok" : "FAIL", what);
    if (!ok) ++g_failed;
}

/// 记录型 Sink：把引擎发出的变更按事件名打印（宿主侧的真实做法是包进 WS 信封广播）
struct PrintSink : IEntitySink {
    int changes = 0;
    int states = 0;
    int consistencies = 0;
    void onEntityChanged(const EntityChangeEvent& e) override {
        ++changes;
        std::printf("    event entity.changed   %s\n", e.toJson().dump().c_str());
    }
    void onTargetState(const TargetStateEvent& e) override {
        ++states;
        std::printf("    event target.state     %s\n", e.toJson().dump().c_str());
    }
    void onConsistency(const ConsistencyEvent& e) override {
        ++consistencies;
        std::printf("    event entity.consistency diffs=%zu\n", e.diffs.size());
    }
};

/// 记录型 Store：宿主侧应落库；这里只演示"写前提交"契约（save 失败 → 本次变更整体失败）
struct MemStore : IEntityStore {
    int saves = 0;
    bool save(const std::string& missionId, const json& ledger) override {
        ++saves;
        (void)missionId;
        (void)ledger;
        return true;
    }
    bool load(const std::string&, json&) override { return false; }
    bool remove(const std::string&) override { return false; }
};

struct FixedClock : IClock {
    int64_t t = 1750000000000LL;
    int64_t nowMs() const override { return t; }
};

}  // namespace

int main(int argc, char** argv) {
    const std::string typesPath =
        argc > 1 ? argv[1] : std::string(ENTITY_LEDGER_POLICY_TYPES);
    const std::string factorsPath =
        argc > 2 ? argv[2] : std::string(ENTITY_LEDGER_POLICY_FACTORS);

    auto clock = std::make_shared<FixedClock>();
    auto sink = std::make_shared<PrintSink>();
    auto store = std::make_shared<MemStore>();

    EntityLedgerOptions opts;
    opts.clock = clock;
    opts.sink = sink;
    opts.store = store;
    EntityLedger ledger(opts);

    std::printf("== entity-ledger minimal example ==\n");
    std::printf("policies:\n  %s\n  %s\n", typesPath.c_str(), factorsPath.c_str());

    // ① 规则包装载（失败时保留上一次成功装载的规则 = 原子替换）
    const LoadResult a = ledger.loadPoliciesFile(typesPath);
    const LoadResult b = ledger.loadPoliciesFile(factorsPath);
    std::printf("load: code=%d (%s) | code=%d (%s)\n", a.code, a.message.c_str(), b.code,
                b.message.c_str());
    check(a.code == 0 && b.code == 0, "policies loaded");
    const DefinitionInfo info = ledger.definitionInfo();
    std::printf("definitionVersion: %s\n", info.definitionVersion.c_str());
    std::printf("rules: types=%d actions=%d views=%d factors=%d bands=%d\n",
                info.entityTypeCount, info.actionCount, info.viewCount, info.factorCount,
                info.bandCount);

    const json rules = ledger.effectivePolicies();
    const json et = rules["entityTypes"];
    const std::string mission = "demo-mission";
    const std::string typeKey = ledger.entityTypeKeys().front();
    const std::string sourceKey = et["confidence"]["sources"][0]["key"].get<std::string>();

    // ② 登记（类型/来源/编号规则全部来自规则包）
    RegisterInput in;
    in.missionId = mission;
    in.typeKey = typeKey;
    in.lng = et["reference"]["lng"].get<double>();
    in.lat = et["reference"]["lat"].get<double>() + 0.1;  // 约 11.1 km 外
    in.obsKey = "demo-obs-1";
    in.operatorId = "demo";
    SourceObs obs;
    obs.source = sourceKey;
    obs.obsKey = in.obsKey;
    obs.confidence = 0.9;
    obs.at = clock->t;
    in.sources.push_back(obs);
    const RegisterResult reg = ledger.registerEntity(in);
    std::printf("register: code=%d status=%s id=%s no=%d type=%s confidence=%.6f band=%s\n", reg.code,
                reg.status.c_str(), reg.data.id.c_str(), reg.data.no,
                reg.data.typeName.c_str(), reg.data.confidence, reg.data.threatBand.c_str());
    check(reg.code == 0, "registration succeeded");
    check(reg.data.no == et["numbering"]["start"].get<int>(), "no follows the rule start value");

    // ③ 评级：逐因子得分 + 总分（Σ贡献 == 总分，可手算复算）
    const ThreatAssessment ta = ledger.assessEntity(reg.data.id);
    std::printf("assessment: score=%d band=%s status=%s\n", ta.score, ta.band.c_str(),
                ta.status.c_str());
    int contribSum = 0;
    for (const auto& f : ta.factors) {
        std::printf("  factor %-12s weightPpm=%7d normPpm=%7d contribution=%3d%s\n", f.key.c_str(),
                    f.weightPpm, f.normPpm, f.contribution, f.missing ? " (missing input)" : "");
        contribSum += f.contribution;
    }
    std::printf("  sum(contribution)=%d (score=%d)\n", contribSum, ta.score);
    check(contribSum == ta.score, "sum of per-factor contributions equals the score");

    // ④ 轨迹 → 打击窗口（结构化时间区间）
    const int64_t now = clock->t;
    for (int i = 0; i < 3; ++i) {
        TrackPoint p;
        p.ts = now - (2 - i) * 10000;
        p.lng = in.lng + 0.0004 * i;
        p.lat = in.lat + 0.0002 * i;
        ledger.appendTrack(TrackInput{reg.data.id, p});
    }
    const StrikeWindowResult w = ledger.strikeWindow(reg.data.id, StrikeWindowQuery{});
    std::printf("strike window: found=%s [%lld, %lld) duration=%lld ms lead=%lld ms basis=%s extrapolated=%s\n",
                w.data.found ? "true" : "false", static_cast<long long>(w.data.fromMs),
                static_cast<long long>(w.data.toMs), static_cast<long long>(w.data.durationMs),
                static_cast<long long>(w.data.leadMs), w.data.basis.c_str(),
                w.data.extrapolated ? "true" : "false");
    check(w.code == 0 && w.data.found, "window computed from track and rules");
    check(w.data.toMs > w.data.fromMs && w.data.durationMs == w.data.toMs - w.data.fromMs,
          "window is a structured half-open interval");
    check(w.data.segments.size() >= 1 && w.data.segments.front().predicted,
          "segments carry recomputable basis and prediction flag");

    // ⑤ 可见集合由引擎给出（界面不自行过滤），并落一次一致性检查
    VisibleSetRequest vs;
    vs.missionId = mission;
    vs.viewKey = ledger.viewKeys().front();
    const VisibleSetResult set = ledger.visibleSet(vs);
    std::printf("visible set: view=%s total=%d excluded=%d (reasons available)\n", set.viewName.c_str(),
                set.total, set.excluded);

    std::printf("sinks: store.save=%d | entity.changed=%d | target.state=%d | entity.consistency=%d\n",
                store->saves, sink->changes, sink->states, sink->consistencies);
    check(store->saves > 0 && sink->changes > 0 && sink->states > 0,
          "persistence and broadcast go through injected interfaces");

    std::printf("result: %s\n", g_failed == 0 ? "ALL GREEN" : "FAILED");
    return g_failed == 0 ? 0 : 1;
}
