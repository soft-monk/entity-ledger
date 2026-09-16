// examples/full_flow/main.cc —— 一致性收口演示（初稿「待确认问题清单」第 12 项的现场复刻）
//
// 复刻的矛盾（见 docs/需求/entity-ledger需求专篇.md §0 关键差距 1）：
//   · 场景二 T4-1 是 5 个目标 / T4-2 是 6 个 / T7-2 是 7 个
//   · 场景一 T4 高价值标红是 002，而文字稿写 003
// 本示例**不做任何界面过滤**，只做两件事：
//   ① `visibleSet()`        —— 引擎给出"某阶段/某视图应可见的目标集合"（CTR-EN-06）
//   ② `checkConsistency()`  —— 逐条差异报告，定位到**具体编号**与**具体视图**（CTR-EN-08）
// 退出码：0 = 差异被完整定位（收口成立）；1 = 有断言不成立
//
// 全部业务取值（视图标签、阶段 key、旗标名、类型名、动作名）都从规则包读取，示例内不写死。
// 运行：  example_consistency [entityTypes.json] [threatFactors.json]
#include <algorithm>
#include <map>
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

struct FixedClock : IClock {
    int64_t t = 1750000000000LL;
    int64_t nowMs() const override { return t; }
};

struct CountingSink : IEntitySink {
    int changes = 0;
    int states = 0;
    int consistencies = 0;
    json lastConsistency;
    void onEntityChanged(const EntityChangeEvent&) override { ++changes; }
    void onTargetState(const TargetStateEvent&) override { ++states; }
    void onConsistency(const ConsistencyEvent& e) override {
        ++consistencies;
        lastConsistency = e.toJson();
    }
};

struct MemStore : IEntityStore {
    std::map<std::string, json> data;
    bool save(const std::string& missionId, const json& ledger) override {
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

std::string phaseOfFilter(const json& view, std::size_t filterIndex) {
    const json& filters = view["phaseFilters"];
    if (filterIndex >= filters.size()) return std::string();
    for (const auto& p : filters[filterIndex]["phases"]) {
        const std::string s = p.get<std::string>();
        if (s != "*") return s;
    }
    return std::string();
}

}  // namespace

int main(int argc, char** argv) {
    const std::string typesPath =
        argc > 1 ? argv[1] : std::string(ENTITY_LEDGER_POLICY_TYPES);
    const std::string factorsPath =
        argc > 2 ? argv[2] : std::string(ENTITY_LEDGER_POLICY_FACTORS);

    auto clock = std::make_shared<FixedClock>();
    auto sink = std::make_shared<CountingSink>();
    auto store = std::make_shared<MemStore>();
    EntityLedgerOptions opts;
    opts.clock = clock;
    opts.sink = sink;
    opts.store = store;
    EntityLedger ledger(opts);

    std::printf("== entity-ledger consistency demo ==\n");
    if (ledger.loadPoliciesFile(typesPath).code != 0 ||
        ledger.loadPoliciesFile(factorsPath).code != 0) {
        std::printf("policies failed to load\n");
        return 1;
    }
    const json rules = ledger.effectivePolicies();
    const json et = rules["entityTypes"];
    const std::string mission = "m-scenario";
    const std::vector<std::string> types = ledger.entityTypeKeys();
    const std::string sourceKey = et["confidence"]["sources"][0]["key"].get<std::string>();
    const std::string flagKey = et["flags"][0]["key"].get<std::string>();
    const double refLng = et["reference"]["lng"].get<double>();
    const double refLat = et["reference"]["lat"].get<double>();

    // ---- 台账：7 个目标由**同一份台账**产出（置信度决定各档位可见数量）----
    const double confidences[7] = {0.9, 0.8, 0.7, 0.6, 0.55, 0.45, 0.35};
    std::vector<std::string> ids;
    for (int i = 0; i < 7; ++i) {
        RegisterInput in;
        in.missionId = mission;
        in.typeKey = types[static_cast<std::size_t>(i) % types.size()];
        in.lng = refLng + 0.02 * i;
        in.lat = refLat + 0.01 * i;
        in.dynamicState = et["dynamicStates"]["items"][static_cast<std::size_t>(i) %
                                                       et["dynamicStates"]["items"].size()]["key"]
                              .get<std::string>();
        in.obsKey = "obs-" + std::to_string(i + 1);
        in.operatorId = "demo";
        const int nsrc = 1 + (i % 3);
        const double bonus =
            nsrc > 1 ? std::min(et["confidence"]["multiSourceBonus"].get<double>() * (nsrc - 1),
                                et["confidence"]["maxBonus"].get<double>())
                     : 0.0;
        in.confidence = std::max(0.0, confidences[i] - bonus);
        for (int s = 0; s < nsrc; ++s) {
            SourceObs o;
            o.source = et["confidence"]["sources"][static_cast<std::size_t>(s) %
                                                   et["confidence"]["sources"].size()]["key"]
                           .get<std::string>();
            o.obsKey = in.obsKey;
            o.confidence = in.confidence;
            o.at = clock->t;
            in.sources.push_back(o);
        }
        const RegisterResult r = ledger.registerEntity(in);
        if (r.code == 0) ids.push_back(r.data.id);
    }
    std::printf("ledger: %zu entities registered (single source of truth)\n", ids.size());
    check(ids.size() == 7, "seven entities registered in one ledger");

    // 台账权威：旗标落在 2 号目标上（显式动作 + 留痕）
    FlagInput fi;
    fi.missionId = mission;
    fi.entityId = ids[1];
    fi.flagKey = flagKey;
    fi.operatorId = "demo";
    fi.reason = "commander-order";
    check(ledger.setFlag(fi).code == 0, "flag set on entity no=2 with explicit trace");
    const std::vector<EntityRef> holders = ledger.flagHolders(mission, flagKey);
    check(holders.size() == 1 && holders.front().no == 2, "flag holder is no=2 (authoritative)");

    // ---- ① 引擎给出"某阶段应可见集合"：界面不再自行过滤（CTR-EN-06）----
    const std::string situation = ledger.viewKeys().front();
    const json view = et["views"][0];
    std::printf("\n-- visibleSet(view=%s, name=%s) --\n", situation.c_str(),
                ledger.resolveViewName(situation).c_str());
    std::vector<int> counts;
    for (std::size_t f = 0; f < view["phaseFilters"].size(); ++f) {
        const std::string phase = phaseOfFilter(view, f);
        if (phase.empty()) continue;
        VisibleSetRequest req;
        req.missionId = mission;
        req.viewKey = situation;
        PhaseContext pc;
        pc.phaseKey = phase;
        pc.missionId = mission;
        req.phase = pc;
        const VisibleSetResult vs = ledger.visibleSet(req);
        counts.push_back(vs.total);
        std::printf("  phase=%-4s visible=%d excluded=%d nos=[", phase.c_str(), vs.total,
                    vs.excluded);
        for (std::size_t i = 0; i < vs.items.size(); ++i) {
            std::printf("%s%d", i ? "," : "", vs.items[i].no);
        }
        std::printf("]\n");
    }
    check(counts.size() == 3 && counts[0] == 5 && counts[1] == 6 && counts[2] == 7,
          "same view yields 5 / 6 / 7 across phases (rule-driven, explainable)");
    // 同一阶段两次查询结果一致（ELG-ID-03）
    VisibleSetRequest twice;
    twice.missionId = mission;
    twice.viewKey = situation;
    check(ledger.visibleSet(twice).toJson().dump() == ledger.visibleSet(twice).toJson().dump(),
          "repeated query at the same phase is identical");

    // ---- ② 三个界面视图 + 文字稿：人为制造"五个 / 六个 / 七个"与 002 vs 003 ----
    const std::string screenViews[3] = {"boardA", "boardB", "boardC"};
    const std::string draftView = "brief";
    std::vector<ViewSnapshot> snaps;
    for (const auto& vk : screenViews) {
        VisibleSetRequest req;
        req.missionId = mission;
        req.viewKey = vk;
        const VisibleSetResult vs = ledger.visibleSet(req);
        ViewSnapshot s;
        s.viewKey = vk;
        s.viewName = vs.viewName;
        s.phaseKey = vs.phaseKey;
        s.flagsRendered = true;
        for (const auto& it : vs.items) {
            ViewItem vi;
            vi.id = it.id;
            vi.no = it.no;
            vi.typeKey = it.typeKey;
            vi.flagKeys = it.flags;
            s.items.push_back(vi);
        }
        snaps.push_back(s);
    }
    {
        // 文字稿：与界面就"谁高价值"给出不同答案（界面标 2 号，文字稿写 3 号）
        ViewSnapshot draft = snaps[2];
        draft.viewKey = draftView;
        draft.viewName = ledger.resolveViewName(draftView);
        for (auto& it : draft.items) {
            if (it.no == 2) it.flagKeys.clear();
            if (it.no == 3) it.flagKeys.push_back(flagKey);
        }
        snaps.push_back(draft);
    }
    std::printf("\n-- snapshots handed to checkConsistency() --\n");
    for (const auto& s : snaps) {
        std::printf("  view=%-8s name=%-16s items=%zu\n", s.viewKey.c_str(), s.viewName.c_str(),
                    s.items.size());
    }

    ConsistencyRequest creq;
    creq.missionId = mission;
    creq.views = snaps;
    const ConsistencyReport rep = ledger.checkConsistency(creq);

    std::printf("\n-- consistency report (localized) --\n");
    std::printf("  consistent=%s checkedViews=%d checkedItems=%d diffs=%zu\n",
                rep.consistent ? "true" : "false", rep.checkedViews, rep.checkedItems,
                rep.diffs.size());
    for (const auto& d : rep.diffs) {
        std::printf("  no=%-3d field=%-10s kind=%-8s views=[", d.no, d.field.c_str(),
                    d.kind.c_str());
        for (std::size_t i = 0; i < d.views.size(); ++i) {
            std::printf("%s%s", i ? ", " : "", d.views[i].c_str());
        }
        std::printf("] expected=%s actual=%s\n", d.expected.c_str(), d.actual.c_str());
    }
    check(!rep.consistent, "contradictions detected");
    {
        bool count5v6 = false;
        bool count5v7 = false;
        bool flagDispute = false;
        for (const auto& d : rep.diffs) {
            if (d.field == "presence" && d.no == 6) count5v6 = true;
            if (d.field == "presence" && d.no == 7) count5v7 = true;
            if (d.field == "flag:" + flagKey && d.no == 2) flagDispute = true;
        }
        check(count5v6, "diff localized to a concrete no (6) and concrete views");
        check(count5v7, "diff localized to a concrete no (7) and concrete views");
        check(flagDispute, "flag dispute localized to a concrete no");
    }

    // ---- 跨阶段集合变化可解释（ELG-ID-03）：同一视图在三个阶段的应可见集合 ----
    ConsistencyRequest preq;
    preq.missionId = mission;
    preq.viewKey = situation;
    for (std::size_t f = 0; f < view["phaseFilters"].size(); ++f) {
        const std::string phase = phaseOfFilter(view, f);
        if (phase.empty()) continue;
        VisibleSetRequest req;
        req.missionId = mission;
        req.viewKey = situation;
        PhaseContext pc;
        pc.phaseKey = phase;
        pc.missionId = mission;
        req.phase = pc;
        const VisibleSetResult vs = ledger.visibleSet(req);
        ViewSnapshot s;
        s.viewKey = situation;
        s.viewName = vs.viewName;
        s.phaseKey = phase;
        for (const auto& it : vs.items) {
            ViewItem vi;
            vi.id = it.id;
            vi.no = it.no;
            vi.typeKey = it.typeKey;
            s.items.push_back(vi);
        }
        preq.views.push_back(s);
        if (!preq.phase.has_value()) preq.phase = pc;
    }
    const ConsistencyReport prep = ledger.checkConsistency(preq);
    std::printf("\n-- cross-phase deltas (explainable, basis=current-state) --\n");
    for (const auto& dl : prep.phaseDeltas) {
        std::printf("  phase=%-4s count=%d added=[", dl.phaseKey.c_str(), dl.count);
        for (std::size_t i = 0; i < dl.addedNos.size(); ++i) {
            std::printf("%s%d", i ? "," : "", dl.addedNos[i]);
        }
        std::printf("] removed=[");
        for (std::size_t i = 0; i < dl.removedNos.size(); ++i) {
            std::printf("%s%d", i ? "," : "", dl.removedNos[i]);
        }
        std::printf("] basis=%s\n", dl.basis.c_str());
    }
    check(prep.phaseDeltas.size() == 3 && prep.phaseDeltas[1].addedNos.size() == 1 &&
              prep.phaseDeltas[2].addedNos.size() == 2,
          "cross-phase deltas explain the 5 / 6 / 7 counts");

    // ---- 收口结论：界面 MUST 用 visibleSet，MUST NOT 自行过滤 ----
    std::printf("\n-- verdict --\n");
    std::printf("  ledger is the single source of truth: every diff above is a *view* disagreement,\n");
    std::printf("  not a ledger disagreement. UIs MUST render visibleSet() instead of filtering\n");
    std::printf("  locally (protocol.md CTR-EN-06); counts differ across phases only because the\n");
    std::printf("  rules declare different per-phase filters.\n");
    check(sink->consistencies >= 1, "entity.consistency event emitted");
    check(store->data.size() == 1, "ledger persisted through IEntityStore");

    std::printf("result: %s\n", g_failed == 0 ? "ALL GREEN" : "FAILED");
    return g_failed == 0 ? 0 : 1;
}
