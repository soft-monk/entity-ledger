// entity-ledger · src/internal.h —— 内部实现细节（宿主 MUST NOT 包含）
//
// 权威依据：docs/需求/entity-ledger需求专篇.md（41 条）+ protocol.md v1.0
//
// 本文件与 src/*.cc 同属内部；公开面只有 include/entity_ledger/entity_ledger.h。
// 内部同样 MUST NOT 出现实体类型名 / 动作名 / 阈值 / 中文文案（P6 / P7）：
// 一切业务取值只能来自注入的规则包。
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "entity_ledger/entity_ledger.h"

namespace entity_ledger {
namespace detail {

// ============================================================================
// 规则（全部来自 policies/；引擎只认识机制，不认识取值）
// ============================================================================

/// 评级因子（protocol.md §5.5 `threatFactors`）
struct FactorDef {
    std::string key;
    std::string name;
    std::string source;       // 机制 token：typeBase / distance / state / confidence / sourceCount / attribute
    std::string attributeKey; // source == attribute 时的属性名
    double weight = 0.0;
    int64_t weightPpm = 0;
    std::string normalizeType;  // percent / range / table / identity
    double normMin = 0.0;
    double normMax = 1.0;
    std::string direction;  // higher / lower
    std::map<std::string, double> table;
    std::string missing;  // skip / zero / reject
};

/// 分档（protocol.md §5.5 `bands`：`{key, min}`；`state` 为 target.state 的 status 取值）
struct BandDef {
    std::string key;
    int min = 0;
    std::string state;
};

/// 暴露规律（打击窗口的计算依据；ELG-RATE-06）
struct StrikePattern {
    std::string key;
    std::vector<std::string> appliesToTypes;  // 类型 key 或 "*"
    int64_t cycleMs = 0;
    int64_t exposedMs = 0;
    int64_t offsetMs = 0;
};

struct StrikeWindowRule {
    int64_t horizonMs = 1800000;
    int64_t stepMs = 1000;
    int64_t minDurationMs = 0;
    int minPoints = 2;
    std::vector<StrikePattern> patterns;
};

/// 排序键（ELG-RANK-01）
struct RankKeyDef {
    std::string field;      // priority / threatScore / threatBand / confidence / sourceCount / no
    std::string direction;  // asc / desc
};

struct RankRule {
    std::vector<RankKeyDef> keys;
    int defaultPriority = 9;
    int sequenceLimit = 0;  // 0 = 不限
};

/// 轨迹规则（ELG-TRK-03/05/06）
struct TrackRule {
    int maxPointsPerEntity = 0;  // 0 = 不限（软上限：超出即裁掉最旧点）
    int64_t retentionMaxAgeMs = 0;
    int retentionMaxPoints = 0;
    int decimateEveryNth = 1;
    int64_t decimateMinIntervalMs = 0;
    int64_t predictHorizonMs = 60000;
    int64_t predictStepMs = 10000;
    int predictMinPoints = 2;
    int predictMaxPoints = 12;
    int64_t timelineStepMs = 0;  // 0 = 不下采样（原始点直出，交由回放组件插值）
    bool timelineIncludePredicted = false;
};

/// 去重规则（ELG-REG-04 / R3：默认保守）
struct DedupRule {
    std::string mode = "conservative";
    std::vector<std::string> keys;  // obsKey / typeKey / space / dynamicState
    bool requireTypeMatch = true;
    int64_t spaceRadiusM = 0;
    int64_t timeWindowMs = 0;
    bool allowManualSplit = true;
    std::string onAmbiguous = "separate";
};

/// 来源定义与置信度融合规则（ELG-REG-05）
struct SourceDef {
    std::string key;
    std::string name;
    double weight = 1.0;
    int64_t weightPpm = 1000000;
};

struct ConfidenceRule {
    std::string method = "weighted-mean";  // weighted-mean / max
    std::map<std::string, SourceDef> sources;
    std::vector<std::string> sourceOrder;
    std::string defaultSource;
    double multiSourceBonus = 0.0;
    double maxBonus = 0.0;
};

/// 动态状态机（ELG-REG-06）
struct StateMachineRule {
    std::vector<std::string> keys;
    std::map<std::string, std::string> names;
    std::vector<std::pair<std::string, std::string>> transitions;  // from → to（"*" 通配）
    bool anyTransition = true;  // 未声明 transitions = 全部放行（CTR-PL-04 缺省行为）
    std::string defaultState;
};

/// 视图的逐阶段过滤（ELG-ID-03；界面 MUST NOT 自行过滤，过滤口径在这里声明）
struct PhaseFilterRule {
    std::vector<std::string> phases;  // 阶段 key 或 "*"（首个命中生效）
    std::vector<std::string> includeTypes;
    std::vector<std::string> excludeTypes;
    std::vector<std::string> requireFlags;
    std::vector<std::string> excludeFlags;
    double minConfidence = 0.0;
};

struct ViewRule {
    std::string key;
    std::string name;
    std::vector<PhaseFilterRule> filters;
};

/// 关系种类与两态（ELG-INTEL-01/03）
struct RelationStateDef {
    std::string key;
    std::string name;
};

struct RelationsRule {
    std::vector<RelationDef> kinds;
    std::vector<RelationStateDef> states;
    std::string defaultState;
};

struct NumberingRule {
    int start = 1;
    bool contiguous = true;
    bool reuse = false;
};

/// 装载后的规则（引擎只认识这个形状，不认识取值）
struct Definition {
    bool loaded = false;
    std::string ns;
    std::string schemaVersion;
    int major = 0;
    std::string digest;
    std::string version;

    std::map<std::string, EntityType> types;
    std::vector<std::string> typeOrder;
    NumberingRule numbering;
    double earthRadiusM = 6371000.0;
    bool referenceSet = false;
    double referenceLng = 0.0;
    double referenceLat = 0.0;
    StateMachineRule states;
    DedupRule dedup;
    ConfidenceRule confidence;
    std::vector<FlagDef> flags;
    std::map<std::string, std::size_t> flagIndex;
    std::vector<ViewRule> views;
    std::map<std::string, std::size_t> viewIndex;
    std::vector<ActionDef> actions;
    std::map<std::string, std::size_t> actionIndex;
    RelationsRule relations;

    std::vector<FactorDef> factors;
    int64_t totalWeightPpm = 0;
    std::vector<BandDef> bands;  // 按 min 降序（装载时排好，确定性）
    StrikeWindowRule window;
    RankRule rank;
    TrackRule track;

    std::vector<std::string> warnings;
    std::size_t unknownFields = 0;

    // ---- 查询辅助（不存在 → nullptr / 空） ----
    const EntityType* findType(const std::string& key) const;
    const ActionDef* findAction(const std::string& key) const;
    const ViewRule* findView(const std::string& key) const;
    const FlagDef* findFlag(const std::string& key) const;
    const SourceDef* findSource(const std::string& key) const;
    const StrikePattern* findPattern(const std::string& key) const;
    const EntityType* firstType() const;
    /// 分档：bands 已按 min 降序，取首个 score >= min；bandKeys 为空 → 空串
    const BandDef* bandFor(int score) const;
    /// 视图在某阶段的过滤规则（首个命中；无命中 → 空指针）
    const PhaseFilterRule* filterFor(const ViewRule& v, const std::string& phaseKey) const;
    std::string typeName(const std::string& typeKey) const;
    std::string viewName(const std::string& viewKey) const;
    std::string actionName(const std::string& actionKey) const;
    bool hasState(const std::string& key) const;
    bool transitionAllowed(const std::string& from, const std::string& to) const;
};

/// 校验产物（装载与纯校验共用；原子替换的前提）
struct ValidateOutcome {
    int code = 0;
    std::string message;
    Definition def;
    std::vector<LoadIssue> issues;
};

/// 校验并合并一个规则包（纯函数：不触碰引擎状态）
ValidateOutcome buildDefinition(const Definition& base, const json& pkg);
/// "当前生效规则"导出（CTR-PL-06；digest 亦由此计算）
json definitionToJson(const Definition& def);
/// 规范化字节（digest 用；FNV-1a 64 → 16 位小写十六进制）
std::string canonicalBytes(const json& pkg);
std::string fnv1a64Hex(const std::string& bytes);

// ============================================================================
// 台账状态
// ============================================================================

/// 每任务一份台账（引擎内的真值；落库经 IEntityStore，写前提交）
struct MissionState {
    std::string missionId;
    std::vector<std::string> order;                // 登记顺序（确定性迭代顺序）
    std::map<std::string, EntityRecord> entities;  // id → 记录
    std::map<int, std::string> byNo;               // no → id（任务内唯一，CTR-EN-04）
    std::set<int> usedNos;                         // 历史占用过的编号（reuse=false 时 MUST NOT 复用）
    int nextNo = 0;
    std::map<std::string, std::set<std::string>> obsKeys;  // entityId → 观测主键集合（去重键）
    std::map<std::string, std::vector<TrackPoint>> tracks;  // entityId → ts 升序
    std::map<std::string, TrackStats> trackStats;
    std::vector<RelationEdge> relations;
    std::vector<SequenceEntry> sequence;
    std::vector<SequenceAuditEntry> sequenceAudit;
    std::vector<ActionLogEntry> actionLog;
    std::map<std::string, std::set<std::string>> applied;  // entityId → 已执行动作 key
    bool referenceSet = false;
    double referenceLng = 0.0;
    double referenceLat = 0.0;
};

/// 引擎全局状态（EntityLedger::Impl 的实体）
struct State {
    Definition def;
    std::map<std::string, MissionState> missions;
    std::map<std::string, ActionGateFn> actionGates;

    std::shared_ptr<IEntityStore> store;
    std::shared_ptr<IClock> clock;  // 空 → SystemClock
    std::shared_ptr<IEntitySink> sink;
    std::shared_ptr<ILogSink> log;
    std::shared_ptr<IClock> systemClock;
    bool storeLoaded = false;  // ensureStoreLoadedLocked 是否已跑过

    mutable std::recursive_mutex mtx;  // 保护 missions / def / metrics（可重入：Sink 回调里的只读查询合法）
    std::mutex busyMtx;                // 保护 busy
    std::set<std::string> busy;        // 正在执行的动作主体（try-lock 语义）

    Metrics metrics;

    /// try-lock：拿不到立刻返回 false（MUST NOT 阻塞等待）
    bool tryAcquire(const std::string& key);
    void release(const std::string& key);
    /// 取任务；store 注入且内存无该任务时尝试 load（懒加载）
    MissionState& missionLocked(const std::string& missionId);
    MissionState* findMissionLocked(const std::string& missionId);
    /// store 支持列举时，把尚未载入内存的任务整体载入一次（读路径的懒加载）
    void ensureStoreLoadedLocked();
    int64_t nowLocked() const;
    /// 写前提交：序列化该任务并交 store；无 store 视为成功
    bool persistLocked(const MissionState& m);
    void emitEntityChanged(const std::string& missionId, const EntityRecord& rec,
                           const std::string& change, const std::string& detail, int64_t ts);
    void emitTargetState(const EntityRecord& rec, int64_t ts);
    void audit(const AuditEntry& e);
    void logEvent(int level, const std::string& event, const json& data);
};

/// 台账 ⇄ JSON（宿主落库形状；`IEntityStore::save` 收到的就是它）
json missionToJson(const MissionState& m);
bool missionFromJson(const json& j, MissionState& out);

// ============================================================================
// 机制辅助
// ============================================================================

/// 评级（ELG-RATE-02/03/05）：显式快照 + 规则 → 逐因子得分与总分（∑contribution == score）
///
/// 纯计算，不读全局状态、不落库（elg-rate-05）；`assessThreat` 与此为同一条路径。
ThreatAssessment computeAssessment(const Definition& def, const ThreatSnapshot& snap,
                                   bool refSet, double refLng, double refLat, int64_t ts);

/// 台账记录 → 评级快照（单一来源，避免两处拼装）
ThreatSnapshot snapshotOf(const EntityRecord& rec);

/// 半开区间的判定
inline bool inRange(int64_t v, int64_t from, int64_t to) {
    return v >= from && (to <= 0 || v < to);
}

/// haversine 距离（米；半径由规则注入）。确定性：纯 double 运算 + 最终取整。
double haversineM(double lng1, double lat1, double lng2, double lat2, double radiusM);
/// 正北为 0、顺时针的方位角（度）
double bearingDeg(double lng1, double lat1, double lng2, double lat2);
/// 沿方位角推进 distanceM 后的坐标（局部等距近似；用于预测点与外推）
void advance(double lng, double lat, double headingDeg, double distanceM, double radiusM,
             double& outLng, double& outLat);
/// 点是否暴露（按规则的暴露规律；`nowMs` 为相位基准）
bool exposedAt(int64_t t, int64_t nowMs, const StrikePattern& p);

/// 半开区间取整（half-up，整数运算；跨平台逐字节一致）
inline int64_t roundHalfUp(int64_t num, int64_t den) {
    if (den <= 0) return 0;
    if (num >= 0) return (2 * num + den) / (2 * den);
    return -((2 * (-num) + den) / (2 * den));
}

inline int64_t clampI64(int64_t v, int64_t lo, int64_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

inline double clamp01(double v) {
    if (v < 0.0) return 0.0;
    if (v > 1.0) return 1.0;
    return v;
}

/// 逗号分隔的旗标列表（结构化状态变更的 from/to 表达）
std::string joinFlags(const std::vector<std::string>& v);
std::vector<std::string> splitFlags(const std::string& s);

/// id 生成（确定性：任务 id 摘要 + 序号；已存在则递增直到空闲）
std::string makeEntityId(const std::string& missionId, std::uint64_t serial);
std::string digest8(const std::string& s);

/// 机制 token 判定：`$` 前缀 = 引擎内建守卫；否则为宿主注册 gate id
inline bool isBuiltinGate(const std::string& id) { return !id.empty() && id[0] == '$'; }

/// 取 `$name:arg` 的 name 与 arg（无 arg 时 arg 为空）
std::pair<std::string, std::string> splitGate(const std::string& id);

/// 实体视图（含关系链，供展示；protocol.md §2.4 `{id,no}`）
void decorateEntity(const State& st, const MissionState& m, EntityRecord& rec);

}  // namespace detail

/// 引擎实现的唯一成员（PIMPL；各 src/*.cc 通过它访问 detail::State）
struct EntityLedger::Impl {
    detail::State st;
};

}  // namespace entity_ledger
