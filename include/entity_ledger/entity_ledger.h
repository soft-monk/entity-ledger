// entity-ledger · entity_ledger.h —— 唯一公开头文件
//
// 需求依据：docs/需求/entity-ledger需求专篇.md（41 条：ELG-REG 6 / ELG-ID 5 / ELG-RATE 6 /
//          ELG-RANK 4 / ELG-TRK 6 / ELG-ACT 6 / ELG-INTEL 3 / ELG-NFR 5）
// 上游共享契约：phase-engine/docs/契约/protocol.md v1.0（冻结）
//   §2 实体标识（id 全局唯一 / no 任务内唯一 / 展示处带 {id,no}；CTR-EN-01..08）
//   §3 错误码（0/1000/1002/1003/1004/1005/1006；1001 保留不用）
//   §4 事件名（entity.changed / entity.consistency / target.state）
//   §5 规则包 schema（kind: entityTypes / threatFactors + 骨架四字段）
//   §6 反向接口命名（IEntitySink / IEntityStore / IClock / ILogSink）
//   P1–P10（引擎不 import 其它引擎、不依赖 Web/SQL、业务词零内建、时间可注入…）
// 冲突裁决：phase-engine/docs/契约/冲突裁决.md（C15 废弃 1001；C16 收窄 1002）
//
// 三条不可协商的口径：
//   1. **引擎不认识任何业务取值**：实体类型名（机动指挥节点…）、动作名、威胁分档、
//      视图名、编号起始值、抽稀参数 —— 全部住在规则包 policies/（kind 见 §5.3）。
//      本文件内 MUST NOT 出现实体类型名 / 动作名 / 阈值 / 文案（ELG-REG-01、ELG-ACT-01、P6）。
//   2. **引擎不落库、不广播、不取系统时间**：出口为反向接口 IEntityStore / IEntitySink /
//      IClock（MUST 注入）与 ILogSink（可选）；未注入时引擎仍 MUST 可工作（纯内存）。
//   3. **失败 MUST NOT 抛异常跨边界**（P10）：一切裁决走 {code, message, data} 信封，
//      code 逐值对齐 protocol.md §3.2。
//
// 本引擎是初稿 §10.12「同一场景内目标编号与类型在不同界面不一致」的**唯一收口点**：
//   · `visibleSet()`  —— 某阶段/某视图应可见的实体集合（界面 MUST NOT 自行过滤，CTR-EN-06）
//   · `checkConsistency()` —— 逐条差异报告，可定位到具体 no 与具体视图（CTR-EN-08、ELG-ID-02）
//   · `reclassifyType()` —— 类型重判的唯一显式路径，留痕（CTR-EN-07、ELG-ID-04）
//
// 宿主只允许 #include <entity_ledger/entity_ledger.h>；其余头文件是内部实现细节。
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

namespace entity_ledger {

/// 引擎的 JSON 类型。
///
/// 为什么是 `ordered_json`（而不是 nlohmann 默认的 `json`）：与 phase-engine 同因 ——
/// 事件的 `data` 键序要求与结构体成员声明顺序一致（protocol.md §4.1 CTR-EV-05 +
/// realtime-hub 信封惯例），默认 `json`（std::map 后端）会按键名字典序重排。
/// 两者取值语义、`dump()`、`parse()` 行为一致；宿主用默认 `json` 接收结果仍可正常比较。
using json = nlohmann::ordered_json;

/// 引擎支持的 policies MAJOR（§5.2：不匹配 → 拒绝装载 + 1006，MUST NOT 静默降级）
inline constexpr int kSupportedPoliciesMajor = 1;
/// 引擎版本（capabilities 自述用）
inline constexpr const char* kEngineVersion = "0.1.0";

// ============================================================================
// §1 错误码（protocol.md §3.2 的子集，逐值对齐；1001 保留不用）
// ============================================================================

enum class ErrorCode {
    Ok = 0,
    BadRequest = 1000,
    Conflict = 1002,        ///< 冲突拒绝：该动作正在执行 / 已由他方执行（HTTP 409）
    GateUnmet = 1003,       ///< 前置条件未满足（动作 requires / 内建守卫 / 规则上限）
    NotFound = 1004,        ///< 资源不存在（含"引用已删除实体"）
    Internal = 1005,        ///< 服务端执行失败（含 store 写失败）
    VersionMismatch = 1006, ///< 规则包 schemaVersion 或 definitionVersion 不符
};

// ============================================================================
// §2 实体标识与阶段上下文（protocol.md §2 / §1.4，形状逐字对齐）
// ============================================================================

/// 跨引擎实体引用（protocol.md §2.4）。
///
/// CTR-EN-01：跨引擎引用实体 MUST 只带 `id`（本头文件内一切入参都用 `id` 字符串）；
/// CTR-EN-02：需要展示编号的场合 MUST 同时携带 `{id, no}` —— 本结构即该展示形状。
struct EntityRef {
    std::string id;
    int no = 0;
};

/// "当前阶段"入参（protocol.md §1.4 的五个字段，逐字）。
///
/// P1 要求引擎之间 MUST NOT 互相 import，因此本引擎**镜像**该形状而不包含
/// phase-engine 的头文件；宿主用 `phase.phaseContext(missionId)` 取值后转交本结构。
/// 引擎 MUST 接受 `PhaseContext` 而非裸阶段名字符串（protocol.md §1.4 约束）。
struct PhaseContext {
    std::string phaseKey;
    int seq = 0;
    std::string scenarioKey;
    int64_t enteredAt = 0;  // epoch ms
    std::string missionId;
};

/// 前置条件未满足项（与 phase-engine 的 `UnmetItem` 同形；内建守卫以 `$` 开头）
struct UnmetItem {
    std::string gate;
    std::string reason;  // ASCII 机制短语（可读；文案归宿主/规则包）
    std::string detail;  // 规则里的取值（如阈值、上限）
};

// ============================================================================
// §3 规则包（policies）装载结果
// ============================================================================

/// 逐条装载问题（`path` 形如 `items[3].weight`；CTR-PL-02 要求逐条可读原因）
struct LoadIssue {
    std::string path;
    std::string field;
    std::string reason;
};

/// 定义版本与变更检测（CTR-PL-06 可导出"当前生效规则"）
struct DefinitionInfo {
    bool loaded = false;
    std::string policiesNamespace;
    std::string schemaVersion;
    std::string definitionVersion;  // "<namespace>:<schemaVersion>:<digest>"
    std::string digest;             // FNV-1a 64 → 16 位小写十六进制
    int policiesMajor = 0;
    int entityTypeCount = 0;
    int actionCount = 0;
    int viewCount = 0;
    int factorCount = 0;
    int bandCount = 0;
    int flagCount = 0;
    int relationKindCount = 0;
    int dynamicStateCount = 0;
    std::vector<std::string> entityTypeKeys;
    std::vector<std::string> actionKeys;
    std::vector<std::string> viewKeys;
    std::vector<std::string> bandKeys;
    std::vector<std::string> warnings;  // 未知字段/未知段（CTR-PL-03：忽略并计入告警）
};

/// 装载结果（**不抛异常**）
struct LoadResult {
    int code = 0;
    std::string message;
    DefinitionInfo data;
    std::vector<LoadIssue> issues;
    json toJson() const;
};

// ============================================================================
// §4 实体台账（ELG-REG-02 的字段清单）
// ============================================================================

/// 实体类型条目（ELG-REG-01：`{key, 名称, 基础威胁, 属性}` 全部由规则声明）
struct EntityType {
    std::string key;
    std::string name;
    double baseThreat = 0.0;
    json attributes = json::object();
};

/// 一次来源观测（多源汇入的最小单位）
struct SourceObs {
    std::string source;   // 规则 `confidence.sources[].key`
    std::string obsKey;   // 规则 `dedup.keys[]` 声明的主键取值（外部观测标识）
    double confidence = 0.0;
    int64_t at = 0;       // epoch ms
};

/// 合并后的来源标注（ELG-REG-04：同一实体的多来源观测 → 一条 + 多源标注）
struct SourceRef {
    std::string source;
    std::string name;  // 规则里的显示名（引擎不造文案）
    double confidence = 0.0;
    int count = 0;
    int64_t firstAt = 0;
    int64_t lastAt = 0;
};

/// 置信度融合的逐项贡献（ELG-REG-05：结果可复现、可手算）
struct ConfidenceContribution {
    std::string source;
    double value = 0.0;
    int weightPpm = 0;    // 规则权重（百万分之一整数）
    int contribution = 0;  // 该来源对最终置信度的贡献（百万分之一）
};

/// 台账字段变更留痕（CTR-EN-07：类型重判 MUST 留痕，MUST NOT 静默改变）
struct EntityTrace {
    int64_t at = 0;
    std::string field;       // "type" | "state" | "flag" | "priority" | "retired" | ...
    std::string from;
    std::string to;
    std::string action;      // 机制 token：register / reclassify / flag-set / state-change / retire …
    std::string operatorId;
    std::string reason;
};

/// 关系链引用（实体视图里的直接边；完整链路查询见 `chain()`）
struct EntityLink {
    std::string kind;   // 规则 `relations.kinds[].key`
    std::string state;  // 规则 `relations.states[].key`（已确认 / 疑似两态）
    std::string toId;
    int toNo = 0;
    bool outgoing = true;  // true = 本实体为 from，false = 本实体为 to
};

/// 台账记录（ELG-REG-02）：`{id, no, 类型, 坐标, 来源, 置信度, 动态状态, 威胁等级, 优先级, 关系链, 时间}`
struct EntityRecord {
    std::string id;
    int no = 0;
    std::string missionId;
    std::string typeKey;
    std::string typeName;  // 规则里的显示名（展示用；引擎不造）
    double lng = 0.0;
    double lat = 0.0;
    double alt = 0.0;
    std::vector<SourceRef> sources;
    int sourceCount = 0;
    bool multiSource = false;
    double confidence = 0.0;
    std::string dynamicState;  // 规则 `dynamicStates.items[].key`
    std::vector<std::string> flags;
    json attributes = json::object();  // 宿主/规则属性（评级 attribute 因子的取值来源）
    int threatScore = 0;    // 最近一次评级的 0..100（未评过 = 0）
    std::string threatBand; // 规则 `bands[].key`
    std::string status;     // 规则 `bands[].state`（target.state 事件的 status 字段）
    bool assessed = false;
    int priority = 0;
    bool prioritySet = false;
    std::vector<EntityLink> relations;
    std::vector<EntityTrace> trace;
    bool retired = false;
    int64_t retiredAt = 0;
    std::string retireReason;
    int64_t createdAt = 0;
    int64_t updatedAt = 0;
};

/// 可能的重复候选（ELG-REG-04 / R3：默认保守 —— 宁可标多源也不合并）
struct MergeCandidate {
    std::string id;
    int no = 0;
    std::string typeKey;
    int64_t distanceM = 0;
    std::vector<std::string> matchedKeys;    // 命中的去重键
    std::vector<std::string> unmatchedKeys;  // 未命中的去重键（保守不合并的依据）
    double confidence = 0.0;
};

/// 登记入参
struct RegisterInput {
    std::string missionId;
    std::string typeKey;
    double lng = 0.0;
    double lat = 0.0;
    double alt = 0.0;
    std::vector<SourceObs> sources;
    double confidence = 0.0;      // 未给来源时使用；给了 sources 则由规则融合
    std::string dynamicState;     // 空 = 规则 `defaultDynamicState`
    int no = 0;                   // 0 = 按规则编号；> 0 = 显式指定（须任务内唯一）
    std::string obsKey;           // 去重主键（规则 `dedup.keys[]`）
    json attributes = json::object();
    std::vector<std::string> flagKeys;  // 登记即打旗标（受规则 `flags[].unique` 约束）
    std::string operatorId;
};

/// 登记结果（部分成功语义：候选重复逐条标注，MUST NOT 静默丢弃）
struct RegisterResult {
    int code = 0;
    std::string message;
    std::string status;  // "created" | "merged" | "updated"
    bool idempotent = false;
    bool merged = false;
    bool created = false;
    EntityRecord data;
    std::vector<MergeCandidate> candidates;
    std::vector<ConfidenceContribution> contributions;
    std::vector<UnmetItem> unmet;  // 结构化拒绝原因（如唯一旗标已被持有、人工拆分被规则禁用）
    int64_t ts = 0;
    json toJson() const;
};

/// 台账查询
struct EntityQuery {
    std::string missionId;
    std::string typeKey;
    std::string dynamicState;
    std::string flagKey;
    std::string bandKey;
    double minConfidence = 0.0;
    bool includeRetired = false;
    int limit = 100;
    int offset = 0;
};

// ============================================================================
// §5 阶段可见集合（ELG-ID-03 / CTR-EN-06）与一致性检查（ELG-ID-02 / CTR-EN-08）
// ============================================================================

/// 视图里的一条目（界面/报告"看到"了什么）
struct ViewItem {
    std::string id;
    int no = 0;
    std::string typeKey;              // 空 = 该视图不展示类型
    std::vector<std::string> flagKeys;
    double confidence = 0.0;
};

/// 一个视图/界面在某一时刻的呈现快照（由宿主在渲染前采集）
struct ViewSnapshot {
    std::string viewKey;    // 规则 `views[].key`；未知视图 = 宿主自定义视图
    std::string viewName;   // 展示名（宿主提供；引擎原样回写）
    std::string phaseKey;   // 该快照对应的阶段（PhaseContext.phaseKey）
    std::string scenarioKey;
    int64_t reportedAt = 0;
    bool flagsRendered = false;  // 该视图是否渲染旗标（true 才比对旗标，避免误报）
    std::vector<ViewItem> items;
};

/// 逐条差异（protocol.md §4.4 `entity.consistency` 的 `diffs[]` 元素）
///
/// 键序 MUST 为 `no, field, views[]`（已冻结的事件负载）+ 只增可选字段（CTR-EV-04）。
struct DiffItem {
    int no = 0;                     // 定位到**具体编号**
    std::string field;              // "presence" | "no" | "type" | "id" | "flag:<key>" | "confidence"
    std::vector<std::string> views;  // 定位到**具体视图**（≥1，通常 2）
    std::string kind;               // 机制 token：missing / extra / mismatch / stale / unknown / drift
    std::string id;
    std::string expected;
    std::string actual;
    std::string phaseKey;
    std::string reason;  // 只读补充（ASCII 机制短语，非自然语言文案）
};

/// 跨阶段集合变化（ELG-ID-03："跨阶段集合变化可解释"）
struct PhaseDelta {
    std::string phaseKey;
    int count = 0;
    std::vector<int> addedNos;
    std::vector<int> removedNos;
    std::string basis;  // 计算依据（"current-state"：按当前台账状态投影）
};

/// 类型重判留痕（checkConsistency 回写，供"允许并留痕"验收）
struct ReclassifyRecord {
    std::string id;
    int no = 0;
    std::string fromType;
    std::string toType;
    int64_t at = 0;
    std::string operatorId;
    std::string reason;
};

/// 一致性检查入参
struct ConsistencyRequest {
    std::string missionId;
    std::string scenarioKey;
    std::vector<ViewSnapshot> views;
    std::optional<PhaseContext> phase;  // 给定阶段时附带该阶段的"应可见集合"对账
    std::string viewKey;                // 与 phase 同时给出时用于可见集合对账
};

/// 一致性报告（CTR-EN-08：逐条差异，可定位到具体编号与视图）
struct ConsistencyReport {
    int code = 0;
    std::string message;
    std::string missionId;
    bool consistent = true;
    int checkedViews = 0;
    int checkedItems = 0;
    std::vector<DiffItem> diffs;
    std::vector<PhaseDelta> phaseDeltas;
    std::vector<ReclassifyRecord> reclassifications;
    std::string phaseKey;
    std::vector<EntityRef> expectedVisible;  // 引擎给出的"应可见集合"（界面 MUST NOT 自行过滤）
    int64_t ts = 0;
    json toJson() const;
};

/// 可见集合查询入参（ELG-ID-03）
struct VisibleSetRequest {
    std::string missionId;
    std::string viewKey;
    std::string scenarioKey;
    std::optional<PhaseContext> phase;
    bool includeExcluded = true;  // 是否返回被排除项及原因（跨阶段变化可解释）
};

/// 可见条目（界面直接渲染所需，无需二次过滤）
struct VisibleItem {
    std::string id;
    int no = 0;
    std::string typeKey;
    std::string typeName;
    std::vector<std::string> flags;
    std::string dynamicState;
    std::string threatBand;
    std::string status;
    int threatScore = 0;
    double confidence = 0.0;
    double lng = 0.0;
    double lat = 0.0;
};

/// 被排除项及原因（机制 token，可解释）
struct ExcludedItem {
    std::string id;
    int no = 0;
    std::string reason;  // type / confidence / flag-required / flag-excluded / retired
};

/// 可见集合结果
struct VisibleSetResult {
    int code = 0;
    std::string message;
    std::string missionId;
    std::string viewKey;
    std::string viewName;
    std::string phaseKey;
    std::string scenarioKey;
    std::vector<VisibleItem> items;  // no 升序（确定性）
    int total = 0;
    int excluded = 0;
    std::vector<ExcludedItem> excludedItems;
    std::string basis;  // "current-state"
    int64_t ts = 0;
    json toJson() const;
};

// ============================================================================
// §6 威胁评级（ELG-RATE）与打击窗口（ELG-RATE-06）
// ============================================================================

/// 评级输入快照（ELG-RATE-05：评级输入显式，引擎 MUST NOT 读全局状态或数据库）
struct ThreatSnapshot {
    std::string entityId;
    int no = 0;
    std::string missionId;
    std::string typeKey;
    double lng = 0.0;
    double lat = 0.0;
    double confidence = 0.0;
    std::string dynamicState;
    int sourceCount = 0;
    std::vector<std::string> flagKeys;
    json attributes = json::object();
    int64_t observedAt = 0;
    bool referenceSet = false;  // 距离因子的基准点（未给则取任务基准点）
    double referenceLng = 0.0;
    double referenceLat = 0.0;
};

/// 逐因子得分（ELG-RATE-02：输出逐因子得分与总分，导出后可手算核对）
struct FactorScore {
    std::string key;
    std::string name;
    std::string source;        // 机制 token：typeBase/distance/state/confidence/sourceCount/attribute
    int weightPpm = 0;         // 规则权重（micro）
    int normPpm = 0;           // 归一后取值（micro，0..1000000）
    int contribution = 0;      // 对总分的贡献（与总分同刻度，Σcontribution == score）
    bool missing = false;      // 该因子输入缺失（按规则 `missing` 策略处理）
    std::string missingPolicy; // skip / zero / reject
    double rawNumber = 0.0;    // 原始数值（distance 为米；percent 为 0..1）
    std::string rawText;       // 原始枚举取值（state / attribute）
};

/// 评级结果（可复算：score == Σ contribution）
struct ThreatAssessment {
    std::string entityId;
    int no = 0;
    std::string missionId;
    int score = 0;        // 0..100
    std::string band;     // 规则 `bands[].key`
    std::string status;   // 规则 `bands[].state`
    int totalWeightPpm = 0;
    bool rejected = false;       // 必填因子输入缺失（规则 `missing: "reject"`）
    std::string rejectReason;    // 机制短语：缺失的因子 key
    std::vector<FactorScore> factors;
    std::vector<std::string> skippedFactors;
    int64_t ts = 0;
    json toJson() const;
};

/// 打击窗口查询
struct StrikeWindowQuery {
    int64_t nowMs = 0;  // 0 = 用注入时钟
    int horizonOverrideMs = 0;
};

/// 窗口段（逐段可复算依据：暴露规律 + 外推位置）
struct WindowSegment {
    int64_t fromMs = 0;
    int64_t toMs = 0;  // 半开区间 [from, to)
    int64_t durationMs = 0;
    std::string basis;  // 规则 `strikeWindow.patterns[].key`
    bool predicted = true;
    double lng = 0.0;
    double lat = 0.0;
    double speedMps = 0.0;
    double headingDeg = 0.0;
};

/// 打击窗口（ELG-RATE-06：**结构化时间区间**，由轨迹与规则推算；MUST NOT 是硬编码字符串）
struct StrikeWindow {
    std::string entityId;
    int no = 0;
    std::string missionId;
    bool found = false;
    int64_t fromMs = 0;
    int64_t toMs = 0;
    int64_t durationMs = 0;
    int64_t leadMs = 0;  // fromMs - now（窗口起始相对当前时刻的提前量，可复算）
    std::string basis;
    int horizonMs = 0;
    int stepMs = 0;
    int trackPoints = 0;
    bool extrapolated = false;  // 位置由轨迹外推（预测，非实测）
    std::vector<WindowSegment> segments;  // 全部候选暴露段（含未达 minDuration 的）
    int64_t ts = 0;
    json toJson() const;
};

/// 打击窗口结果
struct StrikeWindowResult {
    int code = 0;
    std::string message;
    StrikeWindow data;
    json toJson() const;
};

// ============================================================================
// §7 优先级与打击序列（ELG-RANK）
// ============================================================================

/// 排序条目（稳定次序：末位键恒为 no）
struct RankedEntity {
    int rank = 0;
    std::string id;
    int no = 0;
    std::string typeKey;
    int threatScore = 0;
    std::string threatBand;
    int priority = 0;
    bool prioritySet = false;
    double confidence = 0.0;
    int sourceCount = 0;
    int sequenceIndex = -1;  // 在打击序列中的位置（-1 = 不在序列）
    std::vector<std::string> sortKeys;  // 逐键取值（可复现排序过程）
};

/// 序列条目
struct SequenceEntry {
    std::string entityId;
    int no = 0;
    int position = 0;
    int64_t addedAt = 0;
    std::string actor;
    std::string reason;
};

/// 序列变更审计（ELG-RANK-04：谁在什么时候把谁加入了序列）
struct SequenceAuditEntry {
    int64_t at = 0;
    std::string actor;
    std::string action;  // "add" | "remove"
    std::string entityId;
    int no = 0;
    int position = 0;
    std::string reason;
};

/// 序列操作入参 / 结果
struct SequenceInput {
    std::string missionId;
    std::string entityId;
    std::string operatorId;
    std::string reason;
    int position = -1;  // -1 = 追加到末尾
};

struct SequenceResult {
    int code = 0;
    std::string message;
    std::string status;  // "added" | "removed" | "already-in-sequence" | "not-in-sequence"
    bool idempotent = false;
    std::string missionId;
    std::string entityId;
    std::vector<SequenceEntry> sequence;
    std::vector<UnmetItem> unmet;
    int64_t ts = 0;
    json toJson() const;
};

/// 排序查询
struct RankQuery {
    std::string missionId;
    std::string viewKey;  // 非空时只排该视图可见集合
    int limit = 0;        // 0 = 不限
};

// ============================================================================
// §8 轨迹服务（ELG-TRK）
// ============================================================================

/// 轨迹点（`predicted=true` 的点只在预测查询中出现，MUST NOT 与实测混淆）
struct TrackPoint {
    int64_t ts = 0;  // epoch ms
    double lng = 0.0;
    double lat = 0.0;
    double alt = 0.0;
    bool predicted = false;
    bool hasSpeed = false;
    double speedMps = 0.0;
    bool hasHeading = false;
    double headingDeg = 0.0;
    std::string basis;  // 预测点的推算依据（"extrapolation"）
};

/// 轨迹写入入参
struct TrackInput {
    std::string entityId;
    TrackPoint point;
};

/// 轨迹写入结果
struct TrackAppendResult {
    int code = 0;
    std::string message;
    std::string entityId;
    int appended = 0;
    int replaced = 0;   // 同 ts 覆盖（upsert）
    bool ordered = true;  // 写入后仍按 ts 有序（乱序写入的保证）
    int total = 0;
    int64_t ts = 0;
    json toJson() const;
};

/// 轨迹区间查询（ELG-TRK-02：`[from, to)` + 分页/上限截断且**不静默丢**）
struct TrackQuery {
    std::string entityId;
    int64_t fromMs = 0;
    int64_t toMs = 0;       // 0 = 不设上界
    int limit = 1000;       // 返回上限
    int offset = 0;
    bool descending = false;
    int everyNth = 0;       // 抽稀：每 N 点取 1（0 = 规则缺省）
    int64_t minIntervalMs = 0;  // 抽稀：最小时间间隔（0 = 规则缺省）
    bool includeStats = true;
};

/// 轨迹统计（ELG-TRK-06：清理计数可查）
struct TrackStats {
    int points = 0;
    int64_t oldestTs = 0;
    int64_t newestTs = 0;
    int64_t droppedByRetention = 0;
    int64_t droppedByCap = 0;
    int64_t replacedSamples = 0;
};

/// 轨迹查询结果（截断/抽稀如实标注）
struct TrackQueryResult {
    int code = 0;
    std::string message;
    std::string entityId;
    int no = 0;
    int64_t fromMs = 0;
    int64_t toMs = 0;
    std::vector<TrackPoint> points;  // ts 升序（descending 时降序）
    int totalInRange = 0;            // 截断前区间内总点数
    int returned = 0;
    bool truncated = false;          // 超限被截断（MUST NOT 静默丢）
    int64_t nextCursor = 0;          // 续取游标（下一个 ts；无更多 = 0）
    bool decimated = false;          // 已抽稀（如实标注）
    int decimatedFrom = 0;           // 抽稀前点数
    int everyNth = 0;                // 生效抽稀参数
    int64_t minIntervalMs = 0;
    bool hasPredicted = false;       // 结果中含预测点
    TrackStats stats;
    json toJson() const;
};

/// 预测查询（ELG-TRK-05）
struct PredictQuery {
    std::string entityId;
    int64_t nowMs = 0;      // 0 = 注入时钟
    int horizonMs = 0;      // 0 = 规则缺省
    int stepMs = 0;         // 0 = 规则缺省
    int maxPoints = 0;      // 0 = 规则缺省
};

/// 时间轴查询（ELG-TRK-04：输出可被 map-2d 回放接口消费，由宿主适配）
struct TrackTimelineQuery {
    std::string entityId;
    int64_t fromMs = 0;
    int64_t toMs = 0;
    int stepMs = 0;              // 0 = 规则缺省（1 = 原始点，不重采样）
    bool includePredicted = false;
    std::string label;           // 回放轨迹显示名（宿主提供；引擎不造）
    std::string color;           // 回放配色（宿主提供）
    std::string kind;            // 回放图元类别（宿主提供；空 = 不下发）
};

/// 回放采样点（map-2d `ReplaySample` 形状：`t/lng/lat/heading?/speed?/props?`）
struct ReplaySample {
    int64_t t = 0;
    double lng = 0.0;
    double lat = 0.0;
    bool hasHeading = false;
    double heading = 0.0;
    bool hasSpeed = false;
    double speed = 0.0;
    bool predicted = false;     // 借 props 表达（map-2d 回放输入无 predicted 槽位）
    bool interpolated = false;  // 重采样插值点（非实测；同样借 props 表达）
};

/// 回放轨迹（map-2d `ReplayTrack` 形状）
struct ReplayTrack {
    std::string id;
    std::string label;
    std::string kind;
    std::string color;
    std::vector<ReplaySample> samples;
};

/// 回放数据（map-2d `ReplayData` 形状：`{id?, tracks:[...]}`）
struct ReplayData {
    std::string id;
    std::vector<ReplayTrack> tracks;
};

/// 时间轴输出
struct TrackTimeline {
    std::string entityId;
    int no = 0;
    std::string missionId;
    int64_t fromMs = 0;
    int64_t toMs = 0;
    int64_t durationMs = 0;
    int stepMs = 0;
    std::vector<TrackPoint> points;
    bool decimated = false;
    int decimatedFrom = 0;
    bool truncated = false;
    bool hasPredicted = false;
    ReplayData replay;  // 可直接喂 map-2d loadReplay（宿主适配层可零转换）
    json toJson() const;
};

struct TrackTimelineResult {
    int code = 0;
    std::string message;
    TrackTimeline data;
    json toJson() const;
};

/// 轨迹保留（ELG-TRK-06）
struct RetentionInput {
    std::string missionId;  // 空 = 全部实体
    std::string entityId;   // 空 = 该任务全部实体
    int64_t nowMs = 0;      // 0 = 注入时钟
    int64_t maxAgeMs = 0;   // 0 = 规则缺省
    int maxPoints = 0;      // 0 = 规则缺省
};

struct RetentionResult {
    int code = 0;
    std::string message;
    int entities = 0;
    int64_t removedByAge = 0;
    int64_t removedByCap = 0;
    int64_t remaining = 0;
    int64_t ts = 0;
    json toJson() const;
};

// ============================================================================
// §9 动作状态机（ELG-ACT）
// ============================================================================

/// 动作定义（ELG-ACT-01 / ELG-ACT-04 / ELG-ACT-06：全部由规则声明）
struct ActionDef {
    std::string key;
    std::string name;
    std::vector<std::string> requires;   // 内建 `$…` 守卫 + 宿主注册 gate id
    std::vector<std::string> setsFlags;
    std::vector<std::string> clearsFlags;
    std::string setsDynamicState;
    std::vector<std::string> clearsDynamicState;  // 语义占位（规则可留空）
    bool reversible = true;
    bool exclusive = false;    // true = 同实体互斥（并发 → 1002）
    bool once = true;          // true = 已执行后重复请求 → 幂等"已执行"语义
    int64_t undoWithinMs = 0;  // 0 = 不限
    bool setsPriority = false;
    int priorityValue = 0;
    bool addsToSequence = false;
};

/// 结构化状态变更（ELG-ACT-03：动作**只产出结构化状态变更**，MUST NOT 产出自然语言文案）
struct StateChange {
    std::string field;  // "dynamicState" | "flags" | "priority" | "sequence" | "type" | "threat"
    std::string from;
    std::string to;
};

/// 动作请求
struct ActionRequest {
    std::string entityId;
    std::string actionKey;
    std::string reason;
    std::string operatorId;
    json params = json::object();
};

/// 动作结果
///
/// 幂等命中 MUST 为 `code=0` + `idempotent=true`（protocol.md §3.3 CTR-EC-01/02、ADR-C15-02）；
/// `status="already-done"` 承载需求专篇 ELG-ACT-02 的"已执行"语义。
/// 互斥冲突（同实体动作正在执行）MUST 为 `code=1002` + `conflict=true`（ADR-C16-01）。
/// 前置条件未满足 MUST 为 `code=1003` + `unmet[]`（ADR-C16-03）。
struct ActionResult {
    int code = 0;
    std::string message;
    std::string status;  // "ok" | "already-done" | "rejected" | "conflict"
    bool idempotent = false;
    bool conflict = false;
    std::string entityId;
    int no = 0;
    std::string missionId;
    std::string actionKey;  // 规则动作 key，或机制 op token（flag-set / type-reclassify / priority-set）
    std::vector<StateChange> changes;
    std::vector<UnmetItem> unmet;
    std::vector<std::string> skippedGates;  // 规则引用但宿主未注册 → 放行
    std::optional<EntityRecord> state;
    int64_t undoDeadline = 0;
    int64_t ts = 0;
    json toJson() const;
};

/// 动作日志（ELG-ACT-05：对齐现状 `target.strike` / `target.upgrade` 的落日志要求）
struct ActionLogEntry {
    int64_t at = 0;
    std::string missionId;
    std::string entityId;
    int no = 0;
    std::string actionKey;
    std::string actor;
    std::string status;
    bool reversible = true;
    std::vector<StateChange> changes;
    std::string reason;
    int64_t undoneAt = 0;
    std::string undoneBy;
};

struct ActionLogQuery {
    std::string missionId;
    std::string entityId;
    std::string actionKey;
    int limit = 0;  // 0 = 不限
};

// ============================================================================
// §10 情报关联（ELG-INTEL）
// ============================================================================

/// 关系种类（规则 `relations.kinds[]`；`cyclic=true` 允许成环，其余 MUST 拒环）
struct RelationDef {
    std::string key;
    std::string name;
    bool cyclic = false;
};

/// 有向关系边
struct RelationEdge {
    std::string missionId;
    std::string kind;
    std::string state;  // 规则 `relations.states[].key`
    std::string fromId;
    int fromNo = 0;
    std::string toId;
    int toNo = 0;
    int64_t at = 0;
    std::string operatorId;
};

struct RelationInput {
    std::string missionId;
    std::string kind;
    std::string state;
    std::string fromId;
    std::string toId;
    std::string operatorId;
};

/// 成环报告（ELG-INTEL-01 / R6：成环 MUST 被检出，否则查询死循环）
struct CyclePath {
    std::string missionId;
    std::vector<std::string> ids;
    std::vector<int> nos;
    std::vector<std::string> kinds;
};

struct RelationResult {
    int code = 0;
    std::string message;
    std::string status;  // "added" | "removed" | "already-exists" | "not-found"
    bool idempotent = false;
    RelationEdge edge;
    std::vector<std::string> cycle;  // 被拒时给出成环路径
    std::vector<UnmetItem> unmet;
    int64_t ts = 0;
    json toJson() const;
};

struct RelationQuery {
    std::string missionId;
    std::string entityId;  // 空 = 全部
    std::string kind;
    std::string state;
    std::string direction;  // "out" | "in" | "both"（缺省 both）
    int limit = 0;
    int offset = 0;
};

/// 链路节点
struct ChainNode {
    std::string id;
    int no = 0;
    std::string typeKey;
    int depth = 0;
    std::string viaKind;
    std::string viaState;
};

/// 链路查询（ELG-INTEL-02：上下游链路 + 关联目标数）
struct ChainQuery {
    std::string entityId;
    int depthLimit = 8;
    std::string kind;
    bool includeSuspected = true;
};

struct ChainResult {
    int code = 0;
    std::string message;
    std::string entityId;
    int no = 0;
    std::vector<ChainNode> upstream;
    std::vector<ChainNode> downstream;
    int relatedCount = 0;  // 关联目标数（去重后的节点数）
    int depthLimit = 0;
    bool truncated = false;
    bool cycleDetected = false;  // 查询途中检出环（已用已访问集合终止）
    std::vector<CyclePath> cycles;
    json toJson() const;
};

/// 关联统计（ELG-INTEL-03：已确认/疑似两态可筛选、可统计）
struct RelationStatItem {
    std::string key;
    int count = 0;
};

struct RelationStats {
    std::string missionId;
    int edges = 0;
    int entitiesWithRelations = 0;
    int isolatedEntities = 0;
    std::vector<RelationStatItem> byKind;
    std::vector<RelationStatItem> byState;
    json toJson() const;
};

// ============================================================================
// §11 旗标（ELG-ID-05：标记唯一性 —— "高价值"标记的键由规则声明）
// ============================================================================

/// 旗标定义（规则 `flags[]`）
struct FlagDef {
    std::string key;
    std::string name;
    bool unique = false;          // true = 同一任务内至多一个持有者
    std::vector<std::string> exclusive;  // 与该旗标互斥的旗标 key（不要求持有者唯一）
};

struct FlagInput {
    std::string missionId;
    std::string entityId;
    std::string flagKey;
    std::string operatorId;
    std::string reason;
    bool transfer = false;  // unique 旗标：true = 从原持有者转移到目标实体
};

struct ReclassifyInput {
    std::string entityId;
    std::string typeKey;
    std::string operatorId;
    std::string reason;  // 必填（CTR-EN-07 留痕）
};

struct PriorityInput {
    std::string entityId;
    int priority = 0;
    std::string operatorId;
    std::string reason;
};

// ============================================================================
// §12 反向接口（宿主 MUST 实现；命名遵循 protocol.md §6）
// ============================================================================

/// 事件负载前置声明（见 §13）
struct EntityChangeEvent;
struct TargetStateEvent;
struct ConsistencyEvent;

/// §12.1 变更通知出口 —— 对应 `entity.changed` / `target.state` / `entity.consistency`
///
/// 三个方法 MUST 立即返回，MUST NOT 在调用路径上阻塞（不做网络 IO / 不等锁 / 不落库）。
/// 回调抛出的异常 MUST 被引擎吞掉并计入 `metrics.sinkErrors`，MUST NOT 影响已生效的状态。
class IEntitySink {
public:
    virtual ~IEntitySink() = default;
    /// → 广播 `entity.changed`（protocol.md §4.4）
    virtual void onEntityChanged(const EntityChangeEvent& e) = 0;
    /// → 广播 `target.state`（protocol.md §4.2，既有冻结负载）
    virtual void onTargetState(const TargetStateEvent& e) = 0;
    /// → 广播 `entity.consistency`（protocol.md §4.4）
    virtual void onConsistency(const ConsistencyEvent& e) = 0;
};

/// §12.2 持久化出口（引擎不接触 SQL，P3）
///
/// 写前提交：`save()` 返回 true 之前 MUST 已完成持久化；返回 false 或抛异常 →
/// 本次变更整体失败（`1005`）且**内存状态不变**。
class IEntityStore {
public:
    virtual ~IEntityStore() = default;
    virtual bool save(const std::string& missionId, const json& ledger) = 0;
    virtual bool load(const std::string& missionId, json& out) = 0;
    virtual bool remove(const std::string& missionId) = 0;
    virtual bool supportsList() const { return false; }
    virtual std::vector<std::string> listMissionIds() { return {}; }
};

/// §12.3 时间注入（epoch 毫秒，P5/P9）
class IClock {
public:
    virtual ~IClock() = default;
    virtual int64_t nowMs() const = 0;
};

/// §12.4 可选日志出口（缺省 = 静默；留痕仍写台账 trace[] 与动作日志）
struct AuditEntry {
    int64_t at = 0;
    std::string actor;
    std::string action;
    std::string target;
    std::string detail;
    bool violation = false;
};

class ILogSink {
public:
    virtual ~ILogSink() = default;
    virtual void log(int level, const std::string& event, const json& data) {
        (void)level;
        (void)event;
        (void)data;
    }
    virtual void commandAudit(const AuditEntry& e) { (void)e; }
};

/// §12.5 动作前置条件回调（宿主注册；规则里以 gate id 引用）
///
/// 动作 Gate 入参（**只读**）
struct ActionGateContext {
    const EntityRecord& entity;
    const ActionDef& action;
    const json& params;
    int64_t nowMs = 0;
};

using ActionGateFn = std::function<UnmetItem(const ActionGateContext&)>;

/// §12.6 依赖注入结构（只有四个依赖，**没有业务配置** —— 业务全在规则包）
struct EntityLedgerOptions {
    std::shared_ptr<IEntityStore> store;  // 可空 → 纯内存
    std::shared_ptr<IClock> clock;        // 可空 → SystemClock
    std::shared_ptr<IEntitySink> sink;    // 可空 → 空 Sink
    std::shared_ptr<ILogSink> log;        // 可空 → 静默
};

// ============================================================================
// §13 事件负载（= protocol.md §4 各事件的 `data` 部分；信封由宿主 realtime-hub 侧包）
// ============================================================================

/// = `entity.changed` 的 data：`{entityId, no, missionId, change}`（冻结字段）+ 只增可选字段
struct EntityChangeEvent {
    std::string entityId;
    int no = 0;
    std::string missionId;
    std::string change;  // 规则枚举：动作 key，或机制 token（registered / merged / reclassified / flag-set / track / relation …）
    std::string detail;  // 机制短语（可选）
    int64_t ts = 0;
    json toJson() const;
};

/// = `target.state` 的 data（**既有冻结负载**）：`{targetId, targetNo, threat, confidence,
///   dynamicState, lng, lat, status}` —— 字段逐字保留；`ts` 为允许新增的可选字段（CTR-EV-04）
struct TargetStateEvent {
    std::string targetId;
    int targetNo = 0;
    std::string threat;  // 规则 `bands[].key`
    double confidence = 0.0;
    std::string dynamicState;
    double lng = 0.0;
    double lat = 0.0;
    std::string status;  // 规则 `bands[].state`（红/黄/灰由规则声明）
    int64_t ts = 0;
    json toJson() const;
};

/// = `entity.consistency` 的 data：`{missionId, diffs:[{no, field, views[]}]}` + 只增可选字段
struct ConsistencyEvent {
    std::string missionId;
    std::vector<DiffItem> diffs;
    bool consistent = true;
    int checkedViews = 0;
    std::string phaseKey;
    int64_t ts = 0;
    json toJson() const;
};

// ============================================================================
// §14 自述与观测
// ============================================================================

struct Capabilities {
    bool policiesLoaded = false;
    std::string schemaVersion;
    int policiesMajor = kSupportedPoliciesMajor;
    std::string definitionVersion;
    bool persistent = false;
    bool storeList = false;
    bool clockInjected = false;
    bool sinkInjected = false;
    bool logInjected = false;
    int registeredActionGates = 0;
    int missions = 0;
    int entities = 0;
};

struct Metrics {
    int64_t registrations = 0;
    int64_t merges = 0;
    int64_t updates = 0;
    int64_t splits = 0;
    int64_t duplicatesFlagged = 0;
    int64_t reclassifications = 0;
    int64_t assessments = 0;
    int64_t windowsComputed = 0;
    int64_t actions = 0;
    int64_t actionRejected = 0;
    int64_t actionIdempotent = 0;
    int64_t actionConflicts = 0;
    int64_t trackAppends = 0;
    int64_t trackTruncated = 0;
    int64_t trackDecimated = 0;
    int64_t predictions = 0;
    int64_t retentionDropped = 0;
    int64_t relationsAdded = 0;
    int64_t relationsRejected = 0;
    int64_t cycleRejected = 0;
    int64_t consistencyChecks = 0;
    int64_t consistencyDiffs = 0;
    int64_t gateErrors = 0;
    int64_t sinkErrors = 0;
    int64_t storeErrors = 0;
    int64_t unknownFields = 0;
};

/// 内置系统时钟：**引擎唯一的非确定性来源**（未注入时才使用）
class SystemClock : public IClock {
public:
    int64_t nowMs() const override;
};

// ============================================================================
// §15 引擎（唯一入口）
// ============================================================================

/// 目标与情报台账引擎。构造后不抛异常；未装载规则包时一切需要规则/定义的入口返回 1005。
class EntityLedger {
public:
    EntityLedger();
    explicit EntityLedger(const EntityLedgerOptions& opts);

    ~EntityLedger();
    EntityLedger(const EntityLedger&) = delete;
    EntityLedger& operator=(const EntityLedger&) = delete;
    EntityLedger(EntityLedger&&) noexcept;
    EntityLedger& operator=(EntityLedger&&) noexcept;

    // ---- 规则包装载（P7 / CTR-PL-*） ----

    /// 装载规则包（kind ∈ {entityTypes, threatFactors}，§5.3）。失败时保留上一次成功装载的规则。
    LoadResult loadPolicies(const json& pkg);
    /// 从文件装载（便利方法；读不到/非法 JSON → 1000）
    LoadResult loadPoliciesFile(const std::string& path);
    /// 纯函数：只校验不装载（供 CI / 宿主预检）
    static LoadResult validatePolicies(const json& pkg);
    /// 定义版本与变更检测
    DefinitionInfo definitionInfo() const;
    /// 导出"当前生效规则"（CTR-PL-06，供审计与问题复现）
    json effectivePolicies() const;

    // ---- 规则自述（宿主与界面据此渲染，引擎不造业务取值） ----

    std::vector<std::string> entityTypeKeys() const;
    std::vector<std::string> actionKeys() const;
    std::vector<std::string> viewKeys() const;
    std::optional<EntityType> entityType(const std::string& key) const;
    std::optional<ActionDef> actionDef(const std::string& key) const;
    /// 视图展示名（未命中 → 视图 key，MUST NOT 造文案）
    std::string resolveViewName(const std::string& viewKey) const;
    /// 类型展示名（未命中 → 类型 key，MUST NOT 造文案）
    std::string resolveTypeName(const std::string& typeKey) const;

    // ---- 实体登记（ELG-REG） ----

    RegisterResult registerEntity(const RegisterInput& in);
    std::optional<EntityRecord> getEntity(const std::string& id) const;
    std::optional<EntityRecord> getEntityByNo(const std::string& missionId, int no) const;
    std::vector<EntityRecord> listEntities(const EntityQuery& q = {}) const;
    /// 新观测到达 → 按规则融合置信度与来源（ELG-REG-05；不是简单覆盖）
    RegisterResult updateObservation(const std::string& entityId, const SourceObs& obs);
    /// 人工合并（去重规则判定为"疑似"后由人工确认）
    RegisterResult mergeEntities(const std::string& primaryId, const std::vector<std::string>& otherIds,
                                 const std::string& operatorId);
    /// 人工拆分（ELG-REG-04 / R3：保守去重的补偿手段）
    RegisterResult splitEntity(const std::string& entityId, const std::vector<std::string>& sourceKeys,
                               double lng, double lat, const std::string& operatorId);
    /// 疑似重复候选（保守去重：不自动合并，但可查、可人工确认）
    std::vector<MergeCandidate> duplicateCandidates(const std::string& missionId) const;
    /// 动态状态迁移（ELG-REG-06：合法迁移由规则声明，非法迁移被拒绝并给原因）
    ActionResult setDynamicState(const std::string& entityId, const std::string& toState,
                                 const std::string& reason, const std::string& operatorId);
    /// 注销（软删除：保留历史，`no` MUST NOT 被复用）
    ActionResult retireEntity(const std::string& entityId, const std::string& reason,
                              const std::string& operatorId);

    // ---- 编号与一致性（ELG-ID；本引擎是全仓唯一收口点） ----

    /// 某阶段/某视图**应可见**的实体集合（CTR-EN-06：界面 MUST NOT 自行过滤）
    VisibleSetResult visibleSet(const VisibleSetRequest& req) const;
    /// 一致性检查：逐条差异报告（CTR-EN-08 / ELG-ID-02），可定位到具体 no 与视图
    ConsistencyReport checkConsistency(const ConsistencyRequest& req);
    /// 类型重判：类型变化的**唯一显式路径**，留痕（CTR-EN-07 / ELG-ID-04）
    ActionResult reclassifyType(const ReclassifyInput& in);
    /// 旗标集合（ELG-ID-05：标记数量与去向可查）
    std::vector<EntityRef> flagHolders(const std::string& missionId, const std::string& flagKey) const;
    ActionResult setFlag(const FlagInput& in);
    ActionResult clearFlag(const FlagInput& in);

    // ---- 威胁评级与打击窗口（ELG-RATE） ----

    /// 评级（ELG-RATE-05：输入为显式快照；纯计算，不读全局状态）
    ThreatAssessment assessThreat(const ThreatSnapshot& snapshot) const;
    /// 按台账中的实体评级（内部先取快照再走同一条计算路径；**不写回**台账）
    ThreatAssessment assessEntity(const std::string& entityId) const;
    /// 全量重评并写回台账（威胁分档随观测/状态变化；返回重评实体数）
    int refreshThreats(const std::string& missionId);
    /// 打击窗口（ELG-RATE-06：由轨迹与规则推算的结构化时间区间）
    StrikeWindowResult strikeWindow(const std::string& entityId, const StrikeWindowQuery& q = {}) const;
    /// 任务基准点（距离因子的参照；宿主注入）
    void setMissionReference(const std::string& missionId, double lng, double lat);
    std::optional<std::pair<double, double>> missionReference(const std::string& missionId) const;

    // ---- 优先级与序列（ELG-RANK） ----

    std::vector<RankedEntity> ranking(const RankQuery& q) const;
    ActionResult setPriority(const PriorityInput& in);
    /// 加入打击序列（重复加入幂等）
    SequenceResult addToSequence(const SequenceInput& in);
    SequenceResult removeFromSequence(const SequenceInput& in);
    std::vector<SequenceEntry> sequence(const std::string& missionId) const;
    std::vector<SequenceAuditEntry> sequenceAudit(const std::string& missionId) const;

    // ---- 轨迹服务（ELG-TRK） ----

    TrackAppendResult appendTrack(const TrackInput& in);
    TrackAppendResult appendTrackBatch(const std::string& entityId, const std::vector<TrackPoint>& points);
    /// 区间查询（超限返回截断标记与游标，MUST NOT 静默丢）
    TrackQueryResult queryTrack(const TrackQuery& q) const;
    /// 预测轨迹（显式标记为预测，不与实测混淆）
    TrackQueryResult predictTrack(const PredictQuery& q) const;
    /// 时间轴输出（可被 map-2d 回放接口消费；由宿主适配）
    TrackTimelineResult trackTimeline(const TrackTimelineQuery& q) const;
    TrackStats trackStats(const std::string& entityId) const;
    /// 轨迹保留（过期点清理可配；计数可查）
    RetentionResult applyRetention(const RetentionInput& q = {});

    // ---- 动作状态机（ELG-ACT） ----

    /// 动作（幂等：重复请求 → "已执行"语义；前置条件声明；只产结构化状态变更）
    ActionResult applyAction(const ActionRequest& req);
    /// 撤销（ELG-ACT-06：可撤销性由规则声明）
    ActionResult undoAction(const ActionRequest& req);
    std::vector<ActionLogEntry> actionLog(const ActionLogQuery& q = {}) const;
    /// 注册动作前置条件回调（未注册 → 放行并计入 skippedGates，与 phase-engine 的 Gate 语义一致）
    bool registerActionGate(const std::string& gateId, ActionGateFn fn);
    bool unregisterActionGate(const std::string& gateId);

    // ---- 情报关联（ELG-INTEL） ----

    /// 加有向关系（非 cyclic 种类成环 MUST 被拒并给出路径）
    RelationResult addRelation(const RelationInput& in);
    RelationResult removeRelation(const RelationInput& in);
    std::vector<RelationEdge> relations(const RelationQuery& q) const;
    /// 上下游链路 + 关联目标数（查询 MUST 用已访问集合终止，成环也不死循环）
    ChainResult chain(const ChainQuery& q) const;
    /// 成环检出（全任务扫描）
    std::vector<CyclePath> detectCycles(const std::string& missionId) const;
    RelationStats relationStats(const std::string& missionId) const;

    // ---- 依赖注入 ----

    void setStore(std::shared_ptr<IEntityStore> store);
    void setClock(std::shared_ptr<IClock> clock);
    void setSink(std::shared_ptr<IEntitySink> sink);
    void setLog(std::shared_ptr<ILogSink> log);

    // ---- 自述与观测 ----

    Capabilities capabilities() const;
    Metrics metrics() const;
    /// 码的稳定短名；未知码 → "unknown"
    static const char* errorCodeName(int code);
    /// 台账快照（宿主落库/审计用；`IEntityStore::save` 收到的就是这个形状）
    json ledgerSnapshot(const std::string& missionId) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// §16 自由函数与 JSON 序列化
// ============================================================================

/// 规则包装载校验（纯函数，等价于 EntityLedger::validatePolicies）
LoadResult validatePolicies(const json& pkg);
/// 错误码短名（等价于 EntityLedger::errorCodeName）
const char* errorCodeName(int code);

/// FNV-1a 64 → 16 位小写十六进制（规则包 digest；不依赖加密库）
std::string policiesDigest(const json& pkg);

// JSON 序列化（camelCase；键序与成员声明顺序一致）
json toJson(const EntityRef& v);
json toJson(const PhaseContext& v);
json toJson(const LoadIssue& v);
json toJson(const DefinitionInfo& v);
json toJson(const EntityType& v);
json toJson(const SourceObs& v);
json toJson(const SourceRef& v);
json toJson(const ConfidenceContribution& v);
json toJson(const EntityTrace& v);
json toJson(const EntityLink& v);
json toJson(const EntityRecord& v);
json toJson(const MergeCandidate& v);
json toJson(const VisibleItem& v);
json toJson(const ExcludedItem& v);
json toJson(const DiffItem& v);
json toJson(const PhaseDelta& v);
json toJson(const ReclassifyRecord& v);
json toJson(const FactorScore& v);
json toJson(const WindowSegment& v);
json toJson(const RankedEntity& v);
json toJson(const SequenceEntry& v);
json toJson(const SequenceAuditEntry& v);
json toJson(const TrackPoint& v);
json toJson(const TrackStats& v);
json toJson(const ReplaySample& v);
json toJson(const ReplayTrack& v);
json toJson(const ReplayData& v);
json toJson(const ActionDef& v);
json toJson(const UnmetItem& v);
json toJson(const StateChange& v);
json toJson(const ActionLogEntry& v);
json toJson(const RelationDef& v);
json toJson(const RelationEdge& v);
json toJson(const CyclePath& v);
json toJson(const ChainNode& v);
json toJson(const RelationStatItem& v);
json toJson(const FlagDef& v);
json toJson(const Capabilities& v);
json toJson(const Metrics& v);
json toJson(const EntityChangeEvent& v);
json toJson(const TargetStateEvent& v);
json toJson(const ConsistencyEvent& v);

}  // namespace entity_ledger
