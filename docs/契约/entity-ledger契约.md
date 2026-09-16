# entity-ledger · 目标与情报台账引擎契约（v0.1）

| 项 | 内容 |
|---|---|
| 文档编号 | `CTR-ELG-001` |
| 版本 | **v0.1（首版，随实现冻结）** |
| 适用范围 | `entity-ledger`：**后端 C++17 库**（无 Web 框架、无 SQL、不 import 任何其它模块内部） |
| 需求依据 | [`../需求/entity-ledger需求专篇.md`](../需求/entity-ledger需求专篇.md)（`ELG-REG/ID/RATE/RANK/TRK/ACT/INTEL/NFR`，共 **41** 条） |
| 上游共享契约 | [`protocol.md`](../../../phase-engine/docs/契约/protocol.md)（v1.0 冻结：P1–P10、§1 `PhaseDef`/`PhaseContext`、§2 实体标识、§3 错误码、§4 事件名、§5 规则包、§6 反向接口） |
| 冲突裁决 | [`冲突裁决.md`](../../../phase-engine/docs/契约/冲突裁决.md)（**C15** 废弃 `1001`、**C16** 收窄 `1002`） |
| 唯一公开头 | `#include <entity_ledger/entity_ledger.h>` |
| 命名空间 | `entity_ledger` |
| 状态 | 首版（已实现）。破坏性变更 MUST 走 protocol.md §9 的修订流程 |

---

## 0. 这份契约解决什么

entity-ledger 回答四个问题：**这个实体是什么 / 有多危险 / 排第几 / 去过哪**。
它不回答"打不打"（`scoring` 出方案与成功率），也不回答"画成什么符号"（`view-composer` + `map-2d`）。

它同时是**需求初稿「待确认问题清单」第 12 项**（同一场景内目标编号与类型在不同界面不一致）的**唯一收口点**：
"T4-1 五个 / T4-2 六个 / T7-2 七个"与"高价值 002 vs 003"这两处矛盾，本引擎用
`visibleSet()` + `checkConsistency()` 两条接口把它从"约定"变成"可机检的差异报告"。

| 本引擎负责 | 不负责（归谁） |
|---|---|
| 实体登记、多源去重（**默认保守**）、置信度融合 | 实体类型名（规则包 `kind: entityTypes`） |
| 编号生成与**跨视图一致性检查**、阶段可见集合 | 界面渲染与过滤（界面 MUST 消费 `visibleSet()`） |
| 威胁评级（因子/权重/阈值全部注入，**可手算复算**） | 打击方案与成功率（`scoring`） |
| 优先级与打击序列（含审计） | 告警产生（`alert-engine`；本引擎只发变更事件） |
| 轨迹：写入 / 区间查询 / 抽稀标注 / 时间轴 / 预测标注 / 保留 | 回放播放控件（`map-2d` `ReplayBar`） |
| 动作状态机（幂等 / 前置条件 / 撤销 / 事件日志） | 动作**文案**（`llm-provider` / 规则包） |
| 情报关联链（有向关系、成环检出、已确认/疑似两态） | 自然语言研判（`llm-provider`） |

### 0.1 三条不可协商的口径

1. **引擎不认识任何业务取值。** 类型名、动作名、旗标名、分档阈值与状态色、视图名、阶段 key、
   编号起始值、抽稀与预测参数、暴露规律 —— 全部住在 `policies/mapapp/`。
   判据：引擎源码（`include/` + `src/` + `examples/`）内**字符串字面量零 CJK、业务词零命中**。
2. **引擎不落库、不广播、不取系统时间。** 出口为 `IEntityStore` / `IEntitySink` / `IClock`（MUST 注入）
   与 `ILogSink`（可选）；**全空依赖时引擎仍 MUST 可工作**（纯内存）。
3. **失败 MUST NOT 抛异常跨边界**（P10）。一切裁决走 `{code, message, data}` 信封，`code` 逐值对齐
   protocol.md §3.2（`0/1000/1002/1003/1004/1005/1006`；`1001` 保留不用）。

---

## 1. 公开入口

| 项 | 取值 |
|---|---|
| 语言 / 标准 | C++17 |
| 构建 | CMake ≥ 3.20；目标名 `entity_ledger`（静态库）+ `example_minimal` + `example_consistency` + `selftest` |
| 依赖 | 仅 `nlohmann/json`（内置 `third_party/nlohmann/json.hpp` 单头回落） |
| 对外字段命名 | camelCase（P4）；JSON 键序 = 结构体成员声明顺序（`ordered_json`） |
| 时间戳 | epoch 毫秒 `int64_t`（P5） |
| 引擎产出的 JSON | 事件的 `data` 部分与 `ts`；**WS 信封由宿主包**（`realtime-hub`） |

---

## 2. `PhaseContext` 的消费方式（镜像形状，不跨仓 import）

`protocol.md` §1.4 冻结的五字段由本引擎**镜像声明**（同名字段、同类型、同语义）：

```
entity_ledger::PhaseContext = { phaseKey, seq, scenarioKey, enteredAt, missionId }
```

- **为什么镜像而不 import**：P1 要求引擎之间 MUST NOT 互相 import；跨引擎只经**宿主**转交
  （宿主调用 `phase.phaseContext(missionId)` 后把值交给本引擎）。
- **约束**：本引擎一切"当前阶段"入参 MUST 用 `PhaseContext`，MUST NOT 用裸阶段名字符串。
- **引擎不认识阶段取值**：视图的逐阶段过滤规则写在规则包里（`views[].phaseFilters[].phases`），
  引擎只做字符串匹配，MUST NOT 校验"阶段 key 是否为 T0…T7"。

---

## 3. 实体标识（protocol.md §2 的落地）

| 约束 | 本引擎的落点 |
|---|---|
| CTR-EN-01 跨引擎引用只带 `id` | 一切入参用 `id` 字符串（`entityId`）；事件负载的 `targetId` / `entityId` |
| CTR-EN-02 展示处带 `{id, no}` | `EntityRef{id,no}`；`VisibleItem` / `RankedEntity` 同时给 `id` 与 `no` |
| CTR-EN-03 编号规则属规则包 | `numbering{start, contiguous, reuse}`；引擎不内建起始值 |
| CTR-EN-04 重复 `no` 被拒 | 同一任务内重复登记 → `1000` + 可读原因（`duplicate no in mission`） |
| CTR-EN-05 `id↔no↔类型` 全阶段全视图强一致 | `checkConsistency()` 的 `presence` / `no` / `type` 三类差异项 |
| CTR-EN-06 可见集合由本引擎提供 | `visibleSet()`；界面 MUST NOT 自行过滤 |
| CTR-EN-07 类型重判走显式动作并留痕 | `reclassifyType()` 是唯一路径，写 `trace[]`；无留痕的变化被检出 |
| CTR-EN-08 逐条差异报告 | `ConsistencyReport.diffs[]`，每项含 `{no, field, views[]}` + 机制 token `kind` |
| §2.3 引用不存在实体 | 单查 → 结构化"未找到"（`1004` / `nullopt`）；批量 → 部分成功并逐条标注 |

`id` 生成是**确定性**的（`ent-<missionDigest8>-<6 位序号>`），冲突时递增；注销后 `no` 与 `id` 均不复用
（`numbering.reuse=false` 时）。

---

## 4. 规则包（`policies/mapapp/`）

骨架遵循 protocol.md §5.1（`policiesNamespace` / `schemaVersion` / `kind` / `items`），
`kind` 只用 §5.3 已冻结、归属本引擎的两个取值：**`entityTypes`** 与 **`threatFactors`**。

| 文件 | `kind` | 顶层段 |
|---|---|---|
| `entityTypes.json` | `entityTypes` | `items`（类型：`{key,name,baseThreat,attributes}`）、`numbering`、`geometry`、`reference`、`dynamicStates`、`dedup`、`confidence`、`flags`、`views`、`actions`、`relations` |
| `threatFactors.json` | `threatFactors` | `items`（因子：`{key,name,source,weight,normalize,direction,missing}`）、`bands`、`strikeWindow`、`rank`、`trajectory` |

**为什么用"顶层兄弟段"**：§5.3 只给了本引擎两个 `kind`，而规则内容多于两个 `kind` 能承载的范围。
兄弟段是 §5.5 自身已有的惯例（`threatFactors` 的 `bands`、`entityTypes` 的 `numbering`、
`linkThresholds` 的 `states`/`hysteresis`），phase-engine 的 `phases.json` 亦同（其 `D-PHE-01`）。
**已登记为开放问题**（见实现报告）：建议 protocol 下一版为"动作集/视图/轨迹/关系"登记新 `kind`。

装载语义：

| 编号 | 约束 |
|---|---|
| `TR-ELG-PL-01` | 校验覆盖 §5.1 骨架、逐条目必填字段、枚举取值、**引用完整性**（视图引用的类型/旗标、动作引用的旗标/状态/动作、`$…` 守卫参数），失败 MUST 拒绝**整包**并逐条给出 `{path, field, reason}`（`path` 形如 `items[1].baseThreat`、`views[0].phaseFilters[1].minConfidence`） |
| `TR-ELG-PL-02` | 未知字段/未知段 MUST 忽略并计入 `definitionInfo().warnings` 与 `metrics().unknownFields`（CTR-PL-03） |
| `TR-ELG-PL-03` | 缺失可选字段回落**引擎内置缺省**并在本文档写明（CTR-PL-04）：`bands[].state` → 回落 `band.key`；`dynamicStates.default` → 首个状态；`confidence.defaultSource` → 首个来源；`rank.keys` → `[priority asc, threatScore desc, no asc]`；`rank.defaultPriority` → 9；`relations.default` → 首个状态；`trajectory.timeline.stepMs` → 0（不下采样） |
| `TR-ELG-PL-04` | `MAJOR` 与引擎支持值（1）不符 → 拒绝 + `1006`，MUST NOT 静默降级（§5.2） |
| `TR-ELG-PL-05` | **原子替换**：装载失败 MUST 保留上一次成功装载的规则 |
| `TR-ELG-PL-06` | 可多次装载（先类型包后因子包）；同 `kind` 的 `items` **整体替换**；合并后做一次整体语义校验 |
| `TR-ELG-PL-07` | `effectivePolicies()` 导出当前生效规则；`definitionVersion = <ns>:<schemaVersion>:<digest>`，`digest` = FNV-1a 64（16 位小写十六进制，不依赖加密库） |

---

## 5. 公开接口（按域）

> 全部声明在 `include/entity_ledger/entity_ledger.h`；下列"落点"列即需求条目的实现位置。

### 5.1 实体登记（ELG-REG）

| 接口 | 签名要点 | 落点 |
|---|---|---|
| `registerEntity` | `RegisterResult(const RegisterInput&)`：按规则去重 → 新建或合并；`status ∈ {created, merged, updated}` | REG-01..05 |
| `updateObservation` / `mergeEntities` / `splitEntity` | 新观测融合 / 人工合并 / 人工拆分（保守去重的补偿） | REG-04/05 |
| `duplicateCandidates` | 疑似重复候选（**不自动合并**，可查可人工确认） | REG-04、R3 |
| `setDynamicState` | 规则声明的迁移表裁决；未声明 → `1003` + `$transition` | REG-06 |
| `retireEntity` | 软删除：历史保留，`no`/`id` 不复用 | §2.3 |

**去重口径（默认保守）**：`dedup.keys`（`obsKey` / `typeKey` / `space` / `dynamicState`）**全部命中**才合并；
只命中一部分 → **不合并**，但在 `candidates[]` 逐条标注（宁可标多源不合并）。
`mode=aggressive` 才按"任一命中"合并；`mode=off` 从不合并。

### 5.2 编号与一致性（ELG-ID；收口点）

| 接口 | 语义 |
|---|---|
| `visibleSet({missionId, viewKey, phase?, scenarioKey, includeExcluded})` | **某阶段应可见的实体集合**。过滤口径来自规则 `views[].phaseFilters`（首个命中生效）；`excludedItems[]` 给出每条的排除原因（`retired` / `phase` / `type` / `confidence` / `flag-required` / `flag-excluded`）。同一输入两次调用**逐字节一致**；`basis="current-state"` 如实标注"按当前台账状态投影" |
| `checkConsistency({missionId, views[], phase?, viewKey?})` | 逐条差异报告：`diffs[{no, field, views[], kind, id, expected, actual, phaseKey, reason}]` + `phaseDeltas[]`（跨阶段集合变化，可解释）+ `reclassifications[]`（类型重判留痕）+ `expectedVisible[]`（引擎给出的应可见集合） |
| `reclassifyType` | 类型变化的**唯一显式路径**：`reason` 必填（否则 `1000`）、写 `trace[]`、发 `entity.changed{change:"reclassified"}` |
| `setFlag` / `clearFlag` / `flagHolders` | 旗标（规则声明，如"高价值"）：`unique=true` 时同任务至多一个持有者（越界 `1003` + `$flag-unique`），`transfer=true` 才可显式转移；持有者数量与去向可查 |

**差异种类（`field` / `kind`，机制 token）**

| `field` | `kind` | 含义 |
|---|---|---|
| `presence` | `missing` / `extra(unknown)` / `duplicate` | 同一 `no` 在某视图缺席而在另一视图在场（"五个 vs 七个"）；视图引用了台账没有的实体；同一视图内重复 |
| `no` | `mismatch` / `missing` | 同一 `id` 在两处编号不同；视图条目未带 `id`（违反 CTR-EN-02） |
| `type` | `mismatch` / `stale` / `unknown` | 与台账不一致且**无重判留痕**；渲染的是已被显式重判取代的旧类型（留痕见 `reclassifications[]`）；类型不在规则内 |
| `flag:<key>` | `missing` / `extra` | 旗标持有者在视图间不一致（"002 vs 003"） |

`views[]` MUST 给出**两个**展示名（缺席方 + 对侧一致方），使报告可直接定位到界面。

### 5.3 威胁评级与打击窗口（ELG-RATE）

| 接口 | 语义 |
|---|---|
| `assessThreat(ThreatSnapshot)` | **纯计算**：输入为显式快照（不读全局状态、不读数据库）；输出逐因子 `{key, source, weightPpm, normPpm, contribution, missing, missingPolicy, rawNumber, rawText}` + `score` + `band` + `status` |
| `assessEntity(id)` | 按台账记录取快照后走同一条计算路径（不写回） |
| `refreshThreats(missionId)` | 全量重评并写回台账（威胁分档随观测/状态变化） |
| `strikeWindow(id, {nowMs?, horizonOverrideMs?})` | **结构化时间区间**：`{found, fromMs, toMs, durationMs, leadMs, basis, horizonMs, stepMs, trackPoints, extrapolated, segments[]}`；由**轨迹外推 + 规则暴露规律**推算，MUST NOT 是硬编码字符串 |
| `setMissionReference` / `missionReference` | 距离因子的参照点（宿主注入；规则亦可声明缺省 `reference`） |

**复算口径（写死，供手算核对）**

```
contribution_i = round_half_up( normPpm_i * weightPpm_i * 100 / (totalWeightPpm * 1e6) )
score          = Σ contribution_i                    （**逐项贡献求和**）
```

- 归一化前输入先量化为整数（`percent` → ppm；`distance` → 整米；`table` → 规则给定的 ppm 值），
  因此"按导出项手算 == 引擎值"，不存在浮点噪声。
- `normalize.type`：`percent` / `identity`（0..1 直取）、`range`（`[min,max]` 线性，`direction=lower` 取反）、
  `table`（按 `state` / `attribute` 取值查表）。
- `source`（机制 token）：`typeBase` / `distance` / `state` / `confidence` / `sourceCount` / `attribute`。
- `missing`：`zero`（缺省，贡献 0）/ `skip`（剔除且权重重归一）/ `reject`（评级整体拒绝，`rejected=true` + `rejectReason`）。
- **分档由阈值决定**：`bands[{key,min,state}]` 按 `min` 降序取首个 `score >= min`；装载时 MUST 至少有一个 `min <= 0`。
- 距离用 **haversine**（地球半径由规则注入）；窗口段边界量化到规则 `stepMs` 网格（确定性）。

### 5.4 优先级与打击序列（ELG-RANK）

| 接口 | 语义 |
|---|---|
| `ranking({missionId, viewKey?, limit?})` | 逐键比较（键序与方向由规则声明，末位键恒为 `no`）；`sortKeys[]` 回写逐键取值；`viewKey` 非空时只排该视图可见集合 |
| `setPriority` | 显式设置优先级（幂等：同值重复 → `already-done`） |
| `addToSequence` / `removeFromSequence` / `sequence` | 加入/移出（重复 → 幂等）、序列内唯一、移出后序号键重新连续；超限 → `1003` + `$sequence-limit` |
| `sequenceAudit` | 谁在何时把谁加入/移出（可复原），并经 `ILogSink::commandAudit` 放大 |

### 5.5 轨迹服务（ELG-TRK）

| 接口 | 语义 |
|---|---|
| `appendTrack` / `appendTrackBatch` | 按 `ts` **有序插入**（乱序写入后查询仍有序）；同 `ts` 覆盖（`replaced`）；软上限 `trajectory.maxPointsPerEntity` 裁最旧并计数 |
| `queryTrack` | `[from,to)`；`truncated` + `nextCursor`（**不静默丢**）；`decimated` + `decimatedFrom` + 生效参数（**抽稀如实标注**） |
| `predictTrack` | 规则外推若干点：`predicted=true` + `basis="extrapolation"`，**不入库**（实测查询里一个都没有） |
| `trackTimeline` | `points[]`（含显式 `predicted`）+ **`replay` 子结构逐字段对齐 map-2d `ReplayData`**：`{id?, tracks:[{id,label?,kind?,color?,samples:[{t,lng,lat,heading?,speed?,props?}]}]}`，`t` 为 epoch 毫秒、`samples` 升序；`props.predicted/interpolated` 承载标记（map-2d 回放输入无对应槽位，已在实现报告登记） |
| `trackStats` / `applyRetention` | 清理计数可查（`droppedByRetention` / `droppedByCap` / `replacedSamples`） |

### 5.6 动作状态机（ELG-ACT）

| 接口 | 语义 |
|---|---|
| `applyAction` | 裁决顺序：入参 → 规则已装载 → 动作在规则内（未声明 → `1004`）→ 实体互斥闸门（`try_lock`，拿不到 → `1002` + `conflict=true`）→ 幂等（已执行 → **`code=0`** + `idempotent=true` + `status="already-done"`）→ 前置条件（**全部**求值，不短路）→ 结构化状态变更 → **写前提交** → 事件与审计 |
| `undoAction` | 可撤销性由规则声明（不可撤销 → `1003` + `$irreversible`）；`undoWithinMs` 窗口外 → `1003` + `$undo-window`；未执行过 → 幂等 no-op |
| `actionLog` | 事件日志（对齐现状 `target.strike` / `target.upgrade` 的落日志要求）：含 `changes[]`，可按任务/实体/动作筛选 |
| `registerActionGate` / `unregisterActionGate` | 宿主前置条件回调（id `^[a-z][a-z0-9-]{0,63}$`，不得以 `$` 开头）；**未注册 → 放行并计入 `skippedGates[]`**（与 phase-engine 的 Gate fail-open 同口径） |

**动作产出**：只有 `StateChange{field, from, to}[]`（字段与前后值）与 `unmet[{gate, reason, detail}]`；
**MUST NOT 产出自然语言文案**（ELG-ACT-03）。事件为 `entity.changed`（`change` = 规则动作 key）
与 `target.state`（既有冻结八字段 + `ts`）。

**内建守卫（引擎机制，`$` 前缀）**：`$in-sequence` / `$flag:<key>` / `$state:<key>` /
`$action:<key>` / `$not-action:<key>` / `$confidence-min:<0..1>` / `$reversible` /
`$retired` / `$transition` / `$flag-unique` / `$sequence-limit` / `$undo-window` / `$irreversible` / `$manual-split`。

> ⚠ **幂等与冲突的表达方式以 protocol.md §3.3 + ADR-C15/C16 为准**，与需求专篇 ELG-ACT-02 的字面表述
> 存在冲突，已在实现报告"开放问题"逐条登记（结论：幂等成功 `code=0`；`1002` 只用于互斥冲突）。

### 5.7 情报关联（ELG-INTEL）

| 接口 | 语义 |
|---|---|
| `addRelation` / `removeRelation` / `relations` | 有向关系增删查（幂等）；引用不存在的实体 → `1004`；**非 `cyclic` 种类成环 → `1003` + `$acyclic` + 成环路径** |
| `chain` | 上下游链路（深度上限 + 已访问集合，**成环也不会死循环**）+ **关联目标数**（去重计数） |
| `detectCycles` | 全任务成环检出（含 `cyclic=true` 种类），供审计与演示 |
| `relationStats` | 按种类/两态统计、孤立实体数（第三屏统计项口径） |

---

## 6. 反向接口（宿主 MUST 实现）

```cpp
class IEntitySink {   // 三个方法 MUST 立即返回，MUST NOT 阻塞
  virtual void onEntityChanged(const EntityChangeEvent&) = 0;   // → entity.changed
  virtual void onTargetState(const TargetStateEvent&)   = 0;   // → target.state
  virtual void onConsistency(const ConsistencyEvent&)   = 0;   // → entity.consistency
};
class IEntityStore {  // 写前提交：save() 返回 true 前 MUST 已持久化；失败 → 1005 + 内存不变
  virtual bool save(const std::string& missionId, const json& ledger) = 0;
  virtual bool load(const std::string& missionId, json& out) = 0;
  virtual bool remove(const std::string& missionId) = 0;
  virtual bool supportsList() const;
  virtual std::vector<std::string> listMissionIds();
};
class IClock { virtual int64_t nowMs() const = 0; };            // epoch ms；一次状态变更恰好一次
class ILogSink { virtual void log(int, const std::string&, const json&); virtual void commandAudit(const AuditEntry&); };
```

`EntityLedgerOptions{store, clock, sink, log}` 四个可空 `shared_ptr`；
全空 = 纯内存 + 系统时钟 + 空 Sink + 静默。`ledgerSnapshot(missionId)` 是 `store->save` 收到的形状（可往返）。

---

## 7. 事件（复用 protocol.md §4，不新增事件名）

| 事件名 | 本引擎的产出点 | 负载 |
|---|---|---|
| `entity.changed` | 登记 / 观测融合 / 状态迁移 / 旗标 / 重判 / 轨迹 / 关系 / 优先 / 序列 / 注销 | `{entityId, no, missionId, change}` + 可选 `detail`、`ts` |
| `target.state` | 登记 / 观测更新 / 动作 / 状态迁移 / 重判 / 全量重评 | 既有冻结八字段 `{targetId, targetNo, threat, confidence, dynamicState, lng, lat, status}` + `ts` |
| `entity.consistency` | 每次 `checkConsistency()` | `{missionId, diffs:[{no, field, views[]}], consistent, checkedViews, phaseKey?, ts}` |

约束：幂等命中 MUST NOT 重发状态事件；一次状态变更的 `ts` 同源（结果 / 事件 / 台账一致）。

---

## 8. 可机检清单（本契约的验收）

| # | 断言 | 方式 |
|---|---|---|
| 1 | 引擎产物内业务词（类型名 / 动作名 / 旗标名 / 语义文案）零命中 | `scripts/acceptance.ps1` C09/C09b/C14 |
| 2 | 引擎产物与示例的字符串字面量内**零 CJK 文案**（注释豁免） | C11 |
| 3 | 硬编码窗口字符串零命中，窗口为规则参数驱动的结构化区间 | C10/C10b + `rate06` |
| 4 | 跨仓 import 与 Web/SQL 依赖零命中；唯一公开头 | C12/C13/C21 |
| 5 | 规则包骨架 + `kind` + `MAJOR`；装载失败逐条原因且原子替换 | C16 + `ctr_pl_*` |
| 6 | 41 条需求逐条有用例引用且至少一条通过 | C06/C07/C08 |
| 7 | §7 验收清单 17 行逐条 | S07-01..S07-17 |
| 8 | 幂等命中 = `code=0` + `idempotent`；互斥 = `1002` + `conflict` | `act02` |
| 9 | 实体引用带 `id`；展示处带 `{id,no}` | `ctr_en_*` |
| 10 | 确定性：同输入 + 同假时钟 → 逐字节一致 | `nfr03` |

---

## 9. 开放问题（不阻塞本波，详见 `docs/实现报告.md`）

1. **ELG-ACT-02 与 protocol.md §3.3 / ADR-C15 的冲突**：需求专篇要求"重复 `upgrade` 返回 `code=1002`"，
   冻结契约要求"幂等成功 MUST `code=0` + `idempotent=true`"。本实现按冻结契约执行，"已执行"语义由
   `status="already-done"` 承载，`1002` 只表达互斥冲突。**需人类裁决**（改需求口径或改契约）。
2. **protocol.md §5.3 的 `kind` 覆盖不足**：本引擎的规则内容多于 `entityTypes` + `threatFactors` 两个
   `kind`。当前用顶层兄弟段承载（有 §5.5 与 `D-PHE-01` 先例），建议下一版登记新 `kind`。
3. **回放输入无 `predicted` 槽位**：map-2d `ReplaySample` 只有 `t/lng/lat/heading/speed/props`，
   预测点标记只能借 `props` 传递（且 `props` 到不了地图图元，只在 `ReplayState`/回调可见）。
4. **需求专篇 §0 的"共 28 条"** 与 §8 的 41 条不一致（专篇内部过期数字，本实现以 41 条为准）。
5. **毁伤状态（红→黄→灰）判定口径**、**多源去重权威规则**、**打击窗口计算依据** 仍是专篇 §9 的待确认项；
   本实现只提供机制与规则参数位，具体取值待产品给定。
