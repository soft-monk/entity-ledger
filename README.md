# entity-ledger · 目标与情报台账引擎

> **目标编号在不同界面不一致且无人收口；威胁评级是读字段加三元判断，不可复算。**
>
> 本仓已实现：**编号一致性收口**（`visibleSet()` + `checkConsistency()`）、**可手算复算的威胁评级**、
> **由轨迹推算的结构化打击窗口**、**只产结构化状态变更的动作状态机**、轨迹服务与情报关联。

---

## 它解决什么问题

目标编号在不同界面不一致且无人收口；威胁评级是读字段加三元判断，不可复算。

**本引擎是需求初稿「待确认问题清单」第 12 项的唯一收口点**：同一场景内"T4-1 五个 / T4-2 六个 /
T7-2 七个"与"高价值 002 vs 003"这类矛盾，由 `checkConsistency()` 输出**逐条差异报告**
（定位到具体 `no` 与具体视图），并由 `visibleSet()` 提供"某阶段应可见的目标集合"——
**界面 MUST NOT 自行过滤**（自行过滤正是数量不一致的根因）。

## 做 / 不做

| 做 | 不做 |
|---|---|
| 实体登记、多源去重（默认保守）与置信度融合 | 不内建实体类型名（类型集在规则包） |
| 编号规则与跨视图一致性检查、阶段可见集合 | 不做打击方案与成功率（`scoring`） |
| 威胁评级引擎（因子/权重/阈值注入，逐项可复算） | 不做地理符号与配色（`view-composer` / `map-2d`） |
| 优先级排序与打击序列（含审计） | 不做自然语言分析文案（`llm-provider`） |
| 轨迹写入 / 区间查询 / 抽稀标注 / 时间轴 / 预测标注 / 保留 | 不做回放播放控件（`map-2d` `ReplayBar`） |
| 动作状态机（幂等 / 前置条件 / 撤销 / 事件日志）与情报关联链 | 不做告警产生（`alert-engine`；本引擎只发变更事件） |

## 快速开始

```powershell
# 构建（仅需 CMake ≥ 3.20 与 C++17 编译器；nlohmann/json 已内置单头回落）
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release

# 零依赖自测（用例/断言逐条打印）
build\bin\Release\selftest.exe

# 示例：一致性收口演示（五个 / 六个 / 七个 + 002 vs 003 的差异报告）
build\bin\Release\example_consistency.exe

# 独立验收（需求专篇 §7 逐条 + 需求↔用例对账 + 结构纪律；退出码 0/1）
powershell -ExecutionPolicy Bypass -File scripts\acceptance.ps1
```

```cpp
#include <entity_ledger/entity_ledger.h>
using namespace entity_ledger;

EntityLedger ledger;                                   // 全空依赖 = 纯内存（可注入 store/sink/clock）
ledger.loadPoliciesFile("policies/mapapp/entityTypes.json");
ledger.loadPoliciesFile("policies/mapapp/threatFactors.json");

// 登记（类型/编号/去重/置信度口径全部来自规则包）
RegisterInput in; in.missionId = "m-1"; in.typeKey = "cmdNode";
in.lng = 118.35; in.lat = 24.72; in.obsKey = "obs-1";
const RegisterResult reg = ledger.registerEntity(in);

// 评级：逐因子得分 + 总分（Σ贡献 == 总分，可手算）
const ThreatAssessment ta = ledger.assessEntity(reg.data.id);

// 可见集合（界面直接渲染，无需自行过滤）
VisibleSetRequest vs; vs.missionId = "m-1"; vs.viewKey = "situation";
const VisibleSetResult set = ledger.visibleSet(vs);

// 一致性检查：逐条差异报告，定位到具体编号与视图
ConsistencyRequest creq; creq.missionId = "m-1"; creq.views = screenSnapshots;
const ConsistencyReport rep = ledger.checkConsistency(creq);
```

## 依赖与出口

- 仅依赖 `nlohmann/json`（`third_party/nlohmann/json.hpp` 内置单头回落）；无 Web 框架、无 SQL、不 import 其它模块。
- 出口全部为注入的反向接口：`IEntityStore` / `IEntitySink` / `IClock`（MUST 注入）+ `ILogSink`（可选）；
  未注入时引擎仍可工作（纯内存）。
- 业务取值（类型名、动作名、旗标名、分档阈值与状态色、视图与阶段过滤、编号起始值、轨迹参数、
  暴露规律）一律住在 `policies/mapapp/`。

## 文档

| 文档 | 内容 |
|---|---|
| [`docs/需求/entity-ledger需求专篇.md`](docs/需求/entity-ledger需求专篇.md) | 需求专篇（唯一权威）：41 条需求、验收标准、边界、决策记录、风险、验收清单 |
| [`docs/契约/entity-ledger契约.md`](docs/契约/entity-ledger契约.md) | 本模块契约：公开面、规则包形状、事件、可机检清单、开放问题 |
| [`docs/实现报告.md`](docs/实现报告.md) | 实现报告：文件清单、需求→落点对照、一致性收口的实际演示输出、需人类裁决的开放问题 |
| [业务引擎需求专篇 · 汇总索引](https://github.com/soft-monk/phase-engine/blob/main/docs/需求/业务引擎需求专篇_汇总索引.md) | 十个业务引擎的索引、共性口径、跨模块冲突与建仓顺序 |

## 状态

- 需求：已冻结（见上表）
- 契约（接口）：v0.1（随实现冻结）
- 设计（拆仓与迁移）：不适用（独立仓）
- 实现：**已完成**（构建成功；`selftest` 用例 48 个 / 断言 1028 条全绿；`scripts/acceptance.ps1` 检查 47 项全通过）

## 定位

这是一个**业务引擎**，与其它模块**互不 import**，只通过注入的反向接口与宿主装配。与业务相关的内容（阶段名、型号、权重、文案、阈值）一律通过规则包注入，不写进本仓代码。

## 许可

Apache License 2.0，见 [LICENSE](LICENSE)。
