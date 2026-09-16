# tests/ · 零依赖自测（一个可执行 + 手写断言）
#
# 覆盖需求专篇 §7 验收清单 17 行与 §3 的 41 条需求（ELG-REG/ID/RATE/RANK/TRK/ACT/INTEL/NFR）。
# **不需要任何外部服务、不需要网络、不依赖真实时间**（时钟全部由假时钟注入，ELG-NFR-03）。
#
# 运行： selftest            → 跑全部
#        selftest --list     → 只列用例名
#        selftest --json     → 机检输出（acceptance.ps1 读它做需求↔用例对账）
#        selftest <名字片段>  → 只跑名字里含该片段的用例

add_executable(selftest selftest.cc)
target_link_libraries(selftest PRIVATE entity_ledger)

set_target_properties(selftest PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

if(MSVC)
  # /wd4819：源文件是 UTF-8，但 MSVC 在控制台代码页被切到 UTF-8 时会报"当前代码页(0)"——环境噪声
  target_compile_options(selftest PRIVATE /utf-8 /W4 /wd4819)
  target_compile_definitions(selftest PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  target_compile_options(selftest PRIVATE -Wall -Wextra)
endif()

# 规则包与夹具路径由 CMake 以绝对路径注入，**不依赖当前工作目录**（ELG-NFR-04）
target_compile_definitions(selftest PRIVATE
  ENTITY_LEDGER_POLICY_TYPES="${CMAKE_SOURCE_DIR}/policies/mapapp/entityTypes.json"
  ENTITY_LEDGER_POLICY_FACTORS="${CMAKE_SOURCE_DIR}/policies/mapapp/threatFactors.json"
  ENTITY_LEDGER_TEST_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")

add_test(NAME entity_ledger_selftest COMMAND selftest)
