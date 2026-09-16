# examples/ · 可跑示例（各自独立可执行 + 独立退出码）
#
# 与 tests/ 一样，示例都需要一份**外部注入的规则包**（P7）：
# 文件路径由 CMake 以绝对路径注入，**不依赖当前工作目录**（ELG-NFR-04）。

add_executable(example_minimal minimal/main.cc)
target_link_libraries(example_minimal PRIVATE entity_ledger)

add_executable(example_consistency full_flow/main.cc)
target_link_libraries(example_consistency PRIVATE entity_ledger)

foreach(tgt example_minimal example_consistency)
  set_target_properties(${tgt} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
  if(MSVC)
    target_compile_options(${tgt} PRIVATE /utf-8 /W4 /wd4819)
    target_compile_definitions(${tgt} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
  else()
    target_compile_options(${tgt} PRIVATE -Wall -Wextra)
  endif()
endforeach()

# 规则包位置：默认用仓库内的策略目录，可由调用方用命令行参数覆盖
set(ENTITY_LEDGER_POLICY_TYPES "${CMAKE_SOURCE_DIR}/policies/mapapp/entityTypes.json")
set(ENTITY_LEDGER_POLICY_FACTORS "${CMAKE_SOURCE_DIR}/policies/mapapp/threatFactors.json")

target_compile_definitions(example_minimal PRIVATE
  ENTITY_LEDGER_POLICY_TYPES="${ENTITY_LEDGER_POLICY_TYPES}"
  ENTITY_LEDGER_POLICY_FACTORS="${ENTITY_LEDGER_POLICY_FACTORS}")
target_compile_definitions(example_consistency PRIVATE
  ENTITY_LEDGER_POLICY_TYPES="${ENTITY_LEDGER_POLICY_TYPES}"
  ENTITY_LEDGER_POLICY_FACTORS="${ENTITY_LEDGER_POLICY_FACTORS}")
