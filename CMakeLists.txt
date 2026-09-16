# entity-ledger · 目标与情报台账引擎（独立构建）
#
# 需求依据：docs/需求/entity-ledger需求专篇.md（41 条）
#   ELG-NFR-01 零外部依赖 / ELG-NFR-04 独立交付（一条命令构建 → 一条命令验收）
# 上游契约：../phase-engine/docs/契约/protocol.md v1.0（P1–P10、§5 规则包 schema）
#
# 目标：
#   entity_ledger   静态库（宿主唯一依赖）
#   example_*       examples/ 下的示例
#   selftest        tests/ 下的零依赖自测（注册为 ctest 用例）
#
# 依赖：仅 nlohmann/json（优先系统包，找不到时回落内置单头 third_party/nlohmann/json.hpp）。
# 本模块**永远不需要** Web 框架 / SQL / 其它引擎（P1/P2/P3）。
cmake_minimum_required(VERSION 3.20)
project(entity_ledger
  VERSION 0.1.0
  DESCRIPTION "目标与情报台账引擎：实体登记 / 编号与一致性 / 威胁评级 / 优先级与序列 / 轨迹 / 动作状态机 / 情报关联"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "构建类型" FORCE)
endif()

# ---------------------------------------------------------------- 选项
option(ENTITY_LEDGER_BUILD_TESTS    "编译 tests/（零依赖自测）" ON)
option(ENTITY_LEDGER_BUILD_EXAMPLES "编译 examples/（最小示例、全流程演示）" ON)
option(ENTITY_LEDGER_WARNINGS_AS_ERRORS "把编译告警当错误" OFF)

# ---------------------------------------------------------------- 依赖
find_package(nlohmann_json CONFIG QUIET)
if(nlohmann_json_FOUND)
  set(ENTITY_LEDGER_JSON_TARGET nlohmann_json::nlohmann_json)
  message(STATUS "[entity-ledger] nlohmann/json: 使用已安装的包")
else()
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann/json.hpp")
    message(FATAL_ERROR
      "[entity-ledger] 未找到 nlohmann/json：既没有安装包，也没有内置副本 "
      "third_party/nlohmann/json.hpp。请安装 nlohmann-json 或放入内置副本。")
  endif()
  add_library(entity_ledger_nlohmann INTERFACE)
  target_include_directories(entity_ledger_nlohmann INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party")
  set(ENTITY_LEDGER_JSON_TARGET entity_ledger_nlohmann)
  message(STATUS "[entity-ledger] nlohmann/json: 使用内置单头副本 third_party/nlohmann/json.hpp")
endif()

find_package(Threads REQUIRED)

# ---------------------------------------------------------------- 库
file(GLOB_RECURSE ENTITY_LEDGER_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cc")

add_library(entity_ledger STATIC ${ENTITY_LEDGER_SOURCES})
add_library(entity_ledger::entity_ledger ALIAS entity_ledger)

target_include_directories(entity_ledger
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:include>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_link_libraries(entity_ledger
  PUBLIC  ${ENTITY_LEDGER_JSON_TARGET}
  PRIVATE Threads::Threads)

target_compile_definitions(entity_ledger PUBLIC
  ENTITY_LEDGER_VERSION="${PROJECT_VERSION}")

if(MSVC)
  target_compile_options(entity_ledger PRIVATE /utf-8 /W4 /permissive-)
  target_compile_definitions(entity_ledger PRIVATE
    NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00
    _CRT_SECURE_NO_WARNINGS)
  if(ENTITY_LEDGER_WARNINGS_AS_ERRORS)
    target_compile_options(entity_ledger PRIVATE /WX)
  endif()
else()
  target_compile_options(entity_ledger PRIVATE -Wall -Wextra)
  if(ENTITY_LEDGER_WARNINGS_AS_ERRORS)
    target_compile_options(entity_ledger PRIVATE -Werror)
  endif()
endif()

set_target_properties(entity_ledger PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# ---------------------------------------------------------------- 示例 / 测试
if(ENTITY_LEDGER_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(ENTITY_LEDGER_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# ---------------------------------------------------------------- 汇总
message(STATUS "[entity-ledger] ${PROJECT_NAME} ${PROJECT_VERSION} · C++${CMAKE_CXX_STANDARD}")
message(STATUS "[entity-ledger]   构建类型 : ${CMAKE_BUILD_TYPE}")
message(STATUS "[entity-ledger]   examples/tests : "
               "${ENTITY_LEDGER_BUILD_EXAMPLES}/${ENTITY_LEDGER_BUILD_TESTS}")
