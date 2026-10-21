# 단위 테스트 (4_ §4-1)·시나리오 테스트 (4_ §4-2). GoogleTest는 태그를 고정해 받는다 (4_ §1).
include(FetchContent)
FetchContent_Declare(googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG        v1.15.2
  GIT_SHALLOW    TRUE
)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(detect_tests
  core/test_message.cpp
  core/test_series.cpp
  core/test_alert.cpp
  core/test_baseline.cpp
  core/test_bts_variant.cpp
  core/test_scenarios.cpp
  core/test_evidence.cpp
)
target_link_libraries(detect_tests PRIVATE detect detect_io GTest::gtest_main)
target_include_directories(detect_tests PRIVATE ${PROJECT_SOURCE_DIR}/third_party)
target_compile_definitions(detect_tests PRIVATE
  DETECT_SCENARIO_DIR="${PROJECT_SOURCE_DIR}/tests/data/scenarios"
  DETECT_TMP_DIR="${CMAKE_CURRENT_BINARY_DIR}")
target_compile_options(detect_tests PRIVATE -Wall -Wextra)

include(GoogleTest)
gtest_discover_tests(detect_tests)
