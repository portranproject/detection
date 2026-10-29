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
  core/test_config.cpp
  core/test_ue_table.cpp
  core/test_deadline_queue.cpp
  core/test_ue_evidence.cpp
  core/test_ue_alert.cpp
  core/test_blind_dos.cpp
  core/test_auth_stall.cpp
  core/test_uplink_dos.cpp
  io/test_uds_server.cpp
  io/test_file_replay.cpp
)
target_link_libraries(detect_tests PRIVATE detect detect_io GTest::gtest_main)
target_compile_definitions(detect_tests PRIVATE
  DETECT_SCENARIO_DIR="${PROJECT_SOURCE_DIR}/tests/data/scenarios"
  DETECT_TMP_DIR="${CMAKE_CURRENT_BINARY_DIR}"
  DETECT_SOURCE_DIR="${PROJECT_SOURCE_DIR}")
target_compile_options(detect_tests PRIVATE -Wall -Wextra)

include(GoogleTest)
gtest_discover_tests(detect_tests)
# 데이터 시나리오 묶음 (4_ §4.2, 이슈 #38): 시나리오 시험은 tests/data/의 파일로 시험을 만드는데, 위 목록은 시험
# 바이너리를 다시 링크할 때만 다시 모인다. 바이너리가 실행할 때 폴더를 읽어 모든 데이터를 도는 항목을 하나 더 둔다 —
# 데이터만 넣거나 바꿔도 다음 ctest에서 돈다
add_test(NAME data.scenarios COMMAND detect_tests --gtest_filter=Data/*:Stage2Data.*)

# 실행 파일 통합 테스트 — detector + mock_producer.py, T20 (4_ §4-2·§4-4)
find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(NAME integration.detector
  COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/integration/test_detector.py
          $<TARGET_FILE:detector> ${PROJECT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/integration)

# CU 로그 변환기 테스트 (4_ §4.1) — 변환 규칙 + 변환 결과를 detector로 재생
add_test(NAME tools.ocu_log_to_kpm2
  COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tests/tools/test_ocu_log_to_kpm2.py
          ${PROJECT_SOURCE_DIR} $<TARGET_FILE:detector> ${CMAKE_CURRENT_BINARY_DIR}/tools)
