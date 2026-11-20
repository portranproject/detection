# 퍼즈 하네스 (4_ §4, 16_ W-19 — 이슈 #52). 두 모드:
#  - 기본: standalone_main.cpp를 붙여 GCC로도 빌드 — 시드 코퍼스(tests/data/ 그대로)와 결정적 변형을 ctest가 매번 돈다
#  - -DDETECT_LIBFUZZER=ON: clang의 -fsanitize=fuzzer로 링크(main은 libFuzzer). 코퍼스는 tools/make_fuzz_corpus.py,
#    사전은 input.dict, 캠페인 명령은 README
if(DETECT_LIBFUZZER AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  message(FATAL_ERROR "DETECT_LIBFUZZER needs clang: CC=clang CXX=clang++ cmake -B build-fuzz -DDETECT_LIBFUZZER=ON ...")
endif()

set(DETECT_FUZZ_DATA
  ${PROJECT_SOURCE_DIR}/tests/data/scenarios
  ${PROJECT_SOURCE_DIR}/tests/data/stage2_green
  ${PROJECT_SOURCE_DIR}/tests/data/captured)

foreach(t IN ITEMS fuzz_parse_line fuzz_uds_lines)
  if(DETECT_LIBFUZZER)
    add_executable(${t} ${t}.cpp)
    target_compile_options(${t} PRIVATE -fsanitize=fuzzer)
    target_link_options(${t} PRIVATE -fsanitize=fuzzer)
  else()
    add_executable(${t} ${t}.cpp standalone_main.cpp)
  endif()
  target_link_libraries(${t} PRIVATE detect_io)
  target_compile_options(${t} PRIVATE -Wall -Wextra)
endforeach()

if(DETECT_LIBFUZZER)
  # 코퍼스(입력 하나 = 파일 하나)를 빌드 폴더에 만들고 그 위로 짧게 돈다. 긴 캠페인은 손으로(README)
  add_test(NAME fuzz.corpus
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/make_fuzz_corpus.py ${CMAKE_CURRENT_BINARY_DIR}/corpus
            --data ${PROJECT_SOURCE_DIR}/tests/data)
  add_test(NAME fuzz.parse_line COMMAND fuzz_parse_line -runs=20000 ${CMAKE_CURRENT_BINARY_DIR}/corpus/parse_line)
  add_test(NAME fuzz.uds_lines
    COMMAND fuzz_uds_lines -runs=300 -max_len=70000 ${CMAKE_CURRENT_BINARY_DIR}/corpus/uds_lines)
  set_tests_properties(fuzz.parse_line fuzz.uds_lines PROPERTIES DEPENDS fuzz.corpus)
else()
  # 독립 실행 모드: 시드 전부 + 고정 시드 변형(Debug 기준 각 5 s 안팎, ASan은 3배). 실행 수는 각 시험이 stderr에 적는다
  add_test(NAME fuzz.parse_line COMMAND fuzz_parse_line --per-line --mutations 50000 --seed 1 ${DETECT_FUZZ_DATA})
  add_test(NAME fuzz.uds_lines COMMAND fuzz_uds_lines --mutations 1000 --seed 1 ${DETECT_FUZZ_DATA})
endif()
