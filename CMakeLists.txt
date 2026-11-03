# 탐지 엔진 빌드 (4_ §1·§5): C++17, 핵심부는 라이브러리 libdetect, 테스트는 옵션으로 켜고 끈다.
cmake_minimum_required(VERSION 3.22)
project(detection LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 배포 빌드는 -DDETECT_BUILD_TESTS=OFF — 박스에서 GoogleTest를 받지 않게 (4_ §1·§5)
option(DETECT_BUILD_TESTS "Build unit tests (fetches GoogleTest)" ON)

# Sanitizer 빌드 (4_ §4, 16_ W-18 — 이슈 #42): -DDETECT_SANITIZE=address|thread|undefined, 쉼표로 묶을 수 있다
# (address,undefined). address와 thread는 함께 쓰지 못한다. 증거 큐의 두 스레드(3_ §7.1)는 thread로 본다.
# 모든 타깃(FetchContent로 받는 GoogleTest 포함)에 걸리도록 타깃 정의보다 앞에서 디렉터리 옵션으로 건다.
# thread는 최근 커널의 ASLR과 부딪혀 기동하지 못할 수 있다 — 그때는 빌드·ctest를 setarch -R로 감싼다(README)
set(DETECT_SANITIZE "" CACHE STRING "Sanitizers to enable: address, thread, undefined (comma-separated); empty = off")
if(DETECT_SANITIZE)
  add_compile_options(-fsanitize=${DETECT_SANITIZE} -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=${DETECT_SANITIZE})
endif()

# libdetect: I/O 없는 순수 로직 (4_ §2 'core는 I/O를 모른다')
add_library(detect
  src/core/diag.cpp
  src/core/message.cpp
  src/core/series.cpp
  src/core/alert.cpp
  src/core/baseline.cpp
  src/core/engine.cpp
  src/core/ue_table.cpp
  src/core/deadline_queue.cpp
  src/core/ue_evidence.cpp
  src/core/ue_alert.cpp
  src/core/ue_lookback.cpp
  src/core/ue_hits.cpp
  src/core/rules/bts_variant.cpp
  src/core/rules/blind_dos.cpp
  src/core/rules/auth_stall.cpp
  src/core/rules/uplink_dos.cpp
  src/core/rules/imsi_extractor.cpp
  src/core/rules/cap_hijack.cpp
  src/core/rules/nas_desync.cpp
  src/core/rules/sync_failure.cpp
  src/core/rules/sec_reauth.cpp
  src/core/rules/identity_request.cpp
  src/core/evidence.cpp
  src/core/evidence_queue.cpp
  src/core/config.cpp
)
find_package(Threads REQUIRED)
target_include_directories(detect
  PUBLIC include
  PUBLIC third_party   # nlohmann/json 동봉본 3.11.3 (4_ §1) — 공개 헤더 alert.h의 values·params가 ordered_json (4_ §6.1 #5)
)
target_link_libraries(detect PUBLIC Threads::Threads)  # 증거 큐 (3_ §7.1)
target_compile_options(detect PRIVATE -Wall -Wextra -Wpedantic)

# detect_io: 파일·소켓 같은 I/O (4_ §2 src/io)
add_library(detect_io
  src/io/evidence_sink.cpp
  src/io/uds_server.cpp
  src/io/file_replay.cpp
)
target_link_libraries(detect_io PUBLIC detect)
target_compile_options(detect_io PRIVATE -Wall -Wextra -Wpedantic)

# 실행 파일 detector (4_ §2 app, §5 배포)
add_executable(detector src/app/detector_main.cpp)
target_link_libraries(detector PRIVATE detect_io)
target_compile_options(detector PRIVATE -Wall -Wextra -Wpedantic)

if(DETECT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
