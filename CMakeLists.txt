# 탐지 엔진 빌드 (4_ §1·§5): C++17, 핵심부는 라이브러리 libdetect, 테스트는 옵션으로 켜고 끈다.
cmake_minimum_required(VERSION 3.22)
project(detection LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 배포 빌드는 -DDETECT_BUILD_TESTS=OFF — 박스에서 GoogleTest를 받지 않게 (4_ §1·§5)
option(DETECT_BUILD_TESTS "Build unit tests (fetches GoogleTest)" ON)

# libdetect: I/O 없는 순수 로직 (4_ §2 'core는 I/O를 모른다')
add_library(detect
  src/core/diag.cpp
  src/core/message.cpp
  src/core/series.cpp
  src/core/alert.cpp
  src/core/baseline.cpp
  src/core/engine.cpp
  src/core/rules/bts_variant.cpp
)
target_include_directories(detect
  PUBLIC include
  PRIVATE third_party   # nlohmann/json 동봉본 3.11.3 (4_ §1)
)
target_compile_options(detect PRIVATE -Wall -Wextra -Wpedantic)

if(DETECT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
