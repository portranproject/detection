# detection

5G RAN L3 공격 탐지 엔진 (C++17). 분석 엔진의 KPM(JSON Lines)을 받아 룰로 판정한다.

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j4
ctest --test-dir build --output-on-failure

# 배포 빌드 (GoogleTest를 받지 않음)
cmake -B build-rel -DCMAKE_BUILD_TYPE=Release -DDETECT_BUILD_TESTS=OFF && cmake --build build-rel -j2
```

- `third_party/nlohmann/json.hpp`: nlohmann/json 3.11.3 (MIT), 저장소에 동봉
