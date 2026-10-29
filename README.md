# detection

5G RAN L3 공격 탐지 엔진 (C++17). 분석 엔진의 KPM(JSON Lines)을 받아 룰로 판정한다.

## 빌드·테스트

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j4
ctest --test-dir build --output-on-failure

# 배포 빌드 (GoogleTest를 받지 않음)
cmake -B build-rel -DCMAKE_BUILD_TYPE=Release -DDETECT_BUILD_TESTS=OFF && cmake --build build-rel -j2

# Sanitizer 빌드 — thread(증거 큐 두 스레드) 또는 address,undefined. address와 thread는 함께 못 씀.
# thread는 최근 커널(WSL2 6.x 등)에서 ASLR 때문에 "unexpected memory mapping"으로 기동하지 못하므로
# 빌드(테스트 목록을 모으며 바이너리를 실행)와 ctest 모두 setarch -R(ASLR 끔)을 앞에 붙인다
cmake -B build-tsan -DCMAKE_BUILD_TYPE=Debug -DDETECT_SANITIZE=thread
setarch "$(uname -m)" -R cmake --build build-tsan -j4
setarch "$(uname -m)" -R ctest --test-dir build-tsan --output-on-failure
cmake -B build-asan -DCMAKE_BUILD_TYPE=Debug -DDETECT_SANITIZE=address,undefined && cmake --build build-asan -j4
ctest --test-dir build-asan --output-on-failure
```

## 실행

```bash
# 분석 엔진의 KPM을 Unix 소켓으로 받기 (소켓 디렉터리는 미리 만든다)
sudo install -d -o "$USER" -g "$USER" -m 0755 /run/ran-detect
./build-rel/detector --socket /run/ran-detect/kpm.sock --config config/detector.json

# .jsonl 재생 (--speed max = 최대 속도, N = N배속, 1 = 실시간)
./build-rel/detector --replay tests/data/scenarios/T05_공격종료.jsonl --speed max

# 가짜 분석 엔진으로 소켓에 보내기
python3 tools/mock_producer.py --socket /run/ran-detect/kpm.sock --file tests/data/scenarios/T05_공격종료.jsonl --speed 10
```

- 경보(`ALERT …`)는 stdout, 진단·기동 정보는 stderr로 나온다.
- 소켓 모드에서 마지막 `kpm2` 뒤 `input_silent_ms`(기본 10 s) 동안 `kpm2`가 없으면 진단 `input_silent`를 내고 진행 중 경보를 `END reason=input_silent`로 끝낸다. 버퍼·기준선·UE 상태표는 그대로라 다시 오면 이어 간다. 재생 모드에서는 하지 않는다. 시험은 `mock_producer.py --pause-after N --pause-sec S`.
- 증거 레코드는 설정 `evidence.out_path`(기본 `evidence.jsonl`)에 이어 쓴다.
- SIGINT·SIGTERM을 받으면 남은 증거를 다 쓰고 소켓 파일을 지운 뒤 끝낸다.
- 종료 코드: 0 정상, 1 기동·설정 오류, 2 사용법 오류.

- `third_party/nlohmann/json.hpp`: nlohmann/json 3.11.3 (MIT), 저장소에 동봉
