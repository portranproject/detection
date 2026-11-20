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

# 퍼즈 (tests/fuzz): 기본 빌드에도 독립 실행 모드로 들어 있어 ctest(fuzz.parse_line·fuzz.uds_lines)가 시드(tests/data)와
# 고정 시드 변형을 매번 돈다. 더 오래 돌리려면 --mutations·--seed를 바꾼다
./build-asan/tests/fuzz/fuzz_parse_line --per-line --mutations 200000 --seed 7 tests/data/scenarios tests/data/stage2_green
./build-asan/tests/fuzz/fuzz_uds_lines --mutations 3000 --seed 7 tests/data/scenarios tests/data/stage2_green
# libFuzzer 캠페인(커버리지 유도)은 clang이 필요하다
CC=clang CXX=clang++ cmake -B build-fuzz -DDETECT_LIBFUZZER=ON -DDETECT_SANITIZE=address,undefined && cmake --build build-fuzz -j4
python3 tools/make_fuzz_corpus.py build-fuzz/corpus
./build-fuzz/tests/fuzz/fuzz_parse_line build-fuzz/corpus/parse_line -dict=tests/fuzz/input.dict -max_total_time=600
./build-fuzz/tests/fuzz/fuzz_uds_lines build-fuzz/corpus/uds_lines -dict=tests/fuzz/input.dict -max_len=65536 -max_total_time=600
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

## 대시보드 전송기

증거 파일(`evidence.jsonl`)의 새 줄을 줄 그대로 대시보드 `/ingest`(HTTPS)로 보내는 별도 프로그램이다. 탐지 엔진 코드와는 파일로만 이어진다.

```bash
# 탐지 엔진과 함께 띄우기 (저장소 최상위에서). 시작 전에 evidence.out_path와 전송기 입력 경로가 같은지 확인한다
tools/run_with_sender.sh config/sender.json -- ./build-rel/detector --socket /run/ran-detect/kpm.sock --config config/detector.json

# 전송기만 — 계속 따라 읽기 / 지금 있는 줄만 보내고 끝내기 / 보내지 않고 묶음만 확인
python3 tools/dashboard_sender.py --config config/sender.json
python3 tools/dashboard_sender.py --config config/sender.json --once
python3 tools/dashboard_sender.py --config config/sender.json --dry-run
```

- 설정 `config/sender.json`: 수집 주소 `url`, 대시보드 자체 서명 인증서 `ca_file`(저장소 밖에 둔다 — 받기 전에는 `null`이라 TLS 검증에 실패한다), 환경 헤더 `env`(`X-Env` — `aws`(AWS 테스트베드)·`on-premise`(연구실) 둘 중 하나, 기본 `on-premise`). 토큰은 쓰지 않는다.
- 보낸 위치는 `sender_state.json`에 저장한다(200·400을 받은 뒤에만). 다시 띄우면 그 자리부터 보낸다. 실험마다 깨끗이 보내려면 옛 `evidence.jsonl`을 옮겨 둔다.
- 전송기가 오류로 끝나도 실행 스크립트는 탐지 엔진을 멈추지 않는다. 끝날 때 `--once`로 남은 줄을 한 번 더 보낸다(최대 60초).
- **상시 KPM (기본 끔):** 탐지 엔진 설정 `input_record.path`를 `"input.jsonl"`로 켜고, 전송기 설정 `inputs`에 `{"path": "input.jsonl", "kind": "input"}`을 더한다. 그러면 `hello`·`f1_evt`는 줄 그대로, `kpm2`는 셀마다 `kpm2_interval_ms`(기본 3000 = 3초, 1,000의 배수)로 묶은 줄만 보낸다 — 0.1초 원본은 보내지 않는다. `ue_evt`는 `send_ue_evt`가 `true`일 때만. 실행 스크립트는 두 입력 기록 경로가 같은지도 시작 전에 확인한다.
- 주기는 운영 중에도 바꿀 수 있다 — `kpm2_interval_ms`를 고치고 전송기만 다시 띄운다(`SIGTERM` 뒤 `python3 tools/dashboard_sender.py --config …`). 탐지 엔진은 계속 돈다.
- 종료 코드: 0 정상, 1 설정 오류, 2 약속에 없는 응답(주소·권한·보안 그룹 확인), 3 TLS 검증 실패(`ca_file`·`url` 확인), 4 상태 파일 저장 실패, 5 같은 `state_path`를 다른 전송기가 쓰는 중.

- `third_party/nlohmann/json.hpp`: nlohmann/json 3.11.3 (MIT), 저장소에 동봉
