# detection

5G RAN L3 공격 탐지 엔진 (C++17). 분석 엔진의 KPM(JSON Lines)을 받아 룰로 판정한다.

## 빌드·테스트

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j4
ctest --test-dir build --output-on-failure

# 배포 빌드 (GoogleTest를 받지 않음)
cmake -B build-rel -DCMAKE_BUILD_TYPE=Release -DDETECT_BUILD_TESTS=OFF && cmake --build build-rel -j2
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
- 증거 레코드는 설정 `evidence.out_path`(기본 `evidence.jsonl`)에 이어 쓴다.
- SIGINT·SIGTERM을 받으면 남은 증거를 다 쓰고 소켓 파일을 지운 뒤 끝낸다.
- 종료 코드: 0 정상, 1 기동·설정 오류, 2 사용법 오류.

- `third_party/nlohmann/json.hpp`: nlohmann/json 3.11.3 (MIT), 저장소에 동봉
