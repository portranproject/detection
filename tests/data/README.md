# 테스트 데이터셋 (더미 JSON)

탐지 엔진 테스트용 더미 JSON 데이터셋(`.jsonl`, 입력 명세의 `kpm2`·`ue_evt`)을 둔다.
구조·명명·용도는 명세 `~/RAN/04_분석/탐지엔진-설계/4_탐지엔진_구현_계획서.md` §4.2를 따른다.

| 폴더 | 담는 것 |
|---|---|
| `scenarios/` | 룰 동작 시나리오 T1~T24 (3_ §9) |
| `stage1/` | 1단계 표 II kpm2 (UE 컨텍스트 고갈 룰) |
| `stage2_green/` | 2단계 녹색 4종 (kpm2 + ue_evt) |
| `stage3_lightgreen/` | 3단계 연한 녹색 5종 |
| `stage4_yellow/` | 4단계 노란색 12종 |
| `captured/` | 실측 녹화 (회귀 테스트용) |

- 파일명: `<시나리오·공격ID>_<짧은 설명>.jsonl`, 기대 결과는 같은 이름 `.expected.json`.
- 생성: `tools/gen_kpm2.py`(합성) / `tools/ocu_log_to_kpm2.py`(실측 변환).
