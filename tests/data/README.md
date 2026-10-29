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

## `stage2_green/` 파일 요건 (10/29 이슈 #33)

`tests/core/test_scenarios.cpp`가 이 폴더의 `.jsonl`을 실행 파일과 같은 룰 구성(1단계 + 2단계 세 룰, 기본값)으로 재생해 같은 이름 `.expected.json`과 비교한다. 파일은 분석 엔진 출력 녹화 또는 직접 작성으로 준비한다.

- `hello`에 `"ue_evt": true`가 있어야 2단계 룰이 돈다(입력 명세 `2_` §6.5).
- 모든 `kpm2`에 `"ue_evt_lost"`(로스가 없으면 `[]`)를 넣는다. 빠지면 양방향 로스로 보아 2단계의 '없음' 판정이 모두 보류된다(`14_` §6.2).
- 같은 창의 `ue_evt`는 그 창 `kpm2`보다 먼저 둔다(`2_` §6.1). `.jsonl`마다 `.expected.json` 짝이 있어야 한다(시험이 확인).
- `.expected.json`: `scenario`·`description`·`t0_ms`·`tolerance_ms`·`alerts`. `alerts`의 항목은 `kind`(`RAISE`·`UPDATE`·`CLEAR`·`END`)·`rule`·`cell`·`t_rel_ms`가 필수이고, `mode`·`severity`·`branch`·`reason`은 적으면 비교한다. `rule`이 없으면 `L3-01-V`로 본다.
