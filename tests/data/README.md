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

- ctest에서는 `data.scenarios`가 데이터 폴더 전체를 돈다 — 데이터만 넣거나 바꿔도 다음 `ctest`에서 돈다. 파일별 항목(`Data/Stage2Scenario...`)은 시험 바이너리를 다시 빌드한 뒤에 목록에 생긴다(이슈 #38).

- `hello`에 `"ue_evt": true`가 있어야 2단계 룰이 돈다(입력 명세 `2_` §6.5).
- 모든 `kpm2`에 `"ue_evt_lost"`(로스가 없으면 `[]`)를 넣는다. 빠지면 양방향 로스로 보아 2단계의 '없음' 판정이 모두 보류된다(`14_` §6.2).
- 같은 창의 `ue_evt`는 그 창 `kpm2`보다 먼저 둔다(`2_` §6.1). `.jsonl`마다 `.expected.json` 짝이 있어야 한다(시험이 확인).
- `.expected.json`: `scenario`·`description`·`t0_ms`·`tolerance_ms`·`alerts`. **경보 시각은 정확히 비교한다** — `tolerance_ms`(허용 오차)는 1단계 데이터(`scenarios/`·`captured/`)에만 쓰고 2단계부터는 쓰지 않는다(이슈 #40). `alerts`의 항목은 `kind`(`RAISE`·`UPDATE`·`CLEAR`·`END`)·`rule`·`cell`·`t_rel_ms`가 필수이고, `mode`·`severity`·`branch`·`reason`은 적으면 비교한다. `rule`이 없으면 `L3-01-V`로 본다.

### 현재 들어 있는 시나리오 (29개 — 손 작성)

`14_` §10 결정(합성 생성기 범위 밖, 직접 작성)에 따라 손으로 쓴 재생 시나리오다. 룰마다 정상(무경보)·RAISE·심각도(medium/high)·UPDATE·보류(로스)·CLEAR·END를 덮는다. 기대 경보 시각은 명세 식(마감 = t₀/t_f + 대기, 처리는 그 이상인 첫 `kpm2` `t_end`)으로 손 계산하고 네 룰 재생으로 확인했다. 파일명은 `S<단계>_<룰ID>_<설명>_<결과>`, 대응 명세 시험은 설명 끝 괄호(`15_` §2.8·§4.8·§5.8). 생성기는 `tools/gen_stage2.py`(1단계 `gen_kpm2.py`와 같은 틀).

- **L3-01-O 인증 단계 고착 (9):** 정상등록·무응답1·고착4(무경보) / 고착5 RAISE(medium)·고착5 high(UeCtxMax 96)·응답경계 늦음·실패는응답·로스보류·해제 CLEAR
- **L3-20 Blind DoS (10):** 정상첫등록·RLF재접속·IDLE(무경보) / CONNECTED high(피해자 해제)·medium·공격연결닫힘·peer_uncertain·반복 UPDATE·해제 CLEAR·세션변경 END
- **L3-21 상향 DoS (10):** 정상·실패4·등록반복무실패·수락경계정시·SecModeReject·로스보류(무경보) / 원형 갈래① RAISE·변형 갈래② RAISE·혼합 high·해제 CLEAR

#3 Null 암호·무결성(L3-03)과 #20 IDLE형(L3-20-V2)은 탐지 대상이 아니므로(사용자 결정 10/29, `15_` §3·§2.1) 공격 시나리오를 두지 않는다. L3-20 IDLE형은 '경보 없음' 반례(`S20_L3-20_IDLE_무경보`)로만 둔다.
