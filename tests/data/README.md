# 테스트 데이터셋 (더미 JSON)

탐지 엔진 테스트용 더미 JSON 데이터셋(`.jsonl`, 입력 명세의 `kpm2`·`ue_evt`)을 둔다.
구조·명명·용도는 명세 `~/RAN/04_분석/탐지엔진-설계/4_탐지엔진_구현_계획서.md` §4.2를 따른다.

| 폴더 | 담는 것 |
|---|---|
| `scenarios/` | 룰 동작 시나리오 T1~T24 (3_ §9) |
| `stage1/` | 1단계 표 II kpm2 (UE 컨텍스트 고갈 룰) |
| `stage2_green/` | 2단계 녹색 4종 (kpm2 + ue_evt) |
| `stage3_lightgreen/` | 3단계 — 룰 3개 L3-24(#24 하향 IMSI 추출)·L3-14(#14 UE 능력 탈취)·L3-06(#6 NAS 카운터 비동기화 — 4단계에서 올림, M9), `kpm2` + `ue_evt`(명세 `20_` §3.8·§4.8·§5.8, 11/03). #9·#19·#23은 3단계 룰이 없다(L3-09 탐지 안 함, #19·#23 원형은 L3-20이 받음). 합성 생성기 `tools/gen_stage3.py`로 채운다(아래 절) |
| `stage4_yellow/` | 4단계 — 이상 유형 룰(`kind` anomaly·`stage` 4, 명세 `21_`). 11/04 AN-01(인증 동기 실패 재인증, `21_` §3.8)·AN-06a(보안 수립 뒤 재인증·SMC 재등장, §4.8) — 룰 6개를 구현 이슈마다 더한다. 합성 생성기 `tools/gen_stage4.py`(아래 절) |
| `captured/` | 실측 녹화 (회귀 테스트용) |

- 파일명: `<시나리오·공격ID>_<짧은 설명>.jsonl`, 기대 결과는 같은 이름 `.expected.json`.
- 생성: `tools/gen_kpm2.py`(1단계 합성) / `tools/gen_stage2.py`(2단계 합성) / `tools/gen_stage3.py`(3단계 합성) / `tools/gen_stage4.py`(4단계 합성) / `tools/ocu_log_to_kpm2.py`(실측 변환).

## `stage2_green/` 파일 요건 (10/29 이슈 #33)

`tests/core/test_scenarios.cpp`가 이 폴더의 `.jsonl`을 실행 파일과 같은 룰 구성(1단계 + 2단계 세 룰, 기본값)으로 재생해 같은 이름 `.expected.json`과 비교한다. 파일은 분석 엔진 출력 녹화 또는 직접 작성으로 준비한다.

- ctest에서는 `data.scenarios`가 데이터 폴더 전체를 돈다 — 데이터만 넣거나 바꿔도 다음 `ctest`에서 돈다. 파일별 항목(`Data/Stage2Scenario...`)은 시험 바이너리를 다시 빌드한 뒤에 목록에 생긴다(이슈 #38).

- `hello`에 `"ue_evt": true`가 있어야 2단계 룰이 돈다(입력 명세 `2_` §6.5).
- 모든 `kpm2`에 `"ue_evt_lost"`(로스가 없으면 `[]`)를 넣는다. 빠지면 양방향 로스로 보아 2단계의 '없음' 판정이 모두 보류된다(`14_` §6.2).
- 같은 창의 `ue_evt`는 그 창 `kpm2`보다 먼저 둔다(`2_` §6.1). `.jsonl`마다 `.expected.json` 짝이 있어야 한다(시험이 확인).
- `.expected.json`: `scenario`·`description`·`t0_ms`·`tolerance_ms`·`alerts`. **경보 시각은 정확히 비교한다** — `tolerance_ms`(허용 오차)는 1단계 데이터(`scenarios/`·`captured/`)에만 쓰고 2단계부터는 쓰지 않는다(이슈 #40). `alerts`의 항목은 `kind`(`RAISE`·`UPDATE`·`CLEAR`·`END`)·`rule`·`cell`·`t_rel_ms`가 필수이고, `mode`·`severity`·`branch`·`reason`·`alert_kind`(`attack`·`anomaly` — 불확실 경보, 이슈 #48)는 적으면 비교한다. `rule`이 없으면 `L3-01-V`로 본다.

### 현재 들어 있는 시나리오 (35개 — 손 작성)

`14_` §10 결정(합성 생성기 범위 밖, 직접 작성)에 따라 손으로 쓴 재생 시나리오다. 룰마다 정상(무경보)·RAISE·심각도(medium/high)·UPDATE·보류(로스)·CLEAR·END를 덮는다. 기대 경보 시각은 명세 식(마감 = t₀/t_f + 대기, 처리는 그 이상인 첫 `kpm2` `t_end`)으로 손 계산하고 네 룰 재생으로 확인했다. 파일명은 `S<단계>_<룰ID>_<설명>_<결과>`, 대응 명세 시험은 설명 끝 괄호(`15_` §2.8·§4.8·§5.8). 생성기는 `tools/gen_stage2.py`(1단계 `gen_kpm2.py`와 같은 틀).

- **L3-01-O 인증 단계 고착 (9):** 정상등록·무응답1·고착4(무경보) / 고착5 RAISE(medium)·고착5 high(UeCtxMax 96)·응답경계 늦음·실패는응답·로스보류(불확실 경보 RAISE — 이슈 #48)·해제 CLEAR
- **L3-20 Blind DoS (10):** 정상첫등록·RLF재접속·IDLE(무경보) / CONNECTED high(피해자 해제)·medium·공격연결닫힘·peer_uncertain·반복 UPDATE·해제 CLEAR·세션변경 END
- **L3-21 상향 DoS (10):** 정상(L3-21 무경보 — 동기 실패 #21을 4단계 AN-01이 받아 AN-01 RAISE 하나, 11/04 이슈 #70)·실패4·등록반복무실패·수락경계정시·SecModeReject(무경보)·로스보류(불확실 경보 RAISE — 이슈 #48) / 원형 갈래① RAISE·변형 갈래② RAISE·혼합 high·해제 CLEAR

- **입력 불완전 (4, 이슈 #42 — `16_` §3.1·W-17):** 순서역전1줄(UE마다 RegistrationRequest가 자기 창 `kpm2` 뒤 → `late`)·순서역전전부는 '경보 없음'(이슈 #46 `late_until` 16 s 뒤에도 마감 2 s가 그 안). UL로스1칸(t = 1.5 s 한 칸으로 5건 전부 보류)·`ue_evt_lost`누락(양방향 로스로 보아 전부 보류)은 이슈 #48부터 **불확실 경보 RAISE**(`alert_kind` anomaly) — 공격 경보는 없다.
- **불확실 경보 뒤 공격 경보 (1, 이슈 #48 — `14_` §6.2·§8.2, U-T30·L01-T20):** `불확실뒤공격_CLEAR-RAISE` — 보류 5건으로 불확실 RAISE 3.0 s, 그 뒤 로스 없이 고착 5건 → 같은 칸(7.0 s)에서 불확실 CLEAR 다음 공격 RAISE.
- **`late_until` 만료 (1, 이슈 #46 — `14_` §4.3, `15_` L01-T21):** `순서역전1줄_만료뒤_RAISE` — 같은 5대가 17 s 뒤 두 번째 AuthenticationRequest에 무응답 → 마감이 `late_until` 뒤라 고착 5건, RAISE 20.0 s. 생성기 옵션은 `Scenario.late_msgs`·`Scenario.drop_lost`. 상태표 포화는 기본 설정으로 재현되지 않아 단위 테스트(`tests/core/test_auth_stall.cpp` `SaturationStopsVerdicts_CurrentBehavior`, 상한 100)로 둔다.

#3 Null 암호·무결성(L3-03)과 #20 IDLE형(L3-20-V2)은 탐지 대상이 아니므로(사용자 결정 10/29, `15_` §3·§2.1) 공격 시나리오를 두지 않는다. L3-20 IDLE형은 '경보 없음' 반례(`S20_L3-20_IDLE_무경보`)로만 둔다.

## `stage3_lightgreen/` 파일 요건 (11/03 이슈 #60·#62 — `20_` §3.8·§4.8, `4_` §6.2 #5·#6 · 11/04 이슈 #68 L3-06 — `20_` §5.8)

`tests/core/test_scenarios.cpp`가 이 폴더를 실행 파일과 같은 룰 구성(1단계 + 2단계 세 룰 + 3단계 룰, 기본값)으로 재생해 같은 이름 `.expected.json`과 비교한다(`Stage3Scenario`). ctest `data.scenarios`가 이 폴더도 매번 돈다. 요건은 `stage2_green/`과 같고 다른 것만 적는다.

- **경보 시각은 정확히 비교한다.** 3단계 판정은 '판정할 줄이 든 창의 `kpm2`'(마감 = 줄 시각 + 1 ms, `20_` §1.2-3)로 시각이 정확히 정해진다.
- `.expected.json`의 `alerts` 항목에 **`conditions`**(3단계 성립 전제 배열, `20_` §1.3)를 적으면 그 이벤트에 그 값이 실렸는지 비교한다. 공격 경보 RAISE는 `["mitm_ul_relay"]`, 불확실 경보(`alert_kind` anomaly)에는 싣지 않는다.
- **생성:** `python3 tools/gen_stage3.py [출력 폴더]`. 2단계 생성기 `gen_stage2.py`의 `UE`·`Scenario` 틀을 그대로 쓰고 3단계 메시지 4개와 기본 흐름 F(`20_` §3.8)를 더했다. 기대 경보 시각은 생성기가 계산하지 않고 명세 식 K(t)(t를 품은 창의 `t_end`)로 손 계산한 값이다. 연결 시작 t0 = 1000(상대 ms).
- 파일명은 `S<룰 번호>_<룰 ID>_<설명>_<결과>`, 대응 명세 시험은 설명 끝 괄호(`20_` §3.8 L24-T·§4.8 L14-T·§5.8 L06-T).

### 현재 들어 있는 시나리오 (77개 — 생성기)

- **L3-24 하향 IMSI 추출 (30):** 정상흐름·모르는GUTI식별·AMF재전송(늦은응답1회·두번응답)·AS무결성뒤응답·NAS암호·중간합류·늦은응답줄·NGAP미연결(무경보) / 요청없는응답·약속밖f무시·정상식별뒤추가응답·같은연결추가응답·같은창두응답·연결전로스·UL로스·창경계응답·같은창해제·nia0·보안명령뒤완료전(RAISE) / 두UE UPDATE / 해제·extra는해제를안늦춤(CLEAR) / 요청줄로스·연결뒤로스·보류연결추가응답(대기중·결정뒤)·DL미관측(불확실 경보 RAISE — DL미관측은 t0+175 능력 응답 때문에 L3-14 불확실 경보도 같은 칸에 남, L14-T16) / 순서위반·응답중복(RAISE — 분석 엔진 전제를 어긴 입력의 오탐을 기록해 두는 시험, `20_` §3.7).
- **L3-14 UE 능력 탈취 (22, 이슈 #62):** 정상흐름·능력교환없음·보안명령뒤요청(CMD)·보안완료뒤요청(ON)·능력요청줄로스·중간합류·늦은응답줄·보안뒤순서위반(무경보) / 요청없는능력응답 갈래1·보안전능력요청 갈래2·보안실패뒤요청 갈래2·연결당한번·nia0 갈래1·마감전해제 갈래2(RAISE) / 갈래섞임(심각도 UPDATE)·갈래섞임역순(전제 `conditions` UPDATE)·한연결두갈래(같은 칸 RAISE-UPDATE)·CU설정오류5UE(모음 UPDATE) / 해제(CLEAR, branch 2) / 보안명령줄로스·DL미관측(불확실 경보 RAISE) / 보안전순서위반(RAISE-UPDATE — 오탐을 기록해 두는 시험, `20_` §4.7).
- **L3-06 NAS 카운터 비동기화 (25, 이슈 #68):** 정상흐름·정상거부·AMF재전송(거부1회·명령마다거부)·AS무결성뒤거부·중간합류·늦은거부줄·명령줄순서위반(무경보) / 보안전주입(J1)·정상완료뒤주입(J2 — Complete를 응답으로 셈)·nia0·RRC보안명령뒤완료전·같은연결추가거부·같은창두거부·연결전로스·UL로스·창경계거부·같은창해제(RAISE) / 두UE UPDATE / 해제·extra는해제를안늦춤(CLEAR) / 명령줄로스·연결뒤로스·DL미관측(불확실 경보 RAISE) / 거부중복(RAISE — 오탐을 기록해 두는 시험, `20_` §5.7). 메시지는 2단계부터 받는 NAS SecurityModeCommand·Complete·Reject뿐이다.
- 데이터로 두지 않은 시험은 단위 시험에만 있다 — L24-T23·L14-T18·L06-T18(상태표 밀어내기, 상한 100), L24-T26·L14-T21·L06-T20(재생 결정성)은 `tests/core/test_imsi_extractor.cpp`·`test_cap_hijack.cpp`·`test_nas_desync.cpp`, L24-T25·L14-T20·L06-T20(설정)은 `test_config.cpp`.

## `stage4_yellow/` 파일 요건 (11/04 이슈 #70·#72 — `21_` §1·§3.8·§4.8)

`tests/core/test_scenarios.cpp`가 이 폴더를 실행 파일과 같은 룰 구성(1~4단계, 기본값)으로 재생해 같은 이름 `.expected.json`과 비교한다(`Stage4Scenario`). ctest `data.scenarios`가 이 폴더도 매번 돈다. 요건은 `stage3_lightgreen/`과 같고 다른 것만 적는다.

- 경보 시각은 정확히 비교한다 — 4단계는 걸림이 든 창의 `kpm2`에서 RAISE한다(`21_` §1.1).
- `.expected.json`의 `alerts` 항목에 **`candidates`**(raise의 후보 배열)를 적으면 그 이벤트의 값과 비교한다. 4단계 경보는 공격이 아니라 이상 유형이라 어느 공격 후보인지가 경보의 뜻이다(`21_` §1). 4단계 RAISE는 `alert_kind` `anomaly`로 적는다 — 불확실 경보와는 `rule` 접두사(`AN-`)로 가른다.
- **생성:** `python3 tools/gen_stage4.py [출력 폴더]`. 3단계 생성기의 UE·Scenario·기본 흐름 F·K(t)를 그대로 쓰고 4단계 흐름(AN-01 동기 실패 흐름 S·AN-06a 재등장 흐름 R)과 `candidates`만 더한다. 3단계 생성기 출력은 그대로다.
- 파일명은 `S<룰 번호>_<룰 ID>_<설명>_<결과>` — 4단계 룰 번호는 `AN01`처럼 쓴다.
- 재생은 설정 기본값이라 문턱을 바꾼 시험(AN01-T6·T7 `n_sync` 2, AN06a-T6 `n_reauth` 2), 밀어내기(AN01-T10·AN06a-T9 뒤 경우), 설정(AN01-T11·AN06a-T10), 결정성(AN01-T12·AN06a-T10)은 단위 시험(`tests/core/test_sync_failure.cpp`·`test_sec_reauth.cpp`·`test_config.cpp`)에만 있다.

### 현재 들어 있는 시나리오 (18개 — 생성기)

- **AN-01 인증 동기 실패 재인증 (9, 이슈 #70):** 정상흐름·MAC실패(원인값 20)·원인값없음(무경보) / 동기실패·두번째동기실패(연결당 한 번, 경보 값 extra)·중간합류(`mid_join`)·로스창(보류 없음)(RAISE) / 두UE(UPDATE) / 해제(CLEAR). 앞 단계 데이터에서는 `stage2_green/S21_L3-21_정상_무경보`의 동기 실패가 AN-01 RAISE를 낸다.
- **AN-06a 보안 수립 뒤 재인증·SMC 재등장 (9, 이슈 #72):** 정상흐름·AMF재전송(SMC — 갱신 전 CMD·인증 — 갱신 전 AUTH)·중간합류·완료줄로스(무경보) / 보안뒤재인증·보안뒤SMC재등장·두번째재등장(경보 값 extra)(RAISE) / 해제(CLEAR). 앞 단계 데이터에는 이 모양이 없다.
