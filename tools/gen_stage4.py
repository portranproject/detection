#!/usr/bin/env python3
"""합성 ue_evt+kpm2 4단계 시나리오(.jsonl)와 기대 경보(.expected.json) 생성기.

명세: 4단계 룰 21_탐지엔진_4단계-노란색룰_명세서.md(AN-01 §3.8·AN-06a §4.8·AN-02 §5.8·AN-04 §6.8·AN-07 §7.8·AN-08 §8.8),
입력 2_ §6,
상태·경보 14_.
실행: python3 tools/gen_stage4.py [출력 폴더]  (기본 tests/data/stage4_yellow/).
tests/core/test_scenarios.cpp가 이 폴더를 실행 파일과 같은 룰 구성(1~4단계, 기본값)으로 재생해 같은 이름 .expected.json과
비교한다(Stage4Scenario, 시각 정확 비교). 3단계 생성기 gen_stage3.py의 UE3·Scenario3·기본 흐름 F·K(t)를 그대로 쓰고
4단계 흐름(AN-01 동기 실패 흐름 S·AN-06a 재등장 흐름 R·AN-02 등록 흐름 G·AN-04 짧은 연결 흐름 P·AN-07 미완료 흐름 Q·AN-08 이동 등록 흐름 M)과 기대 경보의 candidates(4단계는 후보가 경보의
뜻이다, 21_ §1)만 더한다.

기대 경보 시각은 명세 식으로 손 계산한 값이다(3단계와 같은 방식):
 - 연결 시작 t0 = 1000(창 시작). K(t) = t를 품은 창의 t_end — 걸림이 든 창의 kpm2에서 RAISE(21_ §1.1)
 - UPDATE = 새 UE가 걸린 뒤 RAISE·UPDATE에서 update_min_ms(1,000) 이상인 첫 kpm2(14_ §8.2)
 - CLEAR = 경보에 실린 마지막 걸림 + clear_quiet_ms(60,000) 이상인 첫 kpm2(21_ §3.5)
 - AN-04·AN-07은 연결이 닫힐 때 판정한다 — 걸림 = 닫힌 시각(해제 완료 줄), RAISE = 그 시각이 든 창의 kpm2(21_ §1.3).
   stale_setup으로 닫히면 닫힌 시각 = 마감(마지막 줄 + 30 s)이고 그 마감을 처리한 kpm2(t_end = 마감)에서 RAISE
재생은 설정 기본값(AN-01 n_sync 1·AN-06a n_reauth 1)이라 문턱을 바꾼 시험(AN01-T6·T7·AN06a-T6)·밀어내기·설정·결정성은
단위 시험만이다. AN-04 창 밖(AN04-T3 둘째 — 400 s 넘는 데이터)·유령 정리 닫힘(AN04-T7 — 기본값으로는 유령 17개 필요)도 단위
시험만이고, 재생은 같은 '판정하지 않는 닫힘' 갈래인 du_reset(F1Reset)으로 본다. AN-07의 reused 닫힘·회복 뒤 다시 걸림도 단위
시험만이다. AN-08의 known_ms 만료·RRC 또는 NAS·같은 연결 재전송·mid_join·로스·회복도 단위 시험만이다.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_stage2  # noqa: E402
import gen_stage3  # noqa: E402  (UE3·Scenario3·K·B)
from gen_stage2 import T0  # noqa: E402
from gen_stage3 import B, K  # noqa: E402

SYNCH_FAILURE = 21  # 5GMM 원인값 #21 synch failure (21_ §3.1)
S_ALLOC = "0x0123456789ab"    # 이 망이 RegistrationAccept로 준 S-TMSI (AN-02 등록 흐름 G)
S_UNKNOWN = "0x00fedcba9876"  # 모르는 S-TMSI
S_SHORT = "0x00000a0b0c0d"    # 짧은 연결을 반복하는 S-TMSI (AN-04 짧은 연결 흐름 P)
S_SHORT2 = "0x0000fedcba98"   # 둘째 S-TMSI (AN-04 UPDATE)
S_MOB = ["0x0000b000000%d" % i for i in range(1, 6)]  # AN-08 이동 등록 흐름 M의 S1~S5


def part1_of(s):
    """48비트 S-TMSI의 하위 39비트 Part1 (14_ §3.1)."""
    return "0x%010x" % (int(s, 16) & ((1 << 39) - 1))


class UE4(gen_stage3.UE3):
    """4단계 흐름을 더한 UE."""

    # 동기 실패 흐름 S (21_ §3.8): F에서 t0+118 응답 대신 AuthenticationFailure(f.cause) → t0+160 재인증 요청 →
    # t0+173 응답 → 그 뒤 F의 NAS SMC부터 55 ms 늦춤. cause=None이면 f 없는 실패 줄(AN01-T5)
    def flow_S(self, t0, cause=SYNCH_FAILURE):
        self.flow_F(t0, until=118)
        self.auth_fail(t0 + 118, cause)
        self.auth_req(t0 + 160)
        self.auth_resp(t0 + 173)
        return self.flow_F(t0 + 55, rest_from=125)

    # 재등장 흐름 R (21_ §4.8): F가 등록 완료(t0+200)까지 간 뒤 t0+1,250 AuthenticationRequest(nas_sec ON) → t0+1,263 응답 →
    # t0+1,270 NAS SecurityModeCommand → t0+1,276 완료. smc_only면 t0+1,250에 NAS SMC만 다시 옴(+6 ms 완료, AN06a-T3)
    def flow_R(self, t0, smc_only=False, skip=()):
        self.flow_F(t0, skip=skip)
        if smc_only:
            return self.nas_smc(t0 + 1250).nas_smcomplete(t0 + 1256)
        return self.auth_req(t0 + 1250).auth_resp(t0 + 1263).nas_smc(t0 + 1270).nas_smcomplete(t0 + 1276)

    # 등록 흐름 G의 연결 A (21_ §5.8): SUCI로 F대로 등록하되 RegistrationAccept가 S-TMSI s를 준다(할당 기억) → t0+1,000 해제
    def flow_alloc(self, t0, s=S_ALLOC):
        self.flow_F(t0, skip=("RegistrationAccept",))
        self.reg_accept(t0 + 190, s_tmsi=s)
        return self.release(t0 + 1000)

    # 등록 흐름 G의 연결 B 앞부분: RRC에는 rrc_s(RRCSetupRequest Part1 + RRCSetupComplete 48비트, rrc_full이 False면 Part1만),
    # 등록 요청은 5G-GUTI nas_s. 중간자가 NAS GUTI만 바꾸면 rrc_s ≠ nas_s (#25, 21_ §5.1·§5.3-1)
    def guti_head(self, t0, rrc_s=S_ALLOC, nas_s=S_ALLOC, rrc_full=True):
        self.setup_req(t0, random=False, part1=part1_of(rrc_s))
        self.setup(t0)
        self.setup_complete(t0 + 91, s_tmsi=rrc_s if rrc_full else None)
        return self.reg_req(t0 + 91, id_type="5G-GUTI", s_tmsi=nas_s)

    # 짧은 연결 흐름 P (21_ §6.8): 같은 S-TMSI s로 RRCSetupRequest(Part1, est) → RRCSetupComplete(s) → ServiceRequest(s) →
    # ServiceAccept → RRCRelease → 시작 + length에 해제 완료. full이 False면 RRC·NAS에 48비트가 없고 Part1만(AN04-T6),
    # du_release면 해제 전에 DU의 UEContextReleaseRequest(rl-failure)(AN04-T4), release가 False면 해제 줄이 없다(AN04-T7)
    def flow_P(self, t0, s=S_SHORT, est="mt-Access", full=True, length=1200, du_release=False, release=True):
        self.setup_req(t0, random=False, part1=part1_of(s), est=est)
        self.setup(t0)
        self.setup_complete(t0 + 10, s_tmsi=s if full else None)
        self.svc_req(t0 + 20, s_tmsi=s if full else None)
        self.svc_accept(t0 + 30)
        if not release:
            return self
        if du_release:
            self.ctx_release_req(t0 + length - 20)
        self.rrc_release(t0 + length - 10)
        self.ctx_release_cmd(t0 + length - 5)
        return self.ctx_release_complete(t0 + length)

    # 미완료 흐름 Q (21_ §7.8): 같은 Part1로 RRCSetupRequest → RRCSetup → (Complete 없음) → 시작 + 2 s에 CU의 UEContextReleaseCommand/
    # Complete. random이면 randomValue(AN07-T5), reject면 RRCSetup 대신 RRCReject — OCUDU는 거절을 UE 컨텍스트 해제로 보내므로 같은
    # 시각에 UEContextReleaseCommand, 5 ms 뒤 완료(AN07-T4, 11/04). release가 False면 해제 줄이 없다(stale_setup으로 닫힘)
    def flow_Q(self, t0, s=S_SHORT, random=False, reject=False, release=True):
        self.setup_req(t0, random=random, part1=None if random else part1_of(s))
        if reject:
            self.rrc_reject(t0)
            if release:
                self.ctx_release_cmd(t0)
                self.ctx_release_complete(t0 + 5)
            return self
        self.setup(t0)
        if release:
            self.ctx_release_cmd(t0 + 1995)
            self.ctx_release_complete(t0 + 2000)
        return self

    # 같은 Part1로 연결까지 가는 정상 접속 — Setup·Complete 뒤 6 s에 해제 (AN07-T1). 길이를 AN-04 short_ms(5 s)보다 길게 둔다 —
    # 같은 S-TMSI의 짧은 연결 3번은 AN-04에 걸린다
    def flow_connected(self, t0, s=S_SHORT):
        self.setup_req(t0, random=False, part1=part1_of(s))
        self.setup(t0)
        self.setup_complete(t0 + 10, s_tmsi=s)
        self.ctx_release_cmd(t0 + 5995)
        return self.ctx_release_complete(t0 + 6000)

    # 이동 등록 흐름 M의 뒷부분 (21_ §8.8): RRCSetupRequest(Part1) → RRCSetupComplete(s) → t0+20 RegistrationRequest(reg_type, 5G-GUTI,
    # s) → 시작 + length에 해제. 길이를 AN-04 short_ms(5 s)보다 길게 둔다 — 같은 S-TMSI의 짧은 연결이 쌓이면 AN-04에 걸린다
    def flow_mob(self, t0, s, reg_type="mobility", length=6000):
        self.setup_req(t0, random=False, part1=part1_of(s))
        self.setup(t0)
        self.setup_complete(t0 + 10, s_tmsi=s)
        self.reg_req(t0 + 20, reg_type=reg_type, id_type="5G-GUTI", s_tmsi=s)
        return self.release(t0 + length)

    # 할당 기억 없이 UE가 낸 S-TMSI만 남기는 연결 (AN08-T5): RRCSetupComplete·ServiceRequest에 s → ServiceAccept → 1 s에 해제
    def flow_ue_stmsi(self, t0, s):
        self.setup_req(t0)
        self.setup(t0)
        self.setup_complete(t0 + 10, s_tmsi=s)
        self.svc_req(t0 + 20, s_tmsi=s)
        self.svc_accept(t0 + 30)
        return self.release(t0 + 1000)

    def rrc_reject(self, t):
        # RRCReject(DL) → rrc REJECTED (14_ §5.1). 뒤에 UEContextReleaseCommand가 오면 RELEASING으로 덮인다
        return self._line(t, "DL", "RRC", "RRCReject")

    def ctx_release_req(self, t, cause="radioNetwork:rl-failure"):
        # UEContextReleaseRequest(UL) — DU가 먼저 해제를 요청(UE가 사라짐). f.cause가 상태표 rel_req_cause (14_ §2.2, AN-04 #33)
        return self._line(t, "UL", "F1AP", "UEContextReleaseRequest", {"cause": cause})


class Scenario4(gen_stage3.Scenario3):
    """4단계 시나리오 — UE4 흐름, hello node_id, 기대 경보의 candidates."""

    def ue(self, du, cell=1, crnti=None):
        u = UE4(du, cell=cell, crnti=crnti)
        self.ues.append(u)
        return u

    def hello(self, seq, session):
        h = super().hello(seq, session)
        h["node_id"] = "stage4_yellow"
        return h

    def alert(self, kind, t_rel, rule, cell=1, mode=None, severity=None, branch=None, reason=None, alert_kind=None,
              conditions=None, candidates=None, ues_total=None):
        a = super().alert(kind, t_rel, rule, cell=cell, mode=mode, severity=severity, branch=branch, reason=reason,
                          alert_kind=alert_kind, conditions=conditions)
        if candidates is not None:
            a["candidates"] = candidates   # raise의 후보 (14_ §8.3, 21_ §1) — 시험이 그 이벤트의 값과 비교
        if ues_total is not None:
            a["ues_total"] = ues_total     # 지금까지 걸린 UE 수 — CLEAR 뒤 옛 걸림 재수록 회귀(이슈 #84), 시험이 비교
        return a


# ============ AN-01 인증 동기 실패 재인증 (21_ §3.8 AN01-T1~T12 — T6·T7(n_sync 2)·T10 밀어내기·T11 설정·T12 결정성은 단위 시험) ============

RAN01 = "AN-01"
CAND01 = ["L3-07-OV"]


def raise01(sc, t_rel):
    return sc.alert("RAISE", t_rel, RAN01, severity="medium", alert_kind="anomaly", candidates=CAND01)


def san01_normal():
    sc = Scenario4("SAN01_AN-01_정상흐름_무경보", "기본 흐름 F + 해제 — 실패 줄 없음 (AN01-T1)", 3000)
    sc.ue(3).flow_F(B).release(B + 1000)
    return sc


def san01_raise():
    sc = Scenario4("SAN01_AN-01_동기실패_RAISE",
                   "S — t0+118 동기 실패(#21) 걸림, K = t0+200에 RAISE(kind anomaly, 후보 L3-07-OV). t0+160 재인증은 경보 값 "
                   "reauth 1 (AN01-T2)", 3000)
    sc.ue(3).flow_S(B)
    raise01(sc, K(B + 118))
    return sc


def san01_second_failure():
    sc = Scenario4("SAN01_AN-01_두번째동기실패_RAISE",
                   "t0+160 재인증 요청 뒤 t0+173에 다시 동기 실패, t0+180 AuthenticationReject — RAISE 1번(연결당 한 번), "
                   "경보 값 extra 1·reauth 1 (AN01-T3)", 8000)
    u = sc.ue(3).flow_F(B, until=118)
    u.auth_fail(B + 118, SYNCH_FAILURE).auth_req(B + 160).auth_fail(B + 173, SYNCH_FAILURE).auth_reject(B + 180)
    raise01(sc, K(B + 118))
    return sc


def san01_mac_failure():
    sc = Scenario4("SAN01_AN-01_MAC실패_무경보", "S에서 원인값 20(MAC 실패) — 걸림 없음, L3-21 몫 (AN01-T4)", 3000)
    sc.ue(3).flow_S(B, cause=20)
    return sc


def san01_no_cause():
    sc = Scenario4("SAN01_AN-01_원인값없음_무경보", "S에서 f 없는 AuthenticationFailure — 원인을 몰라 걸림 없음 (AN01-T5)", 3000)
    sc.ue(3).flow_S(B, cause=None)
    return sc


def san01_mid_join():
    sc = Scenario4("SAN01_AN-01_중간합류_RAISE",
                   "첫 줄이 AuthenticationFailure(21)(mid_join) — 원인값은 줄 자체에 있어 걸림, uncertain mid_join (AN01-T8)", 3000)
    sc.ue(5).auth_fail(B + 50, SYNCH_FAILURE)
    raise01(sc, K(B + 50))
    return sc


def san01_loss():
    sc = Scenario4("SAN01_AN-01_로스창_RAISE",
                   "S + 실패 줄이 든 창 [t0+100, t0+200) ue_evt_lost [\"UL\",\"DL\"] — 보류 없이 같은 RAISE, uncertain loss "
                   "(AN01-T9)", 3000)
    sc.ue(3).flow_S(B)
    sc.lost(B + 100, ["UL", "DL"])
    raise01(sc, K(B + 118))
    return sc


def san01_clear():
    sc = Scenario4("SAN01_AN-01_해제_CLEAR", "S 뒤 마지막 걸림(t0+118) + 60 s 이상인 첫 kpm2에 CLEAR (AN01-T10)", 62000)
    sc.ue(3).flow_S(B)
    raise01(sc, K(B + 118))
    sc.alert("CLEAR", K(B + 118 + 60000 - 1), RAN01, alert_kind="anomaly")
    return sc


def san01_two_ues():
    sc = Scenario4("SAN01_AN-01_두UE_UPDATE",
                   "UE A는 S(t0), UE B는 S(t0+500) — RAISE + 1 s 모음 UPDATE(경보 값 누적 수, UE 칸은 B만) (21_ §3.5)", 3000)
    sc.ue(1).flow_S(B)
    sc.ue(2).flow_S(B + 500)
    raise01(sc, K(B + 118))
    sc.alert("UPDATE", K(B + 118) + 1000, RAN01, severity="medium", alert_kind="anomaly")
    return sc


# ============ AN-06a 보안 수립 뒤 재인증·SMC 재등장 (21_ §4.8 AN06a-T1~T10 — T6(n_reauth 2)·T9 밀어내기·T10 설정·결정성은 단위 시험) ============

RAN06A = "AN-06a"
CAND06A = ["L3-06-O1"]


def raise06a(sc, t_rel):
    return sc.alert("RAISE", t_rel, RAN06A, severity="medium", alert_kind="anomaly", candidates=CAND06A)


def san06a_normal():
    sc = Scenario4("SAN06a_AN-06a_정상흐름_무경보", "기본 흐름 F + 해제 — 보안 뒤 명령이 다시 오지 않음 (AN06a-T1)", 3000)
    sc.ue(3).flow_F(B).release(B + 1000)
    return sc


def san06a_reauth():
    sc = Scenario4("SAN06a_AN-06a_보안뒤재인증_RAISE",
                   "R — t0+1,250 인증 요청(갱신 전 nas_sec ON) 걸림, K = t0+1,300에 RAISE(kind anomaly, 후보 L3-06-O1). "
                   "t0+1,270 NAS SMC는 갱신 전 AUTH_OK라 재등장 아님 (AN06a-T2)", 4000)
    sc.ue(3).flow_R(B)
    raise06a(sc, K(B + 1250))
    return sc


def san06a_smc_only():
    sc = Scenario4("SAN06a_AN-06a_보안뒤SMC재등장_RAISE",
                   "t0+1,250에 재인증 없이 NAS SecurityModeCommand만 다시 옴 — 걸림(msg SecurityModeCommand), RAISE (AN06a-T3)", 4000)
    sc.ue(3).flow_R(B, smc_only=True)
    raise06a(sc, K(B + 1250))
    return sc


def san06a_retx_smc():
    sc = Scenario4("SAN06a_AN-06a_AMF재전송SMC_무경보",
                   "F에서 t0+131 완료를 빼고 t0+6,125에 NAS SMC 재전송 — 갱신 전 CMD라 걸림 없음 (AN06a-T4)", 8000)
    sc.ue(3).flow_F(B, skip=("NasSecurityModeComplete",)).nas_smc(B + 6125)
    return sc


def san06a_retx_auth():
    sc = Scenario4("SAN06a_AN-06a_AMF재전송인증_무경보",
                   "t0+118 응답 없이 t0+6,105에 인증 요청 재전송 — 갱신 전 AUTH라 걸림 없음 (AN06a-T4)", 8000)
    sc.ue(3).flow_F(B, until=118).auth_req(B + 6105)
    return sc


def san06a_second():
    sc = Scenario4("SAN06a_AN-06a_두번째재등장_RAISE",
                   "R + t0+2,250 인증 요청(두 번째 재등장) — RAISE 1번, 경보 값 extra 1 (AN06a-T5)", 4000)
    sc.ue(3).flow_R(B).auth_req(B + 2250)
    raise06a(sc, K(B + 1250))
    return sc


def san06a_mid_join():
    sc = Scenario4("SAN06a_AN-06a_중간합류_무경보",
                   "첫 줄이 AuthenticationRequest(mid_join) — nas_sec UNKNOWN이라 걸림 없음 (AN06a-T7)", 3000)
    sc.ue(5).auth_req(B + 50).auth_resp(B + 60)
    return sc


def san06a_complete_lost():
    sc = Scenario4("SAN06a_AN-06a_완료줄로스_무경보",
                   "F의 t0+131 완료 줄을 로스로 놓침(그 창 ue_evt_lost [\"UL\",\"DL\"]) — nas_sec이 CMD로 남아 R의 재등장을 못 봄 "
                   "(AN06a-T8)", 4000)
    sc.ue(3).flow_R(B, skip=("NasSecurityModeComplete",))
    sc.lost(B + 100, ["UL", "DL"])
    return sc


def san06a_clear():
    sc = Scenario4("SAN06a_AN-06a_해제_CLEAR", "R 뒤 마지막 걸림(t0+1,250) + 60 s 이상인 첫 kpm2에 CLEAR (AN06a-T9)", 63000)
    sc.ue(3).flow_R(B)
    raise06a(sc, K(B + 1250))
    sc.alert("CLEAR", K(B + 1250 + 60000 - 1), RAN06A, alert_kind="anomaly")
    return sc


# ============ AN-02 식별 요청 증가 (21_ §5.8 AN02-T1~T8 + 11/04 결정 AN02-T9 — T6 보안 뒤·T7 할당 만료·mid_join·설정·결정성은 단위 시험) ============

RAN02 = "AN-02"
CAND02 = ["L3-25-OV"]


def an02(sc, kind, t_rel, branch):
    return sc.alert(kind, t_rel, RAN02, severity="medium" if kind in ("RAISE", "UPDATE") else None, branch=branch,
                    alert_kind="anomaly", candidates=CAND02 if kind == "RAISE" else None)


def san02_suci():
    sc = Scenario4("SAN02_AN-02_SUCI등록_무경보", "기본 흐름 F(SUCI 첫 등록) + 해제 — 식별 요청 없음 (AN02-T1)", 3000)
    sc.ue(3).flow_F(B).release(B + 1000)
    return sc


def san02_guti_no_idreq():
    sc = Scenario4("SAN02_AN-02_준GUTI식별없음_무경보",
                   "G — A가 RegistrationAccept로 S를 받고 해제, B가 5G-GUTI S로 등록해 식별 요청 없이 진행 (AN02-T1)", 8000)
    sc.ue(1).flow_alloc(B)
    sc.ue(2).guti_head(5000).flow_F(5000, rest_from=105)
    return sc


def san02_known_guti():
    sc = Scenario4("SAN02_AN-02_준GUTI식별요청_RAISE",
                   "G에서 B의 등록 요청(t+91) 뒤 t+96 IdentityRequest — 갈래 ① 걸림, K에 RAISE branch 1 (AN02-T2)", 8000)
    sc.ue(1).flow_alloc(B)
    u = sc.ue(2).guti_head(5000)
    u.id_req(5096).id_resp(5099).flow_F(5000, rest_from=105)
    an02(sc, "RAISE", K(5096), "1")
    return sc


def san02_attack_shape():
    sc = Scenario4("SAN02_AN-02_공격모양RRC원래값_RAISE",
                   "중간자가 NAS 등록 요청의 GUTI만 모르는 값으로 바꿈 — RRC S-TMSI는 원래 값(할당됨)이라 갈래 ① RAISE "
                   "(11/04 결정, AN02-T9)", 8000)
    sc.ue(1).flow_alloc(B)
    sc.ue(2).guti_head(5000, nas_s=S_UNKNOWN).id_req(5096).id_resp(5099)
    an02(sc, "RAISE", K(5096), "1")
    return sc


def san02_unknown_guti():
    sc = Scenario4("SAN02_AN-02_모르는GUTI_무경보",
                   "B가 모르는 GUTI(RRC·NAS 모두 S′)로 등록 → IdentityRequest — 갈래 ① 없음, 갈래 ② 수 1 (AN02-T3)", 8000)
    sc.ue(1).flow_alloc(B)
    sc.ue(2).guti_head(5000, rrc_s=S_UNKNOWN, nas_s=S_UNKNOWN).id_req(5096).id_resp(5099)
    return sc


def san02_five():
    sc = Scenario4("SAN02_AN-02_식별요청5UE_RAISE",
                   "5 UE가 10 s 간격으로 SUCI 등록 뒤 IdentityRequest — 5번째에서 창 안 5, RAISE branch 2 (AN02-T4)", 45000)
    for i in range(5):
        sc.ue(10 + i).flow_F(B + 10000 * i, identity=True)
    an02(sc, "RAISE", K(B + 40000 + 95), "2")
    return sc


def san02_four():
    sc = Scenario4("SAN02_AN-02_식별요청4UE_무경보", "T4에서 4 UE만 — 창 안 4 (AN02-T5)", 45000)
    for i in range(4):
        sc.ue(10 + i).flow_F(B + 10000 * i, identity=True)
    return sc


def san02_clear():
    sc = Scenario4("SAN02_AN-02_해제_CLEAR",
                   "T2 RAISE 뒤 30 s에 SUCI 식별 요청 UE 하나(성립 아님) — UPDATE로 실리지만 해제는 마지막 성립(t+96) + 60 s "
                   "(21_ §5.5, AN02-T8)", 66000)
    sc.ue(1).flow_alloc(B)
    sc.ue(2).guti_head(5000).id_req(5096).id_resp(5099)
    sc.ue(3).flow_F(35000, identity=True)
    an02(sc, "RAISE", K(5096), "1")
    an02(sc, "UPDATE", K(35095), "1")
    an02(sc, "CLEAR", K(5096 + 60000 - 1), "1")
    return sc


# ============ AN-04 같은 UE의 짧은 연결 반복 (21_ §6.8 AN04-T1~T8 — 창 밖·유령 정리·설정·결정성·회복은 단위 시험) ============

RAN04 = "AN-04"
CAND04_PAGING = ["L3-02-Oa", "L3-34-OV", "L3-12-V"]


def an04(sc, kind, t_rel, candidates=None, ues_total=None):
    return sc.alert(kind, t_rel, RAN04, severity="medium" if kind in ("RAISE", "UPDATE") else None, alert_kind="anomaly",
                    candidates=candidates, ues_total=ues_total)


def p_n(sc, n, t0, gap, du0, s=S_SHORT, **kw):
    """같은 S-TMSI s의 P를 n번 (시작 t0, 간격 gap, du는 du0부터). 마지막 연결이 닫힌 시각을 돌려준다."""
    length = kw.get("length", 1200)
    for i in range(n):
        sc.ue(du0 + i).flow_P(t0 + gap * i, s=s, **kw)
    return t0 + gap * (n - 1) + length


def san04_long():
    sc = Scenario4("SAN04_AN-04_긴세션3번_무경보",
                   "같은 S-TMSI가 6 s 세션(> short_ms 5 s)을 20 s 간격 3번 — 짧은 연결이 아님 (AN04-T1)", 50000)
    p_n(sc, 3, B, 20000, 10, length=6000)
    return sc


def san04_three():
    sc = Scenario4("SAN04_AN-04_짧은연결3번_RAISE",
                   "P × 3(1.2 s 연결, 20 s 간격, est_cause mt-Access) — 3번째 닫힘에서 K 3, RAISE 후보는 페이징 셋 (AN04-T2)",
                   45000)
    t_end = p_n(sc, 3, B, 20000, 10)
    an04(sc, "RAISE", K(t_end), CAND04_PAGING)
    return sc


def san04_two():
    sc = Scenario4("SAN04_AN-04_짧은연결2번_무경보", "P × 2 — K 2 < n_short 3 (AN04-T3)", 25000)
    p_n(sc, 2, B, 20000, 10)
    return sc


def san04_du_release():
    sc = Scenario4("SAN04_AN-04_DU해제요청_RAISE",
                   "P에서 est_cause mo-Data, 해제가 DU의 UEContextReleaseRequest(rl-failure) 뒤 × 3 — 후보 L3-33-V (AN04-T4)",
                   45000)
    t_end = p_n(sc, 3, B, 20000, 10, est="mo-Data", du_release=True)
    an04(sc, "RAISE", K(t_end), ["L3-33-V"])
    return sc


def san04_four():
    sc = Scenario4("SAN04_AN-04_네번째반복_RAISE",
                   "P × 4 — RAISE 1번, 4번째는 경보 values.extra(UE 칸·UPDATE 아님, 11/04 결정) (AN04-T5)", 65000)
    p_n(sc, 4, B, 20000, 10)
    an04(sc, "RAISE", K(B + 40000 + 1200), CAND04_PAGING)
    return sc


def san04_part1():
    sc = Scenario4("SAN04_AN-04_Part1만_RAISE",
                   "RRCSetupComplete·ServiceRequest에 s_tmsi 없이 Part1만 아는 P × 3 — Part1 색인으로 세어 RAISE (AN04-T6)", 45000)
    t_end = p_n(sc, 3, B, 20000, 10, full=False)
    an04(sc, "RAISE", K(t_end), CAND04_PAGING)
    return sc


def san04_du_reset():
    sc = Scenario4("SAN04_AN-04_DU리셋닫힘_무경보",
                   "P × 3 중 둘째가 해제 줄 없이 F1Reset(du_reset)으로 닫힘 — 판정하지 않는 닫힘이라 세지 않아 K 2 "
                   "(11/04 결정, AN04-T7 갈래)", 45000)
    sc.ue(10).flow_P(B)
    sc.ue(11).flow_P(B + 20000, release=False)
    sc.add_raw(B + 20500, {"type": "f1_evt", "t_ms": T0 + B + 20500, "msg": "F1Reset", "cells": [1], "du_ue_ids": [11]})
    sc.ue(12).flow_P(B + 40000)
    return sc


def san04_two_stmsi():
    sc = Scenario4("SAN04_AN-04_두STMSI_UPDATE",
                   "S × 4(RAISE, 4번째는 extra) + 둘째 S-TMSI × 3(45 s부터) — 둘째가 걸린 칸에 UPDATE (AN04-T5)", 88000)
    p_n(sc, 4, B, 20000, 10)
    t2 = p_n(sc, 3, 45000, 20000, 20, s=S_SHORT2)
    an04(sc, "RAISE", K(B + 40000 + 1200), CAND04_PAGING)
    an04(sc, "UPDATE", K(t2))
    return sc


def san04_clear():
    sc = Scenario4("SAN04_AN-04_해제_CLEAR",
                   "P × 3 RAISE 뒤 마지막 걸림 + 60 s 이상인 첫 kpm2에 CLEAR (AN04-T8)", 103000)
    t_end = p_n(sc, 3, B, 20000, 10)
    an04(sc, "RAISE", K(t_end), CAND04_PAGING)
    an04(sc, "CLEAR", K(t_end + 60000 - 1))
    return sc


def san04_clear_then_other():
    sc = Scenario4("SAN04_AN-04_CLEAR뒤다른STMSI_RAISE",
                   "P × 3(RAISE) → 60 s 조용 → CLEAR → 둘째 S-TMSI × 3(150 s부터, 창 W 300 s 안) — 둘째 RAISE는 CLEAR 뒤 걸림만 싣는다"
                   "(ues_total 1). 그전에는 창에 남은 첫 S-TMSI 걸림이 다시 실려 ues_total 2였다 (23_ §3.1-2, 이슈 #84)", 260000)
    t1 = p_n(sc, 3, B, 20000, 10)
    t2 = p_n(sc, 3, 150000, 20000, 20, s=S_SHORT2)
    an04(sc, "RAISE", K(t1), CAND04_PAGING, ues_total=1)
    an04(sc, "CLEAR", K(t1 + 60000 - 1), ues_total=1)
    an04(sc, "RAISE", K(t2), CAND04_PAGING, ues_total=1)
    an04(sc, "CLEAR", K(t2 + 60000 - 1), ues_total=1)
    return sc


def san04_sustained():
    sc = Scenario4("SAN04_AN-04_지속공격_CLEAR",
                   "P × 20(20 s 간격) — 3번째 닫힘에서 RAISE, 4번째부터 경보 values.extra, 마지막 걸림 + 60 s에 CLEAR, 그 뒤 17회가 이어져도 "
                   "경보 없음 — 명세(21_ §6.3-2·§6.5)대로의 지금 동작(Q-69 미결, 23_ §3.1-1). 결정(W-28) 뒤 기대값을 바꾼다", 420000)
    p_n(sc, 20, B, 20000, 10)
    an04(sc, "RAISE", K(B + 40000 + 1200), CAND04_PAGING, ues_total=1)
    an04(sc, "CLEAR", K(B + 40000 + 1200 + 60000 - 1), ues_total=1)
    return sc


# ============ AN-07 같은 S-TMSI의 Setup 반복·Complete 없음 (21_ §7.8 AN07-T1~T7 — reused·회복·설정·결정성은 단위 시험) ============

RAN07 = "AN-07"
CAND07 = ["L3-11-V1", "L3-11-V2"]


def an07(sc, kind, t_rel):
    return sc.alert(kind, t_rel, RAN07, severity="medium" if kind in ("RAISE", "UPDATE") else None, alert_kind="anomaly",
                    candidates=CAND07 if kind == "RAISE" else None)


def q_n(sc, n, t0, gap, du0, s=S_SHORT, **kw):
    """같은 Part1의 Q를 n번 (시작 t0, 간격 gap, du는 du0부터). 마지막 연결이 해제 줄로 닫힌 시각을 돌려준다."""
    for i in range(n):
        sc.ue(du0 + i).flow_Q(t0 + gap * i, s=s, **kw)
    return t0 + gap * (n - 1) + 2000


def san07_connected():
    sc = Scenario4("SAN07_AN-07_정상등록3번_무경보",
                   "같은 Part1로 Setup·Complete까지 가는 6 s 접속 × 3 — CONNECTED라 세지 않음(6 s라 AN-04 짧은 연결도 아님) (AN07-T1)",
                   30000)
    for i in range(3):
        sc.ue(10 + i).flow_connected(B + 10000 * i)
    return sc


def san07_three():
    sc = Scenario4("SAN07_AN-07_미완료3번_RAISE",
                   "Q × 3(Complete 없이 2 s 뒤 CU 해제, 10 s 간격) — 3번째 닫힘에서 K 3, RAISE 후보 L3-11-V1·V2 (AN07-T2)", 25000)
    t_end = q_n(sc, 3, B, 10000, 10)
    an07(sc, "RAISE", K(t_end))
    return sc


def san07_two():
    sc = Scenario4("SAN07_AN-07_미완료2번_무경보", "Q × 2 — K 2 < n_fail 3 (AN07-T3)", 15000)
    q_n(sc, 2, B, 10000, 10)
    return sc


def san07_outside():
    sc = Scenario4("SAN07_AN-07_창밖_무경보", "Q × 3을 61 s 간격 — 창 60 s 안에 늘 하나뿐 (AN07-T3)", 127000)
    q_n(sc, 3, B, 61000, 10)
    return sc


def san07_reject_release():
    sc = Scenario4("SAN07_AN-07_망거절해제_무경보",
                   "RRCSetup 대신 RRCReject + 같은 시각 UEContextReleaseCommand × 3 — rrc는 RELEASING으로 덮이지만 거절을 봐서 "
                   "세지 않음 (11/04 사용자 결정, AN07-T4)", 25000)
    q_n(sc, 3, B, 10000, 10, reject=True)
    return sc


def san07_reject_stale():
    sc = Scenario4("SAN07_AN-07_망거절정리_무경보",
                   "RRCReject × 3, 해제 줄 없이 30 s 뒤 stale_setup으로 닫힘(rrc REJECTED) — 세지 않음 (AN07-T4)", 53000)
    q_n(sc, 3, B, 10000, 10, reject=True, release=False)
    return sc


def san07_random():
    sc = Scenario4("SAN07_AN-07_무작위ID_무경보", "randomValue로 Q × 3 — Part1이 없어 잇지 못함, 1단계 몫 (AN07-T5)", 25000)
    q_n(sc, 3, B, 10000, 10, random=True)
    return sc


def san07_stale():
    sc = Scenario4("SAN07_AN-07_정리닫힘포함_RAISE",
                   "Q × 3 중 둘째가 해제 줄 없이 stale_setup(마지막 줄 + 30 s)으로 닫힘 — 센다. 셋째 닫힘 때는 K 2, 둘째가 닫히는 "
                   "마감을 처리한 kpm2에서 RAISE (AN07-T6)", 43000)
    sc.ue(10).flow_Q(B)
    sc.ue(11).flow_Q(B + 10000, release=False)
    sc.ue(12).flow_Q(B + 20000)
    an07(sc, "RAISE", B + 10000 + 30000)   # 마감 41,000 = 그 kpm2의 t_end
    return sc


def san07_du_reset():
    sc = Scenario4("SAN07_AN-07_DU리셋닫힘_무경보",
                   "Q × 3 중 둘째가 해제 줄 없이 F1Reset(du_reset)으로 닫힘 — 판정하지 않는 닫힘이라 세지 않아 K 2 (11/04 결정)",
                   25000)
    sc.ue(10).flow_Q(B)
    sc.ue(11).flow_Q(B + 10000, release=False)
    sc.add_raw(B + 11000, {"type": "f1_evt", "t_ms": T0 + B + 11000, "msg": "F1Reset", "cells": [1], "du_ue_ids": [11]})
    sc.ue(12).flow_Q(B + 20000)
    return sc


def san07_two_part1():
    sc = Scenario4("SAN07_AN-07_두Part1_UPDATE",
                   "Part1 하나 × 4(RAISE, 4번째는 경보 값 extra — 11/04 결정) + 둘째 Part1 × 3(25 s부터) — 둘째가 걸린 칸에 UPDATE",
                   49000)
    q_n(sc, 4, B, 10000, 10)
    t2 = q_n(sc, 3, 25000, 10000, 20, s=S_SHORT2)
    an07(sc, "RAISE", K(B + 20000 + 2000))
    an07(sc, "UPDATE", K(t2))
    return sc


def san07_clear():
    sc = Scenario4("SAN07_AN-07_해제_CLEAR", "Q × 3 RAISE 뒤 마지막 걸림 + 60 s 이상인 첫 kpm2에 CLEAR (AN07-T7)", 84000)
    t_end = q_n(sc, 3, B, 10000, 10)
    an07(sc, "RAISE", K(t_end))
    an07(sc, "CLEAR", K(t_end + 60000 - 1))
    return sc


# ============ AN-08 기존 UE들의 재등록 급증 (21_ §8.8 AN08-T1~T8 — known_ms·RRC 또는 NAS·설정·결정성·회복은 단위 시험) ============

RAN08 = "AN-08"
CAND08 = ["L3-17-OV", "L3-26-O"]
M0 = 21000   # 이동 등록 시작 — 첫 등록(1~10 s) 뒤 (명세 M의 '2분 뒤'를 줄임 — known_ms 10분 안이면 같다)


def an08(sc, kind, t_rel):
    return sc.alert(kind, t_rel, RAN08, severity="medium" if kind in ("RAISE", "UPDATE") else None, alert_kind="anomaly",
                    candidates=CAND08 if kind == "RAISE" else None)


def alloc_all(sc, accept=True):
    """흐름 M의 앞부분: S1~S5가 B부터 2 s 간격으로 첫 등록(du 1~5). accept면 RegistrationAccept가 Si를 줌(할당 기억), 아니면 UE가 낸
    S-TMSI의 연결 레코드만(AN08-T5)."""
    for i in range(5):
        u = sc.ue(1 + i)
        u.flow_alloc(B + 2000 * i, s=S_MOB[i]) if accept else u.flow_ue_stmsi(B + 2000 * i, S_MOB[i])


def mob_all(sc, n=5, gap=10000, reg_type="mobility"):
    """흐름 M의 뒷부분: S1~Sn이 M0부터 gap 간격으로 이동 등록(du 11~). 마지막 걸림(등록 요청) 시각을 돌려준다."""
    for i in range(n):
        sc.ue(11 + i).flow_mob(M0 + gap * i, S_MOB[i], reg_type=reg_type)
    return M0 + gap * (n - 1) + 20


def san08_initial():
    sc = Scenario4("SAN08_AN-08_초기등록5UE_무경보", "5 UE의 첫 등록(initial, RegistrationAccept로 S1~S5 할당) — 걸림 없음 (AN08-T1)",
                   12000)
    alloc_all(sc)
    return sc


def san08_five():
    sc = Scenario4("SAN08_AN-08_이동등록5UE_RAISE",
                   "M — S1~S5를 할당받은 5 UE가 20 s 뒤부터 10 s 간격으로 이동 등록(5G-GUTI Si) — 5번째에서 서로 다른 S-TMSI 5, "
                   "RAISE (AN08-T2)", 68000)
    alloc_all(sc)
    t = mob_all(sc)
    an08(sc, "RAISE", K(t))
    return sc


def san08_four():
    sc = Scenario4("SAN08_AN-08_이동등록4UE_무경보", "M에서 4 UE만 — 창 안 4 (AN08-T3)", 58000)
    alloc_all(sc)
    mob_all(sc, n=4)
    return sc


def san08_outside():
    sc = Scenario4("SAN08_AN-08_창밖_무경보", "M에서 5번째가 첫째의 61 s 뒤 — 창 안 4 (AN08-T3)", 89000)
    alloc_all(sc)
    mob_all(sc, n=4)
    sc.ue(15).flow_mob(M0 + 61000, S_MOB[4])
    return sc


def san08_periodic():
    sc = Scenario4("SAN08_AN-08_주기등록_무경보", "M에서 reg_type periodic — 세지 않음 (AN08-T4)", 68000)
    alloc_all(sc)
    mob_all(sc, reg_type="periodic")
    return sc


def san08_initial_again():
    sc = Scenario4("SAN08_AN-08_초기재접속_무경보", "M에서 reg_type initial(재시작 뒤 일제 재접속) — 세지 않음 (AN08-T4)", 68000)
    alloc_all(sc)
    mob_all(sc, reg_type="initial")
    return sc


def san08_history():
    sc = Scenario4("SAN08_AN-08_이력만_RAISE",
                   "할당 기억 없이(RegistrationAccept 없음) UE가 낸 S-TMSI의 연결 레코드만 있는 5 UE의 이동 등록 — known history로 "
                   "세어 RAISE (AN08-T5)", 68000)
    alloc_all(sc, accept=False)
    t = mob_all(sc)
    an08(sc, "RAISE", K(t))
    return sc


def san08_unknown():
    sc = Scenario4("SAN08_AN-08_처음보는STMSI_무경보", "처음 보는 S-TMSI 5개의 이동 등록 — 최근 본 UE가 아님 (AN08-T6)", 68000)
    mob_all(sc)
    return sc


def san08_retries():
    sc = Scenario4("SAN08_AN-08_한UE재시도_무경보",
                   "S1이 이동 등록을 10 s 간격 5번(실패 뒤 T3511 재시도 — 연결마다 새 du) — 서로 다른 S-TMSI 1 (11/04 사용자 결정, "
                   "AN08-T8)", 70000)
    alloc_all(sc)
    for k in range(5):
        sc.ue(20 + k).flow_mob(M0 + 10000 * k, S_MOB[0])
    return sc


def san08_retries_then_four():
    sc = Scenario4("SAN08_AN-08_재시도뒤4UE_RAISE",
                   "S1의 재시도 5번 뒤 S2~S5가 창 안에 이동 등록 — 서로 다른 S-TMSI 5로 RAISE(S1 칸 하나, 경보 값 extra 4) "
                   "(11/04 사용자 결정, AN08-T8)", 78000)
    alloc_all(sc)
    for k in range(5):
        sc.ue(20 + k).flow_mob(M0 + 10000 * k, S_MOB[0])
    for i in range(1, 5):
        sc.ue(30 + i).flow_mob(M0 + 42000 + 2000 * i, S_MOB[i])
    an08(sc, "RAISE", K(M0 + 42000 + 2000 * 4 + 20))
    return sc


def san08_clear():
    sc = Scenario4("SAN08_AN-08_해제_CLEAR", "M RAISE 뒤 마지막 성립 + 60 s 이상인 첫 kpm2에 CLEAR (AN08-T7)", 123000)
    alloc_all(sc)
    t = mob_all(sc)
    an08(sc, "RAISE", K(t))
    an08(sc, "CLEAR", K(t + 60000 - 1))
    return sc


SCENARIOS = [
    san01_normal, san01_raise, san01_second_failure, san01_mac_failure, san01_no_cause, san01_mid_join, san01_loss,
    san01_clear, san01_two_ues,
    san06a_normal, san06a_reauth, san06a_smc_only, san06a_retx_smc, san06a_retx_auth, san06a_second, san06a_mid_join,
    san06a_complete_lost, san06a_clear,
    san02_suci, san02_guti_no_idreq, san02_known_guti, san02_attack_shape, san02_unknown_guti, san02_five, san02_four,
    san02_clear,
    san04_long, san04_three, san04_two, san04_du_release, san04_four, san04_part1, san04_du_reset, san04_two_stmsi,
    san04_clear, san04_clear_then_other, san04_sustained,
    san07_connected, san07_three, san07_two, san07_outside, san07_reject_release, san07_reject_stale, san07_random,
    san07_stale, san07_du_reset, san07_two_part1, san07_clear,
    san08_initial, san08_five, san08_four, san08_outside, san08_periodic, san08_initial_again, san08_history,
    san08_unknown, san08_retries, san08_retries_then_four, san08_clear,
]


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "tests", "data", "stage4_yellow")
    os.makedirs(out_dir, exist_ok=True)
    for make in SCENARIOS:
        sc = make()
        lines = sc.build()
        with open(os.path.join(out_dir, sc.name + ".jsonl"), "w", encoding="utf-8") as f:
            for line in lines:
                f.write(gen_stage2.json.dumps(line, ensure_ascii=False, separators=(",", ":")) + "\n")
        expected = {"scenario": sc.name, "description": sc.desc, "t0_ms": T0, "tolerance_ms": gen_stage2.P,
                    "alerts": sc.expect}
        with open(os.path.join(out_dir, sc.name + ".expected.json"), "w", encoding="utf-8") as f:
            gen_stage2.json.dump(expected, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print(f"{sc.name}: {len(lines)} lines, {len(sc.expect)} alerts expected")


if __name__ == "__main__":
    main()
