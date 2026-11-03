#!/usr/bin/env python3
"""합성 ue_evt+kpm2 3단계 시나리오(.jsonl)와 기대 경보(.expected.json) 생성기.

명세: 3단계 룰 20_탐지엔진_3단계-연한녹색룰_명세서.md(L3-24 §3.8, L3-14 §4.8), 입력 2_ §6, 상태·경보 14_.
실행: python3 tools/gen_stage3.py [출력 폴더]  (기본 tests/data/stage3_lightgreen/).
tests/core/test_scenarios.cpp가 이 폴더를 실행 파일과 같은 룰 구성(1·2·3단계, 기본값)으로 재생해 같은 이름
.expected.json과 비교한다(Stage3Scenario, 시각 정확 비교). 2단계 생성기 gen_stage2.py의 UE·Scenario 틀을 그대로 쓰고
3단계 메시지 4개(IdentityRequest·IdentityResponse·UECapabilityEnquiry·UECapabilityInformation, 20_ §1.1)와
기본 흐름 F(20_ §3.8)만 더한다(4_ §6.2 #6).

기대 경보 시각은 생성기가 계산하지 않고 명세 식으로 손 계산한 값이다(2단계와 같은 방식):
 - 연결 시작 t0 = 1000(창 시작). K(t) = t를 품은 창의 t_end = t0 + 100 × (⌊(t − t0)/100⌋ + 1) — '요청 없는 응답'의
   판정·RAISE 시각(마감 = 판정 줄 + 1 ms, 20_ §1.2-3)
 - UPDATE = 새 UE가 걸린 뒤 RAISE·UPDATE에서 update_min_ms(1,000) 이상인 첫 kpm2(14_ §8.2)
 - CLEAR = 마지막 걸림(응답 t_r) + clear_quiet_ms(60,000) 이상인 첫 kpm2(20_ §3.5)
시각은 모두 데이터 시작(T0)부터의 상대 ms다.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_stage2  # noqa: E402  (같은 폴더의 2단계 생성기 — UE·Scenario 틀)
from gen_stage2 import P, T0  # noqa: E402

B = 1000       # 연결 시작 t0 (상대 ms, 창 시작)
GUTI = "0x0123456789ab"


def K(t):
    """t를 품은 창의 t_end (20_ §3.8 시험 공통)."""
    return B + P * ((t - B) // P + 1)


class UE3(gen_stage2.UE):
    """3단계 메시지와 기본 흐름 F를 더한 UE 흐름."""

    # --- 3단계 메시지 4개 (20_ §1.1 — f 없음, 메시지 이름만) ---
    def id_req(self, t):
        return self._line(t, "DL", "NAS", "IdentityRequest")

    def id_resp(self, t, f=None):
        # f는 약속에 없다 — L24-T5처럼 일부러 붙일 때만
        return self._line(t, "UL", "NAS", "IdentityResponse", f)

    def cap_enq(self, t):
        return self._line(t, "DL", "RRC", "UECapabilityEnquiry")

    def cap_info(self, t):
        return self._line(t, "UL", "RRC", "UECapabilityInformation")

    # --- 기본 흐름에 쓰는 그 밖의 줄 ---
    def nas_smcomplete(self, t):
        return self._line(t, "UL", "NAS", "SecurityModeComplete", sht=4)

    def protected_nas(self, t):
        # NAS 암호가 켜진 뒤의 줄 — 이름이 보이지 않는다(2_ §6.3, L24-T17)
        return self._line(t, "UL", "NAS", "ProtectedNAS", sht=2)

    def rrc_smfailure(self, t):
        # RRC SecurityModeFailure(UL) → rrc_sec FAILED (14_ §5.3, L14-T5)
        return self._line(t, "UL", "RRC", "SecurityModeFailure")

    def release(self, t):
        self.ctx_release_cmd(t)
        return self.ctx_release_complete(t)

    def ngap_nas(self, t, msg, direction="UL"):
        # F1AP ID에 잇지 못한 NGAP NAS 줄(du_ue_id null, 2_ §6.6) — UE 항목에 붙지 않는다(L24-T21)
        d = {"type": "ue_evt", "t_ms": T0 + t, "cell_id": self.cell, "du_ue_id": None, "cu_ue_id": self.cu,
             "crnti": None, "dir": direction, "proto": "NAS", "msg": msg, "via": "NGAP", "sht": 0}
        self.evts.append((t, d))
        return self

    def out_of_order(self, t_order, t_ms, direction, proto, msg):
        """순서 위반 줄: t_order 자리(같은 시각이면 넣은 순서)에 내되 t_ms는 그보다 이른 값 — 같은 UE 줄 순서 전제(2_ §6.1)를
        깨는 입력(L24-T24)."""
        self._line(t_order, direction, proto, msg)
        self.evts[-1][1]["t_ms"] = T0 + t_ms
        return self

    # 흐름 앞부분 (20_ §3.8 F의 t0~t0+91): RRC 보안 전에 머문 연결
    def head(self, t0, guti=False):
        self.setup_req(t0)
        self.setup(t0)
        self.setup_complete(t0 + 91)
        if guti:
            self.reg_req(t0 + 91, id_type="5G-GUTI", s_tmsi=GUTI)
        else:
            self.reg_req(t0 + 91, id_type="SUCI")
        return self

    # 기본 흐름 F (20_ §3.8). identity = 모르는 5G-GUTI 등록 뒤 AMF의 식별 요청·응답(L24-T2), skip = 뺄 메시지 이름
    def flow_F(self, t0, guti=False, identity=False, integrity="nia2", cap=True, skip=(), rest_from=0, until=None):
        steps = [
            (0, "RRCSetupRequest", lambda t: self.setup_req(t)),
            (0, "RRCSetup", lambda t: self.setup(t)),
            (91, "RRCSetupComplete", lambda t: self.setup_complete(t)),
            (91, "RegistrationRequest",
             lambda t: self.reg_req(t, id_type="5G-GUTI", s_tmsi=GUTI) if guti else self.reg_req(t, id_type="SUCI")),
        ]
        if identity:
            steps += [(95, "IdentityRequest", lambda t: self.id_req(t)),
                      (100, "IdentityResponse", lambda t: self.id_resp(t))]
        steps += [
            (105, "AuthenticationRequest", lambda t: self.auth_req(t)),
            (118, "AuthenticationResponse", lambda t: self.auth_resp(t)),
            (125, "NasSecurityModeCommand", lambda t: self.nas_smc(t)),
            (131, "NasSecurityModeComplete", lambda t: self.nas_smcomplete(t)),
            (140, "RrcSecurityModeCommand", lambda t: self.rrc_smc(t, integrity=integrity)),
            (150, "RrcSecurityModeComplete", lambda t: self.rrc_smcomplete(t)),
        ]
        if cap:
            steps += [(160, "UECapabilityEnquiry", lambda t: self.cap_enq(t)),
                      (175, "UECapabilityInformation", lambda t: self.cap_info(t))]
        steps += [(190, "RegistrationAccept", lambda t: self.reg_accept(t)),
                  (200, "RegistrationComplete", lambda t: self.reg_complete(t))]
        for dt, name, add in steps:
            if name in skip or dt < rest_from or (until is not None and dt >= until):
                continue
            add(t0 + dt)
        return self

    # C2 흐름 (20_ §4.8): F에서 t0+160·t0+175를 빼고 RRC 보안 모드 명령 전 t0+120에 CU 능력 요청 → t0+130 UE 응답
    def c2(self, t0, until=None):
        self.flow_F(t0, cap=False, until=until)
        self.cap_enq(t0 + 120)
        return self.cap_info(t0 + 130)

    # DL을 보지 못하는 분석 엔진(ue_evt_lost 늘 "DL") — DL 줄을 모두 뺀다(L24-T22)
    def drop_dl(self):
        self.evts = [(t, d) for (t, d) in self.evts if d["dir"] != "DL"]
        return self


class Scenario3(gen_stage2.Scenario):
    """3단계 시나리오 — UE3 흐름, hello node_id, 기대 경보의 conditions."""

    def ue(self, du, cell=1, crnti=None):
        u = UE3(du, cell=cell, crnti=crnti)
        self.ues.append(u)
        return u

    def hello(self, seq, session):
        h = super().hello(seq, session)
        h["node_id"] = "stage3_lightgreen"
        return h

    def alert(self, kind, t_rel, rule, cell=1, mode=None, severity=None, branch=None, reason=None, alert_kind=None,
              conditions=None):
        a = super().alert(kind, t_rel, rule, cell=cell, mode=mode, severity=severity, branch=branch, reason=reason,
                          alert_kind=alert_kind)
        if conditions is not None:
            a["conditions"] = conditions   # 3단계 성립 전제 (20_ §1.3) — 시험이 그 이벤트의 값과 비교
        return a

    def lost(self, t_start, dirs):
        """창 [t_start, t_start + 100)의 ue_evt_lost."""
        self.set_loss(1, t_start // P, dirs)

    def lost_all(self, dirs):
        for i in range(self.duration // P):
            self.set_loss(1, i, dirs)


R24 = "L3-24"
MITM = ["mitm_ul_relay"]


def raise24(sc, t_rel):
    return sc.alert("RAISE", t_rel, R24, severity="medium", alert_kind="attack", conditions=MITM)


def held24(sc, t_rel):
    return sc.alert("RAISE", t_rel, R24, severity="medium", alert_kind="anomaly")


R14 = "L3-14"


def raise14(sc, t_rel, branch, conditions):
    sev = "high" if branch == "2" else "medium"
    return sc.alert("RAISE", t_rel, R14, severity=sev, branch=branch, alert_kind="attack", conditions=conditions)


def update14(sc, t_rel, branch, conditions=None):
    sev = "high" if branch == "2" else "medium"
    return sc.alert("UPDATE", t_rel, R14, severity=sev, branch=branch, alert_kind="attack", conditions=conditions)


def held14(sc, t_rel):
    return sc.alert("RAISE", t_rel, R14, severity="medium", alert_kind="anomaly")


# ============ L3-24 하향 IMSI 추출 (20_ §3.8 L24-T1~T26 — T23 밀어내기·T25 설정·T26 결정성은 단위 시험) ============

def s24_normal():
    sc = Scenario3("S24_L3-24_정상흐름_무경보", "기본 흐름 F + 해제 — 식별 요청·응답 없음, 후보 없음 (L24-T1)", 3000)
    sc.ue(3).flow_F(B).release(B + 1000)
    return sc


def s24_guti_identity():
    sc = Scenario3("S24_L3-24_모르는GUTI식별_무경보",
                   "모르는 5G-GUTI로 등록 → AMF IdentityRequest(t0+95) → 응답(t0+100). 응답 때 R 1·A 0 (L24-T2)", 3000)
    sc.ue(3).flow_F(B, guti=True, identity=True)
    return sc


def s24_retx_once():
    sc = Scenario3("S24_L3-24_AMF재전송_늦은응답1회_무경보",
                   "IdentityRequest t0+95·t0+3095, 응답 t0+3100 한 번. 응답 때 R 2·A 0 (L24-T3)", 5000)
    u = sc.ue(3).head(B, guti=True)
    u.id_req(B + 95).id_req(B + 3095).id_resp(B + 3100)
    u.flow_F(B + 3000, rest_from=105)
    return sc


def s24_retx_twice():
    sc = Scenario3("S24_L3-24_AMF재전송_두번응답_무경보",
                   "요청마다 응답(t0+100·t0+3100). 둘째 응답 때 R 2·A 1 (L24-T3)", 5000)
    u = sc.ue(3).head(B, guti=True)
    u.id_req(B + 95).id_resp(B + 100).id_req(B + 3095).id_resp(B + 3100)
    u.flow_F(B + 3000, rest_from=105)
    return sc


def s24_raise():
    sc = Scenario3("S24_L3-24_요청없는응답_RAISE",
                   "F + t0+98 요청 없는 IdentityResponse — K = t0+100에 RAISE, medium, 전제 mitm_ul_relay (L24-T4)", 3000)
    sc.ue(3).flow_F(B).id_resp(B + 98)
    raise24(sc, K(B + 98))
    return sc


def s24_unexpected_f():
    sc = Scenario3("S24_L3-24_약속밖f무시_RAISE",
                   "T4에서 응답 줄에 약속에 없는 f(id_type IMEI) — 무시, 같은 RAISE (L24-T5)", 3000)
    sc.ue(3).flow_F(B).id_resp(B + 98, {"id_type": "IMEI"})
    raise24(sc, K(B + 98))
    return sc


def s24_after_normal_identity():
    sc = Scenario3("S24_L3-24_정상식별뒤추가응답_RAISE",
                   "T2 + RRC 보안 전 t0+135에 응답 하나 더 — R 1·A 1 → K = t0+200에 RAISE (L24-T6)", 3000)
    sc.ue(3).flow_F(B, guti=True, identity=True).id_resp(B + 135)
    raise24(sc, K(B + 135))
    return sc


def s24_extra():
    sc = Scenario3("S24_L3-24_같은연결추가응답_RAISE",
                   "T4 + t0+135(보안 전)·t0+250(AS 무결성 뒤) 응답 — RAISE 1번, UPDATE 없음 (L24-T7)", 3000)
    sc.ue(3).flow_F(B).id_resp(B + 98).id_resp(B + 135).id_resp(B + 250)
    raise24(sc, K(B + 98))
    return sc


def s24_two_in_window():
    sc = Scenario3("S24_L3-24_같은창두응답_RAISE",
                   "같은 창 t0+60·t0+98에 요청 없는 응답 둘 — RAISE 1번(extra 1) (L24-T8)", 3000)
    sc.ue(3).flow_F(B).id_resp(B + 60).id_resp(B + 98)
    raise24(sc, K(B + 98))
    return sc


def _request_lost(sc):
    # T2에서 IdentityRequest 줄을 빼고 그 창 [t0, t0+100)이 양방향 로스
    u = sc.ue(3).flow_F(B, guti=True, identity=True, skip=("IdentityRequest",))
    sc.lost(B, ["UL", "DL"])
    return u


def s24_request_lost():
    sc = Scenario3("S24_L3-24_요청줄로스_불확실RAISE",
                   "요청 줄 로스 — 연결 시작 뒤 DL 로스로 보류 → K(t0+100) = t0+200에 불확실 경보 (L24-T9)", 3000)
    _request_lost(sc)
    held24(sc, K(B + 100))
    return sc


def s24_loss_before_start():
    sc = Scenario3("S24_L3-24_연결전로스_RAISE",
                   "T4 + 로스 창 [t0−100, t0) — loss_end[DL] = t0 ≤ t_s → RAISE (L24-T10)", 3000)
    sc.ue(3).flow_F(B).id_resp(B + 98)
    sc.lost(B - 100, ["UL", "DL"])
    raise24(sc, K(B + 98))
    return sc


def s24_loss_after_start():
    sc = Scenario3("S24_L3-24_연결뒤로스_불확실RAISE",
                   "로스 창 [t0, t0+100), 공격 응답 t0+135 — 보류 → K = t0+200에 불확실 경보 (L24-T10)", 3000)
    sc.ue(3).flow_F(B).id_resp(B + 135)
    sc.lost(B, ["UL", "DL"])
    held24(sc, K(B + 135))
    return sc


def s24_ul_loss():
    sc = Scenario3("S24_L3-24_UL로스_RAISE", "T4 + 응답 창 ue_evt_lost [\"UL\"] — DL 로스 아님 → RAISE (L24-T11)", 3000)
    sc.ue(3).flow_F(B).id_resp(B + 98)
    sc.lost(B, ["UL"])
    raise24(sc, K(B + 98))
    return sc


def s24_boundary():
    sc = Scenario3("S24_L3-24_창경계응답_RAISE",
                   "응답 t_r = t0+100(앞 창 t_end) — t0+100이 아니라 K = t0+200에 RAISE (L24-T12)", 3000)
    sc.ue(3).head(B).id_resp(B + 100)
    raise24(sc, K(B + 100))
    return sc


def s24_closed_same_window():
    sc = Scenario3("S24_L3-24_같은창해제_RAISE",
                   "응답 t0+98 직후 t0+99 해제(released) — 마감 때 판정해 K = t0+100에 RAISE (L24-T13)", 3000)
    sc.ue(3).head(B).id_resp(B + 98).release(B + 99)
    raise24(sc, K(B + 98))
    return sc


def s24_mid_join():
    sc = Scenario3("S24_L3-24_중간합류_무경보", "첫 줄이 IdentityResponse(mid_join) — 후보 없음 (L24-T14)", 3000)
    sc.ue(5).id_resp(B + 50)
    return sc


def s24_late():
    sc = Scenario3("S24_L3-24_늦은응답줄_무경보",
                   "공격 응답 줄(t_ms t0+98)이 t0+100 kpm2 뒤에 도착 — late, 판정 없음 (L24-T15)", 3000)
    sc.ue(3).head(B).id_resp(B + 98)
    sc.late_msgs = {"IdentityResponse"}
    return sc


def s24_after_as_integrity():
    sc = Scenario3("S24_L3-24_AS무결성뒤응답_무경보", "F 뒤 t0+220 요청 없는 응답 — AS 무결성(nia2) 뒤라 후보 없음 (L24-T16)",
                   3000)
    sc.ue(3).flow_F(B).id_resp(B + 220)
    return sc


def s24_nia0():
    sc = Scenario3("S24_L3-24_nia0_RAISE", "RRC 보안 nia0 + t0+220 응답 — K = t0+300에 RAISE(rrc_sec ON) (L24-T16)", 3000)
    sc.ue(3).flow_F(B, integrity="nia0").id_resp(B + 220)
    raise24(sc, K(B + 220))
    return sc


def s24_smc_cmd():
    sc = Scenario3("S24_L3-24_보안명령뒤완료전_RAISE",
                   "t0+145(rrc_sec CMD) 응답 — K = t0+200에 RAISE (L24-T16)", 3000)
    sc.ue(3).flow_F(B).id_resp(B + 145)
    raise24(sc, K(B + 145))
    return sc


def s24_protected_nas():
    sc = Scenario3("S24_L3-24_NAS암호_무경보", "공격 응답이 ProtectedNAS — 이름이 보이지 않아 판정 없음 (L24-T17)", 3000)
    sc.ue(3).flow_F(B).protected_nas(B + 98)
    return sc


def s24_clear():
    sc = Scenario3("S24_L3-24_해제_CLEAR", "T4 뒤 마지막 걸림(t0+98) + 60 s 이상인 첫 kpm2에 CLEAR (L24-T18)", 62000)
    sc.ue(3).flow_F(B).id_resp(B + 98)
    raise24(sc, K(B + 98))
    sc.alert("CLEAR", K(B + 98 + 60000 - 1), R24, alert_kind="attack")
    return sc


def s24_clear_extra():
    sc = Scenario3("S24_L3-24_extra는해제를안늦춤_CLEAR",
                   "보안 전 연결에 t0+98 걸림 + t0+30,000 같은 연결 extra — 해제 시각 그대로 (L24-T18)", 62000)
    sc.ue(3).head(B).id_resp(B + 98).id_resp(B + 30000)
    raise24(sc, K(B + 98))
    sc.alert("CLEAR", K(B + 98 + 60000 - 1), R24, alert_kind="attack")
    return sc


def s24_two_ues():
    sc = Scenario3("S24_L3-24_두UE_UPDATE",
                   "UE A는 T4, UE B는 t0+500에 같은 공격 — RAISE + 1 s 모음 UPDATE, 심각도 그대로 (L24-T19)", 3000)
    sc.ue(1).flow_F(B).id_resp(B + 98)
    sc.ue(2).flow_F(B + 500).id_resp(B + 598)
    raise24(sc, K(B + 98))
    sc.alert("UPDATE", K(B + 98) + 1000, R24, severity="medium", alert_kind="attack")
    return sc


def s24_held_more_waiting():
    sc = Scenario3("S24_L3-24_보류연결추가응답_대기중_불확실RAISE",
                   "T9 + 마감 처리 전 t0+135에 응답 하나 더 — 다시 후보를 만들지 않음, held_w 1 (L24-T20)", 3000)
    _request_lost(sc).id_resp(B + 135)
    held24(sc, K(B + 100))
    return sc


def s24_held_more_decided():
    sc = Scenario3("S24_L3-24_보류연결추가응답_결정뒤_불확실RAISE",
                   "T9 + 보류 처리(t0+200) 뒤 t0+235에 응답 하나 더 — 다시 판정하지 않음, held_w 1 (L24-T20)", 3000)
    _request_lost(sc).id_resp(B + 235)
    held24(sc, K(B + 100))
    return sc


def s24_ngap_unlinked():
    sc = Scenario3("S24_L3-24_NGAP미연결_무경보", "du_ue_id null IdentityResponse(via NGAP) — UE 항목에 붙지 않음 (L24-T21)",
                   3000)
    sc.ue(3).head(B).ngap_nas(B + 98, "IdentityResponse")
    return sc


def s24_dl_unobserved():
    sc = Scenario3("S24_L3-24_DL미관측_불확실RAISE",
                   "모든 kpm2 ue_evt_lost [\"DL\"], DL 줄 없음(T2) — 응답이 보류돼 불확실 경보만 (L24-T22). "
                   "t0+175 능력 응답도 rrc_sec OFF·R 0이라 L3-14 불확실 경보가 같은 칸에 함께 남 (L14-T16)", 3000)
    sc.ue(3).flow_F(B, guti=True, identity=True).drop_dl()
    sc.lost_all(["DL"])
    held24(sc, K(B + 100))
    held14(sc, K(B + 175))   # 등록 순서 L3-24 → L3-14 (20_ §0)
    return sc


def s24_order_violation():
    sc = Scenario3("S24_L3-24_순서위반_RAISE",
                   "같은 창에서 요청 줄(t0+95)이 응답 줄(t0+97) 뒤에 옴 — RAISE, 오탐을 기록해 두는 시험 (L24-T24)", 3000)
    u = sc.ue(3).head(B, guti=True).id_resp(B + 97)
    u.out_of_order(B + 97, B + 95, "DL", "NAS", "IdentityRequest")
    raise24(sc, K(B + 97))
    return sc


def s24_duplicate():
    sc = Scenario3("S24_L3-24_응답중복_RAISE",
                   "T2에서 응답 줄이 두 번 옴 — 둘째 때 R 1·A 1 → RAISE, 오탐을 기록해 두는 시험 (L24-T24)", 3000)
    sc.ue(3).flow_F(B, guti=True, identity=True).id_resp(B + 100)
    raise24(sc, K(B + 100))
    return sc


# ============ L3-14 UE 능력 탈취 (20_ §4.8 L14-T1~T21 — T18 밀어내기·T20 설정·T21 결정성은 단위 시험) ============

def s14_normal():
    sc = Scenario3("S14_L3-14_정상흐름_무경보", "F + 해제 — 능력 요청은 RRC 보안 뒤, 응답은 짝이 있음 (L14-T1)", 3000)
    sc.ue(3).flow_F(B).release(B + 1000)
    return sc


def s14_no_cap():
    sc = Scenario3("S14_L3-14_능력교환없음_무경보", "AMF가 단말 능력을 줘 능력 요청·응답이 없음 (L14-T2)", 3000)
    sc.ue(3).flow_F(B, cap=False)
    return sc


def s14_branch1():
    sc = Scenario3("S14_L3-14_요청없는능력응답_갈래1_RAISE",
                   "F + t0+98 요청 없는 UECapabilityInformation — K = t0+100에 갈래 ① RAISE, medium, 전제 mitm_ul_relay (L14-T3)",
                   3000)
    sc.ue(3).flow_F(B).cap_info(B + 98)
    raise14(sc, K(B + 98), "1", MITM)
    return sc


def s14_branch2():
    sc = Scenario3("S14_L3-14_보안전능력요청_갈래2_RAISE",
                   "C2 — CU가 RRC 보안 모드 명령 전 t0+120에 능력 요청 → K = t0+200에 갈래 ② RAISE, high, 전제 없음 (L14-T4)",
                   3000)
    sc.ue(3).c2(B)
    raise14(sc, K(B + 120), "2", [])
    return sc


def s14_cmd():
    sc = Scenario3("S14_L3-14_보안명령뒤요청_무경보", "능력 요청이 RRC 보안 모드 명령 뒤·완료 전(t0+145, CMD) — 후보 없음 (L14-T5)",
                   3000)
    sc.ue(3).flow_F(B, cap=False).cap_enq(B + 145)
    return sc


def s14_failed():
    sc = Scenario3("S14_L3-14_보안실패뒤요청_갈래2_RAISE",
                   "RRC SecurityModeFailure(t0+145) 뒤 t0+150 능력 요청(FAILED) — K = t0+200에 갈래 ② RAISE (L14-T5)", 3000)
    sc.ue(3).flow_F(B, cap=False, skip=("RrcSecurityModeComplete",)).rrc_smfailure(B + 145).cap_enq(B + 150)
    raise14(sc, K(B + 150), "2", [])
    return sc


def s14_on():
    sc = Scenario3("S14_L3-14_보안완료뒤요청_무경보", "능력 요청이 RRC 보안 모드 완료 뒤(t0+155, ON) — 후보 없음 (L14-T5)", 3000)
    sc.ue(3).flow_F(B, cap=False).cap_enq(B + 155)
    return sc


def s14_enq_lost():
    sc = Scenario3("S14_L3-14_능력요청줄로스_무경보",
                   "F에서 t0+160 능력 요청 줄을 빼고 그 창 양방향 로스 — t0+175 응답은 AS 무결성 뒤라 후보 아님 (L14-T6)", 3000)
    sc.ue(3).flow_F(B, skip=("UECapabilityEnquiry",))
    sc.lost(B + 100, ["UL", "DL"])
    return sc


def s14_smc_lost():
    sc = Scenario3("S14_L3-14_보안명령줄로스_불확실RAISE",
                   "F에서 RRC SecurityModeCommand 줄을 빼고 그 창 양방향 로스 — t0+160 능력 요청이 갈래 ② 후보 → 보류 → "
                   "K = t0+200에 불확실 경보 (L14-T7)", 3000)
    sc.ue(3).flow_F(B, skip=("RrcSecurityModeCommand",))
    sc.lost(B + 100, ["UL", "DL"])
    held14(sc, K(B + 160))
    return sc


def _mixed(sc):
    sc.ue(1).flow_F(B).cap_info(B + 98)
    sc.ue(2).c2(B + 400)


def s14_mixed():
    sc = Scenario3("S14_L3-14_갈래섞임_UPDATE",
                   "UE A C1 → 갈래 ① RAISE, UE B C2(t0+520) → 심각도가 올라 바로 UPDATE(branch 2, high) (L14-T8)", 3000)
    _mixed(sc)
    raise14(sc, K(B + 98), "1", MITM)
    update14(sc, K(B + 520), "2")
    return sc


def s14_mixed_reversed():
    sc = Scenario3("S14_L3-14_갈래섞임역순_전제UPDATE",
                   "UE B C2 → 갈래 ② RAISE(전제 없음), 0.9 s 뒤 UE A C1 → 전제가 mitm_ul_relay로 바뀌어 바로 UPDATE (L14-T8)",
                   3000)
    sc.ue(2).c2(B)
    sc.ue(1).flow_F(B + 1000).cap_info(B + 1098)
    raise14(sc, K(B + 120), "2", [])
    update14(sc, K(B + 1098), "2", MITM)
    return sc


def s14_both_branches():
    sc = Scenario3("S14_L3-14_한연결두갈래_RAISE-UPDATE",
                   "C2 + t0+135 요청 없는 능력 응답 — 같은 칸에서 갈래 ② RAISE 직후 전제 변화로 UPDATE (L14-T9)", 3000)
    sc.ue(3).c2(B).cap_info(B + 135)
    raise14(sc, K(B + 120), "2", [])
    update14(sc, K(B + 135), "2", MITM)
    return sc


def s14_once():
    sc = Scenario3("S14_L3-14_연결당한번_RAISE", "C2 + t0+125 보안 전 능력 요청 하나 더 — 갈래 ② 걸림 1번(extra 1) (L14-T10)",
                   3000)
    sc.ue(3).c2(B).cap_enq(B + 125)
    raise14(sc, K(B + 120), "2", [])
    return sc


def s14_nia0():
    sc = Scenario3("S14_L3-14_nia0_갈래1_RAISE", "RRC 보안 nia0 + t0+220 요청 없는 능력 응답 — K = t0+300에 갈래 ① RAISE (L14-T11)",
                   3000)
    sc.ue(3).flow_F(B, integrity="nia0").cap_info(B + 220)
    raise14(sc, K(B + 220), "1", MITM)
    return sc


def s14_cu_misconfig():
    sc = Scenario3("S14_L3-14_CU설정오류5UE_UPDATE",
                   "5개 UE가 200 ms 간격으로 모두 C2 — RAISE(첫 UE) + 1 s 모음 UPDATE (L14-T12)", 3000)
    for i in range(5):
        sc.ue(10 + i).c2(B + 200 * i)
    raise14(sc, K(B + 120), "2", [])
    update14(sc, K(B + 120) + 1000, "2")
    return sc


def s14_mid_join():
    sc = Scenario3("S14_L3-14_중간합류_무경보", "첫 줄이 UECapabilityInformation 또는 UECapabilityEnquiry(mid_join) (L14-T13)",
                   3000)
    sc.ue(5).cap_info(B + 50)
    sc.ue(6).cap_enq(B + 50)
    return sc


def s14_closed():
    sc = Scenario3("S14_L3-14_마감전해제_갈래2_RAISE",
                   "C2 흐름에서 t0+150 해제(released) — 마감 때 판정해 K = t0+200에 갈래 ② RAISE (L14-T14)", 3000)
    sc.ue(3).c2(B, until=140).release(B + 150)
    raise14(sc, K(B + 120), "2", [])
    return sc


def s14_late():
    sc = Scenario3("S14_L3-14_늦은응답줄_무경보", "C1 줄(t_ms t0+98)이 t0+100 kpm2 뒤에 도착 — late, 판정 없음 (L14-T15)", 3000)
    sc.ue(3).head(B).cap_info(B + 98)
    sc.late_msgs = {"UECapabilityInformation"}
    return sc


def s14_dl_unobserved():
    sc = Scenario3("S14_L3-14_DL미관측_불확실RAISE",
                   "모든 kpm2 ue_evt_lost [\"DL\"], DL 줄 없음(F) — t0+175 응답이 보류돼 불확실 경보만 (L14-T16)", 3000)
    sc.ue(3).flow_F(B).drop_dl()
    sc.lost_all(["DL"])
    held14(sc, K(B + 175))
    return sc


def s14_clear():
    sc = Scenario3("S14_L3-14_해제_CLEAR",
                   "L14-T8 앞 경우 뒤 마지막 걸림(B의 t_e = t0+520) + 60 s 이상인 첫 kpm2에 CLEAR, branch 2 (L14-T17)", 62000)
    _mixed(sc)
    raise14(sc, K(B + 98), "1", MITM)
    update14(sc, K(B + 520), "2")
    sc.alert("CLEAR", K(B + 520 + 60000 - 1), R14, branch="2", alert_kind="attack")
    return sc


def s14_order_after_sec():
    sc = Scenario3("S14_L3-14_보안뒤순서위반_무경보",
                   "RRC 보안 뒤 같은 창에서 능력 응답(t0+175)이 요청(t0+160)보다 먼저 옴 — AS 무결성 뒤라 흡수 (L14-T19)", 3000)
    u = sc.ue(3).flow_F(B, cap=False).cap_info(B + 175)
    u.out_of_order(B + 175, B + 160, "DL", "RRC", "UECapabilityEnquiry")
    return sc


def s14_order_before_sec():
    sc = Scenario3("S14_L3-14_보안전순서위반_RAISE-UPDATE",
                   "RRC 보안 전 t0+120 응답·t0+125 요청 — 갈래 ① RAISE 직후 같은 칸 갈래 ② UPDATE, 오탐을 기록해 두는 시험 (L14-T19)",
                   3000)
    sc.ue(3).flow_F(B, cap=False).cap_info(B + 120).cap_enq(B + 125)
    raise14(sc, K(B + 120), "1", MITM)
    update14(sc, K(B + 125), "2")
    return sc


SCENARIOS = [
    s24_normal, s24_guti_identity, s24_retx_once, s24_retx_twice, s24_raise, s24_unexpected_f,
    s24_after_normal_identity, s24_extra, s24_two_in_window, s24_request_lost, s24_loss_before_start,
    s24_loss_after_start, s24_ul_loss, s24_boundary, s24_closed_same_window, s24_mid_join, s24_late,
    s24_after_as_integrity, s24_nia0, s24_smc_cmd, s24_protected_nas, s24_clear, s24_clear_extra, s24_two_ues,
    s24_held_more_waiting, s24_held_more_decided, s24_ngap_unlinked, s24_dl_unobserved, s24_order_violation,
    s24_duplicate,
    s14_normal, s14_no_cap, s14_branch1, s14_branch2, s14_cmd, s14_failed, s14_on, s14_enq_lost, s14_smc_lost,
    s14_mixed, s14_mixed_reversed, s14_both_branches, s14_once, s14_nia0, s14_cu_misconfig, s14_mid_join, s14_closed,
    s14_late, s14_dl_unobserved, s14_clear, s14_order_after_sec, s14_order_before_sec,
]


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "tests", "data", "stage3_lightgreen")
    os.makedirs(out_dir, exist_ok=True)
    for make in SCENARIOS:
        sc = make()
        lines = sc.build()
        with open(os.path.join(out_dir, sc.name + ".jsonl"), "w", encoding="utf-8") as f:
            for line in lines:
                f.write(gen_stage2.json.dumps(line, ensure_ascii=False, separators=(",", ":")) + "\n")
        expected = {"scenario": sc.name, "description": sc.desc, "t0_ms": T0, "tolerance_ms": P,
                    "alerts": sc.expect}
        with open(os.path.join(out_dir, sc.name + ".expected.json"), "w", encoding="utf-8") as f:
            gen_stage2.json.dump(expected, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print(f"{sc.name}: {len(lines)} lines, {len(sc.expect)} alerts expected")


if __name__ == "__main__":
    main()
