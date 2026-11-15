#!/usr/bin/env python3
"""합성 ue_evt+kpm2 2단계 시나리오(.jsonl)와 기대 경보(.expected.json) 생성기.

명세: 입력 2_ §6 ue_evt·§4 kpm2·§6.7 f1_evt, 상태·판정 14_·15_(2단계 녹색 3종).
실행: python3 tools/gen_stage2.py [출력 폴더]  (기본 tests/data/stage2_green/).
tests/core/test_scenarios.cpp가 이 폴더를 실행 파일과 같은 룰 구성(1단계 + 2단계 세 룰,
기본값)으로 재생해 같은 이름 .expected.json과 비교한다(Stage2Scenario). 14_ §10 결정으로
stage2_green 데이터는 '직접 작성'하되, 손으로 한 줄씩 치는 대신 이 컴팩트한 UE 타임라인에서 찍어 낸다.

기대 경보 시각은 이 생성기가 아니라 명세 식으로 손 계산한 값이다(1단계 gen_kpm2.py와 같은 방식):
 - 마감 d는 그 셀 kpm2의 t_end >= d인 첫 칸(= ceil(d/P)*P)에서 처리된다(14_ §6.1).
 - L3-01-O 고착 = t₀(AuthenticationRequest) + auth_wait_ms(2000); 셀 성립은 그 마감 처리 칸(15_ §4.3).
 - L3-20 걸림 = t₀(s_tmsi 정해진 줄) + accept_wait_ms(3000 — 11/15 전 5000, 15_ §2.3·§2.4).
 - L3-21 갈래① 실패 UE = t_f(첫 실패) + fail_accept_wait_ms(5000); 갈래② 즉시(그 줄 t_ms)(15_ §5.3).
 - CLEAR = 마지막 걸림/성립 + clear_quiet_ms(60000) 이상인 첫 kpm2(15_ §2.5·§4.5·§5.5).
시각은 모두 데이터 시작(T0)부터의 상대 ms이고, 테스트는 ±tolerance_ms(1칸)를 허용한다.

입력 불완전 시나리오(이슈 #42, 16_ §3.1·§6 W-17): 분석 엔진의 순서 보장(2_ §6.1 — 같은 창의 ue_evt는
그 창 kpm2보다 먼저)과 ue_evt_lost 필드(2_ §4.6)를 일부러 깬 입력이다. Scenario.late_msgs는 그 메시지(또는 "all")의
ue_evt를 자기 창 kpm2 뒤에 두어 워터마크보다 이른 줄(late, 14_ §4.3)로 만들고, Scenario.drop_lost는 kpm2에서
ue_evt_lost 키를 뺀다(2단계는 양방향 로스로 본다, 14_ §6.2). 기대값은 '지금 동작'(경보 없음)을 고정한 것이고,
4_ §6.1 #7(late_until)·#8(불확실 경보)에서 바뀐다.
"""

import json
import os
import sys

T0 = 1792209000000  # 데이터 시작 시각 (1단계 gen_kpm2.py와 같은 값)
P = 100             # period_ms — kpm2 한 칸


class UE:
    """한 연결(du_ue_id 하나)의 메시지 흐름. 관측한 순서대로 쌓는다(2_ §6.1).

    식별(du_ue_id·crnti·cu_ue_id)은 UE마다 고정, 각 메시지는 상대 시각 t_rel에 둔다."""

    def __init__(self, du, cell=1, crnti=None, cu=None):
        self.du = du
        self.cell = cell
        self.crnti = 10000 + du if crnti is None else crnti
        self.cu = du if cu is None else cu
        self.evts = []  # (t_rel, 공통 필드 뺀 dict)

    # 한 줄(관측 메시지 1개, 2_ §6.2). NAS는 via·sht가 필수다(§6.2)
    def _line(self, t_rel, direction, proto, msg, f=None, via=None, sht=None):
        d = {"type": "ue_evt", "t_ms": T0 + t_rel, "cell_id": self.cell, "du_ue_id": self.du,
             "cu_ue_id": self.cu, "crnti": self.crnti, "dir": direction, "proto": proto, "msg": msg}
        if proto == "NAS":
            d["via"] = via or "F1"      # 테스트베드는 NEA0라 NAS를 F1에서 본다(2_ §6.1)
            d["sht"] = 0 if sht is None else sht
        if f:
            d["f"] = f
        self.evts.append((t_rel, d))
        return self

    # --- RRC (2_ §6.3) ---
    def setup_req(self, t, random=True, part1=None, est="mo-Signalling"):
        # ue_identity: randomValue(정상 첫 접속) 또는 ng-5G-S-TMSI-Part1(S-TMSI 하위 39비트)
        ident = {"type": "randomValue"} if random else {"type": "ng-5G-S-TMSI-Part1", "value": part1}
        return self._line(t, "UL", "RRC", "RRCSetupRequest", {"est_cause": est, "ue_identity": ident})

    def setup(self, t):
        return self._line(t, "DL", "RRC", "RRCSetup")

    def setup_complete(self, t, s_tmsi=None):
        # RRCSetupComplete의 f.s_tmsi로 항목 s_tmsi가 정해진다 → L3-20 t₀(14_ §2.1·15_ §2.3)
        return self._line(t, "UL", "RRC", "RRCSetupComplete", {"s_tmsi": s_tmsi} if s_tmsi else None)

    def rrc_smc(self, t, cipher="nea0", integrity="nia2"):
        # RRC SecurityModeCommand(DL) → rrc_sec CMD. 2단계 공통 '망 수락' 근거(15_ §1.1)
        return self._line(t, "DL", "RRC", "SecurityModeCommand", {"cipher": cipher, "integrity": integrity})

    def rrc_smcomplete(self, t):
        return self._line(t, "UL", "RRC", "SecurityModeComplete")

    def rrc_release(self, t, suspend=False):
        return self._line(t, "DL", "RRC", "RRCRelease", {"suspend": suspend})

    # --- NAS (2_ §6.3). via=F1, sht는 평문이면 0 ---
    def reg_req(self, t, reg_type="initial", id_type="SUCI", s_tmsi=None):
        f = {"reg_type": reg_type, "id_type": id_type}
        if s_tmsi:
            f["s_tmsi"] = s_tmsi     # id_type이 5G-GUTI면 그 안의 5G-S-TMSI
        return self._line(t, "UL", "NAS", "RegistrationRequest", f)

    def auth_req(self, t):
        # AuthenticationRequest(DL) → nas_sec AUTH. L3-01-O 기다림 시작(15_ §4.3)
        return self._line(t, "DL", "NAS", "AuthenticationRequest")

    def auth_resp(self, t):
        return self._line(t, "UL", "NAS", "AuthenticationResponse")

    def auth_fail(self, t, cause=None):
        # AuthenticationFailure(UL) — L3-01-O엔 응답, L3-21엔 실패(15_ §4.2·§5.2)
        return self._line(t, "UL", "NAS", "AuthenticationFailure", {"cause": cause} if cause is not None else None)

    def auth_reject(self, t):
        return self._line(t, "DL", "NAS", "AuthenticationReject")

    def reg_accept(self, t, s_tmsi=None):
        # RegistrationAccept(DL) → nas REGISTERED(망 수락). f.s_tmsi는 망이 새로 준 5G-GUTI(14_ §2.1)
        return self._line(t, "DL", "NAS", "RegistrationAccept", {"s_tmsi": s_tmsi} if s_tmsi else None)

    def reg_complete(self, t):
        return self._line(t, "UL", "NAS", "RegistrationComplete")

    def reg_reject(self, t, cause=None):
        # RegistrationReject(DL) — L3-21 실패 메시지(15_ §5.2)
        return self._line(t, "DL", "NAS", "RegistrationReject", {"cause": cause} if cause is not None else None)

    def svc_req(self, t, s_tmsi=None):
        return self._line(t, "UL", "NAS", "ServiceRequest", {"s_tmsi": s_tmsi} if s_tmsi else None)

    def svc_accept(self, t):
        return self._line(t, "DL", "NAS", "ServiceAccept")

    def svc_reject(self, t, cause=None):
        return self._line(t, "DL", "NAS", "ServiceReject", {"cause": cause} if cause is not None else None)

    def nas_smc(self, t, cipher="5G-EA0", integrity="5G-IA2"):
        return self._line(t, "DL", "NAS", "SecurityModeCommand", {"cipher": cipher, "integrity": integrity}, sht=3)

    def nas_sec_reject(self, t):
        # SecurityModeReject — #3 쪽 신호라 L3-21 실패로 세지 않는다(15_ §5.2)
        return self._line(t, "UL", "NAS", "SecurityModeReject")

    # --- F1AP (2_ §6.3) ---
    def ctx_release_cmd(self, t, cause="radioNetwork:normal-release"):
        # UEContextReleaseCommand(DL) — L3-20 피해 확정(옛 연결 해제, 15_ §2.3)
        return self._line(t, "DL", "F1AP", "UEContextReleaseCommand", {"cause": cause})

    def ctx_release_complete(self, t):
        # UEContextReleaseComplete(UL) — 항목 닫힘(released, 14_ §4.2)
        return self._line(t, "UL", "F1AP", "UEContextReleaseComplete")

    # 흔한 조립: 정상 등록 완료(수락까지) — 2_ §6.4 흐름
    def normal_register(self, t0, s_tmsi=None):
        self.setup_req(t0)
        self.setup(t0 + 1)
        self.setup_complete(t0 + 90, s_tmsi=s_tmsi)
        self.reg_req(t0 + 91, id_type="SUCI")
        self.auth_req(t0 + 105)
        self.auth_resp(t0 + 118)
        self.rrc_smc(t0 + 140)
        self.rrc_smcomplete(t0 + 150)
        self.reg_accept(t0 + 170)
        self.reg_complete(t0 + 180)
        return self

    # 흔한 조립: 인증 고착(응답 없음). t₀ = auth_req 시각 = t0 + 105
    def auth_stall(self, t0, s_tmsi=None, reg_id="SUCI"):
        self.setup_req(t0)
        self.setup(t0 + 1)
        self.setup_complete(t0 + 90, s_tmsi=s_tmsi)
        self.reg_req(t0 + 91, id_type=reg_id, s_tmsi=s_tmsi if reg_id == "5G-GUTI" else None)
        self.auth_req(t0 + 105)
        return self


class Scenario:
    """한 시나리오 = hello + 여러 UE 흐름 + 셀마다 100 ms 간격 kpm2. 재생은 결정적이다(14_ §6)."""

    def __init__(self, name, desc, duration, cells=(1,), max_conn=None):
        self.name = name
        self.desc = desc
        self.duration = duration
        self.cells = list(cells)
        self.max_conn = max_conn
        self.ues = []
        self.raw = {}              # t_rel -> [원본 줄 dict] (f1_evt 등)
        self.loss = {}             # cell -> {tick: ["UL"|"DL"]}  ue_evt_lost 로스 창(2_ §4.6)
        self.gap = {}              # cell -> set(tick)  그 칸 kpm2를 내지 않음(구간 끊김)
        self.uectx = {}            # cell -> {tick: UeCtxMax}  ext.UeCtxMax(2_ §4.4)
        self.session_changes = {}  # tick -> 새 session 이름(새 hello, 상태표 초기화)
        self.late_msgs = None      # None | "all" | {msg, ...}: 그 ue_evt를 자기 창 kpm2 뒤에 둔다(순서 역전, 이슈 #42)
        self.drop_lost = False     # True면 kpm2에 ue_evt_lost 키를 넣지 않는다(이슈 #42)
        self.expect = []

    def ue(self, du, cell=1, crnti=None):
        u = UE(du, cell=cell, crnti=crnti)
        self.ues.append(u)
        return u

    def add_raw(self, t_rel, line):
        self.raw.setdefault(t_rel, []).append(line)

    def set_loss(self, cell, tick, dirs):
        self.loss.setdefault(cell, {})[tick] = dirs

    def set_gap(self, cell, tick):
        self.gap.setdefault(cell, set()).add(tick)

    def set_uectx(self, cell, tick, v):
        self.uectx.setdefault(cell, {})[tick] = v

    def uectx_all(self, cell, value):
        for i in range(self.duration // P):
            self.uectx.setdefault(cell, {})[i] = value

    def change_session(self, tick, name):
        self.session_changes[tick] = name

    # 기대 경보 하나(명세 식으로 손 계산). kind·rule·cell·t_rel_ms는 늘, mode·severity·branch·reason은 있으면 비교(14_ §8.3)
    def alert(self, kind, t_rel, rule, cell=1, mode=None, severity=None, branch=None, reason=None, alert_kind=None):
        # alert_kind: "attack" | "anomaly"(불확실 경보, 14_ §6.2 — 이슈 #48). 적으면 시험이 비교한다
        a = {"kind": kind, "rule": rule, "cell": cell, "t_rel_ms": t_rel}
        for key, val in (("mode", mode), ("severity", severity), ("branch", branch), ("reason", reason),
                         ("alert_kind", alert_kind)):
            if val is not None:
                a[key] = val
        self.expect.append(a)
        return a

    def hello(self, seq, session):
        # hello.ue_evt = true여야 2단계 룰이 돈다(2_ §6.5)
        return {"type": "hello", "ver": 1, "session": session, "seq": seq, "producer": "handwritten",
                "node_id": "stage2_green", "ue_evt": True,
                "cells": [{"cell_id": c, "max_conn": self.max_conn} for c in self.cells],
                "period_ms": P, "noreply_timeout_ms": 1000, "si_sample_ms": P, "clock": "realtime"}

    def kpm2(self, cell, tick, session):
        # 셀마다 100 ms 간격. cc는 0(2단계 시나리오는 kpm2 카운터로 1단계를 깨우지 않는다).
        # ue_evt_lost는 기본 []; 로스 창이면 그 방향을 넣는다(2_ §4.6 — 빠지면 2단계가 양방향 로스로 본다)
        t_start = tick * P
        d = {"type": "kpm2", "ver": 1, "session": session, "cell_id": cell,
             "t_start_ms": T0 + t_start, "t_end_ms": T0 + t_start + P,
             "cc": {"RRC.ConnEstabAtt": {"total": 0}, "RRC.ConnEstabSucc": {"total": 0},
                    "RRC.ConnEstabFailCause": {"NetworkReject": 0, "NoReply": 0, "Other": 0}}}
        dirs = self.loss.get(cell, {}).get(tick)
        if not self.drop_lost:
            d["ue_evt_lost"] = dirs if dirs else []
        if cell in self.uectx and tick in self.uectx[cell]:
            d["ext"] = {"UeCtxMax": self.uectx[cell][tick]}
        return d

    def build(self):
        # 같은 창 [tick*P, tick*P+P)의 ue_evt를 그 창 kpm2보다 먼저 낸다(2_ §6.1)
        per_tick = {}
        for u in self.ues:
            for (t_rel, line) in u.evts:
                per_tick.setdefault(t_rel // P, []).append((t_rel, line))
        session = "S1"
        seq = 1
        lines = [self.hello(1, session)]
        for i in range(self.duration // P):
            # 세션 변경: 새 session·새 hello(seq 1부터) → 상태표·마감·경보 초기화(14_ §7)
            if i in self.session_changes:
                session = self.session_changes[i]
                seq = 1
                lines.append(self.hello(1, session))
            for t_rel in sorted(t for t in self.raw if t // P == i):
                for line in self.raw[t_rel]:
                    seq += 1
                    lo = dict(line)
                    lo.setdefault("ver", 1)
                    lo["session"], lo["seq"] = session, seq
                    lines.append(lo)
            deferred = []   # 순서 역전(late_msgs): 자기 창 kpm2 뒤로 미루는 ue_evt
            for (t_rel, line) in sorted(per_tick.get(i, []), key=lambda x: x[0]):
                if self.late_msgs == "all" or (self.late_msgs and line["msg"] in self.late_msgs):
                    deferred.append(line)
                    continue
                seq += 1
                lo = dict(line)
                lo["ver"], lo["session"], lo["seq"] = 1, session, seq
                lines.append(lo)
            for c in self.cells:
                if i in self.gap.get(c, set()):
                    continue
                seq += 1
                k = self.kpm2(c, i, session)
                k["seq"] = seq
                lines.append(k)
            for line in deferred:   # t_ms < 그 셀 워터마크(kpm2 t_end_ms) → late (14_ §4.3)
                seq += 1
                lo = dict(line)
                lo["ver"], lo["session"], lo["seq"] = 1, session, seq
                lines.append(lo)
        return lines


VIC = "0x0123456789ab"   # 피해자 S-TMSI 예시 (48비트)


# ============ L3-01-O 인증 단계 고착 (15_ §4) ============

def s01_normal():
    # L01-T1: 정상 등록 + 인증 응답 → 고착 없음
    sc = Scenario("S01_L3-01-O_정상등록_무경보", "정상 UE 2대 등록·인증 응답 — 고착 없음 (L01-T1)", 1500)
    sc.ue(1).normal_register(0)
    sc.ue(2).normal_register(300)
    return sc


def s01_one_stall():
    # L01-T2: 전파 끊긴 정상 UE 1대 무응답 → 고착 1, 셀 문턱 N=5 미만 → 경보 없음
    sc = Scenario("S01_L3-01-O_무응답1_무경보", "인증 무응답 1대 — 고착 1, 문턱 미만, 경보 없음 (L01-T2)", 2600)
    sc.ue(1).auth_stall(0)
    return sc


def s01_stall4():
    # L01-T4 앞: 고착 4건 → 경보 없음
    sc = Scenario("S01_L3-01-O_고착4_무경보", "인증 무응답 4대 — 문턱 N=5 미만, 경보 없음 (L01-T4)", 4000)
    for i, t in enumerate([0, 200, 400, 600]):
        sc.ue(i + 1).auth_stall(t)
    return sc


def s01_stall5():
    # L01-T3/T4: 창 안 고착 5건 → RAISE. 5번째 마감 = (800+105)+2000 = 2905 → 처리 t_end=3000
    sc = Scenario("S01_L3-01-O_고착5_RAISE", "인증 무응답 5대(200 ms 간격) — 창 안 고착 5건 성립 → medium (L01-T3)", 4000)
    for i, t in enumerate([0, 200, 400, 600, 800]):
        sc.ue(i + 1).auth_stall(t)
    sc.alert("RAISE", 3000, "L3-01-O", severity="medium", mode="normal")
    return sc


def s01_stall5_high():
    # L01-T14: 성립 창에 UeCtxMax 96(>= 0.9×96) → high (1단계 C4와 같은 신호·문턱, 15_ §4.3)
    sc = Scenario("S01_L3-01-O_고착5_high", "인증 무응답 5대 + 셀 UeCtxMax 96 → high (L01-T14)", 4000)
    for i, t in enumerate([0, 200, 400, 600, 800]):
        sc.ue(i + 1).auth_stall(t)
    sc.uectx_all(1, 96)
    sc.alert("RAISE", 3000, "L3-01-O", severity="high", mode="normal")
    return sc


def s01_fail_is_response():
    # L01-T5: 응답이 AuthenticationFailure → 응답으로 봄(고착 아님). 1대라 L3-21 갈래①도 문턱 미만
    sc = Scenario("S01_L3-01-O_실패는응답_무경보", "인증 응답이 AuthenticationFailure — 고착 아님 (L01-T5)", 1200)
    u = sc.ue(1)
    u.setup_req(0).setup(1).setup_complete(90).reg_req(91).auth_req(105)
    u.auth_fail(300)   # 응답(실패) → L3-01-O 대기 풀림
    return sc


def s01_resp_boundary_late():
    # L01-T6: 응답 t_ms = 마감(t₀+2000) = 늦음 → 고착(14_ §6.1-5). 5대 모두 늦은 응답 → RAISE
    sc = Scenario("S01_L3-01-O_응답경계_늦음_RAISE", "인증 응답이 마감과 같은 시각(늦음) 5대 → 고착 성립 (L01-T6)", 4000)
    for i, t in enumerate([0, 200, 400, 600, 800]):
        u = sc.ue(i + 1)
        u.setup_req(t).setup(t + 1).setup_complete(t + 90).reg_req(t + 91).auth_req(t + 105)
        u.auth_resp(t + 105 + 2000)   # = 마감, 늦은 응답이라 풀리지 않음
    sc.alert("RAISE", 3000, "L3-01-O", severity="medium", mode="normal")
    return sc


def s01_hold():
    # L01-T9: 대기 구간에 UL 로스 창 → 고착 보류(14_ §6.2). 5대 모두 보류 → 공격 경보 없음(오탐 방지).
    # 이슈 #48(Q-58, 14_ §6.2): 보류가 창 안 N=5건이면 불확실 경보(kind anomaly) — 5번째 보류 마감 2905 → RAISE 3000
    sc = Scenario("S01_L3-01-O_로스보류_불확실RAISE",
                  "인증 무응답 5대지만 대기 구간 UL 로스 → 모두 보류, 공격 경보 없이 불확실 경보 RAISE (L01-T9·L01-T20)", 4000)
    for i, t in enumerate([0, 200, 400, 600, 800]):
        sc.ue(i + 1).auth_stall(t)
    for tick in range(10, 31):   # t=1000~3000 UL 로스 — 마감 처리 때 loss_end[UL] > t_from → 보류
        sc.set_loss(1, tick, ["UL"])
    sc.alert("RAISE", 3000, "L3-01-O", severity="medium", mode="normal", alert_kind="anomaly")
    return sc


def s01_held_then_attack():
    # U-T30·L01-T20 재생판 (이슈 #48): 보류 5건으로 불확실 RAISE(3000) 뒤 로스 없이 고착 5건 — 5번째 마감 6905 → 같은 칸 7000에서
    # 불확실 CLEAR → 공격 RAISE (14_ §8.2 '같은 줄에서 먼저 CLEAR')
    sc = Scenario("S01_L3-01-O_불확실뒤공격_CLEAR-RAISE",
                  "UL 로스로 5건 보류 → 불확실 RAISE, 그 뒤 로스 없이 고착 5건 → 같은 칸에서 불확실 CLEAR·공격 RAISE (U-T30·L01-T20)", 7200)
    for i, t in enumerate([0, 200, 400, 600, 800]):
        sc.ue(i + 1).auth_stall(t)
    for tick in range(10, 31):
        sc.set_loss(1, tick, ["UL"])
    for i, t in enumerate([4000, 4200, 4400, 4600, 4800]):   # 인증 요청 t+105, 마감 t+2105: 6105…6905 — 로스 창(≤3100) 뒤
        sc.ue(11 + i).auth_stall(t)
    sc.alert("RAISE", 3000, "L3-01-O", severity="medium", mode="normal", alert_kind="anomaly")
    sc.alert("CLEAR", 7000, "L3-01-O", alert_kind="anomaly")
    sc.alert("RAISE", 7000, "L3-01-O", severity="medium", mode="normal", alert_kind="attack")
    return sc


def s01_clear():
    # L01-T13: RAISE 뒤 60 s 성립 없음 → CLEAR. t_sat=2905 → t_end>=62905 → 63000
    sc = Scenario("S01_L3-01-O_해제_CLEAR", "고착 5건 RAISE 뒤 60 s 조용 → CLEAR (L01-T13)", 63200)
    for i, t in enumerate([0, 200, 400, 600, 800]):
        sc.ue(i + 1).auth_stall(t)
    sc.alert("RAISE", 3000, "L3-01-O", severity="medium", mode="normal")
    sc.alert("CLEAR", 63000, "L3-01-O")
    return sc


def s01_clear_then_rehit():
    # 15_ §4.5 CLEAR 때 창 비움 (11/05 Q-73 해결, 이슈 #94 — 25_ §3.2-3 재현): 고착 5건 RAISE 3000 → 경보 중 불성립 고착 4건(마감
    # 59105~62105, UPDATE 59200·60200·61200·62200) → CLEAR 63000(t_sat 2905 + 60 s) → 고착 1건(마감 63105): 창 (53105, 63105] 안
    # 옛 고착 4건은 CLEAR 때 비워져 S_W 1 → 경보 없음 → 4건 더(마감 63405~64305) → S_W 5 → RAISE 64400, ues_total 5(CLEAR 뒤 걸림만).
    # 11/04까지는 63200에 옛 UE 4개를 다시 실은 RAISE가 났다
    sc = Scenario("S01_L3-01-O_해제뒤재걸림_RAISE",
                  "RAISE → 불성립 고착 4건 → CLEAR 63000 → 고착 1건은 창을 새로 셈(경보 없음) → 4건 더에 RAISE 64400, ues_total 5 (15_ §4.5, 11/05 Q-73)",
                  64600)
    for du, t in _stall5():
        sc.ue(du).auth_stall(t)
    for i in range(4):
        sc.ue(30 + i).auth_stall(57000 + 1000 * i)
    sc.ue(40).auth_stall(61000)
    for i in range(4):
        sc.ue(41 + i).auth_stall(61300 + 300 * i)
    sc.alert("RAISE", 3000, "L3-01-O", severity="medium", mode="normal")
    for t in (59200, 60200, 61200, 62200):
        sc.alert("UPDATE", t, "L3-01-O")
    sc.alert("CLEAR", 63000, "L3-01-O")
    sc.alert("RAISE", 64400, "L3-01-O", severity="medium", mode="normal")
    sc.expect[-1]["ues_total"] = 5
    return sc


# ---- 입력 불완전 (이슈 #42, 16_ §3.1·W-17) — 지금 동작을 고정. 4_ §6.1 #7·#8에서 기대값이 바뀐다 ----

def _stall5():
    # S01_..._고착5_RAISE와 같은 배치: 5대, 200 ms 간격, 5번째 마감 2905 → 정상이면 RAISE 3000
    return [(i + 1, t) for i, t in enumerate([0, 200, 400, 600, 800])]


def s01_late_one():
    # 16_ E1b: UE마다 RegistrationRequest 한 줄만 자기 창 kpm2 뒤에 옴 → 그 UE는 late → '없음' 판정 없음(14_ §4.3).
    # 이슈 #46(late_until = 늦은 줄 + 16 s) 뒤에도 마감(2 s)이 그 안이라 경보 없음 그대로 — 만료 뒤 판정은 s01_late_one_expired
    sc = Scenario("S01_L3-01-O_순서역전1줄_무경보",
                  "인증 무응답 5대, UE마다 RegistrationRequest 한 줄이 자기 창 kpm2 뒤에 옴(late) — 판정 없음, 경보 없음 (16_ E1b, 현재 동작 고정)", 4000)
    for du, t in _stall5():
        sc.ue(du).auth_stall(t)
    sc.late_msgs = {"RegistrationRequest"}
    return sc


def s01_late_one_expired():
    # 이슈 #46 (14_ §4.3 late_until, 15_ L01-T21): s01_late_one과 같이 RegistrationRequest 한 줄이 늦은 5대. 첫 AuthenticationRequest
    # (t+105)의 마감 t+2105는 late_until(t+91+16000)보다 앞이라 판정 없음. 17 s 뒤 두 번째 AuthenticationRequest(t+17105)에도
    # 무응답 → 마감 t+19105 ≥ late_until → 고착. 5번째(t=800) 마감 19905 → RAISE 20000, ues[].uncertain에 late
    sc = Scenario("S01_L3-01-O_순서역전1줄_만료뒤_RAISE",
                  "RegistrationRequest 한 줄이 늦은 5대 — 2 s 마감은 late_until 안(판정 없음), 17 s 뒤 재요청 무응답은 고착 → RAISE (이슈 #46, 15_ L01-T21)", 20200)
    for du, t in _stall5():
        sc.ue(du).auth_stall(t).auth_req(t + 17105)
    sc.late_msgs = {"RegistrationRequest"}
    sc.alert("RAISE", 20000, "L3-01-O", severity="medium", mode="normal")
    return sc


def s01_late_all():
    # 16_ E1a: 모든 ue_evt가 자기 창 kpm2 뒤에 옴 → 모두 late, 경보 없음
    sc = Scenario("S01_L3-01-O_순서역전전부_무경보",
                  "인증 무응답 5대, 모든 ue_evt가 자기 창 kpm2 뒤에 옴(모두 late) — 판정 없음, 경보 없음 (16_ E1a, 현재 동작 고정)", 4000)
    for du, t in _stall5():
        sc.ue(du).auth_stall(t)
    sc.late_msgs = "all"
    return sc


def s01_ul_loss_one():
    # 16_ E2c: t=1500 한 칸(100 ms)만 UL 로스 — 대기 구간 [t₀, t₀+2000)이 모두 그 칸과 겹쳐 5건 전부 보류(14_ §6.2).
    # 기존 '로스보류'는 20칸이고, 여기서는 한 칸이면 충분하다. 이슈 #48: 보류 5건 → 불확실 경보 RAISE 3000(공격 경보는 없음)
    sc = Scenario("S01_L3-01-O_UL로스1칸_불확실RAISE",
                  "인증 무응답 5대, t=1.5 s에 UL 로스 한 칸(100 ms) — 겹치는 5건 모두 보류 → 불확실 경보 RAISE (16_ E2c, L01-T20)", 4000)
    for du, t in _stall5():
        sc.ue(du).auth_stall(t)
    sc.set_loss(1, 15, ["UL"])
    sc.alert("RAISE", 3000, "L3-01-O", severity="medium", mode="normal", alert_kind="anomaly")
    return sc


def s01_lost_missing():
    # 16_ E2: kpm2에 ue_evt_lost 키가 없음 — 알 수 없으므로 양방향 로스(14_ §6.2) → 전부 보류. 이슈 #48: 첫 칸에서 진단
    # ue_evt_lost_missing(시험은 경보만 비교), 보류 5건 → 불확실 경보 RAISE 3000
    sc = Scenario("S01_L3-01-O_ue_evt_lost누락_불확실RAISE",
                  "인증 무응답 5대, 모든 kpm2에 ue_evt_lost 키 없음 — 양방향 로스로 보아 전부 보류 → 불확실 경보 RAISE (16_ E2)", 4000)
    for du, t in _stall5():
        sc.ue(du).auth_stall(t)
    sc.drop_lost = True
    sc.alert("RAISE", 3000, "L3-01-O", severity="medium", mode="normal", alert_kind="anomaly")
    return sc


# ============ L3-20 Blind DoS (15_ §2) ============

def s20_normal():
    # L20-T1: 정상 첫 등록(SUCI, S-TMSI 없음) → 짝 없음, 경보 없음
    sc = Scenario("S20_L3-20_정상첫등록_무경보", "정상 첫 등록(SUCI, S-TMSI 없음) — 짝 없음, 경보 없음 (L20-T1)", 1200)
    sc.ue(1).normal_register(0)
    return sc


def s20_rlf():
    # L20-T3: RLF 충돌 — 옛 항목 열린 채 같은 S-TMSI 새 연결이 300 ms 뒤 RRC SMC 수락 → 풀림
    sc = Scenario("S20_L3-20_RLF재접속_무경보", "RLF — 같은 S-TMSI 새 연결이 300 ms 뒤 RRC SMC 수락 (L20-T3)", 2000)
    sc.ue(1).normal_register(0, s_tmsi=VIC)
    u2 = sc.ue(2)
    u2.setup_req(1000).setup(1001).setup_complete(1090, s_tmsi=VIC)   # t₀ = 1090, concurrent 대기
    u2.rrc_smc(1390).rrc_smcomplete(1400)                              # +300 ms 수락 → 풀림
    return sc


def s20_high():
    # L20-T4: 피해자 열림, 공격 연결 수락 없음, 피해자 +20 ms 해제 → concurrent·high
    sc = Scenario("S20_L3-20_CONNECTED_high", "피해자 S-TMSI로 연 공격 연결, 수락 없음, 피해자 해제 → high (L20-T4)", 7000)
    sc.ue(1).normal_register(0, s_tmsi=VIC)
    a = sc.ue(2)
    a.setup_req(1000).setup(1001).setup_complete(1090, s_tmsi=VIC)   # t₀ = 1090, 마감 4090 → 처리 4100
    a.svc_req(1091, s_tmsi=VIC)
    sc.ue(1).ctx_release_cmd(1110)   # 피해자 해제 +20 ms → victim_released
    sc.alert("RAISE", 4100, "L3-20", severity="high", mode="normal")
    return sc


def s20_medium():
    # L20-T5: 피해자 해제 없음 → concurrent·medium
    sc = Scenario("S20_L3-20_CONNECTED_medium", "공격 연결 수락 없음, 피해자 해제 없음 → medium (L20-T5)", 7000)
    sc.ue(1).normal_register(0, s_tmsi=VIC)
    a = sc.ue(2)
    a.setup_req(1000).setup(1001).setup_complete(1090, s_tmsi=VIC).svc_req(1091, s_tmsi=VIC)
    sc.alert("RAISE", 4100, "L3-20", severity="medium", mode="normal")
    return sc


def s20_closed():
    # L20-T6: 공격 연결이 1 s 뒤 ServiceReject → 해제. 마감 처리 때 걸림(closed_ms 1000), medium
    sc = Scenario("S20_L3-20_공격연결닫힘_RAISE", "공격 연결이 1 s 뒤 거절·해제 — 마감 때 걸림 (L20-T6)", 7000)
    sc.ue(1).normal_register(0, s_tmsi=VIC)
    a = sc.ue(2)
    a.setup_req(1000).setup(1001).setup_complete(1090, s_tmsi=VIC).svc_req(1091, s_tmsi=VIC)   # t₀ = 1090
    a.svc_reject(2000).ctx_release_complete(2090)   # 닫힘(released), closed_ms ≈ 1000
    sc.alert("RAISE", 4100, "L3-20", severity="medium", mode="normal")
    return sc


def s20_idle():
    # L20-T7: 피해자가 먼저 완전히 해제된 뒤 공격 연결 — 열린 짝 없음 → 경보 없음(IDLE형 탐지 안 함, 15_ §2.1)
    sc = Scenario("S20_L3-20_IDLE_무경보", "피해자 해제 뒤 공격 연결 — 열린 짝 없음, 경보 없음 (L20-T7)", 7000)
    v = sc.ue(1)
    v.normal_register(0, s_tmsi=VIC).ctx_release_complete(300)   # 피해자 완전 해제
    a = sc.ue(2)
    a.setup_req(1000).setup(1001).setup_complete(1090, s_tmsi=VIC).svc_req(1091, s_tmsi=VIC)   # 열린 짝 없음
    return sc


def s20_peer_uncertain():
    # L20-T14: 짝(피해자)이 loss 불확실(로스 뒤 줄 없음) → peer_uncertain·medium (15_ §2.3)
    sc = Scenario("S20_L3-20_peer_uncertain_medium", "짝이 loss 불확실(유령일 수 있음) → peer_uncertain·medium (L20-T14)", 7000)
    sc.ue(1).normal_register(0, s_tmsi=VIC)
    sc.set_loss(1, 5, ["UL", "DL"])   # t=500 로스 → 피해자 loss, t_loss=600, 이후 줄 없음 → uncertain
    a = sc.ue(2)
    a.setup_req(1000).setup(1001).setup_complete(1090, s_tmsi=VIC).svc_req(1091, s_tmsi=VIC)
    sc.alert("RAISE", 4100, "L3-20", severity="medium", mode="normal")
    return sc


def s20_repeat_update():
    # L20-T15: 같은 피해자로 공격 연결 3번(1 s 간격) → RAISE + UPDATE ×2 (14_ §8.2, update_min_ms 1000)
    sc = Scenario("S20_L3-20_반복_UPDATE", "같은 피해자로 공격 연결 3번(1 s 간격) → RAISE + UPDATE (L20-T15)", 8600)
    sc.ue(1).normal_register(0, s_tmsi=VIC)
    for k, t in enumerate([1000, 2000, 3000]):
        a = sc.ue(2 + k)
        a.setup_req(t).setup(t + 1).setup_complete(t + 90, s_tmsi=VIC).svc_req(t + 91, s_tmsi=VIC)
    sc.alert("RAISE", 4100, "L3-20", severity="medium", mode="normal")
    sc.alert("UPDATE", 5100, "L3-20")
    sc.alert("UPDATE", 6100, "L3-20")
    return sc


def s20_repeat_prior_attack_released():
    # 15_ §2.3 짝 = 망 수락을 한 번이라도 얻은 열린 항목 (11/05 Q-72 해결, 이슈 #94 — 25_ §3.2-5 재현): 같은 피해자로 공격 연결 2번
    # (1 s 간격), 앞선 공격 연결은 2.5 s에 해제. 둘째 공격의 짝은 피해자뿐이라 앞선 공격의 해제가 victim_released로 세어지지 않는다
    # → RAISE 4100(앞선 공격, 마감 전 닫힘)·UPDATE 5100 모두 medium(11/15 수락 대기 3 s — 그전 6100·7100). 11/04까지는 앞선 공격 연결도 짝이라 UPDATE가 high였다
    sc = Scenario("S20_L3-20_반복_앞선공격해제_medium",
                  "공격 연결 2번, 앞선 공격 연결을 2.5 s에 해제 — 둘째 공격의 짝은 피해자뿐, medium 유지 (15_ §2.3, 11/05 Q-72)", 7600)
    sc.ue(1).normal_register(0, s_tmsi=VIC)
    a = sc.ue(2)
    a.setup_req(1000).setup(1001).setup_complete(1090, s_tmsi=VIC).svc_req(1091, s_tmsi=VIC)   # t₀ = 1090, 마감 4090
    b = sc.ue(3)
    b.setup_req(2000).setup(2001).setup_complete(2090, s_tmsi=VIC).svc_req(2091, s_tmsi=VIC)   # t₀ = 2090, 마감 5090
    a.ctx_release_cmd(2500).ctx_release_complete(2500)   # 앞선 공격 연결 해제 — b의 짝이 아니다
    sc.alert("RAISE", 4100, "L3-20", severity="medium", mode="normal")
    sc.alert("UPDATE", 5100, "L3-20", severity="medium")
    return sc


def s20_clear():
    # L20-T16: RAISE 뒤 60 s 새 걸림 없음 → CLEAR. 마지막 걸림=4090 → t_end>=64090 → 64100
    sc = Scenario("S20_L3-20_해제_CLEAR", "공격 1건 RAISE 뒤 60 s 조용 → CLEAR (L20-T16)", 66300)
    sc.ue(1).normal_register(0, s_tmsi=VIC)
    a = sc.ue(2)
    a.setup_req(1000).setup(1001).setup_complete(1090, s_tmsi=VIC).svc_req(1091, s_tmsi=VIC)
    sc.alert("RAISE", 4100, "L3-20", severity="medium", mode="normal")
    sc.alert("CLEAR", 64100, "L3-20")
    return sc


def s20_session_end():
    # 14_ §7 END: RAISE 뒤 새 session hello → session_reset END. END t = 직전 kpm2 t_end=7000
    sc = Scenario("S20_L3-20_세션변경_END", "공격 RAISE 뒤 분석 엔진 재시작(새 session) → END (14_ §7)", 7100)
    sc.ue(1).normal_register(0, s_tmsi=VIC)
    a = sc.ue(2)
    a.setup_req(1000).setup(1001).setup_complete(1090, s_tmsi=VIC).svc_req(1091, s_tmsi=VIC)
    sc.ue(1).ctx_release_cmd(1110)
    sc.change_session(70, "S2")   # t=7000: 새 session → END(session_reset)
    sc.alert("RAISE", 4100, "L3-20", severity="high", mode="normal")
    sc.alert("END", 7000, "L3-20", reason="session_reset")
    return sc


# ============ L3-21 상향 DoS (15_ §5) ============

def s21_normal():
    # L21-T1/T2: 정상 등록 + 동기 실패 뒤 재인증 수락 → 경보 없음
    sc = Scenario("S21_L3-21_정상_무경보",
                  "정상 등록 + 동기 실패 뒤 재인증 수락 — L3-21 경보 없음 (L21-T1·T2). 동기 실패(#21)는 4단계 이상 유형 AN-01이 명세대로 받는다 — "
                  "t0+520 실패가 든 창 kpm2(t0+600)에 AN-01 RAISE (21_ §3.3, 11/04 M9 이슈 #70 — '무경보'는 L3-21 기준이라 이름은 그대로, 1_ §6)",
                  1500)
    sc.ue(1).normal_register(0)
    u = sc.ue(2)
    u.setup_req(400).setup(401).setup_complete(490).reg_req(491).auth_req(505)
    u.auth_fail(520, cause=21)   # 동기 실패(실패 메시지) → 갈래① 대기 시작
    u.auth_req(540).auth_resp(553).rrc_smc(570).rrc_smcomplete(580)   # 재인증·수락 → 갈래① 풀림
    # 11/04 M9(이슈 #70)에 데이터만 손으로 고치고 생성기는 안 고쳤던 것 — 11/05 이슈 #94에서 생성기를 데이터에 맞춤
    sc.alert("RAISE", 600, "AN-01", severity="medium", alert_kind="anomaly")
    sc.expect[-1]["candidates"] = ["L3-07-OV"]
    return sc


def s21_fail4():
    # L21-T5 앞: 실패 UE 4개 → 경보 없음
    sc = Scenario("S21_L3-21_실패4_무경보", "무효 등록 4대 거절(실패 UE 4개) — 문턱 N=5 미만 (L21-T5)", 6200)
    for i, t in enumerate([0, 200, 400, 600]):
        u = sc.ue(i + 1)
        u.setup_req(t).setup(t + 1).setup_complete(t + 90).reg_req(t + 91).reg_reject(t + 105)
    return sc


def s21_branch1():
    # L21-T4: 실패 UE 5개 → 갈래① RAISE. 5번째 t_f=905, 마감 5905 → 처리 6000
    sc = Scenario("S21_L3-21_원형_갈래1_RAISE", "무효 등록 5대 거절(실패 UE 5개) → 갈래① medium (L21-T4)", 6500)
    for i, t in enumerate([0, 200, 400, 600, 800]):
        u = sc.ue(i + 1)
        u.setup_req(t).setup(t + 1).setup_complete(t + 90).reg_req(t + 91).reg_reject(t + 105)
    sc.alert("RAISE", 6000, "L3-21", branch="1", severity="medium", mode="normal")
    return sc


def s21_branch2():
    # L21-T6: 한 연결에서 RegistrationRequest 3번 + 실패 → 갈래② 즉시(그 줄 t_ms=400). 15_ §5.3
    sc = Scenario("S21_L3-21_변형_갈래2_RAISE", "한 연결 등록 요청 3번 + 거절 → 갈래② 즉시 (L21-T6)", 1000)
    u = sc.ue(1)
    u.setup_req(0).setup(1).setup_complete(90)
    u.reg_req(91, id_type="5G-GUTI", s_tmsi=VIC)    # cnt 1
    u.reg_reject(200, cause=9)                        # 실패
    u.reg_req(300, id_type="5G-GUTI", s_tmsi=VIC)    # cnt 2
    u.reg_req(400, id_type="5G-GUTI", s_tmsi=VIC)    # cnt 3 → 갈래② 걸림
    sc.alert("RAISE", 400, "L3-21", branch="2", severity="medium", mode="normal")
    return sc


def s21_reg_only():
    # L21-T7: 한 연결 등록 3번, 실패 없음 → 갈래② 아님, 경보 없음
    sc = Scenario("S21_L3-21_등록반복무실패_무경보", "한 연결 등록 요청 3번, 실패 없음 — 갈래② 아님 (L21-T7)", 1000)
    u = sc.ue(1)
    u.setup_req(0).setup(1).setup_complete(90).reg_req(91).reg_req(300).reg_req(400)
    return sc


def s21_mixed_high():
    # L21-T11: 갈래① 경보 중 갈래② UE 걸림 → UPDATE·high (15_ §5.5)
    sc = Scenario("S21_L3-21_혼합_high", "갈래① RAISE 뒤 같은 셀 갈래② UE 걸림 → UPDATE·high (L21-T11)", 6800)
    for i, t in enumerate([0, 200, 400, 600, 800]):
        u = sc.ue(i + 1)
        u.setup_req(t).setup(t + 1).setup_complete(t + 90).reg_req(t + 91).reg_reject(t + 105)   # 갈래① 5개 → RAISE 6000
    b2 = sc.ue(6)
    b2.setup_req(6100).setup(6101).setup_complete(6190)
    b2.reg_req(6191).reg_reject(6200).reg_req(6300).reg_req(6400)   # cnt 3 + 실패 → 갈래②, sat1 참 → high
    sc.alert("RAISE", 6000, "L3-21", branch="1", severity="medium", mode="normal")
    sc.alert("UPDATE", 6400, "L3-21", branch="1", severity="high")
    return sc


def s21_accept_boundary_intime():
    # L21-T9 앞: 실패 뒤 수락 t_ms = t_f+4999(제때) → 실패 UE 아님. 5대 모두 회복 → 경보 없음
    sc = Scenario("S21_L3-21_수락경계_정시_무경보", "거절 뒤 t_f+4999 수락(제때) 5대 → 실패 UE 아님 (L21-T9)", 6500)
    for i, t in enumerate([0, 200, 400, 600, 800]):
        u = sc.ue(i + 1)
        u.setup_req(t).setup(t + 1).setup_complete(t + 90).reg_req(t + 91)
        u.reg_reject(t + 105).reg_accept(t + 105 + 4999)   # t_f, 제때 수락 → 대기 풀림
    return sc


def s21_sec_reject():
    # L21-T15: SecurityModeReject만 있는 연결 → 실패로 세지 않음, 경보 없음
    sc = Scenario("S21_L3-21_SecModeReject_무경보", "SecurityModeReject만 있는 연결 — 실패 아님 (L21-T15)", 1000)
    u = sc.ue(1)
    u.setup_req(0).setup(1).setup_complete(90).reg_req(91).nas_smc(200).nas_sec_reject(300)
    return sc


def s21_hold():
    # L21-T10: 갈래 ① 대기 구간에 DL 로스 창 → 실패 UE 보류(14_ §6.2). 5대 모두 보류 → 공격 경보 없음.
    # 이슈 #48(L21-T22): 보류 5건 → 불확실 경보(갈래 없음) — 5번째 마감 5905 → RAISE 6000
    sc = Scenario("S21_L3-21_로스보류_불확실RAISE",
                  "무효 등록 5대 거절이지만 대기 구간 DL 로스 → 모두 보류, 공격 경보 없이 불확실 경보 RAISE (L21-T10·L21-T22)", 6500)
    for i, t in enumerate([0, 200, 400, 600, 800]):
        u = sc.ue(i + 1)
        u.setup_req(t).setup(t + 1).setup_complete(t + 90).reg_req(t + 91).reg_reject(t + 105)
    for tick in range(10, 62):   # t=1000~6100 DL 로스 — 마감 처리 때 loss_end[DL] > t_from → 보류
        sc.set_loss(1, tick, ["DL"])
    sc.alert("RAISE", 6000, "L3-21", severity="medium", mode="normal", alert_kind="anomaly")
    return sc


def s21_clear():
    # L21-T12: 갈래① RAISE 뒤 60 s 조용 → CLEAR. t_active=5905 → t_end>=65905 → 66000
    sc = Scenario("S21_L3-21_해제_CLEAR", "갈래① 5건 RAISE 뒤 60 s 조용 → CLEAR (L21-T12)", 66200)
    for i, t in enumerate([0, 200, 400, 600, 800]):
        u = sc.ue(i + 1)
        u.setup_req(t).setup(t + 1).setup_complete(t + 90).reg_req(t + 91).reg_reject(t + 105)
    sc.alert("RAISE", 6000, "L3-21", branch="1", severity="medium", mode="normal")
    sc.alert("CLEAR", 66000, "L3-21")
    return sc


# 쓰는 순서는 L3-20 → L3-01-O → L3-21(15_ §0)이지만 파일은 룰별로 묶어 둔다
SCENARIOS = [
    s01_normal, s01_one_stall, s01_stall4, s01_stall5, s01_stall5_high,
    s01_fail_is_response, s01_resp_boundary_late, s01_hold, s01_clear, s01_clear_then_rehit,
    s20_normal, s20_rlf, s20_high, s20_medium, s20_closed, s20_idle,
    s20_peer_uncertain, s20_repeat_update, s20_repeat_prior_attack_released, s20_clear, s20_session_end,
    s21_normal, s21_fail4, s21_branch1, s21_branch2, s21_reg_only,
    s21_mixed_high, s21_accept_boundary_intime, s21_sec_reject, s21_hold, s21_clear,
    # 입력 불완전 (이슈 #42) — 뒤에 둔다: 앞의 29개 파일은 그대로다
    s01_late_one, s01_late_all, s01_ul_loss_one, s01_lost_missing,
    # late_until 만료 뒤 판정 (이슈 #46)
    s01_late_one_expired,
    # 불확실 경보 뒤 공격 경보 (이슈 #48)
    s01_held_then_attack,
]


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "tests", "data", "stage2_green")
    os.makedirs(out_dir, exist_ok=True)
    for make in SCENARIOS:
        sc = make()
        lines = sc.build()
        with open(os.path.join(out_dir, sc.name + ".jsonl"), "w", encoding="utf-8") as f:
            for line in lines:
                f.write(json.dumps(line, ensure_ascii=False, separators=(",", ":")) + "\n")
        expected = {"scenario": sc.name, "description": sc.desc, "t0_ms": T0, "tolerance_ms": P,
                    "alerts": sc.expect}
        with open(os.path.join(out_dir, sc.name + ".expected.json"), "w", encoding="utf-8") as f:
            json.dump(expected, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print(f"{sc.name}: {len(lines)} lines, {len(sc.expect)} alerts expected")


if __name__ == "__main__":
    main()
