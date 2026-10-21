#!/usr/bin/env python3
"""합성 kpm2 시나리오(.jsonl)와 기대 경보(.expected.json) 생성기.

명세: 4_ §2·§4-2(시나리오 테스트), 3_ §9(T1~T23). 실행: python3 tools/gen_kpm2.py [출력 폴더]
기본 출력 폴더는 tests/data/scenarios/.

분석 엔진 동작 모델 (2_ §4.2·§5를 단순화):
- 정상 시도: 같은 칸에 Att·Succ (실측 약 89 ms라 한 칸 안, 3_ §9)
- 공격 시도(Msg5 미전송): 그 칸에 Att, D = ⌈T_nr/P⌉칸 뒤 칸에 NoReply (2_ §5)
- 거절 시도(포화 ②): 같은 칸에 Att·NetworkReject (3_ §6.1)
- 속도(건/s)는 칸마다 누적기로 정수 건수로 바꾼다 — 같은 입력이면 항상 같은 파일
- 빠진 칸(gap)은 줄을 내지 않는다. 그 칸의 건수는 사라지고, 앞 칸에서 예약된 NoReply도 그 칸이면 사라진다

기대 경보의 시각은 이 생성기가 아니라 명세 식(3_ §3 지연 식, §6.1 H_sat)으로 손 계산한 값이다.
시나리오 시각은 모두 데이터 시작(T0)부터의 ms이고, 테스트는 ±tolerance_ms(1칸)를 허용한다 (3_ §9).
"""

import json
import math
import os
import sys

T0 = 1792209000000  # 데이터 시작 시각 (Unix epoch ms)
P = 100
T_NR = 1000
D = math.ceil(T_NR / P)


def const(v):
    return lambda t: v


def window(v, start, end=None):
    """[start, end) 동안 v건/s, 밖에서는 0"""
    return lambda t: v if t >= start and (end is None or t < end) else 0


def ramp(peak, start, dur):
    """start부터 dur 동안 0 → peak로 직선 증가, 그 뒤 peak (3_ T18)"""
    return lambda t: 0 if t < start else min(peak, peak * (t - start) / dur)


class Acc:
    """속도(건/s)를 칸별 정수 건수로 바꾸는 누적기"""

    def __init__(self):
        self.acc = 0.0

    def take(self, rate):
        self.acc += rate * P / 1000.0
        n = int(self.acc + 1e-9)
        self.acc -= n
        return n


class Cell:
    def __init__(self, cell_id, normal=const(0), attack=const(0), reject=const(0), drop=(), missing_as=()):
        self.cell_id = cell_id
        self.normal, self.attack, self.reject = normal, attack, reject
        self.drop = set(drop)              # 줄을 내지 않을 칸의 t_start(상대 ms)
        self.missing_as = set(missing_as)  # A·S를 null로 낼 칸
        self.acc = [Acc(), Acc(), Acc()]
        self.noreply = {}                  # 칸 번호 → 예약된 NoReply 수


def hello(session, seq, cells, max_conn=None):
    return {"type": "hello", "ver": 1, "session": session, "seq": seq, "producer": "gen_kpm2",
            "node_id": "synthetic", "cells": [{"cell_id": c.cell_id, "max_conn": max_conn} for c in cells],
            "period_ms": P, "noreply_timeout_ms": T_NR, "si_sample_ms": P, "clock": "realtime"}


def generate(duration_ms, cells, dl_missing=False, events=None):
    """events: {상대 ms: [동작]} — 칸을 내기 전에 실행. 동작은
    ('session', 새 session) / ('hello_same',) / ('hello_changed',) / ('raw', 줄 dict)"""
    events = events or {}
    session = "S1"
    seq = 1
    lines = [hello(session, seq, cells)]
    max_conn = None
    for i in range(duration_ms // P):
        t_rel = i * P
        for ev in events.get(t_rel, []):
            if ev[0] == "session":  # 분석 엔진 재시작: 새 session, seq 1부터, 대기 중 NoReply는 사라짐
                session, seq = ev[1], 1
                for c in cells:
                    c.noreply.clear()
                lines.append(hello(session, seq, cells, max_conn))
            elif ev[0] == "hello_same":  # 재연결: 같은 session·같은 파라미터
                seq += 1
                lines.append(hello(session, seq, cells, max_conn))
            elif ev[0] == "hello_changed":  # 같은 session인데 cells 파라미터가 바뀜
                seq += 1
                max_conn = 96
                lines.append(hello(session, seq, cells, max_conn))
            elif ev[0] == "raw":
                seq += 1
                line = dict(ev[1])
                line.update({"session": session, "seq": seq})
                lines.append(line)
        for c in cells:
            n_norm = c.acc[0].take(c.normal(t_rel))
            n_atk = c.acc[1].take(c.attack(t_rel))
            n_rej = c.acc[2].take(c.reject(t_rel))
            if n_atk:
                c.noreply[i + D] = c.noreply.get(i + D, 0) + n_atk
            f = c.noreply.pop(i, 0)
            if t_rel in c.drop:
                continue
            att, succ = n_norm + n_atk + n_rej, n_norm
            cc = {"RRC.ConnEstabAtt": {"total": att}, "RRC.ConnEstabSucc": {"total": succ}}
            if t_rel in c.missing_as:
                cc = {"RRC.ConnEstabAtt": None, "RRC.ConnEstabSucc": None}
            cc["RRC.ConnEstabFailCause"] = (None if dl_missing else
                                            {"NetworkReject": n_rej, "NoReply": f, "Other": 0})
            seq += 1
            lines.append({"type": "kpm2", "ver": 1, "session": session, "seq": seq, "cell_id": c.cell_id,
                          "t_start_ms": T0 + t_rel, "t_end_ms": T0 + t_rel + P, "cc": cc})
    return lines


def alert(kind, t_rel, cell=1, mode="normal", reason=None):
    a = {"kind": kind, "cell": cell, "t_rel_ms": t_rel, "mode": mode}
    if reason:
        a["reason"] = reason
    return a


# 기대값 계산 메모 (기본값 W 1000, A_min 5, θ 0.5, M 3, H_sat 3000, D 10칸):
#  - 30/s 공격 시작 S: A 윈도우 [t−2000, t−1000)에 공격이 5건 이상 → t = S+1200, M칸 → RAISE S+1400 (3_ §3 식)
#  - 60/s: t = S+1100부터 성립 → RAISE S+1300
#  - 30/s 공격 종료 E: 마지막 성립 = A 윈도우에 공격 6건(2칸) 남는 E+1800, + H_sat → CLEAR E+4800 (3_ T5)
SCENARIOS = {
    "T01_평상시": dict(
        desc="평상시: 0~20 s 정상 0, 20~40 s 정상 2/s", duration=40000,
        cells=lambda: [Cell(1, normal=window(2, 20000))], expect=[]),
    "T02_정상급증": dict(
        desc="정상 급증: 정상 1/s, 10~15 s 정상 30/s (S≈A)", duration=20000,
        cells=lambda: [Cell(1, normal=lambda t: 30 if 10000 <= t < 15000 else 1)], expect=[]),
    "T03_공격": dict(
        desc="공격 30/s (5 s부터), 정상 1/s", duration=12000,
        cells=lambda: [Cell(1, normal=const(1), attack=window(30, 5000))],
        expect=[alert("RAISE", 6400)]),
    "T04_저속공격": dict(
        desc="저속 공격 3/s — A_w = 4 < A_min", duration=20000,
        cells=lambda: [Cell(1, normal=const(1), attack=window(3, 5000))], expect=[]),
    "T05_공격종료": dict(
        desc="공격 30/s 5~15 s, 정상 1/s", duration=25000,
        cells=lambda: [Cell(1, normal=const(1), attack=window(30, 5000, 15000))],
        expect=[alert("RAISE", 6400), alert("CLEAR", 19800)]),
    "T06_공격중끊김": dict(
        desc="공격 중 한 칸(12.0 s) 유실 — 보류 후 재개, 경보 유지", duration=20000,
        cells=lambda: [Cell(1, normal=const(1), attack=window(30, 5000), drop=[12000])],
        expect=[alert("RAISE", 6400)]),
    "T07_세션변경": dict(
        desc="공격 중 12 s에 분석 엔진 재시작(session 변경) — end 후 재탐지(웜업 중 C3 참)", duration=20000,
        cells=lambda: [Cell(1, normal=const(1), attack=window(30, 5000))],
        events={12000: [("session", "S2")]},
        # 재시작 뒤 첫 칸 12.0 s → A 윈도우가 차는 t = 14000부터 성립 → RAISE 14200
        expect=[alert("RAISE", 6400), alert("END", 12000, reason="session_reset"), alert("RAISE", 14200)]),
    "T08_공격정상혼합": dict(
        desc="공격 30/s + 정상 20/s — ratio = 3j/(3j+20) ≥ 0.5 → j = 7", duration=15000,
        cells=lambda: [Cell(1, normal=const(20), attack=window(30, 5000))],
        expect=[alert("RAISE", 6900)]),
    "T13_포화2": dict(
        desc="포화 ②: 공격 60/s 5~10 s, 이후 거절 60/s(Att + NetworkReject) 10~20 s", duration=20000,
        cells=lambda: [Cell(1, normal=const(1), attack=window(60, 5000, 10000), reject=window(60, 10000))],
        expect=[alert("RAISE", 6300)]),
    "T14_포화3": dict(
        desc="포화 ③: T13에 이어 15 s에 Att까지 멈춤 — 마지막 성립 15.9 s + H_sat", duration=25000,
        cells=lambda: [Cell(1, normal=const(1), attack=window(60, 5000, 10000),
                            reject=window(60, 10000, 15000))],
        expect=[alert("RAISE", 6300), alert("CLEAR", 18900)]),
    "T15_순수거절": dict(
        desc="순수 거절 폭증 60/s 5~15 s (미완료 급증 이력 없음)", duration=20000,
        cells=lambda: [Cell(1, normal=const(1), reject=window(60, 5000, 15000))], expect=[]),
    "T17_조용한셀": dict(
        desc="조용한 셀(정상 0)에서 공격 30/s 5~15 s", duration=25000,
        cells=lambda: [Cell(1, attack=window(30, 5000, 15000))],
        expect=[alert("RAISE", 6400), alert("CLEAR", 19800)]),
    "T18a_램프3s": dict(
        desc="정상 2/s, 40 s부터 0→30/s를 3 s에 걸쳐 (웜업 뒤)", duration=55000,
        cells=lambda: [Cell(1, normal=const(2), attack=ramp(30, 40000, 3000))],
        # 3_ §9 T18 값(2.2·2.9·5.3 s)은 base가 정확히 2.0일 때다. 웜업 뒤 EWMA(3_ §5)가 램프 초반의
        # 의심 아닌 칸으로 base를 2.000 → 2.002로 올려 k × base가 6을 넘으므로 A_w = 7이 필요하다 (10/22 사용자 결정)
        expect=[alert("RAISE", 40000 + 2300)]),
    "T18b_램프10s": dict(
        desc="정상 2/s, 40 s부터 0→30/s를 10 s에 걸쳐", duration=55000,
        cells=lambda: [Cell(1, normal=const(2), attack=ramp(30, 40000, 10000))],
        expect=[alert("RAISE", 40000 + 3300)]),
    "T18c_램프30s": dict(
        desc="정상 2/s, 40 s부터 0→30/s를 30 s에 걸쳐", duration=60000,
        cells=lambda: [Cell(1, normal=const(2), attack=ramp(30, 40000, 30000))],
        expect=[alert("RAISE", 40000 + 6600)]),
    "T19_DL미관측": dict(
        desc="F·R가 null + 공격 30/s (5 s부터) — U로 판정, 시차 없음", duration=10000, dl_missing=True,
        cells=lambda: [Cell(1, normal=const(1), attack=window(30, 5000))],
        # A′ 윈도우 [t−1000, t)에 공격 2칸(6건) → t = 5200부터 성립 → RAISE 5400
        expect=[alert("RAISE", 5400, mode="dl_missing")]),
    "T21_두셀한셀끊김": dict(
        desc="셀 2개 모두 공격 30/s, 셀 2만 5.5 s 칸 유실 — 셀 2만 보류", duration=12000,
        cells=lambda: [Cell(1, normal=const(1), attack=window(30, 5000)),
                       Cell(2, normal=const(1), attack=window(30, 5000), drop=[5500])],
        # 셀 2: 5.5 s 칸이 A 윈도우에서 빠지는 t = 7600부터 성립 → RAISE 7800
        expect=[alert("RAISE", 6400, cell=1), alert("RAISE", 7800, cell=2)]),
    "T22a_hello같음": dict(
        desc="공격 중 10 s에 같은 session·같은 파라미터 hello — 상태 유지", duration=15000,
        cells=lambda: [Cell(1, normal=const(1), attack=window(30, 5000))],
        events={10000: [("hello_same",)]},
        expect=[alert("RAISE", 6400)]),
    "T22b_hello다름": dict(
        desc="공격 중 10 s에 같은 session·다른 cells(max_conn) hello — 초기화 후 재탐지", duration=15000,
        cells=lambda: [Cell(1, normal=const(1), attack=window(30, 5000))],
        events={10000: [("hello_changed",)]},
        # 초기화 뒤 첫 칸 10.0 s → A 윈도우가 차는 t = 12000부터 성립 → RAISE 12200
        expect=[alert("RAISE", 6400), alert("END", 10000, reason="session_reset"), alert("RAISE", 12200)]),
    "T22c_hello전kpm2_ver2": dict(
        desc="hello 전 kpm2 한 줄, 8 s에 ver=2 줄 — 둘 다 버림, 판정은 T03과 같음", duration=12000,
        cells=lambda: [Cell(1, normal=const(1), attack=window(30, 5000))],
        events={8000: [("raw", {"type": "kpm2", "ver": 2, "cell_id": 1,
                                "t_start_ms": T0 + 8000, "t_end_ms": T0 + 8100})]},
        before_hello={"type": "kpm2", "ver": 1, "session": "S1", "seq": 1, "cell_id": 1,
                      "t_start_ms": T0 - 100, "t_end_ms": T0,
                      "cc": {"RRC.ConnEstabAtt": {"total": 50}, "RRC.ConnEstabSucc": {"total": 0}}},
        expect=[alert("RAISE", 6400)]),
    "T23_입력장기단절": dict(
        desc="공격 중 10~21 s 입력 끊김(11 s > H_hold 10 s), 이후 정상만", duration=25000,
        cells=lambda: [Cell(1, normal=const(1), attack=window(30, 5000, 10000),
                            drop=range(10000, 21000, P))],
        # 끊김 뒤 첫 칸(21.0 s) 도착 시 보류 11 s > 10 s → END (t = 그 칸의 끝 21100)
        expect=[alert("RAISE", 6400), alert("END", 21100, reason="input_lost")]),
}


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "tests", "data", "scenarios")
    os.makedirs(out_dir, exist_ok=True)
    for name, sc in SCENARIOS.items():
        lines = generate(sc["duration"], sc["cells"](), sc.get("dl_missing", False), sc.get("events"))
        if "before_hello" in sc:
            lines.insert(0, sc["before_hello"])
        with open(os.path.join(out_dir, name + ".jsonl"), "w", encoding="utf-8") as f:
            for line in lines:
                f.write(json.dumps(line, ensure_ascii=False, separators=(",", ":")) + "\n")
        expected = {"scenario": name, "description": sc["desc"], "t0_ms": T0, "tolerance_ms": P,
                    "alerts": sc["expect"]}
        with open(os.path.join(out_dir, name + ".expected.json"), "w", encoding="utf-8") as f:
            json.dump(expected, f, ensure_ascii=False, indent=2)
            f.write("\n")
        print(f"{name}: {len(lines)} lines, {len(sc['expect'])} alerts expected")


if __name__ == "__main__":
    main()
