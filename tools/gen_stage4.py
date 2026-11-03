#!/usr/bin/env python3
"""합성 ue_evt+kpm2 4단계 시나리오(.jsonl)와 기대 경보(.expected.json) 생성기.

명세: 4단계 룰 21_탐지엔진_4단계-노란색룰_명세서.md(AN-01 §3.8 — 뒤 룰은 구현 이슈마다 더함), 입력 2_ §6, 상태·경보 14_.
실행: python3 tools/gen_stage4.py [출력 폴더]  (기본 tests/data/stage4_yellow/).
tests/core/test_scenarios.cpp가 이 폴더를 실행 파일과 같은 룰 구성(1~4단계, 기본값)으로 재생해 같은 이름 .expected.json과
비교한다(Stage4Scenario, 시각 정확 비교). 3단계 생성기 gen_stage3.py의 UE3·Scenario3·기본 흐름 F·K(t)를 그대로 쓰고
4단계 흐름(AN-01 동기 실패 흐름 S)과 기대 경보의 candidates(4단계는 후보가 경보의 뜻이다, 21_ §1)만 더한다.

기대 경보 시각은 명세 식으로 손 계산한 값이다(3단계와 같은 방식):
 - 연결 시작 t0 = 1000(창 시작). K(t) = t를 품은 창의 t_end — 걸림이 든 창의 kpm2에서 RAISE(21_ §1.1)
 - UPDATE = 새 UE가 걸린 뒤 RAISE·UPDATE에서 update_min_ms(1,000) 이상인 첫 kpm2(14_ §8.2)
 - CLEAR = 경보에 실린 마지막 걸림 + clear_quiet_ms(60,000) 이상인 첫 kpm2(21_ §3.5)
재생은 설정 기본값(AN-01 n_sync 1)이라 n_sync 2(AN01-T6·T7)·밀어내기(T10 뒤)·설정(T11)·결정성(T12)은 단위 시험만이다.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_stage2  # noqa: E402
import gen_stage3  # noqa: E402  (UE3·Scenario3·K·B)
from gen_stage2 import T0  # noqa: E402
from gen_stage3 import B, K  # noqa: E402

SYNCH_FAILURE = 21  # 5GMM 원인값 #21 synch failure (21_ §3.1)


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
              conditions=None, candidates=None):
        a = super().alert(kind, t_rel, rule, cell=cell, mode=mode, severity=severity, branch=branch, reason=reason,
                          alert_kind=alert_kind, conditions=conditions)
        if candidates is not None:
            a["candidates"] = candidates   # raise의 후보 (14_ §8.3, 21_ §1) — 시험이 그 이벤트의 값과 비교
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


SCENARIOS = [
    san01_normal, san01_raise, san01_second_failure, san01_mac_failure, san01_no_cause, san01_mid_join, san01_loss,
    san01_clear, san01_two_ues,
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
