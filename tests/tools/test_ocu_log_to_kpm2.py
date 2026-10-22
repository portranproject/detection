#!/usr/bin/env python3
"""CU 로그 변환기 테스트 (4_ §4.1) — ctest가 부른다. 인자: <저장소 경로> <detector 경로> <임시 폴더>

샘플 로그는 4_ §4.1·5_ §5에 적힌 실제 줄 형식(OCUDU 커밋 e0db566aac의 문구)으로 만든다.
실제 박스 로그와 같은 모양인지는 박스에서 따로 확인한다(Q-14).
"""

import json
import os
import subprocess
import sys
import unittest

REPO, DET, TMP = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path.insert(0, os.path.join(REPO, "tools"))
import ocu_log_to_kpm2 as conv  # noqa: E402

os.makedirs(TMP, exist_ok=True)


def L(ts, body, lvl="I"):
    return f"2026-10-17T14:45:{ts} [RRC     ] [{lvl}] {body}\n"


def setup_req_json(cause="mo-Signalling"):
    # RRCSetupRequest 디코드 JSON (여러 줄) — 앞쪽 줄에 메시지 이름과 원인이 보인다
    return ['    "rrcSetupRequest": {\n', f'      "establishmentCause": "{cause}"\n', "    }\n"]


def run(lines):
    events, stats = conv.scan(lines, 0)
    return events, stats


def totals(jsonl):
    a = s = f = r = 0
    for j in jsonl[1:]:
        cc = j["cc"]
        a += cc["RRC.ConnEstabAtt"]["total"]
        s += cc["RRC.ConnEstabSucc"]["total"]
        f += cc["RRC.ConnEstabFailCause"]["NoReply"]
        r += cc["RRC.ConnEstabFailCause"]["NetworkReject"]
    return a, s, f, r


class Convert(unittest.TestCase):
    def test_normal_attach(self):
        # 5_ §5 실제 줄: started → 89 ms 뒤 finished
        lines = setup_req_json() + [
            L("14.341825", 'ue=0 c-rnti=0x4601: "RRC Setup Procedure" started...'),
            L("14.431206", 'ue=0 c-rnti=0x4601: "RRC Setup Procedure" finished successfully'),
        ]
        ev, _ = run(lines)
        out = conv.to_jsonl(ev, "S", 1)
        self.assertEqual(totals(out), (1, 1, 0, 0))
        self.assertEqual(out[0]["type"], "hello")
        # 칸은 끊김 없이 이어진다 (2_ §4.1)
        for prev, cur in zip(out[1:], out[2:]):
            self.assertEqual(cur["t_start_ms"], prev["t_end_ms"])
        self.assertEqual(sum(j["ext"]["CrntiAlloc"] for j in out[1:]), 1)

    def test_noreply_after_timeout(self):
        # Msg5가 없으면 started + 1000 ms 칸에 NoReply (2_ §5), OCUDU 자체 timed out(2000 ms) 줄은 세지 않음
        lines = [
            L("14.000000", 'ue=1 c-rnti=0x4602: "RRC Setup Procedure" started...'),
            L("16.000000", 'ue=1 c-rnti=0x4602: "RRC Setup Procedure" timed out after 2000ms', "W"),
        ]
        ev, stats = run(lines)
        self.assertEqual([k for _, k, _ in ev], ["att", "noreply"])
        self.assertEqual(ev[1][0] - ev[0][0], 1000)
        self.assertEqual(stats["ocudu_timeout_ref"], 1)

    def test_late_finish_counts_both(self):
        # 1000 ms 뒤에 끝난 연결은 NoReply와 Succ에 함께 잡힌다 (2_ §5 — 분석 엔진과 같은 이중 계산)
        lines = [
            L("14.000000", 'ue=2 c-rnti=0x4603: "RRC Setup Procedure" started...'),
            L("15.500000", 'ue=2 c-rnti=0x4603: "RRC Setup Procedure" finished successfully'),
        ]
        ev, _ = run(lines)
        self.assertEqual(sorted(k for _, k, _ in ev), ["att", "noreply", "succ"])

    def test_unexpected_ul_dcch_is_noreply(self):
        lines = [
            L("14.000000", 'ue=3 c-rnti=0x4604: "RRC Setup Procedure" started...'),
            L("14.200000", 'ue=3 c-rnti=0x4604: Unexpected UL-DCCH message type 0 in RRC Setup Procedure', "W"),
        ]
        ev, _ = run(lines)
        self.assertEqual([k for _, k, _ in ev], ["att", "noreply"])
        self.assertEqual(ev[1][0] - ev[0][0], 200)  # 대기 끝 = 그 시각, 1000 ms 뒤 중복 없음

    def test_reject_only_after_setup_request(self):
        # DU 자원 부족 거절은 바로 앞 UL-CCCH가 RRCSetupRequest일 때만 Att + NetworkReject (4_ §4.1)
        lines = setup_req_json() + [
            L("14.000000", 'ue=4 c-rnti=0x4605: "Sending rrcReject. Cause: DU is not able to serve the UE"', "W"),
            '    "rrcReestablishmentRequest": {\n',
            L("14.100000", 'ue=5 c-rnti=0x4606: "Sending rrcReject. Cause: DU is not able to serve the UE"', "W"),
            L("14.200000", 'ue=6 c-rnti=0x4607: "Sending Connection Reject. Cause: RRC connections not allowed"', "W"),
            L("14.300000", "ue=7: UE admission limit reached", "W"),
        ]
        ev, stats = run(lines)
        out = conv.to_jsonl(ev, "S", 1)
        self.assertEqual(totals(out), (3, 0, 0, 3))
        self.assertEqual(stats["reject_du_not_setup"], 1)

    def test_empty_log(self):
        ev, _ = run(["no events here\n"])
        self.assertEqual(len(conv.to_jsonl(ev, "S", 1)), 1)  # hello만

    def test_span_covers_whole_log(self):
        # 사건이 없는 구간도 로그가 찍힌 동안은 0건 칸으로 낸다 (CU가 관측 중이었으므로)
        lines = [
            L("10.000000", "[CU-CP] boot"),
            L("14.000000", 'ue=0 c-rnti=0x4601: "RRC Setup Procedure" started...'),
            L("14.089000", 'ue=0 c-rnti=0x4601: "RRC Setup Procedure" finished successfully'),
            L("20.000000", "[CU-CP] still running"),
        ]
        ev, stats = run(lines)
        out = conv.to_jsonl(ev, "S", 1, span=stats["span_ms"])
        self.assertEqual(len(out) - 1, 101)  # 10.0 s ~ 20.1 s
        self.assertEqual(totals(out), (1, 1, 0, 0))

    def test_utc_offset(self):
        line = [L("14.000000", 'ue=0 c-rnti=0x4601: "RRC Setup Procedure" started...')]
        utc, _ = conv.scan(line, 0)
        kst, _ = conv.scan(line, 9)
        self.assertEqual(utc[0][0] - kst[0][0], 9 * 3600 * 1000)


class EndToEnd(unittest.TestCase):
    # 정상 접속 로그 → 변환 → detector --replay: 경보 없음 (4_ §6 M4.5, 3_ T1)
    def test_normal_log_no_alert(self):
        log = os.path.join(TMP, "ocu_normal.log")
        with open(log, "w") as f:
            for i in range(20):  # 0.5 s마다 정상 접속 20회
                sec = 10 + i // 2
                us = (i % 2) * 500000
                f.writelines(setup_req_json())
                f.write(f"2026-10-17T14:45:{sec:02d}.{us:06d} [RRC     ] [I] ue={i} c-rnti=0x{0x4600 + i:x}: \"RRC Setup Procedure\" started...\n")
                f.write(f"2026-10-17T14:45:{sec:02d}.{us + 89000:06d} [RRC     ] [I] ue={i} c-rnti=0x{0x4600 + i:x}: \"RRC Setup Procedure\" finished successfully\n")
        out = os.path.join(TMP, "ocu_normal.jsonl")
        r = subprocess.run([sys.executable, os.path.join(REPO, "tools", "ocu_log_to_kpm2.py"), log, "-o", out],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        cfg = os.path.join(TMP, "ocu_off.json")
        with open(cfg, "w") as f:
            json.dump({"evidence": {"mode": "off"}}, f)
        d = subprocess.run([DET, "--replay", out, "--config", cfg], capture_output=True, text=True, timeout=60)
        self.assertEqual(d.returncode, 0, d.stderr)
        self.assertNotIn("ALERT", d.stdout)
        self.assertNotIn("format_error", d.stderr)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=1)
