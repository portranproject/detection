#!/usr/bin/env python3
"""정리 도구 시험 PR-T1~PR-T9 (29_ §8.2)·실행 스크립트 S49·S50 (19_ §9) — ctest가 부른다. 인자: <저장소 경로> <detector 경로> <임시 폴더>

- PR-T는 tools/prune_outputs.py를 불러 main()을 직접 부른다. 지금 시각(now_s)·디스크 여유(free_bytes)는 모듈 함수를 바꿔 끼워 주입한다.
  종료 코드 시험(PR-T9)은 따로 프로세스로 띄운다.
- S49·S50은 실행 스크립트를 가짜 탐지 엔진 명령(줄을 쓰는 Python)으로 띄운다 — 회전하는 진짜 탐지 엔진은 쓰지 않는다.
  전송기가 보낼 곳은 가짜 수집 서버(http.server + ssl). 서버 인증서는 시험 시작 때 openssl로 만든다(키·인증서를 저장소에 넣지 않음).
  openssl이 없으면 S49·S50은 건너뛴다.
- detector 경로 인자는 쓰지 않는다(인자 규칙을 다른 tools 시험과 맞춤).
"""

import contextlib
import datetime
import http.server
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

REPO, DET, TMP = sys.argv[1], sys.argv[2], sys.argv[3]
PRUNE = os.path.join(REPO, "tools", "prune_outputs.py")
RUN = os.path.join(REPO, "tools", "run_with_sender.sh")
os.makedirs(TMP, exist_ok=True)

# 정리 도구를 모듈로 불러 now_s·free_bytes를 바꿔 끼운다 (tools/__pycache__를 만들지 않게)
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("prune_outputs", PRUNE)
po = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(po)

# 시험의 '지금' — 2026-11-08 10:00:00 UTC
NOW = datetime.datetime(2026, 11, 8, 10, 0, 0, tzinfo=datetime.timezone.utc).timestamp()
DAY = 86400
MIN_FREE = 209715200  # 200 MiB — input_record.min_free_bytes 범위(≥ 100 MiB) 안


def wait_until(pred, timeout=15.0, step=0.05):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(step)
    return pred()


# ---------------------------------------------------------------- 정리 도구 PR-T1~PR-T9 (29_ §8.2)

class PruneCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix=self._testMethodName[5:14] + "_", dir=TMP)
        self._saved = (po.now_s, po.free_bytes, os.getcwd())
        po.now_s = lambda: NOW
        po.free_bytes = lambda path: 10 ** 15  # 기본: 여유 충분
        self.n_cfg = 0

    def tearDown(self):
        po.now_s, po.free_bytes, cwd = self._saved
        os.chdir(cwd)

    def p(self, *parts):
        return os.path.join(self.dir, *parts)

    def touch(self, path, data=b'{"n":0}\n', mtime=None):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        if mtime is not None:
            os.utime(path, (mtime, mtime))
        return path

    def json_file(self, obj, name=None):
        self.n_cfg += 1
        path = self.p(name or f"cfg_{self.n_cfg}.json")
        with open(path, "w") as f:
            json.dump(obj, f)
        return path

    def det_cfg(self, evidence=None, input_record=None):
        c = {}
        if evidence is not None:
            c["evidence"] = evidence
        if input_record is not None:
            c["input_record"] = input_record
        return self.json_file(c)

    def sender_cfg(self, state_path):
        # 정리 도구는 전송기 설정에서 state_path만 읽는다
        return self.json_file({"inputs": [{"path": "evidence.jsonl", "kind": "evidence"}], "state_path": state_path})

    def write_state(self, path, base, protect):
        # 전송기 상태 파일 (19_ §4.3 형식) — base의 항목이 protect 파일의 (dev, ino)를 가리킴
        st = os.stat(protect)
        with open(path, "w") as f:
            json.dump({"ver": 1, "files": {os.path.abspath(base): {
                "dev": st.st_dev, "ino": st.st_ino, "offset": 0, "saved_ms": int(NOW * 1000)}}}, f)

    def prune(self, *args):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            try:
                rc = po.main(list(args))
            except SystemExit as e:
                rc = e.code
        return rc, err.getvalue()

    def listing(self, d=None):
        out = {}
        for root, _, files in os.walk(d or self.dir):
            for n in files:
                path = os.path.join(root, n)
                out[os.path.relpath(path, self.dir)] = os.lstat(path).st_size
        return out


class PruneTest(PruneCase):
    def test_PR_T1_age_by_name(self):
        # PR-T1: 이름 시각이 보관 기간 앞·뒤인 회전 파일 → 앞의 것만 지움, 지금 파일은 그대로.
        #        나이 = 지금 − 이름의 시각(수정 시각이 아님). 상대 경로는 정리 도구를 띄운 폴더 기준
        os.chdir(self.dir)
        det = self.det_cfg(evidence={"out_path": "evidence.jsonl", "keep_s": 7 * DAY},
                           input_record={"path": "rec/input.jsonl", "keep_s": 3 * DAY})
        old = NOW - 400 * DAY
        cur = self.touch(self.p("evidence.jsonl"), mtime=old)                  # 지금 파일 — 오래돼도 그대로
        e_del = self.touch(self.p("evidence.jsonl.20261101-095959"))           # 나이 7일 + 1초 → 지움
        e_del1 = self.touch(self.p("evidence.jsonl.20261101-095959.1"))        # 같은 시각 .1 → 지움
        e_edge = self.touch(self.p("evidence.jsonl.20261101-100000"))          # 나이 = 7일 정확히 → 남김(> 일 때만)
        e_new = self.touch(self.p("evidence.jsonl.20261108-090000"), mtime=old)  # 이름은 최근, 수정 시각은 오래됨 → 남김
        e_oldname = self.touch(self.p("evidence.jsonl.20261001-000000"), mtime=NOW)  # 이름은 오래됨, 수정 시각은 지금 → 지움
        i_cur = self.touch(self.p("rec", "input.jsonl"), mtime=old)
        i_del = self.touch(self.p("rec", "input.jsonl.20261105-095959"))       # 3일 + 1초 → 지움
        i_keep = self.touch(self.p("rec", "input.jsonl.20261105-100000"))      # 3일 정확히 → 남김
        i_new = self.touch(self.p("rec", "input.jsonl.20261108-000000"))
        rc, log = self.prune("--detector-config", os.path.basename(det),
                             "--sender-config", os.path.basename(self.sender_cfg("sender_state.json")))
        self.assertEqual(rc, 0, log)
        for f in (e_del, e_del1, e_oldname, i_del):
            self.assertFalse(os.path.exists(f), f)
        for f in (cur, e_edge, e_new, i_cur, i_keep, i_new):
            self.assertTrue(os.path.exists(f), f)
        # 로그는 기준 경로를 받은 모양 그대로(상대) — 29_ §7 예
        self.assertIn(" INFO prune file=evidence.jsonl.20261101-095959 reason=age age_s=604801 bytes=8", log)
        self.assertIn("prune file=rec/input.jsonl.20261105-095959 reason=age age_s=259201", log)
        self.assertIn("prune_done deleted=4 bytes=32 free_bytes=", log)
        self.assertNotIn("prune_no_state", log)  # 상태 파일이 아직 없음 = 보낼 회전 파일 없음 — 경고 아님
        # 쓰인 순서(이름 시각, 번호)로 지운다
        self.assertLess(log.index("evidence.jsonl.20261001-000000"), log.index("evidence.jsonl.20261101-095959 "))
        self.assertLess(log.index("evidence.jsonl.20261101-095959 "), log.index("evidence.jsonl.20261101-095959.1"))

    def test_PR_T2_state_file_kept(self):
        # PR-T2: 상태 파일에 적힌 회전 파일이 보관 기간을 넘김 → 지우지 않음, prune_keep
        ev = self.p("evidence.jsonl")
        self.touch(ev)
        sending = self.touch(self.p("evidence.jsonl.20261020-000000"))
        other = self.touch(self.p("evidence.jsonl.20261021-000000"))
        state = self.p("sender_state.json")
        self.write_state(state, ev, sending)
        det = self.det_cfg(evidence={"out_path": ev, "keep_s": 7 * DAY})
        rc, log = self.prune("--detector-config", det, "--sender-config", self.sender_cfg(state))
        self.assertEqual(rc, 0, log)
        self.assertTrue(os.path.exists(sending))
        self.assertFalse(os.path.exists(other))
        self.assertTrue(os.path.exists(ev))
        self.assertIn(f"INFO prune_keep file={sending} reason=sending", log)
        self.assertEqual(log.count("prune_keep"), 1)
        self.assertIn("prune_done deleted=1 ", log)

    def test_PR_T3_names_outside_rule(self):
        # PR-T3: 이름 규칙 밖(evidence.jsonl.old 등) → 지우지 않음. 규칙에 맞아도 일반 파일이 아니면(심볼릭 링크) 건드리지 않음
        ev = self.p("evidence.jsonl")
        self.touch(ev)
        keep = [self.touch(self.p(n)) for n in (
            "evidence.jsonl.old", "evidence.jsonl.bak",
            "evidence.jsonl.20261101-000000.100",   # 번호 세 자리
            "evidence.jsonl.2026110-000000",        # 날짜 7자리
            "evidence.jsonl.20261301-000000",       # 13월 — 날짜로 읽히지 않음
            "evidence.jsonl.20261101-000000x",
            "evidence.jsonl.20261101-000000.1.gz",
            "evidence.jsonl.20261101-000000.",
            "evidence.jsonl.20261101-000000\n",     # 끝 줄바꿈 — 정규식 $가 줄바꿈 앞에서 맞는 함정
            "xevidence.jsonl.20261101-000000",      # 다른 기준 파일
            "evidence.json.20261101-000000",
        )]
        target = self.touch(self.p("target.bin"))
        link = self.p("evidence.jsonl.20261102-000000")
        os.symlink(target, link)
        os.mkdir(self.p("evidence.jsonl.20261103-000000"))  # 폴더
        gone = self.touch(self.p("evidence.jsonl.20261104-000000"))  # 대조: 규칙에 맞는 지난 파일
        det = self.det_cfg(evidence={"out_path": ev, "keep_s": 3600})
        rc, log = self.prune("--detector-config", det, "--sender-config", self.sender_cfg(self.p("st.json")))
        self.assertEqual(rc, 0, log)
        for f in keep + [target, ev]:
            self.assertTrue(os.path.exists(f), f)
        self.assertTrue(os.path.islink(link))
        self.assertTrue(os.path.isdir(self.p("evidence.jsonl.20261103-000000")))
        self.assertFalse(os.path.exists(gone))
        self.assertIn("prune_done deleted=1 ", log)

    def _disk_setup(self):
        # 입력 기록 회전 파일 6개(각 1,000바이트) — 가장 오래된 것은 상태 파일이 가리킴. 증거 회전 파일 2개(하나는 상태 파일)
        rec = self.p("rec", "input.jsonl")
        ev = self.p("evidence.jsonl")
        self.touch(rec)
        self.touch(ev)
        names = ["input.jsonl.20261101-000000",      # f0 — 상태 파일의 파일
                 "input.jsonl.20261101-010000",      # f1
                 "input.jsonl.20261101-010000.2",    # f2 — 번호는 수로 비교(.2 < .10)
                 "input.jsonl.20261101-010000.10",   # f3
                 "input.jsonl.20261101-020000",      # f4
                 "input.jsonl.20261102-000000"]      # f5
        fs = [self.touch(self.p("rec", n), b"x" * 999 + b"\n") for n in names]
        e_old = self.touch(self.p("evidence.jsonl.20200101-000000"))
        e_sending = self.touch(self.p("evidence.jsonl.20200102-000000"))
        state = self.p("sender_state.json")
        st0, st1 = os.stat(fs[0]), os.stat(e_sending)
        with open(state, "w") as f:
            json.dump({"ver": 1, "files": {
                rec: {"dev": st0.st_dev, "ino": st0.st_ino, "offset": 10, "saved_ms": 1},
                ev: {"dev": st1.st_dev, "ino": st1.st_ino, "offset": 0, "saved_ms": 1}}}, f)
        det = self.det_cfg(evidence={"out_path": ev, "keep_s": 0},
                           input_record={"path": rec, "keep_s": 0, "min_free_bytes": MIN_FREE})
        return rec, ev, fs, e_old, e_sending, det, self.sender_cfg(state)

    def _rec_bytes(self):
        return sum(os.path.getsize(self.p("rec", n)) for n in os.listdir(self.p("rec")))

    def test_PR_T4_disk_floor(self):
        # PR-T4: 디스크 여유 하한(여유를 주입) → 입력 기록 회전 파일을 오래된 것부터, 하한 이상이 되면 멈춤.
        #        증거·상태 파일의 파일은 지우지 않음. 여유 = 하한 − 3,000 + (지운 바이트) — 3개를 지우면 하한에 닿는다
        rec, ev, fs, e_old, e_sending, det, scfg = self._disk_setup()
        start = self._rec_bytes()
        calls = []

        def fake_free(path):
            calls.append(path)
            return MIN_FREE - 3000 + (start - self._rec_bytes())
        po.free_bytes = fake_free
        rc, log = self.prune("--detector-config", det, "--sender-config", scfg)
        self.assertEqual(rc, 0, log)
        self.assertTrue(os.path.exists(fs[0]))                    # 상태 파일의 파일
        self.assertFalse(any(os.path.exists(f) for f in fs[1:4]))  # 오래된 것부터 3개
        self.assertTrue(os.path.exists(fs[4]) and os.path.exists(fs[5]))  # 하한에 닿아 멈춤
        self.assertTrue(os.path.exists(rec) and os.path.exists(ev))
        self.assertTrue(os.path.exists(e_old) and os.path.exists(e_sending))  # 증거는 하한으로 지우지 않음
        order = [m.group(1) for m in re.finditer(r"prune file=\S+/(input\.jsonl\.\S+) reason=disk", log)]
        self.assertEqual(order, ["input.jsonl.20261101-010000", "input.jsonl.20261101-010000.2",
                                 "input.jsonl.20261101-010000.10"])
        self.assertIn(f"prune_keep file={fs[0]} reason=sending", log)
        self.assertEqual(os.path.dirname(rec), calls[0])  # 입력 기록 파일이 있는 파일 시스템에서 잼
        self.assertIn("prune_done deleted=3 bytes=3000 free_bytes=" + str(MIN_FREE), log)

    def test_PR_T4_disk_floor_unreachable(self):
        # PR-T4: 지울 것을 다 지워도 하한에 못 미침 → 상태 파일의 파일만 남기고 멈춤(오류 아님). 여유가 충분하면 지우지 않음
        rec, ev, fs, e_old, e_sending, det, scfg = self._disk_setup()
        po.free_bytes = lambda path: MIN_FREE - 10 ** 9
        rc, log = self.prune("--detector-config", det, "--sender-config", scfg)
        self.assertEqual(rc, 0, log)
        self.assertTrue(os.path.exists(fs[0]))
        self.assertFalse(any(os.path.exists(f) for f in fs[1:]))
        self.assertTrue(os.path.exists(e_old) and os.path.exists(e_sending) and os.path.exists(rec))
        self.assertIn("prune_done deleted=5 ", log)
        # 여유가 하한 이상 → 아무것도 지우지 않음
        self.touch(fs[1], b"x\n")
        po.free_bytes = lambda path: MIN_FREE
        rc, log = self.prune("--detector-config", det, "--sender-config", scfg)
        self.assertEqual(rc, 0, log)
        self.assertTrue(os.path.exists(fs[1]))
        self.assertIn("prune_done deleted=0 ", log)

    def test_PR_T5_keep_zero(self):
        # PR-T5: keep_s 0(또는 키 없음 = 코드 기본값 0) → 나이로는 지우지 않음
        ev, rec = self.p("evidence.jsonl"), self.p("input.jsonl")
        old = [self.touch(self.p(n)) for n in ("evidence.jsonl.20000101-000000", "input.jsonl.20000101-000000")]
        for cfg in (self.det_cfg(evidence={"out_path": ev, "keep_s": 0}, input_record={"path": rec, "keep_s": 0}),
                    self.det_cfg(evidence={"out_path": ev}, input_record={"path": rec})):
            rc, log = self.prune("--detector-config", cfg, "--sender-config", self.sender_cfg(self.p("st.json")))
            self.assertEqual(rc, 0, log)
            self.assertTrue(all(os.path.exists(f) for f in old))
            self.assertIn("prune_done deleted=0 bytes=0 ", log)
        # '-'(탐지 엔진 기본값)도 모두 끔
        os.chdir(self.dir)
        self.touch(self.p("evidence.jsonl"))
        rc, log = self.prune("--detector-config", "-", "--sender-config", self.sender_cfg("st.json"))
        self.assertEqual(rc, 0, log)
        self.assertTrue(all(os.path.exists(f) for f in old))

    def test_PR_T6_log_copytruncate(self):
        # PR-T6: 크기를 넘긴 로그 → 복사본이 생기고 원본 0바이트, 이어 쓰던 프로세스(O_APPEND)의 다음 줄은 원본 처음에
        logp = self.p("logs", "detector.log")
        small = self.touch(self.p("logs", "sender.log"), b"short\n")
        os.makedirs(os.path.dirname(logp), exist_ok=True)
        w = open(logp, "ab", buffering=0)  # 실행 스크립트의 2>> 와 같은 이어 쓰기
        try:
            old = b"".join(b"diag line %04d\n" % i for i in range(100))
            w.write(old)
            rc, log = self.prune("--detector-config", "-", "--log", logp, "--log", small, "--log-max-bytes", "1000")
            self.assertEqual(rc, 0, log)
            copy = logp + ".20261108-100000"
            with open(copy, "rb") as f:
                self.assertEqual(f.read(), old)
            self.assertEqual(os.path.getsize(logp), 0)
            w.write(b"next line\n")
            with open(logp, "rb") as f:
                self.assertEqual(f.read(), b"next line\n")  # 앞이 0바이트로 채워지지 않음
            self.assertIn(f"INFO prune_log file={logp} to={copy} bytes={len(old)}", log)
            # 상한 이하 로그는 그대로, 복사본 없음
            with open(small, "rb") as f:
                self.assertEqual(f.read(), b"short\n")
            self.assertFalse(any(n.startswith("sender.log.") for n in os.listdir(self.p("logs"))))
            # 같은 초에 또 넘김 → .1을 붙인 복사본 (29_ §2.3 이름 규칙)
            w.write(old)
            rc, log = self.prune("--detector-config", "-", "--log", logp, "--log-max-bytes", "1000")
            self.assertEqual(rc, 0, log)
            with open(copy + ".1", "rb") as f:
                self.assertEqual(f.read(), b"next line\n" + old)
            self.assertEqual(os.path.getsize(logp), 0)
            # 없는 로그는 건너뜀(오류 아님)
            rc, log = self.prune("--detector-config", "-", "--log", self.p("logs", "none.log"), "--log-max-bytes", "1")
            self.assertEqual(rc, 0, log)
            self.assertNotIn("prune_error", log)
        finally:
            w.close()

    def test_PR_T7_log_copy_keep(self):
        # PR-T7: 로그 복사본 보관 기간 — 지난 복사본만 지움(이름의 시각 기준), 원본·규칙 밖 이름은 그대로
        logp = self.touch(self.p("logs", "detector.log"), b"x\n")
        old = [self.touch(self.p("logs", n), mtime=NOW) for n in ("detector.log.20261101-095959",
                                                                   "detector.log.20261101-095959.1")]
        keep = [self.touch(self.p("logs", n), mtime=NOW - 100 * DAY) for n in ("detector.log.20261101-100000",
                                                                              "detector.log.20261108-000000",
                                                                              "detector.log.old")]
        # --log-keep-s 0 → 지우지 않음
        rc, log = self.prune("--detector-config", "-", "--log", logp, "--log-keep-s", "0")
        self.assertEqual(rc, 0, log)
        self.assertTrue(all(os.path.exists(f) for f in old + keep))
        # 기본 7일
        rc, log = self.prune("--detector-config", "-", "--log", logp)
        self.assertEqual(rc, 0, log)
        self.assertFalse(any(os.path.exists(f) for f in old))
        self.assertTrue(all(os.path.exists(f) for f in keep + [logp]))
        self.assertIn(f"prune file={old[0]} reason=age age_s=604801", log)
        self.assertIn("prune_done deleted=2 ", log)

    def test_PR_T8_dry_run(self):
        # PR-T8: --dry-run → 아무것도 지우지 않고(로그도 비우지 않음) 지울 목록만 로그. 그 목록 = 실제로 돌렸을 때 지우는 것
        rec, ev, fs, e_old, e_sending, det_disk, scfg = self._disk_setup()
        # 나이로도 지울 것을 더한다 — 같은 설정에 보관 기간을 켬
        with open(det_disk) as f:
            c = json.load(f)
        c["evidence"]["keep_s"] = 3600
        det = self.json_file(c)
        logp = self.p("logs", "detector.log")
        self.touch(logp, b"y" * 2000)
        self.touch(self.p("logs", "detector.log.20200101-000000"))
        start = self._rec_bytes()
        po.free_bytes = lambda path: MIN_FREE - 3000 + (start - self._rec_bytes())
        before = self.listing()
        args = ("--detector-config", det, "--sender-config", scfg, "--log", logp, "--log-max-bytes", "1000")
        rc, log = self.prune(*args, "--dry-run")
        self.assertEqual(rc, 0, log)
        self.assertEqual(self.listing(), before)
        dry = re.findall(r"INFO prune file=(\S+) reason=(\w+) .* dry_run=true", log)
        self.assertIn(f"prune_log file={logp} to={logp}.20261108-100000 bytes=2000 dry_run=true", log)
        self.assertIn("prune_done deleted=5 ", log)
        self.assertIn("dry_run=true", log.splitlines()[-1])
        rc, log = self.prune(*args)
        self.assertEqual(rc, 0, log)
        real = re.findall(r"INFO prune file=(\S+) reason=(\w+) age_s=\S+ bytes=\d+$", log, re.M)
        self.assertEqual(dry, real)
        self.assertEqual(sorted(f for f, _ in real),
                         sorted([e_old, self.p("logs", "detector.log.20200101-000000")] + fs[1:4]))
        self.assertTrue(os.path.exists(e_sending) and os.path.exists(fs[0]))

    def test_PR_T9_config_errors(self):
        # PR-T9: 설정 파일 없음·JSON 아님·키 타입 틀림·범위 밖 → 종료 코드 1(아무것도 지우지 않음) /
        #        --sender-config 없음 → 경고(prune_no_state) 후 보호 없이 진행(종료 코드 0). 별도 프로세스로 띄워 종료 코드를 본다
        ev = self.p("evidence.jsonl")
        self.touch(ev)
        victim = self.touch(self.p("evidence.jsonl.20000101-000000"))  # 실제 시각 기준으로도 지난 파일
        good = self.det_cfg(evidence={"out_path": ev, "keep_s": 3600})
        state = self.p("sender_state.json")
        self.write_state(state, ev, victim)
        scfg = self.sender_cfg(state)
        bad_json = self.p("bad.json")
        with open(bad_json, "w") as f:
            f.write("{not json")

        def run(*args):
            return subprocess.run([sys.executable, PRUNE, *args], capture_output=True, text=True, timeout=30,
                                  cwd=self.dir)

        cases = [
            ("--detector-config", self.p("none.json"), "--sender-config", scfg),
            ("--detector-config", bad_json, "--sender-config", scfg),
            ("--detector-config", self.det_cfg(evidence={"out_path": ev, "keep_s": "7d"}), "--sender-config", scfg),
            ("--detector-config", self.det_cfg(evidence={"out_path": ev, "keep_s": True}), "--sender-config", scfg),
            ("--detector-config", self.det_cfg(evidence={"out_path": ev, "keep_s": 10}), "--sender-config", scfg),
            ("--detector-config", self.det_cfg(evidence={"out_path": 5}), "--sender-config", scfg),
            ("--detector-config", self.det_cfg(input_record={"path": "in.jsonl", "min_free_bytes": 5})),
            ("--detector-config", self.det_cfg(input_record={"path": 3})),
            ("--detector-config", self.json_file([1, 2])),
            ("--detector-config", good, "--sender-config", self.p("none.json")),
            ("--detector-config", good, "--sender-config", bad_json),
            ("--detector-config", good, "--sender-config", self.json_file({"state_path": 5})),
            ("--sender-config", scfg),                                      # --detector-config 빠짐
            ("--detector-config", good, "--log-max-bytes", "-1"),
            ("--detector-config", good, "--log-keep-s", "x"),
            ("--detector-config", good, "--bogus"),
        ]
        for args in cases:
            r = run(*args)
            self.assertEqual(r.returncode, 1, (args, r.stderr))
            self.assertIn("ERROR config_error", r.stderr, args)
            self.assertTrue(os.path.exists(victim), args)
        # 상태 파일이 있으면 보호됨
        r = run("--detector-config", good, "--sender-config", scfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(victim))
        self.assertIn("prune_keep", r.stderr)
        # 상태 파일이 깨짐 → 경고 후 보호 없이 진행
        with open(state, "w") as f:
            f.write("{broken")
        r = run("--detector-config", good, "--sender-config", scfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("WARN prune_no_state state=", r.stderr)
        self.assertFalse(os.path.exists(victim))
        # --sender-config 없음 → 경고 후 보호 없이 진행
        self.touch(victim)
        self.write_state(state, ev, victim)
        r = run("--detector-config", good)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('WARN prune_no_state detail="no --sender-config', r.stderr)
        self.assertFalse(os.path.exists(victim))
        self.assertTrue(os.path.exists(ev))


# ---------------------------------------------------------------- 실행 스크립트 S49·S50 (19_ §9)

CERT = {}


def setUpModule():
    if not shutil.which("openssl"):
        return
    d = os.path.join(TMP, "certs")
    os.makedirs(d, exist_ok=True)
    cert, key = os.path.join(d, "a.pem"), os.path.join(d, "a.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=a",
                    "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
    CERT["a"] = (cert, key)


class FakeIngest:
    """가짜 /ingest — status_fn()이 돌려주는 상태로 응답한다(200이면 받은 줄 수를 accepted로)."""

    def __init__(self):
        self.status = 200
        self.lines = []
        self.lock = threading.Lock()

    def start(self):
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                status = fake.status
                n = len([x for x in body.split(b"\n") if x])
                if status == 200:
                    with fake.lock:
                        fake.lines += [x for x in body.split(b"\n") if x]
                    rbody = json.dumps({"accepted": n, "rejected": 0, "duplicates": 0}).encode()
                else:
                    rbody = b'{"error":"busy"}'
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(rbody)))
                self.end_headers()
                self.wfile.write(rbody)

            def log_message(self, *a):
                pass

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*CERT["a"])
        self.server = Server(("127.0.0.1", 0), Handler)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

    def url(self):
        return f"https://127.0.0.1:{self.server.server_address[1]}/ingest"


FAKE_DETECTOR = r'''
import signal, sys, time
# 탐지 엔진 대신 — forever: 증거 파일에 0.1초마다 한 줄 / logs: 표준 출력·오류에 600줄씩 한꺼번에 쓴 뒤
# 표준 오류에만 0.2초마다 한 줄(표준 출력은 더 쓰지 않음). 둘 다 SIGTERM이면 종료 코드 0
mode = sys.argv[1]
stop = False
def on_term(s, f):
    global stop
    stop = True
signal.signal(signal.SIGTERM, on_term)
ev = open("evidence.jsonl", "ab", buffering=0)
if mode == "logs":
    ev.write(b'{"type":"alert","n":0}\n')
    sys.stdout.buffer.write(b"".join(b"ALERT %d\n" % i for i in range(600)))
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(b"".join(b"diag %d\n" % i for i in range(600)))
    sys.stderr.buffer.flush()
    i = 600
    while not stop:
        sys.stderr.buffer.write(b"diag %d\n" % i)
        sys.stderr.buffer.flush()
        i += 1
        time.sleep(0.2)
else:
    i = 0
    while not stop:
        ev.write(b'{"type":"alert","n":%d}\n' % i)
        i += 1
        time.sleep(0.1)
sys.exit(0)
'''


class RunScript(unittest.TestCase):
    def setUp(self):
        if not CERT:
            self.skipTest("openssl not found")
        self.dir = tempfile.mkdtemp(prefix=self._testMethodName[5:9] + "_", dir=TMP)
        self.ev = os.path.join(self.dir, "evidence.jsonl")
        self.fake = os.path.join(self.dir, "fake_detector.py")
        with open(self.fake, "w") as f:
            f.write(FAKE_DETECTOR)
        self.srv = FakeIngest().start()
        self.proc = None
        self.script_log = os.path.join(self.dir, "script.log")

    def tearDown(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()
        self.srv.stop()

    def sender_cfg(self):
        # 실행 스크립트를 띄운 폴더 기준 상대 경로 — 탐지 엔진 기본값 evidence.jsonl과 같은 파일
        c = {"url": self.srv.url(), "ca_file": CERT["a"][0], "env": "on-premise",
             "inputs": [{"path": "evidence.jsonl", "kind": "evidence"}], "state_path": "sender_state.json",
             "batch_interval_ms": 100, "poll_ms": 50, "timeout_ms": 2000, "retry_initial_ms": 100,
             "retry_max_ms": 400, "stats_interval_ms": 0}
        path = os.path.join(self.dir, "sender.json")
        with open(path, "w") as f:
            json.dump(c, f)
        return path

    def popen_script(self, env, *det_args):
        f = open(self.script_log, "w")
        self.proc = subprocess.Popen(["bash", RUN, self.sender_cfg(), "--", sys.executable, self.fake, *det_args],
                                     cwd=self.dir, env=dict(os.environ, PYTHON=sys.executable, **env),
                                     stderr=f, stdout=subprocess.DEVNULL)
        f.close()
        return self.proc

    def read(self, path):
        try:
            with open(path, "rb") as f:
                return f.read().decode("utf-8", "replace")
        except FileNotFoundError:
            return ""

    def test_S49_prune_interval(self):
        # S49: PRUNE_INTERVAL_S 짧게, 보관 기간 지난 회전 파일 → 시작 때와 주기마다 정리 도구가 돌아 지난 파일이 지워짐,
        #      상태 파일의 파일은 남음. 수집 서버가 503을 돌려주는 동안은 전송기가 위치를 저장하지 않아 상태 파일이 그대로다
        det = os.path.join(self.dir, "det.json")
        with open(det, "w") as f:
            json.dump({"evidence": {"out_path": "evidence.jsonl", "keep_s": 3600}}, f)
        p = lambda n: os.path.join(self.dir, n)
        old1 = p("evidence.jsonl.20000101-000000")
        sending = p("evidence.jsonl.20000102-000000")
        outside = p("evidence.jsonl.old")
        with open(old1, "wb") as f:
            f.write(b'{"type":"alert","n":-2}\n')
        with open(sending, "wb") as f:
            f.write(b'{"type":"alert","n":-1}\n')  # 아직 보내지 않은 줄 — 200을 받아야 위치가 넘어감
        with open(outside, "wb") as f:
            f.write(b"x\n")
        st = os.stat(sending)
        with open(p("sender_state.json"), "w") as f:
            json.dump({"ver": 1, "files": {os.path.realpath(self.ev): {
                "dev": st.st_dev, "ino": st.st_ino, "offset": 0, "saved_ms": 946771200000}}}, f)
        self.srv.status = 503
        proc = self.popen_script({"PRUNE_INTERVAL_S": "1"}, "forever", "--config", "det.json")
        self.assertTrue(wait_until(lambda: "started sender_pid=" in self.read(self.script_log)), self.read(self.script_log))
        log = self.read(self.script_log)
        # 시작 때: 두 프로세스를 띄우기 전에 정리
        self.assertIn("INFO prune file=evidence.jsonl.20000101-000000 reason=age", log)
        self.assertLess(log.index("prune file=evidence.jsonl.20000101-000000"), log.index("started sender_pid="))
        self.assertFalse(os.path.exists(old1))
        # 주기: 실행 중에 생긴 지난 회전 파일도 지움
        old3 = p("evidence.jsonl.20000103-000000")
        with open(old3, "wb") as f:
            f.write(b'{"type":"alert","n":-3}\n')
        self.assertTrue(wait_until(lambda: not os.path.exists(old3), timeout=10), self.read(self.script_log))
        log = self.read(self.script_log)
        self.assertGreaterEqual(log.count("INFO prune_done "), 2)
        self.assertTrue(os.path.exists(sending))
        self.assertIn("INFO prune_keep file=evidence.jsonl.20000102-000000 reason=sending", log)
        self.assertTrue(os.path.exists(outside))
        self.assertTrue(os.path.exists(self.ev))
        self.assertIsNone(proc.poll())
        self.assertNotIn("prune_exit", log)
        # 끝내기 — 서버를 살려 마무리 --once가 바로 끝나게
        self.srv.status = 200
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=60), 0, self.read(self.script_log))

    def test_S49_prune_off_and_failure(self):
        # S49 보충: PRUNE_INTERVAL_S=0이면 정리 도구를 부르지 않음(시작 때도) / 정리 도구 실패(설정 오류)는 경고만 — 탐지는 계속
        det = os.path.join(self.dir, "det.json")
        with open(det, "w") as f:
            json.dump({"evidence": {"out_path": "evidence.jsonl", "keep_s": 3600}}, f)
        old1 = os.path.join(self.dir, "evidence.jsonl.20000101-000000")
        with open(old1, "wb") as f:
            f.write(b"x\n")
        proc = self.popen_script({"PRUNE_INTERVAL_S": "0"}, "forever", "--config", "det.json")
        self.assertTrue(wait_until(lambda: "started sender_pid=" in self.read(self.script_log)))
        time.sleep(1.5)
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=60), 0, self.read(self.script_log))
        self.assertTrue(os.path.exists(old1))
        # 정리 도구의 사건 이름으로 본다 — 'prune' 글자만 보면 시험 폴더 경로(ctest의 tools/prune_outputs/)에 걸린다
        log = self.read(self.script_log)
        for ev in (" prune_done ", " prune_no_state ", " prune_exit ", " prune "):
            self.assertNotIn(ev, log)
        # 탐지 엔진은 모르는 키를 경고만 하지만 정리 도구에는 범위 밖(keep_s 10) → 정리 도구 종료 코드 1 → 경고만
        with open(det, "w") as f:
            json.dump({"evidence": {"out_path": "evidence.jsonl", "keep_s": 10}}, f)
        proc = self.popen_script({"PRUNE_INTERVAL_S": "1"}, "forever", "--config", "det.json")
        self.assertTrue(wait_until(lambda: self.read(self.script_log).count("prune_exit code=1") >= 2, timeout=10),
                        self.read(self.script_log))
        self.assertIsNone(proc.poll())
        self.assertIn("started sender_pid=", self.read(self.script_log))
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=60), 0, self.read(self.script_log))
        self.assertTrue(os.path.exists(old1))
        # 환경 변수가 정수가 아니면 아무것도 띄우지 않음
        proc = self.popen_script({"PRUNE_INTERVAL_S": "1h"}, "forever")
        self.assertEqual(proc.wait(timeout=30), 1)
        self.assertIn("not_started reason=bad_env PRUNE_INTERVAL_S=1h", self.read(self.script_log))

    def test_S50_log_dir(self):
        # S50: LOG_DIR·작은 LOG_MAX_BYTES → 네 로그 파일이 생기고, 상한을 넘은 로그는 복사본 + 빈 원본, 그 뒤 줄은 원본에
        logs = os.path.join(self.dir, "logs")
        q = lambda n: os.path.join(logs, n)
        rx_copy = lambda base: re.compile(re.escape(base) + r"\.[0-9]{8}-[0-9]{6}(?:\.[0-9]{1,2})?")

        def copies(base):
            try:
                return sorted(n for n in os.listdir(logs) if rx_copy(base).fullmatch(n))
            except FileNotFoundError:
                return []
        proc = self.popen_script({"LOG_DIR": "logs", "LOG_MAX_BYTES": "4096", "PRUNE_INTERVAL_S": "1"}, "logs")
        self.assertTrue(wait_until(lambda: copies("detector.out") and copies("detector.log"), timeout=15),
                        self.read(q("run_with_sender.log")))
        time.sleep(1.2)  # 비운 뒤 줄이 원본에 쌓이게
        for n in ("detector.out", "detector.log", "sender.log", "run_with_sender.log"):
            self.assertTrue(os.path.exists(q(n)), n)
        # 표준 출력: 600줄을 한꺼번에 쓴 뒤 더 쓰지 않음 → 복사본에 모두, 원본은 빈 채로
        self.assertEqual(len(copies("detector.out")), 1)
        with open(q(copies("detector.out")[0]), "rb") as f:
            self.assertEqual(f.read(), b"".join(b"ALERT %d\n" % i for i in range(600)))
        self.assertEqual(os.path.getsize(q("detector.out")), 0)
        # 표준 오류: 복사본은 상한을 넘은 내용, 원본은 그 뒤 줄 — 앞이 0바이트로 채워지지 않고(이어 쓰기) 번호가 이어짐
        with open(q(copies("detector.log")[-1]), "rb") as f:
            copied = f.read()
        self.assertGreater(len(copied), 4096)
        self.assertTrue(copied.startswith(b"diag 0\n"))
        with open(q("detector.log"), "rb") as f:
            now_data = f.read()
        self.assertNotIn(b"\0", now_data)
        self.assertLess(len(now_data), 4096)
        cur = [int(x.split()[1]) for x in now_data.splitlines()]
        self.assertTrue(cur, now_data)
        last_copied = int(copied.rstrip(b"\n").splitlines()[-1].split()[1])
        self.assertGreater(cur[0], last_copied)
        self.assertEqual(cur, list(range(cur[0], cur[0] + len(cur))))
        run_log = self.read(q("run_with_sender.log"))
        self.assertIn("started sender_pid=", run_log)
        self.assertIn("logs=logs", run_log)
        self.assertIn("INFO prune_log file=logs/detector.out to=logs/detector.out.", run_log)
        self.assertIn("INFO prune_log file=logs/detector.log to=logs/detector.log.", run_log)
        self.assertIn("INFO prune_done ", run_log)
        self.assertIn(" INFO start ", self.read(q("sender.log")))
        self.assertNotIn("started sender_pid=", self.read(self.script_log))  # 스크립트 표준 오류는 LOG_DIR로 감
        proc.send_signal(signal.SIGTERM)
        self.assertEqual(proc.wait(timeout=60), 0, self.read(q("run_with_sender.log")))
        self.assertIn("mode=once", self.read(q("sender.log")))       # 마무리 --once도 sender.log에
        self.assertIn("detector_exit code=0", self.read(q("run_with_sender.log")))
        self.assertIn(b'{"type":"alert","n":0}', self.srv.lines)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
