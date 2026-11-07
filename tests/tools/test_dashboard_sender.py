#!/usr/bin/env python3
"""전송기 시험 S1~S21 (19_ §9)·상시 KPM S22~S39 (24_ §8.2)·회전 파일 S41~S48 (19_ §9, 11/08 이슈 #102) — ctest가 부른다. 인자: <저장소 경로> <detector 경로> <임시 폴더>

- 시험마다 가짜 수집 서버(http.server + ssl)를 로컬 포트에 띄운다. 받은 요청(헤더·본문)을 기록하고, 시험이 정한 응답을 돌려준다.
- 서버 인증서는 시험 시작 때 openssl 명령으로 만든다(SAN IP:127.0.0.1) — 키·인증서를 저장소에 넣지 않는다.
  openssl이 없으면 서버가 필요한 시험은 건너뛴다.
- S1 입력은 시험 때 detector --replay로 tests/data/의 시나리오 13개를 재생해 만든다(19_ §10 #6 — ~/evidence_sample/과 같은 시나리오).
"""

import datetime
import http.server
import json
import math
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest

REPO, DET, TMP = sys.argv[1], sys.argv[2], sys.argv[3]
SENDER = os.path.join(REPO, "tools", "dashboard_sender.py")
RUN = os.path.join(REPO, "tools", "run_with_sender.sh")
os.makedirs(TMP, exist_ok=True)

# ~/evidence_sample/ 13개를 만든 시나리오 (19_ §9 S1)
SAMPLE_SCENARIOS = [
    "scenarios/T06_공격중끊김.jsonl",
    "scenarios/T07_세션변경.jsonl",
    "scenarios/T10_긴공격.jsonl",
    "scenarios/T19_DL미관측.jsonl",
    "stage2_green/S01_L3-01-O_고착5_high.jsonl",
    "stage2_green/S01_L3-01-O_불확실뒤공격_CLEAR-RAISE.jsonl",
    "stage2_green/S01_L3-01-O_해제_CLEAR.jsonl",
    "stage2_green/S20_L3-20_반복_UPDATE.jsonl",
    "stage2_green/S20_L3-20_세션변경_END.jsonl",
    "stage2_green/S20_L3-20_해제_CLEAR.jsonl",
    "stage2_green/S21_L3-21_로스보류_불확실RAISE.jsonl",
    "stage2_green/S21_L3-21_변형_갈래2_RAISE.jsonl",
    "stage2_green/S21_L3-21_혼합_high.jsonl",
]

CERTS = {}       # 이름 → (cert, key)
SAMPLE = None    # S1 증거 파일


def make_cert(name, san):
    d = os.path.join(TMP, "certs")
    os.makedirs(d, exist_ok=True)
    cert, key = os.path.join(d, f"{name}.pem"), os.path.join(d, f"{name}.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "2", "-subj", f"/CN={name}",
                    "-addext", f"subjectAltName={san}"], check=True, capture_output=True)
    return cert, key


def setUpModule():
    global SAMPLE
    if shutil.which("openssl"):
        CERTS["a"] = make_cert("a", "IP:127.0.0.1")    # 수집 서버 인증서 = ca_file
        CERTS["b"] = make_cert("b", "IP:127.0.0.1")    # 다른 자체 서명 인증서 (S9 불일치)
        CERTS["c"] = make_cert("c", "IP:127.0.0.2")    # 이름(IP)이 다른 인증서 (S9 이름 검증)
    # S1 입력: 시나리오 13개를 detector로 재생해 한 증거 파일에 이어 쓴다(탐지 엔진은 append로 연다)
    d = os.path.join(TMP, "sample")
    os.makedirs(d, exist_ok=True)
    SAMPLE = os.path.join(d, "evidence_sample.jsonl")
    if os.path.exists(SAMPLE):
        os.unlink(SAMPLE)
    cfg = os.path.join(d, "detector.json")
    with open(cfg, "w") as f:
        json.dump({"evidence": {"mode": "full", "out_path": SAMPLE}}, f)
    for s in SAMPLE_SCENARIOS:
        r = subprocess.run([DET, "--replay", os.path.join(REPO, "tests", "data", s), "--config", cfg],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            raise RuntimeError(f"detector replay failed for {s}: {r.stderr}")


# ---------------------------------------------------------------- 가짜 수집 서버

def ok_response(body):
    n = len([x for x in body.split(b"\n") if x])
    return 200, json.dumps({"accepted": n, "rejected": 0, "duplicates": 0}).encode()


class FakeIngest:
    """가짜 /ingest. responder(body) → (상태, 본문) 또는 'hang'(응답하지 않고 연결을 붙잡음)."""

    def __init__(self, cert="a", port=0):
        self.cert = cert
        self.port = port
        self.requests = []      # (헤더 dict, 본문 bytes, 응답 상태 또는 'hang')
        self.lock = threading.Lock()
        self.release = threading.Event()
        self.responder = ok_response
        self.server = None

    def start(self):
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(n)
                resp = fake.responder(body)
                with fake.lock:
                    fake.requests.append((dict(self.headers), body, resp if resp == "hang" else resp[0]))
                if resp == "hang":
                    fake.release.wait(30)
                    self.close_connection = True
                    return
                status, rbody = resp
                self.send_response(status)
                if 300 <= status < 400:
                    self.send_header("Location", "https://127.0.0.1/elsewhere")
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

        cert, key = CERTS[self.cert]
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.server = Server(("127.0.0.1", self.port), Handler)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        return self

    def stop(self):
        self.release.set()
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None

    def url(self):
        return f"https://127.0.0.1:{self.port}/ingest"

    def snapshot(self):
        with self.lock:
            return list(self.requests)

    def accepted_bytes(self):
        return b"".join(b for _, b, s in self.snapshot() if s == 200)

    def accepted_lines(self):
        return [x for x in self.accepted_bytes().split(b"\n") if x]


def scripted(seq, then=ok_response):
    """앞에서부터 seq의 응답을 하나씩, 다 쓰면 then."""
    it = list(seq)

    def r(body):
        if it:
            x = it.pop(0)
            if x == "hang":
                return "hang"
            return x if isinstance(x, tuple) else (x, b'{"error":"scripted"}')
        return then(body)
    return r


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_until(pred, timeout=15.0, step=0.05):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(step)
    return pred()


# ---------------------------------------------------------------- 공통 바탕

class Base(unittest.TestCase):
    needs_server = True

    def setUp(self):
        if self.needs_server and not CERTS:
            self.skipTest("openssl not found")
        self.dir = tempfile.mkdtemp(prefix=self._testMethodName + "_", dir=TMP)
        self.ev = os.path.join(self.dir, "evidence.jsonl")
        self.state = os.path.join(self.dir, "sender_state.json")
        self.procs = []
        self.servers = []
        self.srv = self.server() if self.needs_server else None

    def tearDown(self):
        for p, _ in self.procs:
            if p.poll() is None:
                p.kill()
                p.wait()
        for s in self.servers:
            s.stop()

    def server(self, cert="a", port=0, start=True):
        s = FakeIngest(cert, port)
        self.servers.append(s)
        return s.start() if start else s

    def cfg(self, **over):
        c = {
            "url": self.srv.url() if self.srv else "https://127.0.0.1:9/ingest",
            "ca_file": CERTS["a"][0] if CERTS else None,
            "env": "lab",
            "inputs": [{"path": self.ev, "kind": "evidence"}],
            "state_path": self.state,
            "batch_interval_ms": 100,
            "poll_ms": 50,
            "timeout_ms": 2000,
            "retry_initial_ms": 100,
            "retry_max_ms": 400,
            "stats_interval_ms": 0,
        }
        c.update(over)
        path = os.path.join(self.dir, f"sender_{len(os.listdir(self.dir))}.json")
        with open(path, "w") as f:
            json.dump(c, f)
        return path

    def write(self, data, mode="ab", path=None):
        with open(path or self.ev, mode) as f:
            f.write(data)

    def run_sender(self, cfg, *extra, timeout=60, cwd=None):
        return subprocess.run([sys.executable, SENDER, "--config", cfg, *extra], capture_output=True, text=True,
                              timeout=timeout, cwd=cwd or self.dir)

    def once(self, cfg, *extra, **kw):
        return self.run_sender(cfg, "--once", *extra, **kw)

    def start(self, cfg, *extra):
        log = os.path.join(self.dir, f"sender_{len(self.procs)}.log")
        f = open(log, "w")
        p = subprocess.Popen([sys.executable, SENDER, "--config", cfg, *extra], stderr=f, stdout=subprocess.DEVNULL,
                             cwd=self.dir)
        f.close()
        self.procs.append((p, log))
        return p

    def log_of(self, p):
        for q, log in self.procs:
            if q is p:
                with open(log) as f:
                    return f.read()
        return ""

    def term(self, p, timeout=10):
        p.send_signal(signal.SIGTERM)
        return p.wait(timeout=timeout)

    def state_offset(self, path=None):
        try:
            with open(self.state) as f:
                st = json.load(f)
        except FileNotFoundError:
            return None
        e = st["files"].get(os.path.abspath(path or self.ev))
        return e["offset"] if e else None


def L(n, pad=""):
    return b'{"type":"alert","n":%d%s}' % (n, pad.encode())


def lines_bytes(ls):
    return b"".join(x + b"\n" for x in ls)


# ---------------------------------------------------------------- S1~S21

class Sending(Base):
    def test_S01_sample_byte_identical(self):
        # S1: 샘플 증거 파일 → 받은 줄을 이으면 파일과 바이트 동일·순서 같음, 묶음 ≤ 500줄·≤ 1 MiB, 헤더 확인
        with open(SAMPLE, "rb") as f:
            data = f.read()
        self.assertTrue(data.endswith(b"\n"))
        nlines = data.count(b"\n")
        self.assertGreater(nlines, 500, "sample should need more than one batch")
        shutil.copyfile(SAMPLE, self.ev)
        r = self.once(self.cfg(batch_interval_ms=1000))
        self.assertEqual(r.returncode, 0, r.stderr)
        reqs = self.srv.snapshot()
        self.assertEqual(b"".join(b for _, b, _ in reqs), data)
        self.assertEqual(len(reqs), math.ceil(nlines / 500))
        for h, b, s in reqs:
            self.assertEqual(s, 200)
            self.assertLessEqual(b.count(b"\n"), 500)
            self.assertLessEqual(len(b), 1048576)
            self.assertTrue(b.endswith(b"\n"))
            self.assertEqual(h.get("Content-Type"), "application/x-ndjson")
            self.assertEqual(h.get("X-Env"), "lab")
            self.assertNotIn("Authorization", h)
            self.assertTrue(h.get("User-Agent", "").startswith("ran-detect-sender/"))
        self.assertEqual(self.state_offset(), len(data))

    def test_S02_partial_line(self):
        # S2: 끝에 \n 없는 조각은 완성 전에는 보내지 않고, 완성 뒤 한 줄로 보낸다
        self.write(L(1) + b"\n" + b'{"type":"alert","n":')
        p = self.start(self.cfg())
        self.assertTrue(wait_until(lambda: self.srv.accepted_lines() == [L(1)]), self.log_of(p))
        time.sleep(0.5)  # 묶음 간격(100 ms)보다 넉넉히 — 조각은 가지 않아야 한다
        self.assertEqual(self.srv.accepted_lines(), [L(1)])
        self.write(b"2}\n")
        self.assertTrue(wait_until(lambda: self.srv.accepted_lines() == [L(1), L(2)]), self.log_of(p))
        self.assertEqual(self.term(p), 0)

    def test_S03_resume(self):
        # S3: 보낸 뒤 끝내고 줄을 더 써서 다시 띄우면 새 줄만 보낸다. 상태 파일 위치 = 파일 크기
        self.write(lines_bytes([L(1), L(2), L(3)]))
        cfg = self.cfg()
        self.assertEqual(self.once(cfg).returncode, 0)
        n1 = len(self.srv.snapshot())
        self.write(lines_bytes([L(4), L(5)]))
        r = self.once(cfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        new = self.srv.snapshot()[n1:]
        self.assertEqual(b"".join(b for _, b, _ in new), lines_bytes([L(4), L(5)]))
        self.assertEqual(self.state_offset(), os.path.getsize(self.ev))

    def test_S04_die_before_200(self):
        # S4: 응답 전에 전송기가 끝나면 위치는 저장되지 않고, 다시 띄우면 그 묶음을 다시 보낸다(중복 허용)
        self.write(lines_bytes([L(1), L(2)]))
        self.srv.responder = scripted(["hang"])
        cfg = self.cfg()
        p = self.start(cfg)
        self.assertTrue(wait_until(lambda: len(self.srv.snapshot()) == 1))
        self.assertEqual(self.term(p), 0)
        self.assertIsNone(self.state_offset())
        r = self.once(cfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        reqs = self.srv.snapshot()
        self.assertEqual(len(reqs), 2)
        self.assertEqual(reqs[0][1], reqs[1][1])
        self.assertEqual(reqs[1][2], 200)
        self.assertEqual(self.state_offset(), os.path.getsize(self.ev))

    def test_S05_retry_503(self):
        # S5: 503 두 번 뒤 200 — 같은 본문을 세 번, 대기 간격이 늘어나고, 마지막에 위치 저장
        self.write(lines_bytes([L(1), L(2)]))
        self.srv.responder = scripted([503, 503])
        r = self.once(self.cfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        reqs = self.srv.snapshot()
        self.assertEqual([s for _, _, s in reqs], [503, 503, 200])
        self.assertEqual(len({b for _, b, _ in reqs}), 1)
        retries = [x for x in r.stderr.splitlines() if " retry " in x]
        self.assertEqual(len(retries), 2)
        self.assertIn("reason=503", retries[0])
        self.assertIn("wait_ms=100", retries[0])
        self.assertIn("wait_ms=200", retries[1])
        self.assertEqual(self.state_offset(), os.path.getsize(self.ev))

    def test_S06_413_split(self):
        # S6: 413 — 반으로 나눠 다시, 받은 줄 순서 = 파일 순서
        lines = [L(i) for i in range(5)]
        self.write(lines_bytes(lines))
        self.srv.responder = lambda b: (413, b"{}") if b.count(b"\n") > 2 else ok_response(b)
        r = self.once(self.cfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.accepted_lines(), lines)
        self.assertIn(" split ", r.stderr)
        self.assertEqual(self.state_offset(), os.path.getsize(self.ev))

    def test_S06_413_single_line(self):
        # S6: 한 줄짜리가 413이면 그 줄만 빼고 진행
        big = b'{"type":"alert","big":"BIG"}'
        self.write(lines_bytes([L(1), big, L(2)]))
        self.srv.responder = lambda b: (413, b"{}") if b"BIG" in b else ok_response(b)
        r = self.once(self.cfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.accepted_lines(), [L(1), L(2)])
        self.assertIn("reason=http_413", r.stderr)
        self.assertEqual(self.state_offset(), os.path.getsize(self.ev))

    def test_S07_400(self):
        # S7: 400 — 그 묶음 위치를 넘기고 다음 묶음을 보낸다
        self.write(lines_bytes([L(i) for i in range(4)]))
        self.srv.responder = scripted([(400, b'{"error":"unreadable body"}')])
        r = self.once(self.cfg(batch_max_lines=2))
        self.assertEqual(r.returncode, 0, r.stderr)
        reqs = self.srv.snapshot()
        self.assertEqual([s for _, _, s in reqs], [400, 200])
        self.assertEqual(reqs[0][1], lines_bytes([L(0), L(1)]))
        self.assertEqual(reqs[1][1], lines_bytes([L(2), L(3)]))
        self.assertIn("status=400", r.stderr)
        self.assertIn('error="unreadable body"', r.stderr)
        self.assertEqual(self.state_offset(), os.path.getsize(self.ev))

    def test_S08_unexpected_status(self):
        # S8: 401·404·302 — 종료 코드 2, 위치는 그대로
        self.write(lines_bytes([L(1)]))
        for status in (401, 404, 302):
            with self.subTest(status=status):
                if os.path.exists(self.state):
                    os.unlink(self.state)
                self.srv.responder = lambda b, s=status: (s, b"nope")
                r = self.once(self.cfg())
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn(f"reason=http_{status}", r.stderr)
                self.assertIsNone(self.state_offset())

    def test_S09_tls_mismatch(self):
        # S9: 다른 인증서로 띄운 서버 / ca_file 없이 자체 서명 서버 / 인증서 이름(IP)이 다름 — 종료 코드 3
        self.write(lines_bytes([L(1)]))
        other = self.server(cert="b")
        r = self.once(self.cfg(url=other.url()))
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIn("reason=tls", r.stderr)
        r = self.once(self.cfg(ca_file=None))
        self.assertEqual(r.returncode, 3, r.stderr)
        wrong_name = self.server(cert="c")
        r = self.once(self.cfg(url=wrong_name.url(), ca_file=CERTS["c"][0]))
        self.assertEqual(r.returncode, 3, r.stderr)
        self.assertIsNone(self.state_offset())
        self.assertEqual(len(other.snapshot()) + len(wrong_name.snapshot()) + len(self.srv.snapshot()), 0)
        # 맞는 ca_file이면 성공
        r = self.once(self.cfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.accepted_lines(), [L(1)])

    def test_S10_rotate_and_truncate(self):
        # S10: 보내는 중 mv로 옮기고 새 파일 생성 → 옛 파일의 남은 줄을 마저 보낸 뒤 새 파일 처음부터 /
        #      같은 파일을 비움 → 처음부터. 경고 로그
        self.write(lines_bytes([L(1), L(2)]))
        p = self.start(self.cfg())
        self.assertTrue(wait_until(lambda: self.srv.accepted_lines() == [L(1), L(2)]), self.log_of(p))
        l4 = L(4, ',"pad":"' + "x" * 40 + '"')
        self.write(lines_bytes([L(3)]))
        os.rename(self.ev, self.ev + ".old")
        self.write(lines_bytes([l4]))
        self.assertTrue(wait_until(lambda: self.srv.accepted_lines() == [L(1), L(2), L(3), l4]), self.log_of(p))
        self.write(lines_bytes([L(5)]), mode="wb")  # 같은 파일을 비우고 짧은 줄 하나
        self.assertTrue(wait_until(lambda: self.srv.accepted_lines() == [L(1), L(2), L(3), l4, L(5)]),
                        self.log_of(p))
        self.assertEqual(self.term(p), 0)
        log = self.log_of(p)
        self.assertIn("WARN rotate", log)
        self.assertIn("WARN truncate", log)

    def test_S11_skipped_lines(self):
        # S11: 64 KiB 넘는 줄, UTF-8이 아닌 줄, 빈 줄 — 그 줄만 빠지고 나머지는 순서대로
        self.write(L(1) + b"\n" + b"x" * 70000 + b"\n" + b'\xff\xfe{"bad":1}\n' + b"\n" + L(2) + b"\n")
        r = self.once(self.cfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.accepted_lines(), [L(1), L(2)])
        skips = [x for x in r.stderr.splitlines() if " skip_line " in x]
        self.assertEqual(len(skips), 2, r.stderr)
        self.assertIn("reason=too_long", skips[0])
        self.assertIn("reason=not_utf8", skips[1])
        self.assertTrue(all(" ERROR " in x for x in skips))
        self.assertEqual(self.state_offset(), os.path.getsize(self.ev))

    def test_S11_no_newline_fragment(self):
        # S11: 끝 \n 없이 64 KiB를 넘은 조각 — 다음 \n까지 버리고 오류 로그
        self.write(L(1) + b"\n" + b"y" * 70000)
        p = self.start(self.cfg())
        self.assertTrue(wait_until(lambda: "reason=no_newline" in self.log_of(p)), self.log_of(p))
        self.write(b"tail\n" + L(3) + b"\n")
        self.assertTrue(wait_until(lambda: self.srv.accepted_lines() == [L(1), L(3)]), self.log_of(p))
        # 서버는 응답을 쓰기 전에 기록한다 — 전송기가 200을 받아 위치를 저장할 때까지 기다린 뒤 끝낸다
        self.assertTrue(wait_until(lambda: self.state_offset() == os.path.getsize(self.ev)), self.log_of(p))
        self.assertEqual(self.term(p), 0)

    def test_S12_server_down_then_up(self):
        # S12: 서버가 꺼져 있다가 켜짐 — 연결 실패로 다시 보내다가 켜지면 이어서, 빠진 줄 없음
        lines = [L(i) for i in range(3)]
        self.write(lines_bytes(lines))
        port = free_port()
        later = self.server(port=port, start=False)
        p = self.start(self.cfg(url=f"https://127.0.0.1:{port}/ingest"))
        self.assertTrue(wait_until(lambda: "reason=conn_refused" in self.log_of(p)), self.log_of(p))
        later.start()
        self.write(lines_bytes([L(3)]))
        self.assertTrue(wait_until(lambda: later.accepted_lines() == lines + [L(3)]), self.log_of(p))
        self.assertEqual(self.term(p), 0)

    def test_S13_rejected(self):
        # S13: 200에 rejected > 0 — 위치를 넘기고 경고 로그
        self.write(lines_bytes([L(1), L(2), L(3)]))
        self.srv.responder = lambda b: (200, b'{"accepted":1,"rejected":2,"duplicates":0}')
        r = self.once(self.cfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(any(" WARN rejected " in x and "rejected=2" in x for x in r.stderr.splitlines()), r.stderr)
        self.assertEqual(self.state_offset(), os.path.getsize(self.ev))

    def test_S15_sigterm_while_sending(self):
        # S15: 보내는 중 SIGTERM — 종료 코드 0, 저장된 위치는 마지막 200 자리
        self.write(lines_bytes([L(1), L(2)]))
        self.srv.responder = scripted([(200, b'{"accepted":1,"rejected":0,"duplicates":0}'), "hang"])
        p = self.start(self.cfg(batch_max_lines=1))
        self.assertTrue(wait_until(lambda: len(self.srv.snapshot()) == 2), self.log_of(p))
        self.assertEqual(self.term(p), 0)
        self.assertEqual(self.state_offset(), len(L(1)) + 1)

    def test_S17_once_timeout(self):
        # S17: 서버가 계속 503 — --once-timeout-s 뒤 종료 코드 0, 위치는 마지막 200 자리(여기서는 없음)
        self.write(lines_bytes([L(1)]))
        self.srv.responder = lambda b: (503, b"{}")
        t0 = time.monotonic()
        r = self.once(self.cfg(), "--once-timeout-s", "1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertLess(time.monotonic() - t0, 10)
        self.assertIn("once_timeout", r.stderr)
        self.assertIsNone(self.state_offset())

    def test_S19_state_save_failure(self):
        # S19: state_path를 쓸 수 없게 된 뒤 200을 받음 — 종료 코드 4, 저장된 위치는 그 전 200 자리 그대로
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        sd = os.path.join(self.dir, "state")
        os.mkdir(sd)
        self.state = os.path.join(sd, "sender_state.json")
        self.write(lines_bytes([L(1)]))
        p = self.start(self.cfg(state_path=self.state))
        self.assertTrue(wait_until(lambda: self.state_offset() == len(L(1)) + 1), self.log_of(p))
        os.chmod(sd, 0o500)
        try:
            self.write(lines_bytes([L(2)]))
            rc = p.wait(timeout=15)
        finally:
            os.chmod(sd, 0o700)
        self.assertEqual(rc, 4, self.log_of(p))
        self.assertIn("reason=state_save", self.log_of(p))
        self.assertEqual(len(self.srv.snapshot()), 2)  # 둘째 묶음도 200을 받았다
        self.assertEqual(self.state_offset(), len(L(1)) + 1)

    def test_S20_dry_run(self):
        # S20: --dry-run — 서버에 요청이 가지 않고, 묶음 경계·줄 수가 로그에, 상태 파일을 바꾸지 않음, 종료 코드 0
        shutil.copyfile(SAMPLE, self.ev)
        r = self.run_sender(self.cfg(), "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.snapshot(), [])
        dry = [x for x in r.stderr.splitlines() if " dry_run " in x]
        self.assertGreater(len(dry), 1)
        total = sum(int(x.split(" lines=")[1].split()[0]) for x in dry)
        with open(self.ev, "rb") as f:
            self.assertEqual(total, f.read().count(b"\n"))
        self.assertFalse(os.path.exists(self.state))

    def test_S21_two_senders(self):
        # S21: 같은 state_path로 하나가 떠 있는 동안 또 하나 — 둘째는 종료 코드 5로 아무것도 보내지 않음.
        #      첫째는 그대로 돌고, 첫째를 끝내면 둘째가 잠금을 얻어 이어서 보낸다
        cfg = self.cfg()
        self.write(lines_bytes([L(1)]))
        p1 = self.start(cfg)
        self.assertTrue(wait_until(lambda: self.srv.accepted_lines() == [L(1)]), self.log_of(p1))
        n = len(self.srv.snapshot())
        p2 = self.start(cfg)
        self.assertEqual(p2.wait(timeout=10), 5, self.log_of(p2))
        self.assertIn("reason=locked", self.log_of(p2))
        self.assertEqual(len(self.srv.snapshot()), n)
        self.assertIsNone(p1.poll())
        self.write(lines_bytes([L(2)]))
        self.assertTrue(wait_until(lambda: self.srv.accepted_lines() == [L(1), L(2)]), self.log_of(p1))
        self.assertTrue(wait_until(lambda: self.state_offset() == os.path.getsize(self.ev)), self.log_of(p1))
        self.assertEqual(self.term(p1), 0)
        self.write(lines_bytes([L(3)]))
        k = len(self.srv.snapshot())
        r = self.once(cfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(b"".join(b for _, b, _ in self.srv.snapshot()[k:]), lines_bytes([L(3)]))


class Config(Base):
    needs_server = False

    def test_S14_config(self):
        # S14: 범위 밖 값·http:// 주소·타입 오류 → 종료 코드 1 / 모르는 키 → 경고 후 진행
        #      (24_ §8.2로 바뀜) kpm2_interval_ms 1000·send_ue_evt true는 허용 값 — '다음 단계' 경고가 없다
        self.write(lines_bytes([L(1)]))
        for over in ({"batch_max_lines": 0}, {"batch_max_lines": 5001}, {"url": "http://127.0.0.1/ingest"},
                     {"batch_max_lines": "500"}, {"env": "P4"}, {"retry_max_ms": 50},
                     {"inputs": [{"path": "x.jsonl", "kind": "input"}]}, {"start_at": "middle"},
                     {"batch_max_bytes": 4096}):  # < line_max_bytes + 1 (11/05 W-31)
            with self.subTest(over=over):
                r = self.run_sender(self.cfg(**over), "--dry-run")
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertIn("config_error", r.stderr)
        r = self.run_sender(self.cfg(foo=1), "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("unknown key foo", r.stderr)
        r = self.run_sender(self.cfg(kpm2_interval_ms=1000, send_ue_evt=True,
                                     inputs=[{"path": self.ev, "kind": "evidence"},
                                             {"path": "input.jsonl", "kind": "input"}]), "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("next-stage", r.stderr)
        self.assertNotIn("config_warning", r.stderr)
        self.assertIn("lines=1", r.stderr)  # evidence는 그대로 묶었다(input 파일은 아직 없음 — 생길 때까지 기다림)
        # 사용법 오류도 1 (2는 '약속에 없는 응답')
        r = subprocess.run([sys.executable, SENDER], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)

    def test_S18_check_detector_config(self):
        # S18: 탐지 엔진 증거 경로와 전송기 경로 비교 — 같으면 0, 다르면 1(두 경로를 적음), --config 없음은 기본값, off는 경고
        cfg_rel = self.cfg(inputs=[{"path": "evidence.jsonl", "kind": "evidence"}])
        det = os.path.join(self.dir, "det.json")

        def check(det_cfg, sender_cfg=cfg_rel):
            return self.run_sender(sender_cfg, "--check-detector-config", det_cfg)

        with open(det, "w") as f:
            json.dump({"evidence": {"out_path": "a.jsonl"}}, f)
        r = check(det)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn(os.path.realpath(os.path.join(self.dir, "a.jsonl")), r.stderr)
        self.assertIn(os.path.realpath(self.ev), r.stderr)
        with open(det, "w") as f:
            json.dump({"evidence": {"out_path": self.ev}}, f)  # 같은 파일을 절대 경로로 (전송기는 상대 경로)
        self.assertEqual(check(det).returncode, 0)
        self.assertEqual(check("-").returncode, 0)  # 탐지 엔진 기본값 evidence.jsonl
        other = self.cfg(inputs=[{"path": "other.jsonl", "kind": "evidence"}])
        self.assertEqual(check("-", other).returncode, 1)
        with open(det, "w") as f:
            json.dump({"evidence": {"mode": "off"}}, f)
        r = check(det)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("evidence_mode_off", r.stderr)


# ---------------------------------------------------------------- S22~S39 상시 KPM (24_ §8.2)
# 입력은 시험 때 만든 100 ms 원본 시나리오. 묶은 줄의 기대값은 원본 줄을 시험 안에서 직접 더해 만든다(전송기 코드를 부르지 않음)

SESSION = "20261104T000000Z"
T0 = 1793000000000  # 10초의 배수 — 칸 경계가 시나리오 시작과 맞는다
DET_SCN = os.path.join(REPO, "tests", "data", "scenarios")


def jl(d):
    return json.dumps(d, separators=(",", ":")).encode()


def hello_line(seq, session=SESSION):
    return jl({"type": "hello", "ver": 1, "session": session, "seq": seq, "cells": [{"cell_id": 1, "max_conn": None}],
               "period_ms": 100, "noreply_timeout_ms": 1000, "ue_evt": True})


def kpm2_dict(seq, cell, t, slot, session=SESSION, period=100):
    att = (slot * 3 + cell) % 5
    succ = att // 2
    return {"type": "kpm2", "ver": 1, "session": session, "seq": seq, "cell_id": cell, "t_start_ms": t,
            "t_end_ms": t + period,
            "cc": {"RRC.ConnEstabAtt": {"total": att, "mo-Signalling": att}, "RRC.ConnEstabSucc": {"total": succ},
                   "RRC.ConnEstabFailCause": {"NetworkReject": 0, "NoReply": att - succ, "Other": 0}},
            "si": {"RRC.ConnMean": slot % 7 + cell + 0.5, "RRC.ConnMax": slot % 7 + cell + 1},
            "ext": {"UeCtxMax": 30 + slot % 11, "CrntiAlloc": att},
            "ue_evt_lost": []}


def gen_stream(seconds, cells=(1,), session=SESSION, t0=T0, seq0=1, ue=True, f1=True, hello=True):
    """100 ms 원본 시나리오 — (줄 목록, kpm2 dict 목록). hello 1줄, 칸마다 셀별 kpm2, 가끔 ue_evt, f1_evt 1줄."""
    lines, kpms = [], []
    seq = seq0
    if hello:
        lines.append(hello_line(seq, session))
        seq += 1
    for slot in range(int(round(seconds * 10))):
        t = t0 + slot * 100
        for c in cells:
            d = kpm2_dict(seq, c, t, slot, session)
            lines.append(jl(d))
            kpms.append(d)
            seq += 1
        if ue and slot % 7 == 3:
            lines.append(jl({"type": "ue_evt", "ver": 1, "session": session, "seq": seq, "t_ms": t + 50,
                             "cell_id": cells[0], "du_ue_id": slot, "dir": "UL", "msg": "RRCSetupRequest"}))
            seq += 1
        if f1 and slot == 5:
            lines.append(jl({"type": "f1_evt", "ver": 1, "session": session, "seq": seq, "t_ms": t + 60,
                             "event": "du_reset"}))
            seq += 1
    return lines, kpms


def expect_agg(kpms, n_ms):
    """기대값 — gen_stream 모양의 kpm2를 칸마다 직접 더한다. (session, cell, agg_ms, t_start) → 묶은 줄 바이트 (24_ §5.2)."""
    groups = {}
    for d in kpms:
        groups.setdefault((d["session"], d["cell_id"], d["t_start_ms"] // n_ms * n_ms), []).append(d)
    out = {}
    for (s, c, t0), ds in groups.items():
        att = sum(d["cc"]["RRC.ConnEstabAtt"]["total"] for d in ds)
        succ = sum(d["cc"]["RRC.ConnEstabSucc"]["total"] for d in ds)
        nr = sum(d["cc"]["RRC.ConnEstabFailCause"]["NoReply"] for d in ds)
        means = [d["si"]["RRC.ConnMean"] for d in ds]
        out[(s, c, n_ms, t0)] = jl({
            "type": "kpm2", "ver": 1, "agg_ms": n_ms, "session": s, "cell_id": c, "t_start_ms": t0,
            "t_end_ms": t0 + n_ms, "n": len(ds), "seq_from": min(d["seq"] for d in ds),
            "seq_to": max(d["seq"] for d in ds),
            "cc": {"RRC.ConnEstabAtt": {"total": att, "mo-Signalling": att}, "RRC.ConnEstabSucc": {"total": succ},
                   "RRC.ConnEstabFailCause": {"NetworkReject": 0, "NoReply": nr, "Other": 0}},
            "si": {"RRC.ConnMean": round(sum(means) / len(means), 3),
                   "RRC.ConnMax": max(d["si"]["RRC.ConnMax"] for d in ds)},
            "ext": {"UeCtxMax": max(d["ext"]["UeCtxMax"] for d in ds), "CrntiAlloc": att},
            "partial": []})
    return out


def skew_cell2(lines):
    """셀 2의 kpm2 줄을 다음 셀 1 kpm2 줄 뒤로 미룬다 — 셀 2가 한 칸 늦게 오는 순서(셀마다 순서는 그대로)."""
    out, held = [], None
    for x in lines:
        d = json.loads(x)
        if d.get("type") == "kpm2" and d["cell_id"] == 2:
            if held is not None:
                out.append(held)
            held = x
            continue
        out.append(x)
        if held is not None and d.get("type") == "kpm2" and d["cell_id"] == 1:
            out.append(held)
            held = None
    if held is not None:
        out.append(held)
    return out


def agg_lines(srv):
    """받은 묶은 줄 — 키 → 받은 순서대로의 줄 목록(다시 간 줄이 있으면 2개 이상)."""
    out = {}
    for x in srv.accepted_lines():
        if b'"agg_ms"' in x:
            d = json.loads(x)
            out.setdefault((d["session"], d["cell_id"], d["agg_ms"], d["t_start_ms"]), []).append(x)
    return out


def first_of(got):
    return {k: v[0] for k, v in got.items()}


class InputBase(Base):
    """input 파일 시험의 공통 — 기록 파일 경로·설정·쓰기 (InputSending·RotationInput)."""
    def setUp(self):
        super().setUp()
        self.inp = os.path.join(self.dir, "input.jsonl")

    def icfg(self, **over):
        c = {"inputs": [{"path": self.ev, "kind": "evidence"}, {"path": self.inp, "kind": "input"}],
             "kpm2_interval_ms": 1000}
        c.update(over)
        return self.cfg(**c)

    def write_in(self, lines, mode="ab"):
        self.write(lines_bytes(lines), mode, self.inp)


class InputSending(InputBase):
    def test_S22_kpm2_aggregated_only(self):
        # S22: 1000·send_ue_evt false — hello·f1_evt는 바이트 그대로, kpm2는 묶은 줄만(원본 0줄), ue_evt는 가지 않음
        lines, kpms = gen_stream(3)
        self.write_in(lines)
        r = self.once(self.icfg(send_ue_evt=False))
        self.assertEqual(r.returncode, 0, r.stderr)
        got = self.srv.accepted_lines()
        self.assertEqual([x for x in got if b'"agg_ms"' not in x],
                         [x for x in lines if json.loads(x)["type"] in ("hello", "f1_evt")])
        self.assertFalse(set(got) & {x for x in lines if json.loads(x)["type"] == "kpm2"})
        self.assertFalse(any(b'"type":"ue_evt"' in x for x in got))
        self.assertEqual(first_of(agg_lines(self.srv)), expect_agg(kpms, 1000))

    def test_S23_ue_evt_only(self):
        # S23: 0·send_ue_evt true — hello·f1_evt·ue_evt만 바이트 그대로, kpm2 없음
        lines, _ = gen_stream(3)
        self.write_in(lines)
        r = self.once(self.icfg(kpm2_interval_ms=0, send_ue_evt=True))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.accepted_lines(), [x for x in lines if json.loads(x)["type"] != "kpm2"])

    def test_S24_aggregate_values(self):
        # S24: N 1000·5000·10000, 셀 2개 — 합·평균·최대·n·seq·칸 경계와 키 순서·바이트 모양이 기대값과 같다
        lines, kpms = gen_stream(25, cells=(1, 2))
        self.write_in(lines)
        for n_ms in (1000, 5000, 10000):
            with self.subTest(n_ms=n_ms):
                srv = self.server()
                r = self.once(self.icfg(kpm2_interval_ms=n_ms, url=srv.url(),
                                        state_path=os.path.join(self.dir, f"state_{n_ms}.json")))
                self.assertEqual(r.returncode, 0, r.stderr)
                got = agg_lines(srv)
                self.assertTrue(all(len(v) == 1 for v in got.values()), "each bucket once")
                self.assertEqual(first_of(got), expect_agg(kpms, n_ms))
                for (v,) in got.values():
                    self.assertTrue(v.startswith(b'{"type":"kpm2","ver":1,"agg_ms":%d,"session":' % n_ms))

    def test_S25_unknown_values(self):
        # S25: 모름 — 일부 null → partial / 모두 null → null / 모두 없음 → 키 없음 / cc 자체 null / total 없는 객체
        lines, ds, seq = [hello_line(1)], [], 2
        for slot in range(10):
            d = kpm2_dict(seq, 1, T0 + slot * 100, slot)
            seq += 1
            d["cc"]["RRC.ReEstabAtt"] = None                          # 모든 줄 null → null
            if slot == 0:
                d["ext"]["DuCannotServe"] = 1                         # 한 줄에만 → partial
            if slot == 3:
                d["cc"] = None                                        # 캡처가 멈춘 창 — cc 이름 모두 모름
            if slot == 5:
                d["cc"]["RRC.ConnEstabAtt"] = {"mo-Signalling": 2}    # total 없음 → 그 줄에서 모름
            if slot == 7:
                del d["si"]                                           # si 없음
            ds.append(d)
            lines.append(jl(d))
        lines.append(jl(kpm2_dict(seq, 1, T0 + 1000, 10)))  # 다음 칸 첫 줄 — 앞 칸을 닫는다
        self.write_in(lines)
        r = self.once(self.icfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        a = json.loads(agg_lines(self.srv)[(SESSION, 1, 1000, T0)][0])
        self.assertEqual(a["n"], 10)
        att = [d for i, d in enumerate(ds) if i not in (3, 5)]
        self.assertEqual(a["cc"]["RRC.ConnEstabAtt"]["total"], sum(d["cc"]["RRC.ConnEstabAtt"]["total"] for d in att))
        self.assertEqual(a["cc"]["RRC.ConnEstabSucc"]["total"],
                         sum(d["cc"]["RRC.ConnEstabSucc"]["total"] for i, d in enumerate(ds) if i != 3))
        self.assertIsNone(a["cc"]["RRC.ReEstabAtt"])
        self.assertNotIn("RRC.ResumeAtt", a["cc"])
        self.assertEqual(a["ext"]["DuCannotServe"], 1)
        si = [d for i, d in enumerate(ds) if i != 7]
        self.assertEqual(a["si"]["RRC.ConnMean"], round(sum(d["si"]["RRC.ConnMean"] for d in si) / 9, 3))
        self.assertEqual(a["partial"], ["cc.RRC.ConnEstabAtt", "cc.RRC.ConnEstabSucc", "cc.RRC.ConnEstabFailCause",
                                        "si.RRC.ConnMean", "si.RRC.ConnMax", "ext.DuCannotServe"])

    def test_S40_nested_null_cause(self):
        # S40 (11/05 W-40, 24_ §5.1): 원인별 객체의 하위 값 null은 그 원인만 '모름'이고 줄은 받는다(엔진 파서와 같음).
        #      total null은 그 줄에서 그 이름을 모름(total 없음과 같음). bad_kpm2가 나지 않는다
        lines, ds, seq = [hello_line(1)], [], 2
        for slot in range(10):
            d = kpm2_dict(seq, 1, T0 + slot * 100, slot)
            seq += 1
            if slot == 2:
                d["cc"]["RRC.ConnEstabAtt"]["mo-Signalling"] = None   # 하위 null — total은 셈, 원인만 뺌
            if slot == 4:
                d["cc"]["RRC.ConnEstabFailCause"]["NoReply"] = None  # total 없는 객체의 하위 null
            if slot == 6:
                d["cc"]["RRC.ConnEstabSucc"]["total"] = None         # total null → 그 줄에서 모름
            ds.append(d)
            lines.append(jl(d))
        lines.append(jl(kpm2_dict(seq, 1, T0 + 1000, 10)))
        self.write_in(lines)
        r = self.once(self.icfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("bad_kpm2", r.stderr)
        a = json.loads(agg_lines(self.srv)[(SESSION, 1, 1000, T0)][0])
        self.assertEqual(a["n"], 10)
        att = a["cc"]["RRC.ConnEstabAtt"]
        self.assertEqual(att["total"], sum(d["cc"]["RRC.ConnEstabAtt"]["total"] for d in ds))
        self.assertEqual(att["mo-Signalling"], sum(d["cc"]["RRC.ConnEstabAtt"]["total"] for i, d in enumerate(ds) if i != 2))
        self.assertEqual(a["cc"]["RRC.ConnEstabFailCause"]["NoReply"],
                         sum(d["cc"]["RRC.ConnEstabFailCause"]["NoReply"] for i, d in enumerate(ds) if i != 4))
        self.assertEqual(a["cc"]["RRC.ConnEstabSucc"]["total"],
                         sum(d["cc"]["RRC.ConnEstabSucc"]["total"] for i, d in enumerate(ds) if i != 6))
        self.assertEqual(a["partial"], ["cc.RRC.ConnEstabSucc"])

    def test_S26_missing_slots(self):
        # S26: 10줄 가운데 3줄을 뺀 칸 — n 7
        lines, kpms = gen_stream(2, ue=False, f1=False)
        drop = {kpms[2]["seq"], kpms[5]["seq"], kpms[7]["seq"]}
        self.write_in([x for x in lines if json.loads(x).get("seq") not in drop])
        self.assertEqual(self.once(self.icfg()).returncode, 0)
        a = json.loads(agg_lines(self.srv)[(SESSION, 1, 1000, T0)][0])
        self.assertEqual(a["n"], 7)

    def test_S27_late_overlap_bad(self):
        # S27: 늦은 줄(다른 셀 시각으로 닫힌 칸)·겹친 줄·bad_kpm2 — 보내지 않고 세며 사유마다 경고 한 번, 다른 칸은 그대로
        lines, good, seq = [hello_line(1)], [], 2

        def k(cell, slot):
            nonlocal seq
            d = kpm2_dict(seq, cell, T0 + slot * 100, slot)
            seq += 1
            return d

        for slot in range(5):                       # 셀 1: 칸 [0, 1000)의 앞 5줄
            d = k(1, slot)
            good.append(d)
            lines.append(jl(d))
        for slot in range(31):                      # 셀 2: t 3000(= 1000 + 여유 2000)에서 셀 1의 칸을 닫는다
            d = k(2, slot)
            good.append(d)
            lines.append(jl(d))
            if slot == 10:
                lines.append(jl(d))                 # 같은 줄 다시 — overlap
            if slot in (12, 14):
                bad = k(2, 99)
                bad["cc"]["RRC.ConnEstabAtt"]["total"] = -1
                lines.append(jl(bad))               # bad_kpm2 두 번 — 경고는 한 번
        lines.append(jl(k(1, 5)))                   # 셀 1의 닫힌 칸에 든 늦은 줄
        self.write_in(lines)
        r = self.once(self.icfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(first_of(agg_lines(self.srv)), expect_agg(good, 1000))
        self.assertEqual(r.stderr.count("reason=bad_kpm2"), 1, r.stderr)
        self.assertEqual(r.stderr.count("reason=overlap"), 1, r.stderr)
        self.assertEqual(r.stderr.count(" agg_late "), 1, r.stderr)

    def test_S28_session_change(self):
        # S28: 새 세션 hello — 옛 세션 칸이 그 자리(hello 앞)에서 닫혀 감 / hello 없이 새 세션 kpm2 — 그 셀의 옛 칸이 닫힘
        a_lines, a_kpms = gen_stream(1.5, session="A", ue=False, f1=False)
        b_lines, b_kpms = gen_stream(1.2, session="B", t0=T0 + 5000, ue=False, f1=False)
        self.write_in(a_lines + b_lines)
        self.assertEqual(self.once(self.icfg()).returncode, 0)
        got = self.srv.accepted_lines()
        a_last = expect_agg(a_kpms, 1000)[("A", 1, 1000, T0 + 1000)]
        self.assertLess(got.index(a_last), got.index(b_lines[0]), "A's open bucket closes before B's hello")
        self.assertEqual(first_of(agg_lines(self.srv)), {**expect_agg(a_kpms, 1000), **expect_agg(b_kpms, 1000)})
        # hello 없이 — 상주 모드에서 파일 끝 마무리 없이도 A의 칸이 닫혀 간다(C의 마지막 칸은 열린 채)
        srv = self.server()
        inp2 = os.path.join(self.dir, "input2.jsonl")
        c_lines, c_kpms = gen_stream(1.5, session="C", t0=T0 + 9000, ue=False, f1=False, hello=False)
        self.write(lines_bytes(a_lines + c_lines), "wb", inp2)
        p = self.start(self.icfg(url=srv.url(), state_path=os.path.join(self.dir, "state2.json"),
                                 inputs=[{"path": self.ev, "kind": "evidence"}, {"path": inp2, "kind": "input"}]))
        self.assertTrue(wait_until(lambda: a_last in srv.accepted_lines()), self.log_of(p))
        time.sleep(0.5)
        self.assertNotIn(("C", 1, 1000, T0 + 10000), agg_lines(srv))
        self.assertEqual(self.term(p), 0)

    def test_S29_one_cell_stops(self):
        # S29: 셀 2개 중 셀 2만 1.4 s에서 멈춤 — 셀 1의 t_start가 셀 2 칸 끝 + kpm2_close_lag_ms에 닿을 때 셀 2 칸이 닫힘
        for until, lag, closed in ((50, 2000, True), (39, 2000, False), (50, 3000, False)):
            with self.subTest(until=until, lag=lag):
                lines, _ = gen_stream(until / 10, cells=(1, 2), ue=False, f1=False)
                lines = [x for x in lines if not (json.loads(x).get("cell_id") == 2
                                                  and json.loads(x)["t_start_ms"] >= T0 + 1500)]
                inp = os.path.join(self.dir, f"in_{until}_{lag}.jsonl")
                self.write(lines_bytes(lines), "wb", inp)
                srv = self.server()
                p = self.start(self.icfg(url=srv.url(), kpm2_close_lag_ms=lag,
                                         state_path=os.path.join(self.dir, f"st_{until}_{lag}.json"),
                                         inputs=[{"path": self.ev, "kind": "evidence"}, {"path": inp, "kind": "input"}]))
                # 셀 1의 [2000, 3000) 칸까지는 닫혀 간다 — 그 뒤 셀 2의 [1000, 2000) 칸이 닫혔는지 본다
                self.assertTrue(wait_until(lambda: (SESSION, 1, 1000, T0 + 2000) in agg_lines(srv)), self.log_of(p))
                time.sleep(0.5)
                self.assertEqual((SESSION, 2, 1000, T0 + 1000) in agg_lines(srv), closed)
                self.assertNotIn((SESSION, 1, 1000, T0 + ((until - 1) // 10) * 1000), agg_lines(srv))  # 셀 1 마지막 칸은 열림
                self.assertEqual(self.term(p), 0)

    def test_S30_restart_keeps_open_buckets(self):
        # S30: 열린 칸이 있을 때 멈추고 다시 띄움(여러 위치, 셀 2개) — 빠진 칸 없음, 저장 위치 ≤ 열린 칸 첫 줄,
        #      다시 간 묶은 줄은 처음 것과 바이트 같음(이미 보낸 칸은 반쪽으로 다시 가지 않음)
        #      skew: 셀 2의 줄이 셀 1보다 한 칸 늦게 옴 — 이미 보낸 셀 2 칸의 끝 줄이 셀 1 열린 칸의 첫 줄 뒤에 있어,
        #      다시 읽을 때 '보낸 칸'(상태 파일)으로 건너뛰지 않으면 같은 키의 반쪽 줄이 다시 간다(24_ §4.3)
        base, kpms = gen_stream(8, cells=(1, 2))
        for skew in (False, True):
            lines = skew_cell2(base) if skew else base
            offs, pos = [], 0
            for x in lines:
                offs.append(pos)
                pos += len(x) + 1
            for cut in (15, 27, 44):
                with self.subTest(skew=skew, cut=cut):
                    self._restart_case(lines, offs, kpms, cut, f"{int(skew)}_{cut}")

    def _restart_case(self, lines, offs, kpms, cut, tag):
        inp = os.path.join(self.dir, f"in_{tag}.jsonl")
        state = os.path.join(self.dir, f"st_{tag}.json")
        srv = self.server()
        # 셀 1의 cut 칸 줄 앞까지 쓰고 상주 전송기로 보낸 뒤 멈춘다
        ci = next(i for i, x in enumerate(lines)
                  if json.loads(x).get("cell_id") == 1 and json.loads(x).get("t_start_ms") == T0 + cut * 100)
        self.write(lines_bytes(lines[:ci]), "wb", inp)
        cfg = self.icfg(url=srv.url(), state_path=state,
                        inputs=[{"path": self.ev, "kind": "evidence"}, {"path": inp, "kind": "input"}])
        p = self.start(cfg)
        closed = 2 * ((cut - 1) // 10)  # 셀마다 cut 전에 닫힌 칸
        self.assertTrue(wait_until(lambda: len(agg_lines(srv)) >= closed), self.log_of(p))
        time.sleep(0.3)
        self.assertEqual(self.term(p), 0)
        with open(state) as f:
            off = json.load(f)["files"][os.path.abspath(inp)]["offset"]
        open_t = T0 + ((cut - 1) // 10) * 1000
        first_open = min(offs[i] for i, x in enumerate(lines[:ci]) if json.loads(x).get("t_start_ms") == open_t)
        self.assertLessEqual(off, first_open)
        # 나머지를 쓰고 --once로 다시 띄운다
        self.write(lines_bytes(lines[ci:]), "ab", inp)
        self.assertEqual(self.once(cfg).returncode, 0)
        got = agg_lines(srv)
        for k, v in got.items():
            self.assertEqual(len(set(v)), 1, f"bucket {k} re-sent with different bytes")
        self.assertEqual(first_of(got), expect_agg(kpms, 1000))

    def test_S31_once_closes_open_buckets(self):
        # S31: --once — 파일 끝에서 열린 칸까지 모두 감(마지막 칸은 n 5)
        lines, kpms = gen_stream(3.5)
        self.write_in(lines)
        self.assertEqual(self.once(self.icfg()).returncode, 0)
        got = first_of(agg_lines(self.srv))
        self.assertEqual(got, expect_agg(kpms, 1000))
        self.assertEqual(json.loads(got[(SESSION, 1, 1000, T0 + 3000)])["n"], 5)

    def test_S32_period_mismatch(self):
        # S32: 원본 주기 P가 N을 나누지 못하는 줄(P 300, N 1000) — 보내지 않고 agg_period 한 번, 다른 셀은 그대로 묶임
        lines, good, seq = [hello_line(1)], [], 2
        for slot in range(12):
            d = kpm2_dict(seq, 1, T0 + slot * 100, slot)
            good.append(d)
            lines.append(jl(d))
            seq += 1
            if slot % 3 == 0:
                lines.append(jl(kpm2_dict(seq, 2, T0 + slot * 100, slot, period=300)))
                seq += 1
        self.write_in(lines)
        r = self.once(self.icfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(first_of(agg_lines(self.srv)), expect_agg(good, 1000))
        self.assertEqual(r.stderr.count(" agg_period "), 1, r.stderr)
        self.assertFalse(any(b'"cell_id":2' in x for x in self.srv.accepted_lines()))  # 셀 2(P 300)는 아무것도 가지 않음

    def test_S33_skipped_lines(self):
        # S33: JSON 아님·type 없음·모르는 type — 보내지 않고 위치는 넘어감, 사유마다 경고 한 번
        bad = [b"not json", b"[1,2]", b'{"no":"type"}', b'{"type":5}', b'{"type":"weird"}', b'{"type":"weird2"}']
        self.write_in(bad + [hello_line(1)])
        r = self.once(self.icfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.accepted_lines(), [hello_line(1)])
        for reason in ("not_json", "no_type", "unknown_type"):
            self.assertEqual(r.stderr.count(f"reason={reason}"), 1, r.stderr)
        self.assertEqual(self.state_offset(self.inp), os.path.getsize(self.inp))

    def test_S34_default_interval(self):
        # S34 일부: kpm2_interval_ms 키 없음(기본) + input 항목 — 3초 묶음으로 보냄
        lines, kpms = gen_stream(7)
        self.write_in(lines)
        cfg = self.cfg(inputs=[{"path": self.ev, "kind": "evidence"}, {"path": self.inp, "kind": "input"}])
        self.assertEqual(self.once(cfg).returncode, 0)
        self.assertEqual(first_of(agg_lines(self.srv)), expect_agg(kpms, 3000))

    def test_S36_two_files(self):
        # S36: 두 파일 — 파일마다 순서 유지, input이 밀려 있어도 evidence 묶음은 input 묶음 하나 이상 기다리지 않음
        ev_lines = [L(i) for i in range(150)]  # 50줄 묶음 3개 — 모두 꽉 차 묶음 간격을 기다리지 않는다
        in_lines = [jl({"type": "ue_evt", "ver": 1, "session": SESSION, "seq": i + 1, "t_ms": T0 + i}) for i in range(500)]
        self.write(lines_bytes(ev_lines))
        self.write_in(in_lines)
        p = self.start(self.icfg(kpm2_interval_ms=0, send_ue_evt=True, batch_max_lines=50))
        self.assertTrue(wait_until(lambda: len(self.srv.accepted_lines()) == 650), self.log_of(p))
        self.assertEqual(self.term(p), 0)
        kinds = ["E" if b'"type":"alert"' in b else "I" for _, b, _ in self.srv.snapshot()]
        self.assertEqual(kinds[:6], ["E", "I", "E", "I", "E", "I"])
        got = self.srv.accepted_lines()
        self.assertEqual([x for x in got if b'"type":"alert"' in x], ev_lines)
        self.assertEqual([x for x in got if b'"type":"ue_evt"' in x], in_lines)

    def test_S37_end_to_end(self):
        # S37: detector --replay(기록 켬) + 전송기 N 1000 — 받은 묶은 줄 = 원래 시나리오로 만든 기대값, 증거 줄도 모두 받음
        scn = os.path.join(DET_SCN, "T05_공격종료.jsonl")
        det_cfg = os.path.join(self.dir, "detector.json")
        with open(det_cfg, "w") as f:
            json.dump({"evidence": {"out_path": self.ev}, "input_record": {"path": self.inp}}, f)
        d = subprocess.run([DET, "--replay", scn, "--config", det_cfg], capture_output=True, text=True, timeout=60)
        self.assertEqual(d.returncode, 0, d.stderr)
        r = self.once(self.icfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        raw = [json.loads(x) for x in open(scn, "rb").read().splitlines() if b'"type":"kpm2"' in x]
        groups = {}
        for k in raw:
            groups.setdefault((k["session"], k["cell_id"], 1000, k["t_start_ms"] // 1000 * 1000), []).append(k)
        got = first_of(agg_lines(self.srv))
        self.assertEqual(set(got), set(groups))
        for key, ks in groups.items():
            a = json.loads(got[key])
            self.assertEqual(a["n"], len(ks))
            self.assertEqual((a["seq_from"], a["seq_to"]), (min(k["seq"] for k in ks), max(k["seq"] for k in ks)))
            for name in ("RRC.ConnEstabAtt", "RRC.ConnEstabSucc"):
                self.assertEqual(a["cc"][name]["total"], sum(k["cc"][name]["total"] for k in ks))
            fc = a["cc"]["RRC.ConnEstabFailCause"]
            for cause in ("NoReply", "NetworkReject", "Other"):
                self.assertEqual(fc[cause], sum(k["cc"]["RRC.ConnEstabFailCause"][cause] for k in ks))
            self.assertEqual(a["partial"], [])
        with open(self.ev, "rb") as f:
            ev = [x for x in f.read().split(b"\n") if x]
        self.assertTrue(ev)
        self.assertEqual([x for x in self.srv.accepted_lines() if b'"type":"alert"' in x or b'"type":"evidence"' in x
                          or b'"type":"gap"' in x], ev)

    def test_S38_change_interval(self):
        # S38: N 1000으로 보내다 멈추고 5000으로 다시 띄움 — 모든 원본 kpm2가 어느 묶은 줄에 듦, 원본 줄은 가지 않음
        lines, kpms = gen_stream(20)
        ci = next(i for i, x in enumerate(lines) if json.loads(x).get("t_start_ms") == T0 + 4500)
        self.write_in(lines[:ci])
        p = self.start(self.icfg(kpm2_interval_ms=1000))
        self.assertTrue(wait_until(lambda: len(agg_lines(self.srv)) >= 4), self.log_of(p))
        time.sleep(0.3)
        self.assertEqual(self.term(p), 0)
        self.write_in(lines[ci:])
        self.assertEqual(self.once(self.icfg(kpm2_interval_ms=5000)).returncode, 0)
        got = [json.loads(v[0]) for v in agg_lines(self.srv).values()]
        self.assertTrue({a["agg_ms"] for a in got} == {1000, 5000})
        for d in kpms:
            self.assertTrue(any(a["cell_id"] == d["cell_id"] and a["t_start_ms"] <= d["t_start_ms"] < a["t_end_ms"]
                                and a["seq_from"] <= d["seq"] <= a["seq_to"] for a in got), f"kpm2 seq {d['seq']}")
        self.assertFalse(set(self.srv.accepted_lines()) & {x for x in lines if json.loads(x)["type"] == "kpm2"})

    def test_S39_resend_other_state(self):
        # S39: 같은 기록 파일을 다른 state_path로 --once(N 10000) — 파일 처음부터 새 주기로
        lines, kpms = gen_stream(25)
        self.write_in(lines)
        self.assertEqual(self.once(self.icfg(kpm2_interval_ms=1000)).returncode, 0)
        srv = self.server()
        self.assertEqual(self.once(self.icfg(kpm2_interval_ms=10000, url=srv.url(),
                                             state_path=os.path.join(self.dir, "other_state.json"))).returncode, 0)
        self.assertEqual(first_of(agg_lines(srv)), expect_agg(kpms, 10000))


class InputConfig(Base):
    needs_server = False

    def test_S34_config(self):
        # S34: kpm2_interval_ms 범위 밖 → 1 / input 항목 없음 → 경고 없이 evidence만 / input 2개 → 1 /
        #      input·evidence 같은 경로 → 1 / input 있는데 0·false → 경고 후 evidence만
        self.write(lines_bytes([L(1)]))
        inp = os.path.join(self.dir, "input.jsonl")
        two = [{"path": self.ev, "kind": "evidence"}, {"path": inp, "kind": "input"}]
        for over in ({"kpm2_interval_ms": 100}, {"kpm2_interval_ms": 500}, {"kpm2_interval_ms": 1500},
                     {"kpm2_interval_ms": 700000}, {"kpm2_interval_ms": "3000"}, {"kpm2_close_lag_ms": 50},
                     {"inputs": two + [{"path": inp + "2", "kind": "input"}]},
                     {"inputs": [{"path": self.ev, "kind": "evidence"}, {"path": self.ev, "kind": "input"}]}):
            with self.subTest(over=over):
                r = self.run_sender(self.cfg(**over), "--dry-run")
                self.assertEqual(r.returncode, 1, r.stderr)
                self.assertIn("config_error", r.stderr)
        for over in ({}, {"kpm2_interval_ms": 5000}):
            with self.subTest(no_input=over):
                r = self.run_sender(self.cfg(**over), "--dry-run")
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertNotIn("config_warning", r.stderr)
                self.assertIn("lines=1", r.stderr)
        r = self.run_sender(self.cfg(inputs=two, kpm2_interval_ms=0, send_ue_evt=False), "--dry-run")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("kind=input entry ignored", r.stderr)
        self.assertNotIn("input.jsonl", r.stderr.split("kind=input entry ignored")[1])  # 따라 읽지 않음

    def test_S35_check_detector_config(self):
        # S35: 시작 전 확인(24_ §7 표) — input 있음 × 탐지 엔진 null·다른 경로·같은 경로 / input 없음 × 경로 있음·null
        inp = os.path.join(self.dir, "input.jsonl")
        with_in = self.cfg(inputs=[{"path": self.ev, "kind": "evidence"}, {"path": inp, "kind": "input"}])
        no_in = self.cfg()
        det = os.path.join(self.dir, "det.json")

        def check(rec, sender_cfg):
            with open(det, "w") as f:
                json.dump({"evidence": {"out_path": self.ev}, "input_record": {"path": rec}}, f)
            return self.run_sender(sender_cfg, "--check-detector-config", det)

        r = check(None, with_in)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("not_recording", r.stderr)
        r = check(os.path.join(self.dir, "other.jsonl"), with_in)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("mismatch", r.stderr)
        r = check("input.jsonl", with_in)  # 상대 경로 — 전송기를 띄운 폴더 기준이라 같은 파일
        self.assertEqual(r.returncode, 0, r.stderr)
        r = check(inp, no_in)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("input_not_sent", r.stderr)
        r = check(None, no_in)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("input_not_sent", r.stderr)
        self.assertNotIn("check_input_path", r.stderr)
        self.assertEqual(self.run_sender(with_in, "--check-detector-config", "-").returncode, 1)  # 기본값은 기록 끔


# ---------------------------------------------------------------- 실행 스크립트 (S16·S18)

FAKE_DETECTOR = r'''
import signal, sys, time
# 탐지 엔진 대신 증거 파일에 줄을 쓴다. finite: 5줄 쓰고 종료 코드 3 / forever: SIGTERM까지 0.1초마다
mode = sys.argv[1]
stop = False
def on_term(s, f):
    global stop
    stop = True
signal.signal(signal.SIGTERM, on_term)
with open("evidence.jsonl", "ab", buffering=0) as f:
    if mode == "finite":
        for i in range(5):
            f.write(b'{"type":"alert","n":%d}\n' % i)
        time.sleep(0.5)
        sys.exit(3)
    i = 0
    while not stop:
        f.write(b'{"type":"alert","n":%d}\n' % i)
        i += 1
        time.sleep(0.1)
sys.exit(0)
'''


class RunScript(Base):
    def setUp(self):
        super().setUp()
        self.fake = os.path.join(self.dir, "fake_detector.py")
        with open(self.fake, "w") as f:
            f.write(FAKE_DETECTOR)
        self.env = dict(os.environ, PYTHON=sys.executable)

    def script_cfg(self, **over):
        # 실행 스크립트를 띄운 폴더 기준 상대 경로 — 탐지 엔진 기본값 evidence.jsonl과 같은 파일
        return self.cfg(inputs=[{"path": "evidence.jsonl", "kind": "evidence"}], state_path="sender_state.json",
                        **over)

    def popen_script(self, cfg, *det_args):
        log = os.path.join(self.dir, "script.log")
        f = open(log, "w")
        p = subprocess.Popen(["bash", RUN, cfg, "--", sys.executable, self.fake, *det_args], cwd=self.dir,
                             env=self.env, stderr=f, stdout=subprocess.DEVNULL)
        f.close()
        self.procs.append((p, log))
        return p

    def file_lines(self):
        with open(self.ev, "rb") as f:
            return [x for x in f.read().split(b"\n") if x]

    def test_S16_detector_ends(self):
        # S16: 가짜 명령이 끝나면 전송기를 멈추고 --once로 남은 줄까지 보낸 뒤 그 명령의 종료 코드로 끝남
        #      (묶음 간격을 60초로 둬서 상주 전송기는 보내지 않고, 마무리 --once가 보낸다)
        p = self.popen_script(self.script_cfg(batch_interval_ms=60000), "finite")
        self.assertEqual(p.wait(timeout=60), 3, self.log_of(p))
        self.assertEqual(self.srv.accepted_lines(), self.file_lines())
        self.assertEqual(len(self.file_lines()), 5)
        log = self.log_of(p)
        self.assertIn("started sender_pid=", log)
        self.assertIn("detector_exit code=3", log)

    def test_S16_sender_fails_detector_continues(self):
        # S16: 전송기가 종료 코드 2로 끝남 → 가짜 명령은 계속 돌고 경고만. 스크립트 SIGTERM → 정리 후 명령의 종료 코드(0)
        self.srv.responder = lambda b: (404, b"nope")
        p = self.popen_script(self.script_cfg(), "forever")
        self.assertTrue(wait_until(lambda: "sender_exit code=2" in self.log_of(p), timeout=20), self.log_of(p))
        n = len(self.file_lines())
        time.sleep(0.5)
        self.assertIsNone(p.poll())
        self.assertGreater(len(self.file_lines()), n)  # 탐지 엔진(가짜)은 계속 쓴다
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(timeout=60), 0, self.log_of(p))
        self.assertIn("final_once_exit code=2", self.log_of(p))

    def test_S16_sigterm_script(self):
        # S16: 스크립트에 SIGTERM → 둘 다 멈추고 남은 줄을 보냄
        p = self.popen_script(self.script_cfg(batch_interval_ms=60000), "forever")
        self.assertTrue(wait_until(lambda: os.path.exists(self.ev) and len(self.file_lines()) >= 3), self.log_of(p))
        p.send_signal(signal.SIGTERM)
        self.assertEqual(p.wait(timeout=60), 0, self.log_of(p))
        self.assertEqual(self.srv.accepted_lines(), self.file_lines())

    def test_S18_script_path_mismatch(self):
        # S18: 탐지 엔진 설정 evidence.out_path a.jsonl / 전송기 evidence.jsonl → 종료 코드 1로 아무것도 띄우지 않음
        det = os.path.join(self.dir, "det.json")
        with open(det, "w") as f:
            json.dump({"evidence": {"out_path": "a.jsonl"}}, f)
        p = self.popen_script(self.script_cfg(), "finite", "--config", det)
        self.assertEqual(p.wait(timeout=30), 1, self.log_of(p))
        log = self.log_of(p)
        self.assertIn(os.path.realpath(os.path.join(self.dir, "a.jsonl")), log)
        self.assertIn(os.path.realpath(self.ev), log)
        self.assertFalse(os.path.exists(self.ev))  # 가짜 탐지 엔진을 띄우지 않았다
        self.assertFalse(os.path.exists(os.path.join(self.dir, "sender_state.json.lock")))  # 전송기도

    def test_S35_script_input_not_recorded(self):
        # S35: 전송기에 input 항목이 있는데 탐지 엔진 설정이 기록하지 않음(input_record.path null) → 종료 코드 1, 아무것도 띄우지 않음
        det = os.path.join(self.dir, "det.json")
        with open(det, "w") as f:
            json.dump({"evidence": {"out_path": "evidence.jsonl"}, "input_record": {"path": None}}, f)
        cfg = self.cfg(inputs=[{"path": "evidence.jsonl", "kind": "evidence"}, {"path": "input.jsonl", "kind": "input"}],
                       state_path="sender_state.json")
        p = self.popen_script(cfg, "finite", "--config", det)
        self.assertEqual(p.wait(timeout=30), 1, self.log_of(p))
        self.assertIn("not_recording", self.log_of(p))
        self.assertFalse(os.path.exists(self.ev))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "sender_state.json.lock")))



# ---------------------------------------------------------------- S41~S48 회전 파일 이어 보내기 (S40은 W-40 시험이 씀) (19_ §4.4·§4.5, 24_ §4.3 — 11/08 이슈 #102)

def rot(path, ts, n=None):
    """탐지 엔진의 회전 파일 이름 (29_ §2.3) — <path>.<YYYYMMDD-HHMMSS>[.N]."""
    return f"{path}.{ts}" + (f".{n}" if n else "")


def ts_of(sec):
    return datetime.datetime.fromtimestamp(sec, datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")


class Rotation(Base):
    def test_S41_restart_after_one_rotation_once(self):
        # S41: 보내다 멈춤 → 회전 이름으로 옮기고 새 파일에 씀 → 다시 띄움(--once). 옛 파일 남은 줄 → 새 파일, 빠짐·중복 없음
        self.write(lines_bytes([L(1), L(2)]))
        cfg = self.cfg()
        self.assertEqual(self.once(cfg).returncode, 0)
        self.write(lines_bytes([L(3), L(4)]))
        os.rename(self.ev, rot(self.ev, "20261108-010000"))
        self.write(lines_bytes([L(5)]))
        r = self.once(cfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.accepted_lines(), [L(1), L(2), L(3), L(4), L(5)])
        self.assertIn("INFO catchup", r.stderr)
        self.assertIn("from=evidence.jsonl.20261108-010000", r.stderr)
        self.assertEqual(self.state_offset(), os.path.getsize(self.ev))

    def test_S41_restart_after_one_rotation_resident(self):
        # S41: 같은 경우를 상주 전송기로 — 다시 띄운 뒤 회전 파일 → 지금 파일 순, 이어서 새 줄도 따라감
        self.write(lines_bytes([L(1)]))
        cfg = self.cfg()
        p = self.start(cfg)
        self.assertTrue(wait_until(lambda: self.state_offset() == os.path.getsize(self.ev)), self.log_of(p))
        self.assertEqual(self.term(p), 0)
        self.write(lines_bytes([L(2)]))
        os.rename(self.ev, rot(self.ev, "20261108-010000"))
        self.write(lines_bytes([L(3)]))
        p = self.start(cfg)
        self.assertTrue(wait_until(lambda: self.srv.accepted_lines() == [L(1), L(2), L(3)]), self.log_of(p))
        self.write(lines_bytes([L(4)]))
        self.assertTrue(wait_until(lambda: self.srv.accepted_lines() == [L(1), L(2), L(3), L(4)]), self.log_of(p))
        self.assertEqual(self.term(p), 0)
        self.assertIn("next=evidence.jsonl", self.log_of(p))

    def test_S42_three_rotations_while_stopped(self):
        # S42: 멈춘 동안 회전 3번 — 가운데 파일까지 이름 시각 순으로 모두 (같은 시각의 .1은 그 뒤)
        self.write(lines_bytes([L(1)]))
        cfg = self.cfg()
        self.assertEqual(self.once(cfg).returncode, 0)
        self.write(lines_bytes([L(2)]))
        os.rename(self.ev, rot(self.ev, "20261108-010000"))
        self.write(lines_bytes([L(3)]))
        os.rename(self.ev, rot(self.ev, "20261108-020000"))
        self.write(lines_bytes([L(4)]))
        os.rename(self.ev, rot(self.ev, "20261108-020000", 1))
        self.write(lines_bytes([L(5)]))
        r = self.once(cfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.accepted_lines(), [L(i) for i in range(1, 6)])
        self.assertIn("files=3", r.stderr)

    def test_S43_state_file_deleted(self):
        # S43: 상태 파일의 파일을 지움 — saved_ms 앞에 회전된 파일은 보내지 않고, 뒤에 회전된 파일부터. 경고 catchup found=no
        self.write(lines_bytes([L(1)]))
        cfg = self.cfg()
        self.assertEqual(self.once(cfg).returncode, 0)
        with open(self.state) as f:
            saved_s = json.load(f)["files"][os.path.abspath(self.ev)]["saved_ms"] / 1000.0
        self.write(lines_bytes([L(2)]))
        a = rot(self.ev, ts_of(saved_s + 60))
        os.rename(self.ev, a)
        self.write(lines_bytes([L(9)]), path=rot(self.ev, ts_of(saved_s - 3600)))  # saved_ms 앞 — 이미 보낸 옛 파일
        self.write(lines_bytes([L(3)]), path=rot(self.ev, ts_of(saved_s + 120)))
        self.write(lines_bytes([L(4)]))
        # 상태 파일의 파일이 없어짐(손으로 지움). 다른 파일을 다 만든 뒤에 지운다 — 먼저 지우면 새 파일이 그 inode 번호를 다시
        # 받아 '찾은' 것이 된다(19_ §4.5 ⑨ 한계)
        os.remove(a)
        r = self.once(cfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.accepted_lines(), [L(1), L(3), L(4)])
        self.assertIn("WARN catchup", r.stderr)
        self.assertIn("found=no", r.stderr)

    def test_S44_names_outside_rule(self):
        # S44: 규칙 밖 이름(.old·.bak)은 회전 파일이 아님 — 읽지 않고 지금처럼 지금 파일 처음부터, 경고 rotate
        self.write(lines_bytes([L(1)]))
        cfg = self.cfg()
        self.assertEqual(self.once(cfg).returncode, 0)
        self.write(lines_bytes([L(2)]))
        os.rename(self.ev, self.ev + ".old")
        self.write(lines_bytes([L(8)]), path=self.ev + ".bak")
        self.write(lines_bytes([L(3)]), path=self.ev + ".20261108-01")  # 시각 모양이 아님
        self.write(lines_bytes([L(4)]))
        r = self.once(cfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.accepted_lines(), [L(1), L(4)])
        self.assertIn("WARN rotate", r.stderr)
        self.assertNotIn("catchup", r.stderr)

    def test_S45_no_state_ignores_rotated(self):
        # S45: 상태 파일 없음 + 회전 파일 있음 — 회전 파일은 보지 않고 start_at대로 지금 파일만
        self.write(lines_bytes([L(1)]), path=rot(self.ev, "20261108-010000"))
        self.write(lines_bytes([L(2)]))
        r = self.once(self.cfg())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.srv.accepted_lines(), [L(2)])

    def test_S46_rotations_while_lagging(self):
        # S46: 상주 전송기가 서버를 못 닿는 동안 회전 2번 → 서버 회복. 가운데 파일까지 순서대로 모두 (I-01 P8 — 그전에는 건너뜀)
        self.write(lines_bytes([L(1)]))
        port = free_port()
        later = self.server(port=port, start=False)
        p = self.start(self.cfg(url=f"https://127.0.0.1:{port}/ingest"))
        self.assertTrue(wait_until(lambda: "reason=conn_refused" in self.log_of(p)), self.log_of(p))
        self.write(lines_bytes([L(2)]))
        os.rename(self.ev, rot(self.ev, "20261108-010000"))
        self.write(lines_bytes([L(3)]))
        os.rename(self.ev, rot(self.ev, "20261108-020000"))
        self.write(lines_bytes([L(4)]))
        later.start()
        self.assertTrue(wait_until(lambda: later.accepted_lines() == [L(1), L(2), L(3), L(4)]), self.log_of(p))
        self.write(lines_bytes([L(5)]))
        self.assertTrue(wait_until(lambda: later.accepted_lines() == [L(i) for i in range(1, 6)]), self.log_of(p))
        self.assertEqual(self.term(p), 0)
        self.assertIn("next=evidence.jsonl.20261108-020000", self.log_of(p))


class RotationInput(InputBase):
    def _sent_to(self):
        """상태 파일에 남은 '보낸 칸' — (session, cell) → 마지막으로 받은 칸 t0 (24_ §4.3)."""
        try:
            with open(self.state) as f:
                e = json.load(f)["files"][os.path.abspath(self.inp)]
        except (FileNotFoundError, KeyError, ValueError):
            return {}
        return {(x[0], x[1]): x[2] for x in e.get("agg", {}).get("closed", [])}

    def _wait_saved(self, t0, p, cells=(1, 2)):
        # 서버가 받은 것만 보면 전송기가 200을 처리하기 전에 멈출 수 있다 — 상태 파일에 저장된 뒤 멈춘다
        self.assertTrue(wait_until(lambda: all(self._sent_to().get((SESSION, c), -1) >= t0 for c in cells)),
                        self.log_of(p))

    def _cut_index(self, lines, slot, cell=1):
        return next(i for i, x in enumerate(lines)
                    if json.loads(x).get("cell_id") == cell and json.loads(x).get("t_start_ms") == T0 + slot * 100)

    def _assert_complete_once(self, srv, kpms, p=None):
        got = agg_lines(srv)
        want = expect_agg(kpms, 1000)
        self.assertEqual(sorted(got), sorted(want), self.log_of(p) if p else "")
        for k, v in got.items():
            self.assertEqual(v, [want[k]], k)  # 칸마다 온전한 줄 하나 — 잘린 반쪽 줄이나 다시 간 줄 없음

    def test_S47_input_restart_across_rotations(self):
        # S47: input 파일 — 열린 칸이 있을 때 멈추고, 멈춘 동안 칸 중간에서 회전 2번, 다시 띄움(--once).
        #      원본이 빠지지 않고, 칸마다 온전한 묶은 줄이 한 번만 감
        lines, kpms = gen_stream(6, cells=(1, 2))
        c1, c2, c3 = (self._cut_index(lines, s) for s in (15, 33, 47))
        self.write_in(lines[:c1], "wb")
        cfg = self.icfg()
        p = self.start(cfg)
        self._wait_saved(T0, p)
        self.assertEqual(self.term(p), 0)
        self.write_in(lines[c1:c2])
        os.rename(self.inp, rot(self.inp, "20261108-010000"))
        self.write_in(lines[c2:c3])
        os.rename(self.inp, rot(self.inp, "20261108-020000"))
        self.write_in(lines[c3:])
        r = self.once(cfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        self._assert_complete_once(self.srv, kpms)
        self.assertNotIn("agg_late", r.stderr)

    def test_S48_bucket_across_rotation_live(self):
        # S48: 상주 전송기 — 3초(여기서는 1초) 칸 하나가 회전 경계에 걸침. 칸이 두 파일의 줄을 모두 넣은 줄 하나로 한 번만 감,
        #      agg_late 없음 (I-01 P9 — 그전에는 옛 파일 쪽 줄만으로 가고 새 파일 쪽 줄은 버려짐)
        lines, kpms = gen_stream(4, cells=(1, 2))
        c = self._cut_index(lines, 15)
        self.write_in(lines[:c], "wb")
        cfg = self.icfg()
        p = self.start(cfg)
        self._wait_saved(T0, p)
        os.rename(self.inp, rot(self.inp, "20261108-010000"))
        self.write_in(lines[c:])
        self._wait_saved(T0 + 2000, p)  # 경계에 걸친 칸(T0 + 1000)과 그다음 칸까지 받음 — 이어 온 칸이 다 가 옛 파일 묶임이 풀림
        self.assertEqual(self.term(p), 0)
        r = self.once(cfg)  # 마지막 열린 칸을 닫아 보낸다
        self.assertEqual(r.returncode, 0, r.stderr)
        self._assert_complete_once(self.srv, kpms, p)
        self.assertNotIn("agg_late", self.log_of(p) + r.stderr)

    def test_S48_restart_while_carrying(self):
        # S48: 칸을 다음 파일로 이어 가는 동안 멈춤 — 저장 위치는 옛 파일(회전 파일) 쪽, 열린 칸의 첫 줄 앞.
        #      다시 띄우면 옛 파일을 찾아 그 칸을 다시 만들고, 칸마다 온전한 줄이 한 번만 감
        lines, kpms = gen_stream(4, cells=(1, 2))
        offs, pos = [], 0
        for x in lines:
            offs.append(pos)
            pos += len(x) + 1
        c = self._cut_index(lines, 15)
        c2 = self._cut_index(lines, 18)
        self.write_in(lines[:c], "wb")
        cfg = self.icfg()
        p = self.start(cfg)
        self._wait_saved(T0, p)
        a = rot(self.inp, "20261108-010000")
        os.rename(self.inp, a)
        self.write_in(lines[c:c2])
        self.assertTrue(wait_until(lambda: "WARN rotate" in self.log_of(p)), self.log_of(p))
        time.sleep(0.5)
        self.assertEqual(self.term(p), 0)
        with open(self.state) as f:
            e = json.load(f)["files"][os.path.abspath(self.inp)]
        st = os.stat(a)
        self.assertEqual((e["dev"], e["ino"]), (st.st_dev, st.st_ino))
        first_open = min(offs[i] for i, x in enumerate(lines[:c]) if json.loads(x).get("t_start_ms", 0) >= T0 + 1000)
        self.assertLessEqual(e["offset"], first_open)
        self.write_in(lines[c2:])
        r = self.once(cfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        self._assert_complete_once(self.srv, kpms)
        self.assertIn("INFO catchup", r.stderr)

if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
