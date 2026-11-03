#!/usr/bin/env python3
"""전송기 시험 S1~S21 (19_ §9) — ctest가 부른다. 인자: <저장소 경로> <detector 경로> <임시 폴더>

- 시험마다 가짜 수집 서버(http.server + ssl)를 로컬 포트에 띄운다. 받은 요청(헤더·본문)을 기록하고, 시험이 정한 응답을 돌려준다.
- 서버 인증서는 시험 시작 때 openssl 명령으로 만든다(SAN IP:127.0.0.1) — 키·인증서를 저장소에 넣지 않는다.
  openssl이 없으면 서버가 필요한 시험은 건너뛴다.
- S1 입력은 시험 때 detector --replay로 tests/data/의 시나리오 13개를 재생해 만든다(19_ §10 #6 — ~/evidence_sample/과 같은 시나리오).
"""

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
        # S14: 범위 밖 값·http:// 주소·타입 오류 → 종료 코드 1 / 모르는 키 → 경고 후 진행 / kpm2_interval_ms 1000 → 경고 후 0
        self.write(lines_bytes([L(1)]))
        for over in ({"batch_max_lines": 0}, {"batch_max_lines": 5001}, {"url": "http://127.0.0.1/ingest"},
                     {"batch_max_lines": "500"}, {"env": "P4"}, {"retry_max_ms": 50},
                     {"inputs": [{"path": "x.jsonl", "kind": "input"}]}, {"start_at": "middle"}):
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
        self.assertIn("kpm2_interval_ms=1000", r.stderr)
        self.assertIn("send_ue_evt=true", r.stderr)
        self.assertIn("kind=input", r.stderr)
        self.assertIn("lines=1", r.stderr)  # evidence는 그대로 묶었다
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


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
