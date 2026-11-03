#!/usr/bin/env python3
"""전송기 — 탐지 엔진 증거 파일(evidence.jsonl)의 새 줄을 대시보드 /ingest로 보낸다 (19_ 전송기 명세서).

실행 (19_ §2.2):
  python3 tools/dashboard_sender.py --config config/sender.json            # 계속 따라 읽으며 보냄
  python3 tools/dashboard_sender.py --config config/sender.json --once     # 지금 있는 완성된 줄만 보내고 끝냄
  python3 tools/dashboard_sender.py --config config/sender.json --dry-run  # 보내지 않고 묶음만 로그에
  python3 tools/dashboard_sender.py --config config/sender.json --check-detector-config config/detector.json

- 줄의 내용을 바꾸지 않는다. 환경 이름은 헤더 X-Env로 붙이고 토큰은 쓰지 않는다 (19_ §1, 17_ §1.3).
- 보낸 위치는 200·400을 받은 뒤에만 상태 파일에 저장한다 — '최소 한 번' (19_ §4.3, 17_ §1.5).
- 종료 코드: 0 정상, 1 설정 오류, 2 약속에 없는 응답, 3 TLS 검증 실패, 4 상태 파일 저장 실패, 5 잠금 실패 (19_ §7).
- Python 3.10 이상, 표준 라이브러리만 쓴다.
"""

import argparse
import collections
import contextlib
import datetime
import fcntl
import http.client
import json
import os
import re
import signal
import ssl
import sys
import time
import urllib.parse

VERSION = "1"
USER_AGENT = f"ran-detect-sender/{VERSION}"

EXIT_OK = 0
EXIT_CONFIG = 1
EXIT_HTTP = 2
EXIT_TLS = 3
EXIT_STATE = 4
EXIT_LOCKED = 5

READ_CHUNK = 65536
RESP_READ_MAX = 65536
DETECTOR_DEFAULT_OUT = "evidence.jsonl"  # include/detect/config.h EvidenceConfig::out_path 기본값
DETECTOR_DEFAULT_MODE = "full"           # include/detect/config.h EvidenceConfig::mode 기본값


# ---------------------------------------------------------------- 로그 (19_ §7)
# 표준 오류에 한 줄씩 '시각 수준 사건 키=값 …'. 시각은 벽시계 UTC ISO 8601 — 탐지 엔진 log_err와 같은 모양

def _fmt_val(v):
    if v is None:
        return "none"
    if isinstance(v, bool):
        return "true" if v else "false"
    s = str(v)
    if s == "" or any(c.isspace() for c in s) or '"' in s or "=" in s:
        return json.dumps(s, ensure_ascii=False)
    return s


def log(level, event, **kv):
    now = datetime.datetime.now(datetime.timezone.utc)
    ts = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    parts = [ts, level, event] + [f"{k}={_fmt_val(v)}" for k, v in kv.items()]
    sys.stderr.write(" ".join(parts) + "\n")
    sys.stderr.flush()


def _head(b, n=200):
    return bytes(b[:n]).decode("utf-8", "backslashreplace")


# ---------------------------------------------------------------- 설정 (19_ §3)

class ConfigError(Exception):
    pass


DEFAULTS = {
    "url": "https://3.39.170.31/ingest",
    "ca_file": None,
    "env": "lab",
    "inputs": [{"path": "evidence.jsonl", "kind": "evidence"}],
    "state_path": "sender_state.json",
    "start_at": "beginning",
    "batch_interval_ms": 1000,
    "batch_max_lines": 500,
    "batch_max_bytes": 1048576,
    "line_max_bytes": 65536,
    "poll_ms": 200,
    "timeout_ms": 10000,
    "retry_initial_ms": 1000,
    "retry_max_ms": 60000,
    "stats_interval_ms": 60000,
    "kpm2_interval_ms": 0,
    "send_ue_evt": False,
}

# 정수 키의 허용 범위 — 19_ §3 표. retry_max_ms는 retry_initial_ms에 따라 정해져 아래에서 따로 본다
INT_RANGES = {
    "batch_interval_ms": (100, 60000),
    "batch_max_lines": (1, 5000),
    "batch_max_bytes": (1024, 1048576),
    "line_max_bytes": (1024, 65536),
    "poll_ms": (50, 5000),
    "timeout_ms": (1000, 120000),
    "retry_initial_ms": (100, 60000),
    "stats_interval_ms": (0, 3600000),
}

ENV_RE = re.compile(r"[a-z0-9-]{1,32}")


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def load_config(path):
    """설정 파일을 읽어 검사한다. 범위·타입이 틀리면 ConfigError(종료 코드 1), 모르는 키는 경고만 (19_ §3)."""
    try:
        with open(path, encoding="utf-8") as f:
            raw = json.load(f)
    except OSError as e:
        raise ConfigError(f"cannot read config {path}: {e.strerror}")
    except ValueError as e:
        raise ConfigError(f"config {path}: invalid JSON: {e}")
    if not isinstance(raw, dict):
        raise ConfigError("config: top level must be an object")

    warnings = []
    for k in raw:
        if k not in DEFAULTS:
            warnings.append(f"unknown key {k} (ignored)")
    cfg = {}

    def val(k):
        return raw[k] if k in raw else DEFAULTS[k]

    # 수집 주소 — https만 받는다 (17_ §1.4: 처음부터 HTTPS)
    url = val("url")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise ConfigError("url: must be a string starting with https://")
    u = urllib.parse.urlsplit(url)
    try:
        port = u.port or 443
    except ValueError:
        raise ConfigError(f"url: bad port in {url}")
    if not u.hostname:
        raise ConfigError(f"url: no host in {url}")
    if u.username or u.password:
        raise ConfigError("url: credentials in url are not allowed")
    cfg["url"] = url
    cfg["host"] = u.hostname
    cfg["port"] = port
    cfg["req_path"] = (u.path or "/") + (f"?{u.query}" if u.query else "")

    # 자체 서명 인증서 .pem — 있으면 그 인증서만 믿는다 (19_ §6 TLS, 17_ §1.4)
    ca = val("ca_file")
    if ca is not None:
        if not isinstance(ca, str) or not ca:
            raise ConfigError("ca_file: must be a non-empty string or null")
        ca = os.path.abspath(ca)
        if not os.path.isfile(ca) or not os.access(ca, os.R_OK):
            raise ConfigError(f"ca_file: cannot read {ca}")
    cfg["ca_file"] = ca

    env = val("env")
    if not isinstance(env, str) or not ENV_RE.fullmatch(env):
        raise ConfigError("env: must match [a-z0-9-]{1,32}")
    cfg["env"] = env

    # 따라 읽을 파일 — 지금은 kind evidence만. input(상시 KPM)은 다음 단계라 경고 후 건너뛴다 (19_ §8)
    inputs = val("inputs")
    if not isinstance(inputs, list) or not inputs:
        raise ConfigError("inputs: must be a non-empty array")
    ev_inputs = []
    seen = set()
    for i, it in enumerate(inputs):
        if not isinstance(it, dict):
            raise ConfigError(f"inputs[{i}]: must be an object")
        for k in it:
            if k not in ("path", "kind"):
                warnings.append(f"unknown key inputs[{i}].{k} (ignored)")
        p = it.get("path")
        kind = it.get("kind")
        if not isinstance(p, str) or not p:
            raise ConfigError(f"inputs[{i}].path: must be a non-empty string")
        if kind not in ("evidence", "input"):
            raise ConfigError(f"inputs[{i}].kind: must be evidence|input")
        if kind == "input":
            warnings.append(f"inputs[{i}] kind=input is a next-stage feature (19_ §8) — skipped")
            continue
        ap = os.path.abspath(p)
        if ap in seen:
            raise ConfigError(f"inputs[{i}].path: duplicate {ap}")
        seen.add(ap)
        ev_inputs.append({"path": p, "abspath": ap})
    if not ev_inputs:
        raise ConfigError("inputs: no kind=evidence entry")
    cfg["inputs"] = ev_inputs

    sp = val("state_path")
    if not isinstance(sp, str) or not sp:
        raise ConfigError("state_path: must be a non-empty string")
    sp = os.path.abspath(sp)
    sd = os.path.dirname(sp)
    if not os.path.isdir(sd) or not os.access(sd, os.W_OK | os.X_OK):
        raise ConfigError(f"state_path: directory not writable {sd}")
    cfg["state_path"] = sp

    sa = val("start_at")
    if sa not in ("beginning", "end"):
        raise ConfigError("start_at: must be beginning|end")
    cfg["start_at"] = sa

    for k, (lo, hi) in INT_RANGES.items():
        v = val(k)
        if not _is_int(v) or not lo <= v <= hi:
            raise ConfigError(f"{k}: must be an integer in {lo}..{hi}")
        cfg[k] = v
    v = val("retry_max_ms")
    if not _is_int(v) or not cfg["retry_initial_ms"] <= v <= 600000:
        raise ConfigError(f"retry_max_ms: must be an integer in retry_initial_ms({cfg['retry_initial_ms']})..600000")
    cfg["retry_max_ms"] = v

    # 상시 KPM 자리 — 지금은 0·false만. 다른 값이면 경고 후 끈다 (19_ §3·§8)
    v = val("kpm2_interval_ms")
    if not _is_int(v) or v < 0:
        raise ConfigError("kpm2_interval_ms: must be a non-negative integer")
    if v != 0:
        warnings.append(f"kpm2_interval_ms={v} is a next-stage feature (19_ §8) — using 0")
    cfg["kpm2_interval_ms"] = 0
    v = val("send_ue_evt")
    if not isinstance(v, bool):
        raise ConfigError("send_ue_evt: must be a boolean")
    if v:
        warnings.append("send_ue_evt=true is a next-stage feature (19_ §8) — using false")
    cfg["send_ue_evt"] = False
    return cfg, warnings


def make_tls_context(ca_file):
    """서버 인증서와 이름을 항상 검증한다. ca_file이 있으면 그 인증서만, 없으면 운영체제 기본 목록. TLS 1.2 이상 (19_ §6)."""
    try:
        ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    except (ssl.SSLError, OSError) as e:
        raise ConfigError(f"ca_file: cannot load {ca_file}: {e}")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# ---------------------------------------------------------------- 시작 전 경로 확인 (19_ §2.1)

def check_detector_config(cfg, det_cfg_path):
    """탐지 엔진 설정의 evidence.out_path와 전송기 입력 경로를 절대 경로로 비교한다. 같으면 0, 다르면 1.
    '-'면 탐지 엔진 기본값. evidence.mode가 off면 경고만 한다 (19_ §2.1 시작 전 확인 1~4)."""
    out_path, mode = DETECTOR_DEFAULT_OUT, DETECTOR_DEFAULT_MODE
    if det_cfg_path != "-":
        try:
            with open(det_cfg_path, encoding="utf-8") as f:
                raw = json.load(f)
        except OSError as e:
            log("ERROR", "check_paths", detail=f"cannot read detector config {det_cfg_path}: {e.strerror}")
            return EXIT_CONFIG
        except ValueError as e:
            log("ERROR", "check_paths", detail=f"detector config {det_cfg_path}: invalid JSON: {e}")
            return EXIT_CONFIG
        ev = raw.get("evidence", {}) if isinstance(raw, dict) else None
        if not isinstance(ev, dict):
            log("ERROR", "check_paths", detail=f"detector config {det_cfg_path}: evidence is not an object")
            return EXIT_CONFIG
        out_path = ev.get("out_path", out_path)
        mode = ev.get("mode", mode)
        if not isinstance(out_path, str) or not isinstance(mode, str):
            log("ERROR", "check_paths", detail=f"detector config {det_cfg_path}: evidence.out_path/mode not a string")
            return EXIT_CONFIG
    det_abs = os.path.realpath(os.path.abspath(out_path))
    snd = [os.path.realpath(i["abspath"]) for i in cfg["inputs"]]
    ok = det_abs in snd
    log("INFO" if ok else "ERROR", "check_paths",
        detector_config=det_cfg_path if det_cfg_path != "-" else "defaults",
        detector_out=det_abs, sender_inputs=",".join(snd), result="match" if ok else "mismatch")
    if not ok:
        return EXIT_CONFIG
    if mode == "off":
        log("WARN", "evidence_mode_off", detail="detector evidence.mode=off writes no evidence file — nothing to send")
    return EXIT_OK


# ---------------------------------------------------------------- 파일 읽기 (19_ §4·§5.2)

class Stop(BaseException):
    """SIGINT·SIGTERM — 진행 중인 요청은 버리고 끝낸다 (19_ §2.2)."""


class OnceTimeout(Exception):
    pass


class Fatal(Exception):
    def __init__(self, code, **kv):
        super().__init__(kv.get("reason", ""))
        self.code = code
        self.kv = kv


class Entry:
    """파일의 줄 하나. data가 None이면 보내지 않고 위치만 넘기는 줄(빈 줄·빼는 줄)."""
    __slots__ = ("start", "end", "data", "t")

    def __init__(self, start, end, data, t):
        self.start, self.end, self.data, self.t = start, end, data, t


class Batch:
    """한 파일의 연속된 줄 묶음 — 파일 위치 [start, end) (19_ §5.1)."""

    def __init__(self, entries):
        self.entries = entries
        self.start = entries[0].start
        self.end = entries[-1].end
        self.lines = [e.data for e in entries if e.data is not None]

    def body(self):
        return b"".join(line + b"\n" for line in self.lines)

    def split(self):
        # 413: 보낼 줄 기준으로 앞·뒤 반 — 파일 순서를 지키도록 앞부터 다시 보낸다 (19_ §6)
        half = len(self.lines) // 2
        seen = 0
        for k, e in enumerate(self.entries):
            if e.data is not None:
                if seen == half:
                    return Batch(self.entries[:k]), Batch(self.entries[k:])
                seen += 1
        raise AssertionError("split of a batch with fewer than 2 lines")


class Tracker:
    """따라 읽는 파일 하나 — 보낸 위치(acked)·읽은 위치(read_off)와 아직 안 보낸 완성된 줄(pending)."""

    def __init__(self, cfg, path, abspath):
        self.cfg = cfg
        self.path = path
        self.abspath = abspath
        self.fh = None
        self.dev = self.ino = None
        self.acked = 0
        self.read_off = 0
        self.buf = bytearray()
        self.buf_off = 0
        self.discard_from = None
        self.pending = collections.deque()
        self.pending_bytes = 0
        self.eof = False
        self.rotating = False
        self.rotate_new_ino = None
        self.wait_logged = False
        self.open_err_logged = False
        self.sent_lines = 0

    # --- 열기·위치

    def _attach(self, fh, st, off):
        self.fh = fh
        self.dev, self.ino = st.st_dev, st.st_ino
        self._reset(off)
        self.wait_logged = False
        self.open_err_logged = False

    def _reset(self, off):
        self.acked = self.read_off = self.buf_off = off
        self.buf = bytearray()
        self.discard_from = None
        self.pending.clear()
        self.pending_bytes = 0
        self.eof = False

    def _open(self):
        try:
            fh = open(self.abspath, "rb")
        except FileNotFoundError:
            if not self.wait_logged:
                log("INFO", "wait_file", file=self.path)
                self.wait_logged = True
            return None, None
        except OSError as e:
            if not self.open_err_logged:
                log("WARN", "open_failed", file=self.path, detail=e.strerror)
                self.open_err_logged = True
            return None, None
        return fh, os.fstat(fh.fileno())

    def start(self, entry):
        """처음 시작할 때 — 상태 파일에 같은 파일(dev, ino)의 위치가 있으면 그 자리, 없으면 start_at (19_ §4.2·§4.4)."""
        fh, st = self._open()
        if fh is None:
            return
        if entry and (entry["dev"], entry["ino"]) == (st.st_dev, st.st_ino):
            off = entry["offset"]
            if off > st.st_size:
                log("WARN", "truncate", file=self.path, old_off=off, size=st.st_size)
                off = 0
        elif entry:
            log("WARN", "rotate", file=self.path, old_ino=entry["ino"], new_ino=st.st_ino)
            off = 0
        elif self.cfg["start_at"] == "end":
            off = _last_newline_end(fh, st.st_size)
        else:
            off = 0
        self._attach(fh, st, off)
        log("INFO", "file_open", file=self.path, off=off, size=st.st_size)

    def check(self):
        """poll_ms마다 경로를 다시 stat — 교체·잘림·생김을 본다 (19_ §4.4)."""
        if self.rotating:
            return
        if self.fh is None:
            fh, st = self._open()
            if fh is not None:
                # 전송기가 뜬 뒤 생긴 파일은 모두 새 줄 — 처음부터
                self._attach(fh, st, 0)
                log("INFO", "file_open", file=self.path, off=0, size=st.st_size)
            return
        try:
            st = os.stat(self.abspath)
        except FileNotFoundError:
            st = None
        except OSError:
            return
        if st is None or (st.st_dev, st.st_ino) != (self.dev, self.ino):
            # 옮겨지고 새로 만들어짐(또는 아직 없음) — 옛 파일의 남은 완성된 줄을 열어 둔 핸들로 마저 보낸 뒤 새 파일로
            self.rotating = True
            self.rotate_new_ino = st.st_ino if st else None
        elif st.st_size < self.read_off:
            log("WARN", "truncate", file=self.path, old_off=self.read_off, size=st.st_size)
            self._reset(0)

    def drained(self):
        return self.rotating and self.eof and not self.pending

    def finish_rotate(self):
        dropped = len(self.buf)
        log("WARN", "rotate", file=self.path, old_ino=self.ino, new_ino=self.rotate_new_ino,
            dropped_partial_bytes=dropped)
        self.close()
        self.rotating = False
        self.dev = self.ino = None
        self._reset(0)

    def close(self):
        if self.fh is not None:
            self.fh.close()
            self.fh = None

    # --- 읽기

    def fill(self, want_entries, want_bytes):
        """pending이 묶음 하나를 넘길 만큼 될 때까지, 또는 파일 끝까지 읽는다. 실패가 이어지는 동안 파일이 버퍼다 (19_ §6)."""
        if self.fh is None:
            self.eof = True
            return
        self.eof = False
        while len(self.pending) < want_entries and self.pending_bytes < want_bytes:
            self.fh.seek(self.read_off)
            data = self.fh.read(READ_CHUNK)
            if not data:
                self.eof = True
                return
            self.read_off += len(data)
            self._consume(data)

    def _consume(self, data):
        """\\n으로 끝난 줄만 꺼낸다. 끝 조각은 완성될 때까지 둔다 — 탐지 엔진은 큐가 빌 때만 flush해
        파일에 줄의 앞부분만 보일 수 있다 (19_ §4.1, src/io/evidence_sink.cpp)."""
        lmax = self.cfg["line_max_bytes"]
        buf = self.buf
        buf += data
        n = len(buf)
        pos = 0
        now = time.monotonic()
        while pos < n:
            nl = buf.find(b"\n", pos)
            if self.discard_from is not None:
                # 64 KiB를 넘은 끝 조각 — 다음 \n까지 버린다 (19_ §5.2)
                if nl < 0:
                    pos = n
                    break
                self._add(Entry(self.discard_from, self.buf_off + nl + 1, None, now))
                self.discard_from = None
                pos = nl + 1
                continue
            if nl < 0:
                if n - pos > lmax:
                    start = self.buf_off + pos
                    log("ERROR", "skip_line", file=self.path, off=start, reason="no_newline", bytes=n - pos,
                        head=_head(buf[pos:]))
                    self.discard_from = start
                    pos = n
                break
            start, end = self.buf_off + pos, self.buf_off + nl + 1
            line = bytes(buf[pos:nl])
            pos = nl + 1
            # 보내기 전에 빼는 줄 (19_ §5.2): 빈 줄은 조용히, 64 KiB 초과·UTF-8 아님은 오류 로그. 둘 다 위치는 넘긴다
            if not line:
                self._add(Entry(start, end, None, now))
                continue
            if len(line) > lmax:
                log("ERROR", "skip_line", file=self.path, off=start, reason="too_long", bytes=len(line),
                    head=_head(line))
                self._add(Entry(start, end, None, now))
                continue
            try:
                line.decode("utf-8")
            except UnicodeDecodeError:
                log("ERROR", "skip_line", file=self.path, off=start, reason="not_utf8", bytes=len(line),
                    head=_head(line))
                self._add(Entry(start, end, None, now))
                continue
            self._add(Entry(start, end, line, now))
        del buf[:pos]
        self.buf_off += pos

    def _add(self, e):
        self.pending.append(e)
        if e.data is not None:
            self.pending_bytes += len(e.data) + 1

    # --- 묶기

    def take_batch(self, now, force):
        """묶음을 닫을 때가 됐으면 꺼내 준다 (19_ §5.1). 아니면 (None, 기다릴 초)."""
        if not self.pending:
            return None, None
        max_lines = self.cfg["batch_max_lines"]
        max_bytes = self.cfg["batch_max_bytes"]
        entries = []
        lines = nbytes = 0
        full = False
        for e in self.pending:
            if e.data is not None:
                size = len(e.data) + 1
                if lines and (lines >= max_lines or nbytes + size > max_bytes):
                    full = True
                    break
                lines += 1
                nbytes += size
            entries.append(e)
        if lines >= max_lines:
            full = True
        if lines:
            first_t = next(e.t for e in entries if e.data is not None)
            waited = now - first_t
            interval = self.cfg["batch_interval_ms"] / 1000.0
            if not (full or force or waited >= interval):
                return None, interval - waited
        # 빼는 줄만 있으면 바로 위치를 넘긴다
        for _ in entries:
            e = self.pending.popleft()
            if e.data is not None:
                self.pending_bytes -= len(e.data) + 1
        return Batch(entries), None


def _last_newline_end(fh, size):
    """start_at=end — 파일 끝의 마지막 완성된 줄 뒤. 끝 조각은 완성되면 보낸다."""
    pos = size
    while pos > 0:
        step = min(READ_CHUNK, pos)
        pos -= step
        fh.seek(pos)
        chunk = fh.read(step)
        i = chunk.rfind(b"\n")
        if i >= 0:
            return pos + i + 1
    return 0


# ---------------------------------------------------------------- 전송기 본체 (19_ §4.3·§5·§6)

class Sender:
    def __init__(self, cfg, mode, once_timeout_s=60.0):
        self.cfg = cfg
        self.mode = mode  # run | once | dry_run
        self.once_timeout_s = once_timeout_s
        self.trackers = [Tracker(cfg, i["path"], i["abspath"]) for i in cfg["inputs"]]
        self.ctx = None
        self.state_files = {}
        self.fails = 0
        self.fail_since = None
        self.long_fail_warned = False
        self.deadline = None
        self.critical = 0
        self.stop_signal = None
        self.lock_fd = None
        si = cfg["stats_interval_ms"]
        self.next_stats = time.monotonic() + si / 1000.0 if si > 0 else None

    # --- 신호: 요청 중이면 버리고 끝낸다. 상태 파일을 쓰는 중에는 다 쓴 뒤에 끝낸다 (19_ §2.2)

    def _on_signal(self, signum, frame):
        self.stop_signal = signum
        if self.critical == 0:
            raise Stop()

    @contextlib.contextmanager
    def _critical(self):
        self.critical += 1
        try:
            yield
        finally:
            self.critical -= 1
        if self.stop_signal is not None and self.critical == 0:
            raise Stop()

    def _install_signals(self):
        signal.signal(signal.SIGTERM, self._on_signal)
        # 실행 스크립트가 백그라운드로 띄우면 SIGINT가 무시 상태로 온다 — 그때는 그대로 둔다 (스크립트가 SIGTERM으로 멈춤)
        if signal.getsignal(signal.SIGINT) is not signal.SIG_IGN:
            signal.signal(signal.SIGINT, self._on_signal)

    # --- 잠금·상태 파일 (19_ §4.3)

    def _lock(self):
        # 한 state_path에는 전송기 하나만 — 둘이 보낸 위치를 함께 쓰면 줄이 빠지거나 많이 겹친다
        path = self.cfg["state_path"] + ".lock"
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
        except OSError as e:
            raise Fatal(EXIT_CONFIG, reason="lock_open", lock=path, detail=e.strerror)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise Fatal(EXIT_LOCKED, reason="locked", lock=path)
        self.lock_fd = fd

    def _load_state(self):
        path = self.cfg["state_path"]
        try:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
        except FileNotFoundError:
            return
        except (OSError, ValueError) as e:
            # 원자 저장이라 깨질 일은 드물다. 깨졌으면 start_at대로 시작 — 다시 가는 줄은 대시보드가 거른다
            log("WARN", "state_unreadable", state=path, detail=str(e))
            return
        files = raw.get("files") if isinstance(raw, dict) and raw.get("ver") == 1 else None
        if not isinstance(files, dict):
            log("WARN", "state_unreadable", state=path, detail="not a ver 1 state file")
            return
        for k, v in files.items():
            if (isinstance(v, dict) and all(_is_int(v.get(x)) for x in ("dev", "ino", "offset"))
                    and v["offset"] >= 0):
                self.state_files[k] = v
            else:
                log("WARN", "state_entry_ignored", state=path, file=k)

    def _save_state(self):
        # 임시 파일에 쓰고 rename — 반쯤 쓴 상태 파일이 남지 않게. 실패하면 종료 코드 4
        path = self.cfg["state_path"]
        tmp = path + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"ver": 1, "files": self.state_files}, f, ensure_ascii=False)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except OSError as e:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise Fatal(EXIT_STATE, reason="state_save", state=path, detail=e.strerror or str(e))

    def _commit(self, tr, b):
        """200·400을 받은 뒤(또는 보내지 않는 줄만) 보낸 위치를 넘기고 저장한다 (19_ §4.3)."""
        if self.mode == "dry_run":
            tr.acked = b.end
            return
        with self._critical():
            entry = {"dev": tr.dev, "ino": tr.ino, "offset": b.end, "saved_ms": int(time.time() * 1000)}
            prev = self.state_files.get(tr.abspath)
            self.state_files[tr.abspath] = entry
            try:
                self._save_state()
            except Fatal:
                if prev is None:
                    self.state_files.pop(tr.abspath, None)
                else:
                    self.state_files[tr.abspath] = prev
                raise
            tr.acked = b.end
        tr.sent_lines += len(b.lines)

    # --- 기다림·마감

    def _check_deadline(self):
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise OnceTimeout()

    def _sleep(self, sec):
        if self.deadline is not None:
            sec = min(sec, max(0.0, self.deadline - time.monotonic()))
        if sec > 0:
            time.sleep(sec)
        self._check_deadline()

    def _stats_tick(self):
        # stats_interval_ms마다 — lag_bytes = 파일 크기 − 보낸 위치 (19_ §7)
        if self.next_stats is None:
            return
        now = time.monotonic()
        if now < self.next_stats:
            return
        self.next_stats = now + self.cfg["stats_interval_ms"] / 1000.0
        for t in self.trackers:
            try:
                size = os.stat(t.abspath).st_size if not t.rotating else None
            except OSError:
                size = None
            lag = max(0, size - t.acked) if size is not None and t.fh is not None else None
            log("INFO", "stats", file=t.path, lag_bytes=lag, sent_lines=t.sent_lines, fails=self.fails)

    # --- 보내기 (19_ §6)

    def _post(self, body):
        """요청 하나. (상태 코드, 응답 본문, None) 또는 연결 쪽 실패면 (None, None, 사유)."""
        timeout = self.cfg["timeout_ms"] / 1000.0
        if self.deadline is not None:
            timeout = max(0.1, min(timeout, self.deadline - time.monotonic()))
        conn = http.client.HTTPSConnection(self.cfg["host"], self.cfg["port"], timeout=timeout, context=self.ctx)
        try:
            # 리다이렉트는 따라가지 않는다(http.client는 따라가지 않음). Authorization은 보내지 않는다
            conn.request("POST", self.cfg["req_path"], body=body, headers={
                "Content-Type": "application/x-ndjson",
                "X-Env": self.cfg["env"],
                "User-Agent": USER_AGENT,
            })
            resp = conn.getresponse()
            data = resp.read(RESP_READ_MAX)
            return resp.status, data, None
        except ssl.SSLCertVerificationError as e:
            raise Fatal(EXIT_TLS, reason="tls", detail=getattr(e, "verify_message", None) or str(e))
        except ssl.SSLError:
            return None, None, "tls_error"
        except ConnectionRefusedError:
            return None, None, "conn_refused"
        except TimeoutError:
            return None, None, "timeout"
        except http.client.RemoteDisconnected:
            return None, None, "remote_closed"
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
            return None, None, "conn_reset"
        except http.client.HTTPException:
            return None, None, "http_error"
        except OSError as e:
            return None, None, f"conn_error_{e.errno}" if e.errno else "conn_error"
        finally:
            conn.close()

    def _send_with_retry(self, tr, b):
        """200·400·413을 받을 때까지 같은 묶음을 다시 보낸다 — 5xx·연결 실패는 간격을 두 배씩 늘린다 (19_ §6)."""
        body = b.body()
        wait_ms = self.cfg["retry_initial_ms"]
        long_ms = self.cfg["stats_interval_ms"] or 60000
        while True:
            self._check_deadline()
            t0 = time.monotonic()
            status, data, reason = self._post(body)
            ms = int((time.monotonic() - t0) * 1000)
            if status is not None:
                if status in (200, 400, 413):
                    self.fails = 0
                    self.fail_since = None
                    self.long_fail_warned = False
                    return status, data, ms, len(body)
                if not 500 <= status <= 599:
                    # 약속에 없는 응답(401·403·404·그 밖의 4xx·3xx) — 주소·권한·보안 그룹 설정 문제로 보고 멈춘다
                    raise Fatal(EXIT_HTTP, reason=f"http_{status}", status=status, body=_head(data or b""))
                reason = str(status)
            self.fails += 1
            if self.fail_since is None:
                self.fail_since = t0
            log("WARN", "retry", file=tr.path, off=f"{b.start}-{b.end}", reason=reason, wait_ms=wait_ms,
                fails=self.fails)
            # 보안 그룹이 막으면 응답 없이 시간 초과가 된다 — 오래 이어지면 허용 IP를 확인하라고 한 번 알린다
            if not self.long_fail_warned and (time.monotonic() - self.fail_since) * 1000 >= long_ms:
                log("WARN", "retry_long", file=tr.path, fails=self.fails,
                    hint="check dashboard security group allowed IP")
                self.long_fail_warned = True
            self._stats_tick()
            self._sleep(wait_ms / 1000.0)
            wait_ms = min(wait_ms * 2, self.cfg["retry_max_ms"])

    def send_batch(self, tr, batch):
        todo = [batch]
        while todo:
            b = todo.pop(0)
            if not b.lines:
                self._commit(tr, b)
                continue
            if self.mode == "dry_run":
                log("INFO", "dry_run", file=tr.path, off=f"{b.start}-{b.end}", lines=len(b.lines),
                    bytes=len(b.body()))
                self._commit(tr, b)
                continue
            status, data, ms, nbytes = self._send_with_retry(tr, b)
            off = f"{b.start}-{b.end}"
            if status == 200:
                # 본문을 읽지 못해도 200이면 성공 (19_ §6)
                try:
                    j = json.loads(data)
                    acc, rej, dup = j.get("accepted"), j.get("rejected"), j.get("duplicates")
                except (ValueError, AttributeError):
                    acc = rej = dup = None
                log("INFO", "send", file=tr.path, off=off, lines=len(b.lines), bytes=nbytes, status=200,
                    accepted=acc, rejected=rej, duplicates=dup, ms=ms)
                if _is_int(rej) and rej > 0:
                    log("WARN", "rejected", file=tr.path, off=off, rejected=rej)
                self._commit(tr, b)
            elif status == 400:
                # 묶음 전체를 읽을 수 없음 — 다시 보내지 않고 넘긴다
                try:
                    err = json.loads(data).get("error")
                except (ValueError, AttributeError):
                    err = _head(data or b"")
                log("ERROR", "send", file=tr.path, off=off, lines=len(b.lines), bytes=nbytes, status=400,
                    error=err, ms=ms)
                self._commit(tr, b)
            else:  # 413
                if len(b.lines) > 1:
                    front, back = b.split()
                    log("INFO", "split", file=tr.path, off=off,
                        lines=f"{len(b.lines)}→{len(front.lines)}+{len(back.lines)}")
                    todo[0:0] = [front, back]
                else:
                    log("ERROR", "skip_line", file=tr.path, off=b.start, reason="http_413", bytes=nbytes - 1,
                        head=_head(b.lines[0]))
                    self._commit(tr, b)

    # --- 돌기

    def _want(self):
        return self.cfg["batch_max_lines"] + 1, self.cfg["batch_max_bytes"] + 1

    def _run_forever(self):
        poll = self.cfg["poll_ms"] / 1000.0
        we, wb = self._want()
        while True:
            sent = False
            sleep = poll
            for t in self.trackers:
                t.check()
                t.fill(we, wb)
                b, wait = t.take_batch(time.monotonic(), force=t.rotating)
                if b is not None:
                    self.send_batch(t, b)
                    sent = True
                    continue
                if wait is not None:
                    sleep = min(sleep, wait)
                if t.drained():
                    t.finish_rotate()
                    sent = True  # 새 파일을 바로 연다
            self._stats_tick()
            if not sent:
                self._sleep(max(0.0, sleep))

    def _run_once(self):
        # 지금 있는 완성된 줄을 다 보내고 끝낸다. 시간 제한은 다시 보내기까지 포함 (19_ §2.2)
        we, wb = self._want()
        for t in self.trackers:
            while True:
                self._check_deadline()
                t.fill(we, wb)
                b, _ = t.take_batch(time.monotonic(), force=True)
                if b is None:
                    if t.eof:
                        break
                    continue
                self.send_batch(t, b)

    def run(self):
        try:
            try:
                self._install_signals()
                if self.mode != "dry_run":
                    self._lock()
                self.ctx = make_tls_context(self.cfg["ca_file"])
                self._load_state()
                log("INFO", "start", url=self.cfg["url"], env=self.cfg["env"], inputs=len(self.trackers),
                    ca_file=self.cfg["ca_file"], start_at=self.cfg["start_at"], mode=self.mode, pid=os.getpid())
                if self.mode == "once":
                    self.deadline = time.monotonic() + self.once_timeout_s
                for t in self.trackers:
                    t.start(self.state_files.get(t.abspath))
                if self.mode == "run":
                    self._run_forever()
                else:
                    self._run_once()
                log("INFO", "exit", code=EXIT_OK, reason="done")
                return EXIT_OK
            except Stop:
                log("INFO", "exit", code=EXIT_OK, reason="signal", sig=self.stop_signal)
                return EXIT_OK
            except OnceTimeout:
                log("WARN", "once_timeout", timeout_s=self.once_timeout_s,
                    detail="unsent lines remain — next run continues from the saved position")
                return EXIT_OK
            except ConfigError as e:
                log("ERROR", "config_error", detail=str(e))
                return EXIT_CONFIG
            except Fatal as f:
                log("ERROR", "stop", **f.kv)
                return f.code
        finally:
            self.critical += 1  # 정리 중에는 신호로 끊지 않는다
            for t in self.trackers:
                t.close()
            if self.lock_fd is not None:
                os.close(self.lock_fd)
                self.lock_fd = None


# ---------------------------------------------------------------- 명령줄

class _ArgParser(argparse.ArgumentParser):
    def error(self, message):
        # 사용법 오류도 설정 오류(1)로 — 종료 코드 2는 '약속에 없는 응답'이다 (19_ §7)
        self.print_usage(sys.stderr)
        log("ERROR", "config_error", detail=message)
        sys.exit(EXIT_CONFIG)


def main(argv=None):
    ap = _ArgParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", required=True, help="전송기 설정 파일 (config/sender.json)")
    ap.add_argument("--once", action="store_true", help="지금 있는 완성된 줄을 다 보내고 끝냄")
    ap.add_argument("--once-timeout-s", type=float, default=60.0, help="--once 시간 제한(초, 기본 60)")
    ap.add_argument("--dry-run", action="store_true", help="보내지 않고 묶음만 로그에 — 상태 파일을 바꾸지 않음")
    ap.add_argument("--check-detector-config", metavar="FILE",
                    help="탐지 엔진 설정의 evidence.out_path가 전송기 입력과 같은지만 확인 ('-'면 탐지 엔진 기본값)")
    a = ap.parse_args(argv)
    if sys.version_info < (3, 10):
        log("ERROR", "config_error", detail="python 3.10 or newer is required")
        return EXIT_CONFIG
    if a.once and a.dry_run:
        ap.error("--once and --dry-run cannot be used together")
    if a.once_timeout_s < 0:
        ap.error("--once-timeout-s must be >= 0")
    try:
        cfg, warnings = load_config(a.config)
    except ConfigError as e:
        log("ERROR", "config_error", detail=str(e))
        return EXIT_CONFIG
    for w in warnings:
        log("WARN", "config_warning", detail=w)
    if a.check_detector_config is not None:
        return check_detector_config(cfg, a.check_detector_config)
    mode = "once" if a.once else "dry_run" if a.dry_run else "run"
    return Sender(cfg, mode, a.once_timeout_s).run()


if __name__ == "__main__":
    sys.exit(main())
