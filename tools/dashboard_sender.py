#!/usr/bin/env python3
"""전송기 — 탐지 엔진 증거 파일(evidence.jsonl)의 새 줄을 대시보드 /ingest로 보낸다 (19_ 전송기 명세서).
상시 KPM (24_ §4·§5): inputs에 kind input(탐지 엔진 입력 기록 input.jsonl)이 있으면 그 파일도 따라 읽어 hello·f1_evt·ue_evt는
줄 그대로(hello는 node_id만 hello_node_id로 — 11/13 이슈 #110), kpm2는 셀마다 kpm2_interval_ms(기본 3초)로 묶은 줄만 보낸다
— 0.1초 원본 kpm2는 보내지 않는다.

실행 (19_ §2.2):
  python3 tools/dashboard_sender.py --config config/sender.json            # 계속 따라 읽으며 보냄
  python3 tools/dashboard_sender.py --config config/sender.json --once     # 지금 있는 완성된 줄만 보내고 끝냄
  python3 tools/dashboard_sender.py --config config/sender.json --dry-run  # 보내지 않고 묶음만 로그에
  python3 tools/dashboard_sender.py --config config/sender.json --check-detector-config config/detector.json

- 줄의 내용을 바꾸지 않는다. 환경 이름은 헤더 X-Env로 붙이고 토큰은 쓰지 않는다 (19_ §1, 17_ §1.3).
  환경 이름은 aws·on-premise 둘뿐이다 (19_ §3, 11/20 이슈 #119).
  예외는 상시 경로의 묶은 kpm2 줄과 hello의 node_id뿐이다 (24_ §4.2).
- 보낸 위치는 200·400을 받은 뒤에만 상태 파일에 저장한다 — '최소 한 번' (19_ §4.3, 17_ §1.5).
- 종료 코드: 0 정상, 1 설정 오류, 2 약속에 없는 응답, 3 TLS 검증 실패, 4 상태 파일 저장 실패, 5 잠금 실패 (19_ §7).
- 탐지 엔진이 파일을 회전하면(29_ §2) 회전 파일(<파일>.<YYYYMMDD-HHMMSS>[.N])을 이름 시각 순으로 빠짐없이 따라간다 —
  다시 떴을 때(19_ §4.5)도, 떠 있는 동안 밀렸을 때(19_ §4.4)도 (11/08 이슈 #102).
- Python 3.10 이상, 표준 라이브러리만 쓴다.
"""

import argparse
import collections
import contextlib
import datetime
import fcntl
import http.client
import json
import math
import os
import re
import signal
import ssl
import stat
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
    "env": "on-premise",        # 헤더 X-Env — aws·on-premise 둘뿐, 기본은 온프레미스 (19_ §3, 11/20 이슈 #119)
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
    "kpm2_interval_ms": 3000,   # 상시 KPM 묶음 주기 — 기본 3초 (24_ §4.1, 11/04 사용자 결정)
    "send_ue_evt": False,
    "kpm2_close_lag_ms": 2000,  # 다른 셀 줄로 칸을 닫을 때의 데이터 시각 여유 (24_ §5.3 ②)
    "hello_node_id": "cu",      # 대시보드로 보내는 hello의 node_id — null이면 바이트 그대로 (24_ §4.2, 11/13 사용자 결정)
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
    "kpm2_close_lag_ms": (100, 60000),  # 24_ §4.1
}

# 헤더 X-Env 값 (19_ §3, 11/20 사용자 결정 — 이슈 #119): 환경 이름을 AWS 테스트베드는 aws, 연구실(온프레미스)은
# on-premise 두 가지로 고정한다. 그 전에는 형식만 보고(이슈 #104 — 첫 글자 영숫자) p4·lab·p5·sample 등 무엇이든 받아
# 같은 환경이 여러 이름으로 대시보드에 갔다. 그 밖의 값은 시작할 때 설정 오류로 막는다 — 두 값 모두 대시보드 형식
# ('영숫자로 시작, 영숫자·._- 64자 이하', 어기면 400 — 19_ §6)을 지킨다.
ENV_VALUES = ("aws", "on-premise")


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
    if not isinstance(env, str) or env not in ENV_VALUES:
        raise ConfigError("env: must be one of " + ", ".join(ENV_VALUES))
    cfg["env"] = env

    # 따라 읽을 파일 — evidence 1개 이상(반드시) + input 0~1개. input 항목이 있으면 상시 KPM이 켜진다 (24_ §4.1)
    inputs = val("inputs")
    if not isinstance(inputs, list) or not inputs:
        raise ConfigError("inputs: must be a non-empty array")
    ev_inputs = []
    in_inputs = []
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
        ap = os.path.abspath(p)
        if ap in seen:
            raise ConfigError(f"inputs[{i}].path: duplicate {ap}")
        seen.add(ap)
        (in_inputs if kind == "input" else ev_inputs).append({"path": p, "abspath": ap, "kind": kind})
    if not ev_inputs:
        raise ConfigError("inputs: no kind=evidence entry")
    if len(in_inputs) > 1:
        raise ConfigError("inputs: at most one kind=input entry (24_ §4.1)")

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
    # 설정 교차 제약 (19_ §3 — 11/05 25_ W-31, 이슈 #92): 한 줄짜리 묶음이 본문 상한을 넘기지 않게
    if cfg["batch_max_bytes"] < cfg["line_max_bytes"] + 1:
        raise ConfigError(f"batch_max_bytes: must be >= line_max_bytes + 1 ({cfg['line_max_bytes'] + 1})")

    # 상시 KPM (24_ §4.1): 묶음 주기는 0(kpm2 안 보냄) 또는 1,000의 배수 — 0.1초 원본 그대로 보내는 값은 없다(11/04).
    # 1,000의 배수면 분석 엔진이 쓸 수 있는 주기(1000을 나누는 값, 22_ §2)가 모두 N을 나눈다. 값은 input 항목이 없어도 검사한다
    v = val("kpm2_interval_ms")
    if not _is_int(v) or not (v == 0 or (1000 <= v <= 600000 and v % 1000 == 0)):
        raise ConfigError("kpm2_interval_ms: must be 0 or a multiple of 1000 in 1000..600000")
    cfg["kpm2_interval_ms"] = v
    v = val("send_ue_evt")
    if not isinstance(v, bool):
        raise ConfigError("send_ue_evt: must be a boolean")
    cfg["send_ue_evt"] = v
    # hello의 node_id (24_ §4.1·§4.2, 11/13 이슈 #110): 밖으로 나가는 node_id를 분석 엔진이 넣은 값과 관계없이 한 값으로 맞춘다.
    # 빈 문자열은 받지 않는다 — '이름 없음'을 뜻하려면 null(바이트 그대로)을 쓴다
    v = val("hello_node_id")
    if v is not None and (not isinstance(v, str) or not v):
        raise ConfigError("hello_node_id: must be a non-empty string or null")
    cfg["hello_node_id"] = v
    # 켜고 끄기 = input 항목 (24_ §4.1): 없으면 위 두 값은 쓰이지 않는다. 있는데 보낼 것이 없으면 경고하고 따라 읽지 않는다
    if in_inputs and cfg["kpm2_interval_ms"] == 0 and not cfg["send_ue_evt"]:
        warnings.append("inputs: kind=input entry ignored — kpm2_interval_ms is 0 and send_ue_evt is false (24_ §4.1)")
        in_inputs = []
    # evidence를 앞에 — 파일을 번갈아 보내므로 입력이 밀려 있어도 경보 묶음은 입력 묶음 하나 이상 기다리지 않는다 (24_ §4.2)
    cfg["inputs"] = ev_inputs + in_inputs
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
    '-'면 탐지 엔진 기본값. evidence.mode가 off면 경고만 한다 (19_ §2.1 시작 전 확인 1~4).
    전송기에 kind input 항목이 있으면 탐지 엔진 input_record.path도 같아야 한다 — null이거나 다르면 1. 전송기에 input 항목이
    없는데 탐지 엔진이 기록하면 경고만 (24_ §7 표)."""
    out_path, mode = DETECTOR_DEFAULT_OUT, DETECTOR_DEFAULT_MODE
    rec_path = None  # include/detect/config.h InputRecordConfig::path 기본값 — 끔
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
        ir = raw.get("input_record", {})
        if not isinstance(ir, dict) or not (ir.get("path") is None or isinstance(ir.get("path"), str)):
            log("ERROR", "check_paths", detail=f"detector config {det_cfg_path}: input_record.path not a string or null")
            return EXIT_CONFIG
        rec_path = ir.get("path")
    det_name = det_cfg_path if det_cfg_path != "-" else "defaults"
    det_abs = os.path.realpath(os.path.abspath(out_path))
    snd = [os.path.realpath(i["abspath"]) for i in cfg["inputs"] if i["kind"] == "evidence"]
    ok = det_abs in snd
    log("INFO" if ok else "ERROR", "check_paths", detector_config=det_name,
        detector_out=det_abs, sender_inputs=",".join(snd), result="match" if ok else "mismatch")
    if not ok:
        return EXIT_CONFIG
    # 입력 기록 파일 (24_ §7): 전송기가 따라 읽는 input 파일 = 탐지 엔진이 쓰는 기록 파일
    snd_in = [os.path.realpath(i["abspath"]) for i in cfg["inputs"] if i["kind"] == "input"]
    if snd_in:
        if rec_path is None:
            log("ERROR", "check_input_path", detector_config=det_name, detector_input_record="null",
                sender_input=snd_in[0], result="not_recording",
                detail="detector does not record input (input_record.path is null)")
            return EXIT_CONFIG
        det_in = os.path.realpath(os.path.abspath(rec_path))
        ok = det_in == snd_in[0]
        log("INFO" if ok else "ERROR", "check_input_path", detector_config=det_name, detector_input_record=det_in,
            sender_input=snd_in[0], result="match" if ok else "mismatch")
        if not ok:
            return EXIT_CONFIG
    elif rec_path is not None:
        log("WARN", "input_not_sent", detector_input_record=os.path.realpath(os.path.abspath(rec_path)),
            detail="detector records input but the sender has no kind=input entry")
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
    """파일의 줄 하나. data가 None이면 보내지 않고 위치만 넘기는 줄(빈 줄·빼는 줄).
    safe = 이 줄까지 대시보드가 받으면 저장해도 되는 위치 — evidence는 end. input은 열린 칸의 첫 줄 앞을 넘지 않는다(24_ §4.3).
    key = 묶은 kpm2 줄이면 그 칸 (session, cell, t_start) — 받은 뒤 '보낸 칸'으로 남긴다."""
    __slots__ = ("start", "end", "data", "t", "safe", "key")

    def __init__(self, start, end, data, t, key=None):
        self.start, self.end, self.data, self.t = start, end, data, t
        self.safe = end
        self.key = key


class Batch:
    """한 파일의 연속된 줄 묶음 — 파일 위치 [start, end) (19_ §5.1). safe는 받으면 저장할 위치(마지막 줄의 safe)."""

    def __init__(self, entries):
        self.entries = entries
        self.start = entries[0].start
        self.end = entries[-1].end
        self.safe = entries[-1].safe
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


# ---------------------------------------------------------------- 회전 파일 (19_ §4.5, 29_ §2.3 — 11/08 이슈 #102)
# 탐지 엔진이 회전한 파일 이름은 <기준 파일 이름>.<YYYYMMDD-HHMMSS>[.N]이다. 시각은 회전한 때(UTC)이고, 같은 시각이면 N 순(없는
# 것이 먼저) — 이 순서가 쓰인 순서다. 규칙 밖 이름(evidence.jsonl.old 등)은 회전 파일로 보지 않는다. 손으로 옮긴 파일을
# 다시 보내지 않게 하려는 것이다 (19_ §4.5 ①). 정리 도구(tools/prune_outputs.py)도 같은 규칙을 쓴다

class RotFile:
    """같은 폴더의 회전 파일 하나 — key는 정렬 키 (시각 문자열, N), ms는 이름 시각(UTC, ms)."""
    __slots__ = ("key", "path", "dev", "ino", "ms")

    def __init__(self, key, path, dev, ino, ms):
        self.key, self.path, self.dev, self.ino, self.ms = key, path, dev, ino, ms


def rotated_files(abspath):
    """기준 경로의 회전 파일을 이름 시각 순으로. 폴더를 읽지 못하면 빈 목록."""
    d, base = os.path.split(abspath)
    rx = re.compile(re.escape(base) + r"\.(\d{8}-\d{6})(?:\.(\d{1,2}))?")
    try:
        names = os.listdir(d or ".")
    except OSError:
        return []
    out = []
    for n in names:
        m = rx.fullmatch(n)
        if m is None:
            continue
        try:
            t = datetime.datetime.strptime(m.group(1), "%Y%m%d-%H%M%S").replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
        path = os.path.join(d, n)
        try:
            st = os.stat(path)
        except OSError:
            continue  # 그사이 지워짐
        if not stat.S_ISREG(st.st_mode):
            continue
        out.append(RotFile((m.group(1), int(m.group(2) or 0)), path, st.st_dev, st.st_ino, int(t.timestamp() * 1000)))
    out.sort(key=lambda r: r.key)
    return out


def _rot_index(rot, dev, ino):
    """회전 파일 목록에서 (dev, ino)가 같은 파일의 자리. 없으면 None."""
    for i, r in enumerate(rot):
        if (r.dev, r.ino) == (dev, ino):
            return i
    return None


class Tracker:
    """따라 읽는 파일 하나 — 보낸 위치(acked)·읽은 위치(read_off)와 아직 안 보낸 완성된 줄(pending).
    kind evidence는 줄을 바꾸지 않고 그대로 보낸다. kind input은 InputTracker가 줄마다 고르고 kpm2를 묶는다(24_ §4)."""
    is_input = False
    agg = None

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

    def _open_file(self, path):
        """회전 파일 하나를 연다 — 목록을 만든 뒤 정리 도구가 지웠을 수 있다 (19_ §4.5 ⑧)."""
        try:
            fh = open(path, "rb")
        except OSError as e:
            log("WARN", "open_failed", file=self.path, path=os.path.basename(path), detail=e.strerror)
            return None, None
        return fh, os.fstat(fh.fileno())

    def _open_rotated(self, files, first_off):
        """회전 파일 목록의 앞에서부터 열리는 첫 파일을 연다 — 첫 파일은 first_off부터, 그 뒤 파일은 처음부터.
        다 쓴 파일이므로 rotating으로 둔다 — 끝까지 보내면 finish_rotate()가 다음 파일로 넘어간다 (19_ §4.5 ②·⑤).
        (연 파일, 위치, 남은 회전 파일 수) 또는 None."""
        for i, r in enumerate(files):
            fh, st = self._open_file(r.path)
            if fh is None:
                continue
            off = first_off if i == 0 else 0
            if off > st.st_size:
                log("WARN", "truncate", file=self.path, path=os.path.basename(r.path), old_off=off, size=st.st_size)
                off = 0
            self._attach(fh, st, off)
            self.rotating = True
            self.rotate_new_ino = None
            return r, off, len(files) - i
        return None

    def _catchup(self, entry):
        """멈춘 동안 회전됨 — 상태 파일의 파일을 회전 파일에서 찾으면 그 저장 위치부터, 못 찾으면(손으로 지우거나 옮김)
        saved_ms와 같거나 뒤 시각에 회전된 파일부터 처음부터 보낸다. 지금 파일은 그 뒤에 (19_ §4.5 ②·③, I-01 Q7).
        보낼 회전 파일이 없으면 False — 지금처럼 지금 파일을 처음부터."""
        rot = rotated_files(self.abspath)
        i = _rot_index(rot, entry["dev"], entry["ino"])
        if i is not None:
            got = self._open_rotated(rot[i:], entry["offset"])
        else:
            sm = entry.get("saved_ms")
            files = [r for r in rot if _is_int(sm) and r.ms >= sm]
            got = self._open_rotated(files, 0) if files else None
        if got is None:
            return False
        r, off, n = got
        src = {"from": os.path.basename(r.path)}
        if i is not None:
            log("INFO", "catchup", file=self.path, **src, off=off, files=n)
        else:
            log("WARN", "catchup", file=self.path, found="no", saved_ms=entry.get("saved_ms"), **src, files=n)
        return True

    def start(self, entry):
        """처음 시작할 때 — 상태 파일에 같은 파일(dev, ino)의 위치가 있으면 그 자리, 없으면 start_at (19_ §4.2·§4.4).
        항목은 있는데 지금 파일과 다르면 멈춘 동안 회전된 것 — 회전 파일의 남은 줄부터 이어 보낸다 (19_ §4.5, 11/08 이슈 #102).
        그전에는 지금 파일을 처음부터 읽어 옛 파일의 꼬리와 가운데 파일을 잃었다(I-01 P5)."""
        fh, st = self._open()
        if entry and fh is not None and (entry["dev"], entry["ino"]) == (st.st_dev, st.st_ino):
            off = entry["offset"]
            if off > st.st_size:
                log("WARN", "truncate", file=self.path, old_off=off, size=st.st_size)
                off = 0
        elif entry:
            if self._catchup(entry):
                if fh is not None:
                    fh.close()
                return
            if fh is None:
                return
            log("WARN", "rotate", file=self.path, old_ino=entry["ino"], new_ino=st.st_ino)
            off = 0
        elif fh is None:
            return
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

    def at_rotated_eof(self):
        """다 쓴 파일의 끝 — 다음 파일로 넘어가기 전. evidence는 할 일 없음 (InputTracker가 바꾼다, 24_ §4.3)."""
        self.flush_open()

    def _before_switch(self, found):
        """다음 파일로 넘어가기 직전 — found는 옛 파일을 회전 파일에서 찾았는지 (InputTracker가 바꾼다, 24_ §4.3)."""

    def finish_rotate(self):
        """옛 파일을 끝까지 보냄 — 다음 파일로 (19_ §4.4·§4.5, 11/08 이슈 #102). 다음 파일은 옛 파일보다 이름 시각이 뒤인
        회전 파일 가운데 가장 이른 것이고, 없으면 지금 경로의 파일이다(다음 check()가 연다). 넘어갈 때마다 다시 찾으므로
        옛 파일을 보내는 사이 회전이 또 일어나도 가운데 파일을 건너뛰지 않는다 — 그전에는 지금 경로의 파일로 바로 넘어가
        건너뛰었다(I-01 P8). 옛 파일을 회전 파일에서 찾지 못하면(규칙 밖 이름으로 옮김) 지금처럼 지금 경로의 파일로."""
        dropped = len(self.buf)
        old_ino = self.ino
        rot = rotated_files(self.abspath)
        i = _rot_index(rot, self.dev, self.ino)
        self._before_switch(i is not None)
        self.close()
        self.rotating = False
        self.dev = self.ino = None
        self._reset(0)
        got = self._open_rotated(rot[i + 1:], 0) if i is not None else None
        if got is not None:
            nxt, new_ino = os.path.basename(got[0].path), got[0].ino
        else:
            nxt, new_ino = os.path.basename(self.abspath), self.rotate_new_ino
        log("WARN", "rotate", file=self.path, old_ino=old_ino, new_ino=new_ino, next=nxt,
            dropped_partial_bytes=dropped)

    def save_pos(self, safe):
        """받은 묶음 뒤 상태 파일에 남길 (dev, ino, 위치) — 지금 읽는 파일의 safe (19_ §4.3). InputTracker가 바꾼다."""
        return self.dev, self.ino, safe

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
            self._line(start, end, line, now)
        del buf[:pos]
        self.buf_off += pos

    def _line(self, start, end, line, now):
        """완성된 줄 하나 — evidence는 그대로 보낸다. InputTracker가 바꾼다 (24_ §4.2)."""
        self._add(Entry(start, end, line, now))

    def flush_open(self):
        """파일 끝에서 열린 칸을 닫는다 — evidence는 할 일 없음 (24_ §5.3 ④)."""

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


# ---------------------------------------------------------------- 상시 KPM — kpm2 칸 묶기 (24_ §5)

FAILCAUSE = "RRC.ConnEstabFailCause"  # total 없이 세 원인으로 된 카운터 (22_ §5.1) — 다른 객체 카운터는 total이 있어야 한다
EXT_MAX = ("UeCtxMax",)                 # 최댓값으로 묶는 ext 이름 (24_ §5.2)
EXT_SUM = ("DuCannotServe", "CrntiAlloc")  # 합으로 묶는 ext 이름
# 묶은 줄로 옮기거나 일부러 빼는 맨 위 키 — 이 밖의 키는 처음 한 번 경고 (ue_evt_lost·cov는 11/04 로스 대상 외로 뺌)
KPM2_KEYS = {"type", "ver", "session", "seq", "cell_id", "t_start_ms", "t_end_ms", "cc", "si", "ext", "ue_evt_lost", "cov"}
STATE_SENT_MAX = 256  # 상태 파일에 남기는 '보낸 칸' (세션, 셀) 수 — 오래된 세션부터 뺀다


def _nonneg_int(v):
    return _is_int(v) and v >= 0


def _nonneg_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v) and v >= 0


def _kpm2_head(obj):
    """칸을 정하는 값 (24_ §5.1) — 없거나 타입이 틀리면 None(bad_kpm2). 탐지 엔진도 이런 줄은 버린다 (22_ §6)."""
    s, c, t0, t1, q = (obj.get(k) for k in ("session", "cell_id", "t_start_ms", "t_end_ms", "seq"))
    if isinstance(s, str) and s and _nonneg_int(c) and _is_int(t0) and _is_int(t1) and _is_int(q) and t1 > t0:
        return s, c, t0, t1, q
    return None


def _kpm2_values_ok(obj):
    """카운터·표본 값의 형식 (24_ §5.1, 22_ §5.3·§5.4) — 0 이상 정수(si의 …Mean은 0 이상 수) 또는 null.
    틀린 값이 있으면 탐지 엔진이 줄 전체를 버리므로 칸에도 넣지 않는다. 묶지 않는 si·ext 이름은 형식을 보지 않는다."""
    cc = obj.get("cc")
    if cc is not None:
        if not isinstance(cc, dict):
            return False
        for v in cc.values():
            # 원인별 객체의 하위 값 null은 그 원인만 '모름' — 엔진 파서(message.cpp cause_counter)와 같게 (24_ §5.1, 11/05 W-40)
            if v is None or _nonneg_int(v) or (isinstance(v, dict) and all(x is None or _nonneg_int(x) for x in v.values())):
                continue
            return False
    si = obj.get("si")
    if si is not None:
        if not isinstance(si, dict):
            return False
        for k, v in si.items():
            if v is None or (k.endswith("Mean") and _nonneg_num(v)) or (k.endswith("Max") and _nonneg_int(v)):
                continue
            if k.endswith("Mean") or k.endswith("Max"):
                return False
    ext = obj.get("ext")
    if ext is not None:
        if not isinstance(ext, dict):
            return False
        for k, v in ext.items():
            if v is not None and k in EXT_MAX + EXT_SUM and not _nonneg_int(v):
                return False
    return True


class _Bucket:
    """열린 칸 하나 — (세션, 셀)의 [t0, t0 + N). first_off는 든 첫 원본 줄의 파일 위치(보낸 위치의 상한, 24_ §4.3).
    cont는 cc·si·ext마다 이름 → {"known": 값을 안 줄 수, "v": 누적} — 이름 순서는 처음 나온 순서."""
    __slots__ = ("session", "cell", "t0", "first_off", "gen", "n", "seq_from", "seq_to", "cont")

    def __init__(self, session, cell, t0, first_off, gen=0):
        self.session, self.cell, self.t0, self.first_off = session, cell, t0, first_off
        self.gen = gen  # 칸이 열린 파일의 차례 — first_off는 그 파일의 위치다 (24_ §4.3, 11/08 P9)
        self.n = 0
        self.seq_from = self.seq_to = None
        self.cont = {"cc": {}, "si": {}, "ext": {}}


class KpmAggregator:
    """kpm2를 (세션, 셀)마다 N ms 칸으로 묶는다 (24_ §5). 칸은 파일 내용만으로 닫는다 — 벽시계를 쓰지 않으므로 같은 파일이면
    언제·몇 번 보내도 같은 묶은 줄이 나온다(대시보드 중복 키 (환경, session, cell_id, agg_ms, t_start_ms)와 맞물림, §5.3).
    add·on_hello·flush는 닫은 칸의 (묶은 줄 바이트, (session, cell, t0)) 목록을 닫은 순서대로 돌려준다."""

    def __init__(self, interval_ms, close_lag_ms, warn):
        self.n_ms = interval_ms
        self.lag = close_lag_ms
        self.warn = warn            # warn(한 번만 낼 키, 사건, **값)
        self.open = {}              # (session, cell) → _Bucket — 셀마다 열린 칸은 하나
        self.closed_to = {}         # (session, cell) → 이번 실행에서 닫은 마지막 칸 t0 — 그 칸의 늦은 줄은 agg_late
        self.sent_to = {}           # (session, cell) → 대시보드가 받은(200·400) 마지막 칸 t0 — 상태 파일에 남긴다
        self.restored = {}          # 상태 파일에서 읽은 sent_to — 다시 읽은 그 칸의 줄은 조용히 건너뛴다(resent)
        self.last_end = {}          # (session, cell) → 받아들인 마지막 줄 t_end_ms — 겹침·역행 확인
        self.late = self.resent = 0
        self.gen = 0                # 지금 읽는 파일의 차례 — 회전 파일로 넘어가며 칸을 이어 갈 때마다 1 늘린다 (24_ §4.3, 11/08 P9)

    # --- 상태 파일 (24_ §4.3): 재시작 뒤 다시 읽는 줄 가운데 이미 보낸 칸의 줄은 칸을 다시 만들지 않는다 — 여러 셀이 섞이면
    #     보낸 위치가 다른 셀의 열린 칸 앞에 머물러, 이미 보낸 칸의 뒤쪽 줄만으로 같은 키의 반쪽 줄이 다시 갈 수 있어서다

    def restore(self, st):
        if not isinstance(st, dict) or st.get("ms") != self.n_ms or not isinstance(st.get("closed"), list):
            return  # 주기가 바뀌었으면 키(agg_ms)가 달라 겹치지 않는다 — 처음부터 묶는다 (24_ §4.5)
        for x in st["closed"]:
            if isinstance(x, list) and len(x) == 3 and isinstance(x[0], str) and _nonneg_int(x[1]) and _is_int(x[2]):
                self.restored[(x[0], x[1])] = x[2]
        self.sent_to = dict(self.restored)

    def state(self):
        items = sorted(self.sent_to.items(), key=lambda kv: kv[1])[-STATE_SENT_MAX:]
        return {"ms": self.n_ms, "closed": [[s, c, t0] for (s, c), t0 in items]}

    def note_sent(self, key):
        s, c, t0 = key
        if t0 > self.sent_to.get((s, c), t0 - 1):
            self.sent_to[(s, c)] = t0

    # --- 칸

    def min_open_off(self):
        # 지금 파일에서 열린 칸만 — 앞 파일에서 이어 온 칸의 first_off는 다른 파일의 위치다(그동안은 보낸 위치를 옛 파일에 둠)
        return min((b.first_off for b in self.open.values() if b.gen == self.gen), default=None)

    def drop_open(self):
        self.open.clear()

    def flush(self):
        """파일 끝(--once)·파일 교체 — 열린 칸을 모두 닫는다 (24_ §5.3 ④)."""
        return [self._close(k) for k in list(self.open)]

    def on_hello(self, session):
        """다른 세션의 hello — 옛 세션의 열린 칸을 모두 닫는다. 같은 세션(다시 접속)이면 닫지 않는다 (24_ §5.3 ③)."""
        return [self._close(k) for k in [k for k in self.open if k[0] != session]]

    def add(self, off, obj):
        """원본 kpm2 줄 하나 (24_ §5.1·§5.3). (닫은 칸 목록, 칸에 넣지 않은 사유 또는 None)."""
        head = _kpm2_head(obj)
        if head is None or not _kpm2_values_ok(obj):
            return [], "bad_kpm2"
        s, c, t0, t1, seq = head
        key = (s, c)
        if self.n_ms % (t1 - t0):
            # 원본 주기가 N을 나누지 못함 — 묶지도 보내지도 않는다(0.1초 원본은 보내지 않음, 24_ §5.1)
            self.warn(("agg_period", key), "agg_period", session=s, cell=c, period_ms=t1 - t0,
                      interval_ms=self.n_ms, detail="not sent")
            return [], "agg_period"
        last = self.last_end.get(key)
        if last is not None and t0 < last:
            return [], "overlap"  # 같은 셀 구간이 겹치거나 거꾸로 옴 — 탐지 엔진도 버린다 (22_ §6)
        k0 = (t0 // self.n_ms) * self.n_ms
        if key in self.closed_to and k0 <= self.closed_to[key]:
            # 이미 닫은 칸 — 다시 열지 않는다(같은 키로 다른 줄을 보낼 수 없음, 24_ §5.3)
            self.last_end[key] = t1
            self.late += 1
            self.warn(("agg_late", key), "agg_late", session=s, cell=c, t_start_ms=t0, closed_to=self.closed_to[key])
            return [], "late"
        if key not in self.open and key in self.restored and k0 <= self.restored[key]:
            self.last_end[key] = t1
            self.resent += 1  # 재시작 전에 보낸 칸 — 조용히 건너뛴다
            return [], "resent"
        out = []
        # ③ 같은 셀에 다른 세션의 kpm2 — 그 셀의 옛 세션 칸
        for k in [k for k in self.open if k[1] == c and k[0] != s]:
            out.append(self._close(k))
        # ① 같은 (세션, 셀)의 뒤 칸 줄 — 보통은 이것
        b = self.open.get(key)
        if b is not None and b.t0 != k0:
            out.append(self._close(key))
            b = None
        # ② 다른 셀의 줄이 데이터 시각으로 칸 끝 + 여유를 넘음 — 그 셀만 줄이 멈췄을 때
        for k in [k for k, x in self.open.items() if k[1] != c and x.t0 + self.n_ms + self.lag <= t0]:
            out.append(self._close(k))
        if b is None:
            b = self.open[key] = _Bucket(s, c, k0, off, self.gen)
        self._accumulate(b, obj, seq)
        self.last_end[key] = t1
        return out, None

    def _accumulate(self, b, obj, seq):
        """줄 하나를 칸에 더한다 (24_ §5.2). 값이 null이거나 이름이 없으면 그 줄에서 '모름' — known을 늘리지 않는다."""
        b.n += 1
        b.seq_from = seq if b.seq_from is None else min(b.seq_from, seq)
        b.seq_to = seq if b.seq_to is None else max(b.seq_to, seq)
        for k in obj:
            if k not in KPM2_KEYS:
                self.warn(("key", k), "agg_unknown_key", key=k, detail="not aggregated")
        for cname in ("cc", "si", "ext"):
            cont = obj.get(cname)
            if not isinstance(cont, dict):
                continue  # 없거나 null — 그 안의 이름은 이 줄에서 모두 모름
            names = b.cont[cname]
            for name, v in cont.items():
                if (cname == "si" and not (name.endswith("Mean") or name.endswith("Max"))) or \
                        (cname == "ext" and name not in EXT_MAX + EXT_SUM):
                    self.warn(("key", f"{cname}.{name}"), "agg_unknown_key", key=f"{cname}.{name}",
                              detail="not aggregated")
                    continue
                acc = names.get(name)
                if acc is None:
                    acc = names[name] = {"known": 0, "v": None}
                if v is None:
                    continue
                if cname == "cc":
                    if isinstance(v, dict):
                        # 원인별 객체 — 하위 키마다 합, 줄에 없는 원인은 0. total이 없거나 null이면 이 줄에서 모름(22_ §6).
                        # 하위 값 null은 그 원인만 이 줄에서 모름 — 줄은 받는다 (24_ §5.1, 11/05 W-40)
                        if (name != FAILCAUSE and not _nonneg_int(v.get("total"))) or not isinstance(acc["v"], (dict, type(None))):
                            continue
                        if acc["v"] is None:
                            acc["v"] = {}
                        for sk, x in v.items():
                            if x is None:
                                continue
                            acc["v"][sk] = acc["v"].get(sk, 0) + x
                    else:
                        if not isinstance(acc["v"], (int, type(None))):
                            continue
                        acc["v"] = (acc["v"] or 0) + v
                elif cname == "si" and name.endswith("Mean"):
                    acc["v"] = [v, 1] if acc["v"] is None else [acc["v"][0] + v, acc["v"][1] + 1]
                elif cname == "si" or name in EXT_MAX:
                    acc["v"] = v if acc["v"] is None else max(acc["v"], v)
                else:
                    acc["v"] = (acc["v"] or 0) + v
                acc["known"] += 1

    def _close(self, key):
        b = self.open.pop(key)
        self.closed_to[key] = max(self.closed_to.get(key, b.t0), b.t0)
        return self._render(b), (b.session, b.cell, b.t0)

    def _render(self, b):
        """묶은 줄 (24_ §5.2) — 키 순서 고정, 공백 없는 JSON. 일부 줄에서만 안 이름은 partial에, 모든 줄에서 모르면 null."""
        out = {"type": "kpm2", "ver": 1, "agg_ms": self.n_ms, "session": b.session, "cell_id": b.cell,
               "t_start_ms": b.t0, "t_end_ms": b.t0 + self.n_ms, "n": b.n, "seq_from": b.seq_from, "seq_to": b.seq_to}
        partial = []
        for cname in ("cc", "si", "ext"):
            names = b.cont[cname]
            if not names:
                continue
            o = {}
            for name, acc in names.items():
                if acc["known"] == 0:
                    o[name] = None
                    continue
                v = acc["v"]
                if cname == "si" and name.endswith("Mean"):
                    v = round(v[0] / v[1], 3)  # 칸마다 길이가 같아 시간 평균과 같다
                o[name] = v
                if acc["known"] < b.n:
                    partial.append(f"{cname}.{name}")
            out[cname] = o
        out["partial"] = partial
        return json.dumps(out, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class InputTracker(Tracker):
    """kind input — 탐지 엔진 입력 기록 파일(input.jsonl, 24_ §3)을 따라 읽는다 (24_ §4.2).
    hello·f1_evt·(send_ue_evt면) ue_evt는 줄 그대로(hello는 node_id만 바꿈), kpm2는 칸에 모았다가 닫힐 때 묶은 줄로
    (원본은 보내지 않음), 그 밖의 줄은 보내지 않고 센다. 줄마다 safe를 열린 칸의 첫 줄 앞으로 낮춰 보낸 위치가 열린 칸을
    넘지 않게 한다(§4.3)."""
    is_input = True

    def __init__(self, cfg, path, abspath):
        super().__init__(cfg, path, abspath)
        self.send_ue = cfg["send_ue_evt"]
        self.hello_node_id = cfg["hello_node_id"]
        self.warned = set()
        self.agg = KpmAggregator(cfg["kpm2_interval_ms"], cfg["kpm2_close_lag_ms"], self._warn_once) \
            if cfg["kpm2_interval_ms"] else None
        self.skipped = 0
        self.agg_lines = 0
        # 회전 경계에 걸친 칸 (24_ §4.3, 11/08 이슈 #102 — I-01 P9·Q12): 옛 파일이 회전 파일로 찾아지면 열린 칸을 닫지 않고
        # 다음 파일로 이어 간다. 그 칸들이 모두 보내질 때까지 상태 파일의 보낸 위치는 옛 파일 쪽(pin)에 둔다 — 그사이 멈추면
        # 다음 시작 때 옛 파일을 찾아(19_ §4.5 ②) 그 자리부터 칸을 다시 만든다
        self.carry = None          # 이번 파일 끝에서 칸을 이어 갈지 — at_rotated_eof()가 정하고 _before_switch()가 지운다
        self.keep_open = False     # 다음 파일을 열 때 열린 칸을 버리지 않는다
        self.pin = None            # (dev, ino, offset) — 옛 파일에서 이어 온 칸의 첫 줄 앞
        self.pin_keys = set()      # 이어 온 칸 (session, cell, t0) — 모두 받으면(200·400) pin을 푼다

    # 같은 경고는 한 번만 낸다 (24_ §4.4). 첫 인자 once_key는 '이미 냈나'를 가르는 키일 뿐이다 — 이름을 key로 두면
    # agg_unknown_key가 로그 칸 key=…(24_ §4.4)를 kv로 넘길 때 이름이 겹쳐 TypeError로 전송기가 멈췄다(이슈 #106)
    def _warn_once(self, once_key, event, **kv):
        if once_key not in self.warned:
            self.warned.add(once_key)
            log("WARN", event, file=self.path, **kv)

    def start(self, entry):
        # 상태 파일의 '보낸 칸' — 같은 주기일 때만 (24_ §4.3)
        if self.agg is not None and entry:
            self.agg.restore(entry.get("agg"))
        super().start(entry)

    def _reset(self, off):
        # 처음 열 때·파일 교체 뒤(이미 닫아 보냄)·잘림 — 잘림이면 읽어 둔 줄(pending)과 함께 열린 칸도 버린다(19_ §4.4와 같게).
        # 회전 파일로 넘어가며 칸을 이어 갈 때(keep_open)는 버리지 않는다 (24_ §4.3, 11/08 P9)
        super()._reset(off)
        if self.keep_open:
            return
        if self.agg is not None:
            self.agg.drop_open()
        self.pin = None
        self.pin_keys.clear()

    def _attach(self, fh, st, off):
        super()._attach(fh, st, off)
        self.keep_open = False

    def at_rotated_eof(self):
        """다 쓴 파일의 끝 (24_ §4.3, 11/08 P9): 옛 파일이 회전 파일로 찾아지면 칸을 다음 파일로 이어 간다. 못 찾으면(손으로
        옮김) 지금처럼 열린 칸을 닫아 보낸다 — 다음 시작 때 찾을 수 없는 파일에 보낸 위치를 둘 수 없어서다."""
        if self.agg is None:
            return
        if self.carry is None:
            self.carry = _rot_index(rotated_files(self.abspath), self.dev, self.ino) is not None
        if not self.carry:
            self.flush_open()

    def _before_switch(self, found):
        # 이어 갈 칸이 있으면 보낸 위치를 옛 파일의 칸 첫 줄 앞에 묶어 두고(이미 묶여 있으면 더 앞인 그 자리 그대로),
        # 이 칸들을 '앞 파일의 칸'으로 돌린다 — 다음 파일 줄의 safe를 다른 파일 위치로 자르지 않게
        carry = found if self.carry is None else self.carry  # 보통은 at_rotated_eof()가 이미 정했다
        if carry and self.agg is not None and self.agg.open:
            if self.pin is None:
                self.pin = (self.dev, self.ino, min(b.first_off for b in self.agg.open.values()))
            self.pin_keys.update((b.session, b.cell, b.t0) for b in self.agg.open.values())
            self.agg.gen += 1
            self.keep_open = True
        self.carry = None

    def save_pos(self, safe):
        # 이어 온 칸이 아직 다 보내지지 않았으면 옛 파일 쪽 (24_ §4.3, 11/08 P9)
        if self.pin is not None:
            if self.pin_keys:
                return self.pin
            self.pin = None
        return super().save_pos(safe)

    def _add(self, e):
        m = self.agg.min_open_off() if self.agg is not None else None
        if m is not None and e.safe > m:
            e.safe = m
        super()._add(e)

    def _emit(self, closed, pos, now):
        # 닫은 칸의 묶은 줄 — 그 칸을 닫게 한 줄의 자리(그 줄보다 앞)에 둔다 (24_ §4.2)
        for data, key in closed:
            self._add(Entry(pos, pos, data, now, key=key))

    def _skip(self, reason, start, end, line, now):
        self.skipped += 1
        self._warn_once(("skip", reason), "skip_input", off=start, reason=reason, head=_head(line))
        self._add(Entry(start, end, None, now))

    def _hello_out(self, obj, line):
        """대시보드로 보낼 hello 줄 (24_ §4.2 'hello의 node_id', 11/13 사용자 결정 — 이슈 #110).
        밖으로 나가는 node_id를 분석 엔진·가짜 분석 엔진·시험 생성기가 넣은 값(cu-p4·synthetic 등)과 관계없이
        hello_node_id 하나로 맞춘다. 탐지 엔진의 input.jsonl(재생용 원본)은 건드리지 않고 보내는 줄만 바꾼다.
        - 설정이 null이거나 node_id가 이미 그 값이면 원래 줄을 바이트 그대로 (①)
        - 아니면 node_id만 바꾸고(없으면 맨 끝에 더함 — dict는 키 순서를 지킨다) 공백 없는 JSON 한 줄로 다시 쓴다 (②).
          ensure_ascii는 켠 채 둔다 — 짝 없는 서로게이트(\\ud800 등)가 든 줄도 UTF-8로 인코딩할 수 있게, ASCII 밖 문자는 \\uXXXX
        - 다시 쓴 줄이 line_max_bytes를 넘으면 None — 원래 값이 새어 나가지 않게 보내지 않는다 (③)"""
        nid = self.hello_node_id
        if nid is None or obj.get("node_id") == nid:
            return line
        obj["node_id"] = nid
        out = json.dumps(obj, separators=(",", ":")).encode("ascii")
        if len(out) > self.cfg["line_max_bytes"]:
            return None
        return out

    def _line(self, start, end, line, now):
        try:
            obj = json.loads(line)
        except ValueError:
            obj = None
        if not isinstance(obj, dict):
            return self._skip("not_json", start, end, line, now)
        typ = obj.get("type")
        if not isinstance(typ, str):
            return self._skip("no_type", start, end, line, now)
        if typ == "kpm2":
            if self.agg is None:  # kpm2_interval_ms 0 — kpm2는 보내지 않음
                return self._add(Entry(start, end, None, now))
            closed, reason = self.agg.add(start, obj)
            self._emit(closed, start, now)
            if reason in ("bad_kpm2", "overlap"):
                return self._skip(reason, start, end, line, now)
            if reason == "agg_period":
                self.skipped += 1
            return self._add(Entry(start, end, None, now))
        if typ == "hello":
            if self.agg is not None and isinstance(obj.get("session"), str):
                self._emit(self.agg.on_hello(obj["session"]), start, now)
            out = self._hello_out(obj, line)
            if out is None:
                return self._skip("hello_too_long", start, end, line, now)
            return self._add(Entry(start, end, out, now))
        if typ == "f1_evt":
            return self._add(Entry(start, end, line, now))
        if typ == "ue_evt":
            return self._add(Entry(start, end, line if self.send_ue else None, now))
        if typ == "overhead":
            # 계측 엔진이 낸 줄을 그대로 실음. 형식을 옮기면 대시보드가 거부함
            #   (2026-11-13 p1 실측: 그대로 보낸 줄은 accepted, 옛 형식으로 옮긴 줄은 rejected)
            # link 가 null 인 줄은 보내지 않고 셈. 대시보드는 link 를 배열로만 받는데 [] 로 바꿔 보내면
            #   인터페이스 카운터를 못 읽었다는 뜻이 읽었는데 흐름이 없었다는 뜻과 같아져,
            #   받는 쪽에서 측정 구멍을 가릴 수 없게 됨
            if obj.get("link") is None:
                return self._skip("overhead_no_link", start, end, line, now)
            return self._add(Entry(start, end, line, now))
        return self._skip("unknown_type", start, end, line, now)

    def flush_open(self):
        if self.agg is not None:
            self._emit(self.agg.flush(), self.buf_off, time.monotonic())

    def note_sent(self, b):
        """200·400을 받은 묶음 — 든 묶은 줄의 칸을 '보낸 칸'으로 (상태 파일에 남긴다)."""
        for e in b.entries:
            if e.key is not None:
                self.agg.note_sent(e.key)
                self.agg_lines += 1
                self.pin_keys.discard(e.key)


# ---------------------------------------------------------------- 전송기 본체 (19_ §4.3·§5·§6)

class Sender:
    def __init__(self, cfg, mode, once_timeout_s=60.0):
        self.cfg = cfg
        self.mode = mode  # run | once | dry_run
        self.once_timeout_s = once_timeout_s
        self.trackers = [(InputTracker if i["kind"] == "input" else Tracker)(cfg, i["path"], i["abspath"])
                         for i in cfg["inputs"]]
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

    def _commit(self, tr, b, persist=True):
        """200·400을 받은 뒤(또는 보내지 않는 줄만) 보낸 위치를 넘기고 저장한다 (19_ §4.3).
        저장 위치는 묶음의 safe — evidence는 묶음 끝, input은 열린 칸의 첫 줄 앞을 넘지 않는다. input은 받은 묶은 줄의 칸을
        '보낸 칸'으로 함께 남긴다 (24_ §4.3). persist가 False면 메모리의 위치만 넘긴다 — input의 보낼 줄 없는 묶음(칸에 든
        kpm2만)은 줄마다 상태 파일을 쓰지 않게, 다음에 보낸 묶음과 함께 저장한다(그사이 멈추면 그만큼 다시 읽는다)."""
        if self.mode == "dry_run" or not persist:
            tr.acked = b.safe
            return
        with self._critical():
            if tr.is_input:
                tr.note_sent(b)
            dev, ino, off = tr.save_pos(b.safe)  # input은 이어 온 칸이 남았으면 옛 파일 쪽 (24_ §4.3, 11/08 P9)
            entry = {"dev": dev, "ino": ino, "offset": off, "saved_ms": int(time.time() * 1000)}
            if tr.agg is not None:
                entry["agg"] = tr.agg.state()
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
            tr.acked = b.safe
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
            extra = {}
            if t.is_input:  # 상시 KPM (24_ §4.4)
                extra = {"agg_lines": t.agg_lines, "open_cells": len(t.agg.open) if t.agg else 0,
                         "late": t.agg.late if t.agg else 0, "skipped": t.skipped,
                         "resent": t.agg.resent if t.agg else 0}
            log("INFO", "stats", file=t.path, lag_bytes=lag, sent_lines=t.sent_lines, fails=self.fails, **extra)

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
                self._commit(tr, b, persist=not tr.is_input)
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
                if t.rotating and t.eof:
                    t.at_rotated_eof()  # 옛 파일 끝 — 회전 파일이면 칸을 이어 가고, 아니면 닫아 보낸 뒤 새 파일로 (24_ §4.3·§5.3 ④)
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
        # 회전 파일을 읽는 중이면(19_ §4.5 ⑦) 끝까지 보내고 다음 파일로 — 지금 경로의 파일 끝에서 끝낸다 (11/08 이슈 #102)
        for t in self.trackers:
            while True:
                self._check_deadline()
                t.fill(we, wb)
                if t.eof:
                    if t.rotating:
                        t.at_rotated_eof()  # 다 쓴 파일 끝 — 회전 파일이면 칸을 이어 간다 (24_ §4.3)
                    else:
                        t.flush_open()  # --once는 마지막 파일 끝에서 열린 칸을 모두 닫아 보낸다 (24_ §4.3·§5.3 ④)
                b, _ = t.take_batch(time.monotonic(), force=True)
                if b is not None:
                    self.send_batch(t, b)
                    continue
                if not t.eof:
                    continue
                if t.drained():
                    t.finish_rotate()
                    if t.fh is None:
                        t.check()  # 다음은 지금 경로의 파일 — 없으면 fill이 끝으로 본다
                    continue
                break

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
