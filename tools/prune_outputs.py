#!/usr/bin/env python3
"""정리 도구 — 탐지 엔진의 회전 파일과 실행 스크립트 로그를 보관 기간에 따라 지운다 (29_ §3·§5.2).

실행 (29_ §3.1 — 탐지 엔진을 띄운 폴더에서 부른다. 한 번 돌고 끝난다):
  python3 tools/prune_outputs.py --detector-config config/detector.json --sender-config config/sender.json
                                 [--log FILE ...] [--log-max-bytes N] [--log-keep-s S] [--dry-run]

- 지우는 것: evidence.out_path·input_record.path의 회전 파일(<기준>.<YYYYMMDD-HHMMSS>[.N], 29_ §2.3) 가운데
  이름의 시각으로 잰 나이가 keep_s를 넘은 것. 지금 쓰는 파일(기준 경로)은 건드리지 않는다 (29_ §3.2).
- 전송기 상태 파일에 적힌 파일((dev, ino)가 같은 파일)은 아직 다 보내지 않았을 수 있어 지우지 않는다 (29_ §3.2 3).
- 입력 기록만: 디스크 여유가 input_record.min_free_bytes보다 적으면 보관 기간과 관계없이 오래된 회전 파일부터 더 지운다 (29_ §3.2).
- --log로 받은 로그는 --log-max-bytes를 넘으면 <로그>.<YYYYMMDD-HHMMSS>로 복사한 뒤 원본을 비우고(copytruncate),
  --log-keep-s가 지난 복사본을 지운다 (29_ §5.2).
- 로그는 표준 오류에 '시각 수준 사건 키=값'(전송기와 같은 모양, 29_ §7).
- 종료 코드: 0 끝까지 돎(경고 있어도), 1 명령줄·설정 파일 오류 (29_ §3.3).
- Python 3.10 이상, 표준 라이브러리만 쓴다(전송기와 같음).
"""

import argparse
import datetime
import json
import os
import re
import stat
import sys
import time

EXIT_OK = 0
EXIT_CONFIG = 1

# 탐지 엔진 설정 기본값 — include/detect/config.h (evidence.out_path, input_record.path null = 끔).
# 보관 키는 코드 기본값 0(끔)이다 (29_ §6)
DETECTOR_DEFAULT_OUT = "evidence.jsonl"
SENDER_DEFAULT_STATE = "sender_state.json"  # dashboard_sender.py DEFAULTS state_path
KEEP_RANGE = (3600, 31536000)                  # evidence.keep_s·input_record.keep_s — 0 또는 이 범위 (29_ §6)
MIN_FREE_RANGE = (104857600, 1099511627776)    # input_record.min_free_bytes — 0 또는 이 범위 (29_ §6)
LOG_MAX_BYTES_DEFAULT = 67108864               # LOG_MAX_BYTES 기본 64 MiB (29_ §5.2)
LOG_KEEP_S_DEFAULT = 604800                    # LOG_KEEP_S 기본 7일 (29_ §5.2)
NAME_SUFFIX_MAX = 99                           # 같은 이름이 있으면 .1 … .99 (29_ §2.3)
COPY_CHUNK = 1048576


# ---------------------------------------------------------------- 시각·디스크 여유 — 시험이 바꿔 끼운다

def now_s():
    """지금 벽시계(UTC epoch 초). 나이 계산과 로그 복사본 이름에 쓴다."""
    return time.time()


def free_bytes(path):
    """path가 있는 파일 시스템의 여유 — statvfs의 f_bavail × f_frsize (29_ §3.2)."""
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


# ---------------------------------------------------------------- 로그 (29_ §7)
# 표준 오류에 한 줄씩 '시각 수준 사건 키=값 …'. 시각은 벽시계 UTC ISO 8601 — 전송기 log()와 같은 모양

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


def _err(e):
    return e.strerror or str(e)


# ---------------------------------------------------------------- 설정 (29_ §3.1·§6)

class ConfigError(Exception):
    pass


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _read_json(path, what):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except OSError as e:
        raise ConfigError(f"cannot read {what} {path}: {_err(e)}")
    except ValueError as e:
        raise ConfigError(f"{what} {path}: invalid JSON: {e}")


def _off_or_range(where, v, lo, hi):
    # 0(끔) 또는 [lo, hi] 정수 — 탐지 엔진과 같은 범위 검사(29_ §6). 범위 밖은 설정 오류(종료 코드 1)
    if not _is_int(v):
        raise ConfigError(f"{where}: not an integer")
    if v != 0 and not lo <= v <= hi:
        raise ConfigError(f"{where}: must be 0 or in {lo}..{hi}")
    return v


def load_detector_config(path):
    """탐지 엔진 설정에서 기준 경로와 보관 키를 읽는다 ('-'면 기본값 — 모두 끔). 다른 키는 보지 않는다 (29_ §3.1·§6)."""
    cfg = {"evidence_path": DETECTOR_DEFAULT_OUT, "evidence_keep_s": 0,
           "input_path": None, "input_keep_s": 0, "input_min_free": 0}
    if path == "-":
        return cfg
    raw = _read_json(path, "detector config")
    if not isinstance(raw, dict):
        raise ConfigError(f"detector config {path}: top level must be an object")
    ev = raw.get("evidence", {})
    if not isinstance(ev, dict):
        raise ConfigError("evidence: not an object")
    if "out_path" in ev:
        p = ev["out_path"]
        if not isinstance(p, str) or not p:
            raise ConfigError("evidence.out_path: not a non-empty string")
        cfg["evidence_path"] = p
    if "keep_s" in ev:
        cfg["evidence_keep_s"] = _off_or_range("evidence.keep_s", ev["keep_s"], *KEEP_RANGE)
    ir = raw.get("input_record", {})
    if not isinstance(ir, dict):
        raise ConfigError("input_record: not an object")
    if ir.get("path") is not None:
        p = ir["path"]
        if not isinstance(p, str) or not p:
            raise ConfigError("input_record.path: not a non-empty string or null")
        cfg["input_path"] = p
    if "keep_s" in ir:
        cfg["input_keep_s"] = _off_or_range("input_record.keep_s", ir["keep_s"], *KEEP_RANGE)
    if "min_free_bytes" in ir:
        cfg["input_min_free"] = _off_or_range("input_record.min_free_bytes", ir["min_free_bytes"], *MIN_FREE_RANGE)
    return cfg


def load_state_path(path):
    """전송기 설정에서 state_path만 읽는다(상대 경로는 지금 폴더 기준 — 전송기와 같음, 29_ §3.1)."""
    raw = _read_json(path, "sender config")
    if not isinstance(raw, dict):
        raise ConfigError(f"sender config {path}: top level must be an object")
    sp = raw.get("state_path", SENDER_DEFAULT_STATE)
    if not isinstance(sp, str) or not sp:
        raise ConfigError("state_path: must be a non-empty string")
    return os.path.abspath(sp)


# ---------------------------------------------------------------- 전송 중 파일 보호 (29_ §3.2 3)

def load_protected(state_path):
    """전송기 상태 파일에 적힌 파일들의 (dev, ino) — 아직 다 보내지 않았을 수 있다 (19_ §4.3 형식).
    11/08 (이슈 #102, 29_ §3.2 3): 명세는 files[기준 절대 경로] 항목을 보라고 하지만, 키 경로 표기(심볼릭 링크·상대 경로)가
    탐지 엔진 설정과 달라도 놓치지 않게 상태 파일의 모든 항목을 보호한다 — 더 많이 남길 뿐 더 지우지는 않는다."""
    try:
        with open(state_path, encoding="utf-8") as f:
            raw = json.load(f)
    except FileNotFoundError:
        # 전송기가 아직 위치를 저장하지 않았다 — 상태 항목이 없으면 전송기는 회전 파일을 보지 않으므로 보호할 것이 없다 (19_ §4.5 4)
        return set()
    except (OSError, ValueError) as e:
        log("WARN", "prune_no_state", state=state_path,
            detail=f"cannot read state file: {_err(e) if isinstance(e, OSError) else e} — files being sent are not protected")
        return set()
    files = raw.get("files") if isinstance(raw, dict) and raw.get("ver") == 1 else None
    if not isinstance(files, dict):
        log("WARN", "prune_no_state", state=state_path,
            detail="not a ver 1 state file — files being sent are not protected")
        return set()
    out = set()
    for k, v in files.items():
        if isinstance(v, dict) and _is_int(v.get("dev")) and _is_int(v.get("ino")):
            out.add((v["dev"], v["ino"]))
        else:
            log("WARN", "prune_no_state", state=state_path, file=k,
                detail="state entry without dev/ino ignored — that file is not protected")
    return out


# ---------------------------------------------------------------- 회전 파일 찾기 (29_ §2.3)

def rotated(base):
    """기준 파일의 회전 파일을 쓰인 순서(이름 시각, 붙인 번호 — 번호 없는 것이 먼저)로 돌려준다 (29_ §2.3).
    이름 규칙 ^<기준 이름>\\.(\\d{8}-\\d{6})(?:\\.(\\d{1,2}))?$에 맞고 시각이 날짜로 읽히는 것만 — 나머지는 회전 파일이 아니다.
    돌려주는 것: [(이름 시각 epoch 초, 번호 또는 -1, 경로)] — 경로는 기준 경로를 받은 모양 그대로(상대면 상대)."""
    d, name = os.path.split(base)
    if not name:
        return []
    rx = re.compile(re.escape(name) + r"\.([0-9]{8}-[0-9]{6})(?:\.([0-9]{1,2}))?")
    try:
        names = os.listdir(d or ".")
    except FileNotFoundError:
        return []
    except OSError as e:
        log("WARN", "prune_error", file=d or ".", detail=_err(e))
        return []
    out = []
    for n in names:
        m = rx.fullmatch(n)
        if not m:
            continue
        try:
            t = datetime.datetime.strptime(m.group(1), "%Y%m%d-%H%M%S").replace(tzinfo=datetime.timezone.utc)
        except ValueError:
            continue
        k = int(m.group(2)) if m.group(2) is not None else -1
        out.append((t.timestamp(), k, os.path.join(d, n)))
    out.sort()
    return out


def _stamp(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y%m%d-%H%M%S")


# ---------------------------------------------------------------- 지우기 (29_ §3.2·§5.2)

class Pruner:
    def __init__(self, protected, dry_run):
        self.protected = protected
        self.dry_run = dry_run
        self.deleted = 0
        self.bytes = 0
        self.gone = {}      # 지운(--dry-run이면 지울) 경로 → (dev, 크기)
        self.kept = set()   # prune_keep을 이미 남긴 경로 — 같은 파일을 두 번 적지 않게

    def _dry(self):
        return {"dry_run": True} if self.dry_run else {}

    def _stat(self, path):
        # 일반 파일만 지운다 — 심볼릭 링크·폴더는 이름이 맞아도 건드리지 않는다
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            return None
        except OSError as e:
            log("WARN", "prune_error", file=path, detail=_err(e))
            return None
        return st if stat.S_ISREG(st.st_mode) else None

    def _sending(self, path, st):
        # 전송기 상태 파일의 파일 — 지울 조건이어도 남긴다 (29_ §3.2 3, §7 prune_keep)
        if (st.st_dev, st.st_ino) not in self.protected:
            return False
        if path not in self.kept:
            log("INFO", "prune_keep", file=path, reason="sending")
            self.kept.add(path)
        return True

    def _delete(self, path, st, reason, age_s):
        kv = {"file": path, "reason": reason, "age_s": int(age_s), "bytes": st.st_size}
        if not self.dry_run:
            try:
                os.unlink(path)
            except FileNotFoundError:
                return False
            except OSError as e:
                log("WARN", "prune_error", file=path, detail=_err(e))
                return False
        log("INFO", "prune", **kv, **self._dry())
        self.deleted += 1
        self.bytes += st.st_size
        self.gone[path] = (st.st_dev, st.st_size)
        return True

    # 보관 기간 (29_ §3.2 1~3): 나이 = 지금 − 이름의 시각(수정 시각이 아님). 나이 > keep_s만 지운다.
    # protect=False는 로그 복사본(§5.2) — 전송기가 읽지 않으므로 상태 파일과 대조하지 않는다
    def prune_age(self, base, keep_s, protect=True):
        if keep_s <= 0:
            return
        now = now_s()
        for t, _, path in rotated(base):
            age = now - t
            if age <= keep_s:
                break  # 쓰인 순서로 늘어서 있으므로 뒤는 모두 더 젊다
            st = self._stat(path)
            if st is None or (protect and self._sending(path, st)):
                continue
            self._delete(path, st, "age", age)

    # 디스크 여유 하한 — 입력 기록만 (29_ §3.2): 여유 < min_free면 보관 기간과 관계없이 가장 오래된 회전 파일부터,
    # 여유가 하한 이상이 되거나 지울 것이 없으면 멈춘다. 조건 1(회전 파일)·3(전송 중 보호)은 지킨다.
    # 실제로 지우면 지울 때마다 여유를 다시 잰다. --dry-run은 지우지 않으므로 지울 파일 크기를 더해 어림한다
    def prune_disk(self, base, min_free):
        if min_free <= 0:
            return
        d = os.path.dirname(os.path.abspath(base))
        try:
            free = free_bytes(d)
            dev = os.stat(d).st_dev
        except OSError as e:
            log("WARN", "prune_error", file=d, detail=_err(e))
            return
        if self.dry_run:
            free += sum(size for g_dev, size in self.gone.values() if g_dev == dev)
        if free >= min_free:
            return
        now = now_s()
        for t, _, path in rotated(base):
            if free >= min_free:
                break
            if path in self.gone:
                continue
            st = self._stat(path)
            if st is None or self._sending(path, st):
                continue
            if not self._delete(path, st, "disk", now - t):
                continue
            if self.dry_run:
                free += st.st_size
            else:
                try:
                    free = free_bytes(d)
                except OSError:
                    free += st.st_size

    # 로그 copytruncate (29_ §5.2): 크기 > max_bytes인 로그를 <로그>.<YYYYMMDD-HHMMSS>로 복사한 뒤 원본을 0바이트로 비운다.
    # 쓰는 쪽이 이어 쓰기(>>, O_APPEND)로 열어 두었으므로 다음 줄은 원본 처음에 간다. 복사와 비우기 사이의 몇 줄은 잃을 수 있다.
    # 11/08 (이슈 #102, 29_ §5.2): 같은 초에 복사본이 이미 있으면 회전 파일처럼 .1 … .99를 붙인다(29_ §2.3과 같은 이름 규칙 —
    # 보관 기간 정리가 같은 정규식으로 찾는다). 복사가 실패하면 원본을 비우지 않는다(로그를 잃지 않게)
    def copytruncate(self, logp, max_bytes):
        if max_bytes <= 0:
            return
        try:
            st = os.stat(logp)
        except FileNotFoundError:
            return
        except OSError as e:
            log("WARN", "prune_error", file=logp, detail=_err(e))
            return
        if not stat.S_ISREG(st.st_mode) or st.st_size <= max_bytes:
            return
        stamp = _stamp(now_s())
        cands = [f"{logp}.{stamp}"] + [f"{logp}.{stamp}.{i}" for i in range(1, NAME_SUFFIX_MAX + 1)]
        if self.dry_run:
            to = next((c for c in cands if not os.path.lexists(c)), None)
            log("INFO", "prune_log", file=logp, to=to, bytes=st.st_size, dry_run=True)
            return
        fd = to = None
        for c in cands:
            try:
                fd = os.open(c, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
            except FileExistsError:
                continue
            except OSError as e:
                log("WARN", "prune_error", file=c, detail=_err(e))
                return
            to = c
            break
        if fd is None:
            log("WARN", "prune_error", file=logp, detail=f"no free copy name (.{stamp} .1 … .{NAME_SUFFIX_MAX} taken)")
            return
        n = 0
        try:
            with os.fdopen(fd, "wb") as dst, open(logp, "rb") as src:
                while True:
                    b = src.read(COPY_CHUNK)
                    if not b:
                        break
                    dst.write(b)
                    n += len(b)
                dst.flush()
                os.fsync(dst.fileno())
        except OSError as e:
            try:
                os.unlink(to)
            except OSError:
                pass
            log("WARN", "prune_error", file=logp, detail=f"copy to {to} failed: {_err(e)} (log not truncated)")
            return
        try:
            os.truncate(logp, 0)
        except OSError as e:
            log("WARN", "prune_error", file=logp, detail=f"truncate failed: {_err(e)} (copy kept at {to})")
            return
        log("INFO", "prune_log", file=logp, to=to, bytes=n)


# ---------------------------------------------------------------- 명령줄 (29_ §3.1)

class _ArgParser(argparse.ArgumentParser):
    def error(self, message):
        # 사용법 오류도 종료 코드 1 (29_ §3.3 — 명령줄·설정 파일 오류)
        self.print_usage(sys.stderr)
        log("ERROR", "config_error", detail=message)
        sys.exit(EXIT_CONFIG)


def main(argv=None):
    ap = _ArgParser(description=__doc__.splitlines()[0])
    ap.add_argument("--detector-config", required=True, metavar="FILE|-",
                    help="탐지 엔진 설정 (config/detector.json, '-'면 기본값) — 기준 경로와 보관 키를 읽음")
    ap.add_argument("--sender-config", metavar="FILE",
                    help="전송기 설정 (config/sender.json) — state_path로 전송 중인 파일을 보호. 없으면 보호 없이 지움(경고)")
    ap.add_argument("--log", action="append", default=[], metavar="FILE",
                    help="크기 상한으로 정리할 로그 파일 (여러 번)")
    ap.add_argument("--log-max-bytes", type=int, default=LOG_MAX_BYTES_DEFAULT, metavar="N",
                    help=f"이 크기를 넘은 로그를 복사 후 비움 (기본 {LOG_MAX_BYTES_DEFAULT}, 0이면 안 함)")
    ap.add_argument("--log-keep-s", type=int, default=LOG_KEEP_S_DEFAULT, metavar="S",
                    help=f"로그 복사본 보관 기간(초) (기본 {LOG_KEEP_S_DEFAULT}, 0이면 지우지 않음)")
    ap.add_argument("--dry-run", action="store_true", help="지울 파일만 로그로 남기고 지우지 않음")
    a = ap.parse_args(argv)
    if sys.version_info < (3, 10):
        log("ERROR", "config_error", detail="python 3.10 or newer is required")
        return EXIT_CONFIG
    if a.log_max_bytes < 0:
        ap.error("--log-max-bytes must be >= 0")
    if a.log_keep_s < 0:
        ap.error("--log-keep-s must be >= 0")
    try:
        det = load_detector_config(a.detector_config)
        state_path = load_state_path(a.sender_config) if a.sender_config is not None else None
    except ConfigError as e:
        log("ERROR", "config_error", detail=str(e))
        return EXIT_CONFIG

    # 전송 중 파일 보호 (29_ §3.2 3) — 전송기 설정이 없으면 보호 없이 지우고 경고 (29_ §3.1)
    if state_path is None:
        log("WARN", "prune_no_state", detail="no --sender-config — files being sent are not protected")
        protected = set()
    else:
        protected = load_protected(state_path)

    p = Pruner(protected, a.dry_run)
    # ① 보관 기간 — 증거·입력 기록 회전 파일 (29_ §3.2)
    p.prune_age(det["evidence_path"], det["evidence_keep_s"])
    if det["input_path"] is not None:
        p.prune_age(det["input_path"], det["input_keep_s"])
        # ② 디스크 여유 하한 — 입력 기록만. 증거 파일은 작고 중요해서 하한으로 지우지 않는다 (29_ §3.2)
        p.prune_disk(det["input_path"], det["input_min_free"])
    # ③ 로그 — 지난 복사본을 먼저 지우고(자리를 비움) 상한을 넘은 로그를 복사 후 비운다 (29_ §5.2)
    seen = set()
    for lp in a.log:
        k = os.path.abspath(lp)
        if k in seen:
            continue
        seen.add(k)
        p.prune_age(lp, a.log_keep_s, protect=False)
        p.copytruncate(lp, a.log_max_bytes)

    # 끝 — 여유는 입력 기록이 있는 파일 시스템(없으면 증거 파일 쪽)에서 잰다 (29_ §7 prune_done)
    where = os.path.dirname(os.path.abspath(det["input_path"] or det["evidence_path"]))
    try:
        free = free_bytes(where)
    except OSError:
        free = None
    log("INFO", "prune_done", deleted=p.deleted, bytes=p.bytes, free_bytes=free, **p._dry())
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
