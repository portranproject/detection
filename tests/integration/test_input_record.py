#!/usr/bin/env python3
"""입력 원본 기록 통합 시험 (24_ §3, §8.1 IR-T1~T11·T13) — ctest가 부른다. 단위 시험(IR-T12 등)은 tests/io/test_input_recorder.cpp.

인자: <detector 경로> <저장소 경로> <임시 폴더>
- IR-T1·T2: tests/data/의 모든 재생 파일 — 기록 파일 = 재생 파일(바이트), 기록 켬·끔의 stdout·증거 파일·종료 코드가 같음
- IR-T3: 기록 파일을 다시 재생하면 원래와 같은 출력
- IR-T4: 소켓 모드(mock_producer) — 보낸 줄 = 기록(바이트), 그 기록을 재생하면 같은 ALERT
- IR-T5: 64 KiB 넘는 줄·끊길 때 반쪽 줄은 기록되지 않음
- IR-T6: 형식 오류·hello 전 kpm2·seq 역행·빈 줄도 기록됨
- IR-T7: 이어 쓰기 / IR-T8: 열기 실패 → 1 / IR-T9: 설정 오류 → 1, 모르는 키 → 경고 / IR-T10: /dev/full / IR-T11: 끔(기본)
- IR-T13: 소켓 모드에서 보낸 직후 SIGTERM — 받은 줄이 모두 기록된 뒤 끝남(written = 파일 줄 수, dropped 0)
- RT-T12 (29_ §2.6·§8.1, 이슈 #102): 재생 모드 + 회전 켠 설정 — 회전 파일 없음, 출력·기록이 회전 끈 실행과 바이트 동일
- RT-T13 (29_ §8.1, 이슈 #102): 소켓 모드 + 크기 상한 1 MiB — 회전 파일 여러 개, 회전 파일(이름 시각 순) + 지금 파일 = 받은 줄(바이트)
표준 라이브러리만 쓴다.
"""

import glob
import json
import os
import re
import signal
import socket
import subprocess
import sys
import time

DET, REPO, TMP = (os.path.abspath(a) for a in sys.argv[1:4])  # IR-T9·T11은 작업 폴더를 바꿔 띄운다
DATA = os.path.join(REPO, "tests", "data")
SCN = os.path.join(DATA, "scenarios")
MOCK = os.path.join(REPO, "tools", "mock_producer.py")
MAX_LINE = 65536
os.makedirs(TMP, exist_ok=True)
failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("FAIL:", msg)


def rm(*paths):
    for p in paths:
        if os.path.exists(p):
            os.remove(p)


def read(p):
    with open(p, "rb") as f:
        return f.read()


def write_cfg(name, cfg):
    p = os.path.join(TMP, name + ".json")
    with open(p, "w") as f:
        json.dump(cfg, f)
    return p


def run(args, cwd=None, timeout=120):
    return subprocess.run([DET] + args, capture_output=True, text=True, timeout=timeout, cwd=cwd)


def alerts(stdout):
    return [l for l in stdout.splitlines() if l.startswith("ALERT ")]


def expected_record(data):
    """재생이 엔진에 넘기는 줄 = 파일의 줄(상한 넘는 줄 빼고), 각 줄 끝에 \\n (24_ §3.2)."""
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return b"".join(l + b"\n" for l in lines if len(l) <= MAX_LINE)


def rec_logs(stderr):
    """탐지 엔진의 입력 기록 로그 줄 — `시각 수준 input_record…` (24_ §3.4). 경로에 든 글자와 섞이지 않게 머리로 찾는다."""
    return re.findall(r"^\S+ (?:INFO|WARN|ERROR) input_record\S*", stderr, re.M)


def end_log(stderr):
    m = re.search(r"input_record written=(\d+) dropped=(\d+) rotated=\d+ to ", stderr)
    return (int(m.group(1)), int(m.group(2))) if m else None


def end_rotated(stderr, name):
    """끝 로그의 rotated=N (29_ §7) — name은 evidence 또는 input_record."""
    m = re.search(r"INFO " + name + r" written=\d+ dropped=\d+ rotated=(\d+) to ", stderr)
    return int(m.group(1)) if m else None


def rotated_files(path):
    """회전 파일을 이름 시각 → 번호 순(없는 것이 먼저)으로 (29_ §2.3 이름 규칙)."""
    d, base = os.path.split(path)
    rx = re.compile(re.escape(base) + r"\.(\d{8}-\d{6})(?:\.(\d{1,2}))?")
    found = []
    for n in os.listdir(d):
        m = rx.fullmatch(n)
        if m:
            found.append((m.group(1), int(m.group(2) or 0), os.path.join(d, n)))
    return [f[2] for f in sorted(found)]


def fresh_dir(name):
    d = os.path.join(TMP, name)
    os.makedirs(d, exist_ok=True)
    for n in os.listdir(d):
        os.remove(os.path.join(d, n))
    return d


EV_ON, EV_OFF, REC = (os.path.join(TMP, n) for n in ("ev_on.jsonl", "ev_off.jsonl", "rec.jsonl"))
CFG_ON = write_cfg("on", {"evidence": {"out_path": EV_ON}, "input_record": {"path": REC}})
CFG_OFF = write_cfg("off", {"evidence": {"out_path": EV_OFF}})


def replay_pair(path):
    """같은 파일을 기록 켬·끔으로 재생한다 — (켬 결과, 끔 결과, 기록 바이트, 켬 증거, 끔 증거)."""
    rm(EV_ON, EV_OFF, REC)
    on = run(["--replay", path, "--config", CFG_ON])
    off = run(["--replay", path, "--config", CFG_OFF])
    rec = read(REC) if os.path.exists(REC) else None
    ev_on = read(EV_ON) if os.path.exists(EV_ON) else b""
    ev_off = read(EV_OFF) if os.path.exists(EV_OFF) else b""
    return on, off, rec, ev_on, ev_off


# IR-T1·T2 — 모든 재생 파일
files = sorted(glob.glob(os.path.join(DATA, "**", "*.jsonl"), recursive=True))
check(len(files) >= 100, f"too few data files: {len(files)}")
for path in files:
    name = os.path.relpath(path, DATA)
    on, off, rec, ev_on, ev_off = replay_pair(path)
    check(rec == expected_record(read(path)), f"IR-T1 {name}: record differs from input")
    check(on.returncode == off.returncode == 0, f"IR-T2 {name}: exit {on.returncode}/{off.returncode} {on.stderr[-300:]}")
    check(on.stdout == off.stdout, f"IR-T2 {name}: stdout differs")
    check(ev_on == ev_off, f"IR-T2 {name}: evidence differs")
    n = expected_record(read(path)).count(b"\n")
    check(end_log(on.stderr) == (n, 0), f"IR-T2 {name}: end log {end_log(on.stderr)} != ({n}, 0)")
    check(not rec_logs(off.stderr), f"IR-T11 {name}: recording off must not log input_record")

# IR-T3 — 기록 파일을 다시 재생하면 원래와 같은 출력
for rel in ("scenarios/T05_공격종료.jsonl", "stage2_green/S01_L3-01-O_고착10_RAISE.jsonl"):
    src = os.path.join(DATA, rel)
    on, _, rec, ev_on, _ = replay_pair(src)
    again = os.path.join(TMP, "again.jsonl")
    with open(again, "wb") as f:
        f.write(rec or b"")
    rm(EV_OFF)
    r = run(["--replay", again, "--config", CFG_OFF])
    check(r.returncode == 0 and r.stdout == on.stdout, f"IR-T3 {rel}: replay of record differs")
    check(read(EV_OFF) == ev_on if os.path.exists(EV_OFF) else ev_on == b"", f"IR-T3 {rel}: evidence of record differs")


def start_socket(tag, cfg):
    sock = os.path.join(TMP, tag + ".sock")
    rm(sock)
    det = subprocess.Popen([DET, "--socket", sock, "--config", cfg], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True)
    for _ in range(100):
        if os.path.exists(sock):
            break
        time.sleep(0.05)
    check(os.path.exists(sock), f"{tag}: socket file created")
    return det, sock


def wait_size(path, size, timeout=10.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if os.path.exists(path) and os.path.getsize(path) >= size:
            return True
        time.sleep(0.05)
    return False


def stop(det):
    det.send_signal(signal.SIGTERM)
    out, err = det.communicate(timeout=20)
    return det.returncode, out, err


# IR-T4 — 소켓 모드: 보낸 줄 = 기록, 그 기록을 재생하면 같은 ALERT
for rel in ("scenarios/T05_공격종료.jsonl", "stage2_green/S01_L3-01-O_고착10_RAISE.jsonl"):
    src = os.path.join(DATA, rel)
    rm(EV_ON, REC)
    det, sock = start_socket("t4", CFG_ON)
    m = subprocess.run([sys.executable, MOCK, "--socket", sock, "--file", src], capture_output=True, text=True, timeout=60)
    check(m.returncode == 0, f"IR-T4 {rel}: mock_producer {m.stderr}")
    want = read(src)
    check(wait_size(REC, len(want)), f"IR-T4 {rel}: record did not reach {len(want)} bytes")
    rc, out, err = stop(det)
    check(rc == 0, f"IR-T4 {rel}: exit {rc} {err[-300:]}")
    check(read(REC) == want, f"IR-T4 {rel}: record differs from sent lines")
    r = run(["--replay", REC, "--config", CFG_OFF])
    check(alerts(r.stdout) == alerts(out) and alerts(out), f"IR-T4 {rel}: replay of record {alerts(r.stdout)} != socket {alerts(out)}")

# IR-T5 — 64 KiB 넘는 줄과 끊길 때 반쪽 줄은 엔진에 닿지 않아 기록되지 않는다
with open(os.path.join(SCN, "T05_공격종료.jsonl"), "rb") as f:
    t05 = f.read().split(b"\n")
hello, kpm_a, kpm_b = t05[0], t05[1], t05[2]
rm(EV_ON, REC)
det, sock = start_socket("t5", CFG_ON)
c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
c.connect(sock)
c.sendall(hello + b"\n" + kpm_a + b"\n" + b"x" * (MAX_LINE + 10) + b"\n" + kpm_b + b"\n" + b'{"type":"kpm2","partial')
time.sleep(0.3)
c.close()
want = hello + b"\n" + kpm_a + b"\n" + kpm_b + b"\n"
check(wait_size(REC, len(want)), "IR-T5: record did not reach expected size")
time.sleep(0.3)
rc, out, err = stop(det)
check(rc == 0, f"IR-T5: exit {rc}")
check(read(REC) == want, f"IR-T5: record {read(REC)[:200]!r}")
check("discarded partial line" in err and "exceeds" in err, f"IR-T5: server events missing: {err[-500:]}")

# IR-T6 — 엔진이 버리는 줄(형식 오류·hello 전 kpm2·빈 줄·seq 역행)도 기록된다
odd = os.path.join(TMP, "odd.jsonl")
with open(odd, "wb") as f:
    f.write(kpm_a + b"\n" + b"not json\n" + b"\n" + hello + b"\n" + kpm_a + b"\n" + kpm_b + b"\n" + kpm_a + b"\n")
on, off, rec, ev_on, ev_off = replay_pair(odd)
check(rec == read(odd), f"IR-T6: record {rec!r}")
check(on.stdout == off.stdout and ev_on == ev_off, "IR-T6: outputs differ")
check("DIAG" in on.stderr, "IR-T6: engine should report the odd lines")

# IR-T7 — 이어 쓰기
rm(REC)
for _ in range(2):
    run(["--replay", os.path.join(SCN, "T03_공격.jsonl"), "--config", CFG_ON])
check(read(REC) == read(os.path.join(SCN, "T03_공격.jsonl")) * 2, "IR-T7: record must append across runs")

# IR-T8 — 열기 실패 → 종료 코드 1, 파일이 생기지 않음
bad_rec = os.path.join(TMP, "no_such_dir", "rec.jsonl")
r = run(["--replay", os.path.join(SCN, "T03_공격.jsonl"), "--config",
         write_cfg("t8", {"evidence": {"out_path": EV_ON}, "input_record": {"path": bad_rec}})])
check(r.returncode == 1 and "cannot open input record file" in r.stderr, f"IR-T8: {r.returncode} {r.stderr[-300:]}")
check(not os.path.exists(bad_rec), "IR-T8: record file must not exist")

# IR-T9 — 설정: 증거 파일과 같은 경로(상대·절대·./, evidence.mode off여도) → 1, 빈 문자열·범위 밖 → 1, 모르는 키 → 경고
cwd = os.path.join(TMP, "t9")
os.makedirs(cwd, exist_ok=True)
t03 = os.path.join(SCN, "T03_공격.jsonl")
for tag, ev, rec, extra in [("rel", "same.jsonl", "same.jsonl", {}),
                            ("abs", "same.jsonl", os.path.join(cwd, "same.jsonl"), {}),
                            ("dot", "./same.jsonl", "same.jsonl", {}),
                            ("off", "same.jsonl", "same.jsonl", {"mode": "off"})]:
    evd = {"out_path": ev}
    evd.update(extra)
    r = run(["--replay", t03, "--config", write_cfg("t9_" + tag, {"evidence": evd, "input_record": {"path": rec}})], cwd=cwd)
    check(r.returncode == 1 and "same file as evidence.out_path" in r.stderr, f"IR-T9 {tag}: {r.returncode} {r.stderr[-300:]}")
for tag, ir, key in [("empty", {"path": ""}, "input_record.path"),
                     ("range", {"path": "r.jsonl", "queue_max_bytes": 1}, "input_record.queue_max_bytes")]:
    r = run(["--replay", t03, "--config", write_cfg("t9_" + tag, {"input_record": ir})], cwd=cwd)
    check(r.returncode == 1 and key in r.stderr, f"IR-T9 {tag}: {r.returncode} {r.stderr[-300:]}")
rm(os.path.join(cwd, "r.jsonl"))
r = run(["--replay", t03, "--config", write_cfg("t9_unknown", {"evidence": {"mode": "off"},
                                                               "input_record": {"path": "r.jsonl", "pth": 1}})], cwd=cwd)
check(r.returncode == 0 and "unknown key input_record.pth" in r.stderr, f"IR-T9 unknown: {r.returncode} {r.stderr[-300:]}")
check(os.path.exists(os.path.join(cwd, "r.jsonl")), "IR-T9 unknown: relative record path is under the working folder")

# IR-T10 — 쓰기 오류(/dev/full): 오류 로그 한 번, 판정은 그대로, 종료 코드 0, written 0
if os.access("/dev/full", os.W_OK):
    t05p = os.path.join(SCN, "T05_공격종료.jsonl")
    rm(EV_ON, EV_OFF)
    full = run(["--replay", t05p, "--config", write_cfg("t10", {"evidence": {"out_path": EV_ON},
                                                                "input_record": {"path": "/dev/full"}})])
    off = run(["--replay", t05p, "--config", CFG_OFF])
    n = expected_record(read(t05p)).count(b"\n")
    check(full.returncode == 0, f"IR-T10: exit {full.returncode}")
    check(sum(1 for l in rec_logs(full.stderr) if l.endswith("input_record_error")) == 1,
          f"IR-T10: error log count: {full.stderr[-500:]}")
    check(full.stdout == off.stdout and read(EV_ON) == read(EV_OFF), "IR-T10: outputs must not change")
    check(end_log(full.stderr) == (0, n), f"IR-T10: end log {end_log(full.stderr)} != (0, {n})")
else:
    print("SKIP IR-T10: /dev/full not available")

# IR-T11 — 끔(기본·저장소 설정): 기록 파일·로그 없음
cwd11 = os.path.join(TMP, "t11")
os.makedirs(cwd11, exist_ok=True)
rm(os.path.join(cwd11, "input.jsonl"), os.path.join(cwd11, "evidence.jsonl"))
r = run(["--replay", t03], cwd=cwd11)
r2 = run(["--replay", t03, "--config", os.path.join(REPO, "config", "detector.json")], cwd=cwd11)
check(r.returncode == 0 and r2.returncode == 0, "IR-T11: exit")
check(not rec_logs(r.stderr + r2.stderr), "IR-T11: no input_record log when off")
check(not os.path.exists(os.path.join(cwd11, "input.jsonl")), "IR-T11: no record file when off")

# IR-T13 — 소켓 모드에서 보낸 직후 SIGTERM: 받은 줄은 모두 기록된 뒤 끝난다
src = os.path.join(DATA, "stage4_yellow", "SAN04_AN-04_지속공격_CLEAR.jsonl")
rm(EV_ON, REC)
det, sock = start_socket("t13", CFG_ON)
m = subprocess.run([sys.executable, MOCK, "--socket", sock, "--file", src], capture_output=True, text=True, timeout=60)
check(m.returncode == 0, f"IR-T13: mock_producer {m.stderr}")
rc, out, err = stop(det)  # 기다리지 않고 바로
rec = read(REC)
n13 = rec.count(b"\n")
check(rc == 0, f"IR-T13: exit {rc}")
check(rec.endswith(b"\n") and read(src).startswith(rec), "IR-T13: record must be a line prefix of the sent file")
check(end_log(err) == (n13, 0), f"IR-T13: end log {end_log(err)} vs {n13} lines")

# RT-T12 (29_ §2.6·§8.1) — 재생 모드 + 회전 켠 설정(주기 60 s·크기 1 MiB): 재생 입력이 1 MiB를 넘어도 회전하지 않는다. 기록·stdout·
# 증거가 회전 끈 실행과 바이트 동일, 'rotation off in replay' 한 번, 끝 로그 rotated=0
big_srcs = [os.path.join(DATA, "stage4_yellow", n) for n in ("SAN04_AN-04_지속공격_CLEAR.jsonl", "SAN08_AN-08_지속공격_CLEAR.jsonl")]
big = os.path.join(TMP, "rt12_big.jsonl")
with open(big, "wb") as f:
    for p in big_srcs:
        f.write(read(p))
check(len(read(big)) > 2 * 1048576, "RT-T12: replay input must exceed the size cap")
d12 = fresh_dir("rt12")
ev12, rec12 = os.path.join(d12, "evidence.jsonl"), os.path.join(d12, "input.jsonl")
rot_cfg = {"rotate_s": 60, "rotate_max_bytes": 1048576}
cfg12 = write_cfg("rt12", {"evidence": dict({"out_path": ev12}, **rot_cfg), "input_record": dict({"path": rec12}, **rot_cfg)})
rm(EV_ON, REC)
on = run(["--replay", big, "--config", cfg12])
off = run(["--replay", big, "--config", CFG_ON])
check(on.returncode == 0 and off.returncode == 0, f"RT-T12: exit {on.returncode}/{off.returncode} {on.stderr[-300:]}")
check(sorted(os.listdir(d12)) == ["evidence.jsonl", "input.jsonl"], f"RT-T12: files {sorted(os.listdir(d12))}")
check(read(rec12) == read(REC) == expected_record(read(big)), "RT-T12: record differs")
check(read(ev12) == read(EV_ON), "RT-T12: evidence differs from rotation-off run")
check(on.stdout == off.stdout, "RT-T12: stdout differs from rotation-off run")
check(on.stderr.count("rotation off in replay") == 1 and "rotation off in replay" not in off.stderr,
      f"RT-T12: replay notice {on.stderr.count('rotation off in replay')}")
check(end_rotated(on.stderr, "evidence") == 0 and end_rotated(on.stderr, "input_record") == 0,
      f"RT-T12: end logs {end_rotated(on.stderr, 'evidence')} {end_rotated(on.stderr, 'input_record')}")
check("_rotate" not in on.stderr, "RT-T12: no rotation logs in replay")

# RT-T13 (29_ §8.1) — 소켓 모드 + 작은 크기 상한(1 MiB): 회전 파일이 여러 개 생기고, 회전 파일(이름 시각 순) + 지금 파일을 이으면
# 받은 줄과 바이트 동일. 회전 로그 수 = 회전 파일 수 = 끝 로그 rotated. 증거도 이으면 같은 입력의 재생(회전 끔)과 바이트 동일
srcs13 = [os.path.join(DATA, "stage4_yellow", n) for n in ("SAN04_AN-04_지속공격_CLEAR.jsonl", "SAN08_AN-08_지속공격_CLEAR.jsonl",
                                                          "SAN07_AN-07_지속공격_CLEAR.jsonl",
                                                          "SAN04_AN-04_CLEAR뒤다른STMSI_RAISE.jsonl")]
want13 = b"".join(read(p) for p in srcs13)
d13 = fresh_dir("rt13")
ev13, rec13 = os.path.join(d13, "evidence.jsonl"), os.path.join(d13, "input.jsonl")
cfg13 = write_cfg("rt13", {"evidence": {"out_path": ev13, "rotate_max_bytes": 1048576},
                           "input_record": {"path": rec13, "rotate_max_bytes": 1048576}})
# 같은 세션 이름이 다시 오면 줄마다 진단(seq_regress)이 표준 오류로 나온다 — 파이프가 차서 탐지 엔진이 막히지 않게 파일로 받는다
sock = os.path.join(TMP, "rt13.sock")
rm(sock)
out13_path, err13_path = os.path.join(TMP, "rt13.out"), os.path.join(TMP, "rt13.err")
with open(out13_path, "wb") as fo, open(err13_path, "wb") as fe:
    det = subprocess.Popen([DET, "--socket", sock, "--config", cfg13], stdout=fo, stderr=fe)
for _ in range(100):
    if os.path.exists(sock):
        break
    time.sleep(0.05)
check(os.path.exists(sock), "RT-T13: socket file created")
for p in srcs13:
    m = subprocess.run([sys.executable, MOCK, "--socket", sock, "--file", p], capture_output=True, text=True, timeout=120)
    check(m.returncode == 0, f"RT-T13: mock_producer {p} {m.stderr}")


def total13():
    return sum(os.path.getsize(f) for f in rotated_files(rec13) + [rec13] if os.path.exists(f))


end13 = time.monotonic() + 30
while time.monotonic() < end13 and total13() < len(want13):
    time.sleep(0.05)
det.send_signal(signal.SIGTERM)
rc = det.wait(timeout=30)
with open(out13_path, encoding="utf-8") as f:
    out = f.read()
with open(err13_path, encoding="utf-8") as f:
    err = f.read()
check(rc == 0, f"RT-T13: exit {rc} {err[-300:]}")
rot13 = rotated_files(rec13)
check(len(rot13) >= 2, f"RT-T13: rotated files {rot13}")
got13 = b"".join(read(f) for f in rot13) + read(rec13)
check(got13 == want13, f"RT-T13: concatenated record {len(got13)} != sent {len(want13)} bytes")
check(all(read(f).endswith(b"\n") for f in rot13), "RT-T13: rotated files must end with a newline")
rot_logs = re.findall(r"^\S+ INFO input_record_rotate to=(\S+) reason=(\w+) bytes=(\d+)$", err, re.M)
check(len(rot_logs) == len(rot13) == end_rotated(err, "input_record"),
      f"RT-T13: rotate logs {len(rot_logs)} files {len(rot13)} end {end_rotated(err, 'input_record')}")
check([t for t, _, _ in rot_logs] == rot13 and all(r == "size" for _, r, _ in rot_logs),
      f"RT-T13: rotate logs {rot_logs[:3]}")
check(all(int(b) == os.path.getsize(t) for t, _, b in rot_logs), "RT-T13: bytes= in log must equal rotated file size")
check(end_log(err) == (got13.count(b"\n"), 0), f"RT-T13: end log {end_log(err)}")
ev_rot13 = rotated_files(ev13)
ev_all13 = b"".join(read(f) for f in ev_rot13) + read(ev13)
again13 = os.path.join(TMP, "rt13_again.jsonl")
with open(again13, "wb") as f:
    f.write(got13)
rm(EV_OFF)
r13 = run(["--replay", again13, "--config", CFG_OFF])
check(r13.returncode == 0 and alerts(r13.stdout) == alerts(out), "RT-T13: alerts differ from replay of the record")
check(ev_all13 == read(EV_OFF), f"RT-T13: concatenated evidence ({len(ev_rot13)} rotated) differs from replay")
check(len(re.findall(r"INFO evidence_rotate to=", err)) == len(ev_rot13) == end_rotated(err, "evidence"),
      f"RT-T13: evidence rotations {len(ev_rot13)} end {end_rotated(err, 'evidence')}")

print("OK" if not failures else f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)
