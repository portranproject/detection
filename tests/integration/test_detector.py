#!/usr/bin/env python3
"""실행 파일 통합 테스트 (4_ §4-2·§4-4, 3_ §9 T20) — ctest가 부른다.

인자: <detector 경로> <저장소 경로> <임시 폴더>
1) --replay 최대 속도: T05 → RAISE·CLEAR 로그, 증거 파일, 종료 코드 0
2) T20: 같은 파일을 --speed 50으로 재생해도 ALERT 줄이 똑같다 (T03·T05)
3) 소켓: detector --socket ← mock_producer.py, 결과가 재생과 같고 SIGTERM 뒤 소켓 파일이 지워진다
4) 사용법 오류 → 2, 설정 오류 → 1, 이미 떠 있는 엔진이 있으면 → 1
5) 2단계 설정 (10/29 이슈 #33): 저장소 설정 파일(2단계 키는 기본값)이면 WARN 없이 기본값과 같은 결과, 2단계 키가
   허용 범위를 벗어나면 → 1
"""

import json
import os
import signal
import subprocess
import sys
import time

DET, REPO, TMP = sys.argv[1], sys.argv[2], sys.argv[3]
SCN = os.path.join(REPO, "tests", "data", "scenarios")
MOCK = os.path.join(REPO, "tools", "mock_producer.py")
os.makedirs(TMP, exist_ok=True)
failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)
        print("FAIL:", msg)


def config(name, **evidence):
    p = os.path.join(TMP, name + ".json")
    ev = {"out_path": os.path.join(TMP, name + "_evidence.jsonl")}
    ev.update(evidence)
    if os.path.exists(ev["out_path"]):
        os.remove(ev["out_path"])
    with open(p, "w") as f:
        json.dump({"evidence": ev}, f)
    return p, ev["out_path"]


def alerts(stdout):
    return [l for l in stdout.splitlines() if l.startswith("ALERT ")]


def replay(scenario, speed="max", cfg=None):
    cmd = [DET, "--replay", os.path.join(SCN, scenario + ".jsonl"), "--speed", speed]
    if cfg:
        cmd += ["--config", cfg]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120)


# 1) 최대 속도 재생
cfg, ev_path = config("replay")
r = replay("T05_공격종료", cfg=cfg)
check(r.returncode == 0, f"replay exit {r.returncode}: {r.stderr}")
a = alerts(r.stdout)
check(len(a) == 2 and a[0].startswith("ALERT RAISE rule=L3-01-V cell=1 t=1792209006400")
      and a[1].startswith("ALERT CLEAR rule=L3-01-V cell=1 t=1792209019800"), f"replay alerts: {a}")
with open(ev_path) as f:
    recs = [json.loads(l) for l in f]
check(recs and recs[0]["type"] == "alert" and recs[0]["event"] == "raise", "evidence file starts with raise")

# 2) T20 — 최대 속도와 배속 재생의 ALERT 줄이 같다
for scn in ("T03_공격", "T05_공격종료"):
    off, _ = config("t20_" + scn[:3], mode="off")
    fast = alerts(replay(scn, "max", off).stdout)
    paced = alerts(replay(scn, "50", off).stdout)
    check(fast and fast == paced, f"T20 {scn}: max={fast} paced={paced}")

# 3) 소켓 입력 + mock_producer
sock = os.path.join(TMP, "kpm.sock")
if os.path.exists(sock):
    os.remove(sock)
cfg, ev_path = config("socket")
det = subprocess.Popen([DET, "--socket", sock, "--config", cfg], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
for _ in range(50):
    if os.path.exists(sock):
        break
    time.sleep(0.05)
check(os.path.exists(sock), "socket file created")
# 이미 떠 있는 엔진이 있으면 두 번째 실행은 종료 코드 1 (결정 G6) — 첫 엔진에 클라이언트가 붙기 전에 확인
second = subprocess.run([DET, "--socket", sock, "--config", cfg], capture_output=True, text=True, timeout=10)
check(second.returncode == 1 and "another detector" in second.stderr, f"second instance: {second.returncode} {second.stderr}")
m = subprocess.run([sys.executable, MOCK, "--socket", sock, "--file", os.path.join(SCN, "T05_공격종료.jsonl")],
                   capture_output=True, text=True, timeout=60)
check(m.returncode == 0, f"mock_producer: {m.stderr}")
time.sleep(0.5)
det.send_signal(signal.SIGTERM)
out, err = det.communicate(timeout=10)
check(det.returncode == 0, f"socket detector exit {det.returncode}: {err}")
check(alerts(out) == a, f"socket alerts {alerts(out)} != replay {a}")
check(not os.path.exists(sock), "socket file removed on SIGTERM")
check(os.path.exists(ev_path) and os.path.getsize(ev_path) > 0, "socket evidence written")

# 4) 사용법·설정 오류
check(subprocess.run([DET], capture_output=True).returncode == 2, "usage error exit 2")
bad = os.path.join(TMP, "bad.json")
with open(bad, "w") as f:
    f.write('{"rules":{"L3-01-V":{"theta":"high"}}}')
check(subprocess.run([DET, "--replay", os.path.join(SCN, "T03_공격.jsonl"), "--config", bad],
                     capture_output=True).returncode == 1, "bad config exit 1")
check(subprocess.run([DET, "--replay", os.path.join(SCN, "T03_공격.jsonl"), "--config", os.path.join(TMP, "none.json")],
                     capture_output=True).returncode == 1, "missing config exit 1")

# 5) 2단계 설정 (4_ §1.2, 15_ §1.2, 14_ §9) — 증거 파일만 임시 폴더로 바꿔 저장소 설정 파일을 그대로 쓴다
with open(os.path.join(REPO, "config", "detector.json")) as f:
    repo_cfg = json.load(f)
repo_cfg["evidence"]["out_path"] = os.path.join(TMP, "repo_cfg_evidence.jsonl")
repo_cfg_path = os.path.join(TMP, "repo_cfg.json")
with open(repo_cfg_path, "w") as f:
    json.dump(repo_cfg, f)
r = replay("T05_공격종료", cfg=repo_cfg_path)
default_cfg, _ = config("stage2_defaults")
check(r.returncode == 0, f"repo config exit {r.returncode}: {r.stderr}")
check(" WARN " not in r.stderr, f"repo config warnings: {r.stderr}")
check(alerts(r.stdout) == alerts(replay("T05_공격종료", cfg=default_cfg).stdout), "repo config alerts differ from defaults")
for name, text, key in [("bad_l3_21", '{"rules":{"L3-21":{"reg_repeat":1}}}', "rules.L3-21.reg_repeat"),
                        ("bad_ue_table", '{"ue_table":{"max_ues":50}}', "ue_table.max_ues")]:
    p = os.path.join(TMP, name + ".json")
    with open(p, "w") as f:
        f.write(text)
    r = subprocess.run([DET, "--replay", os.path.join(SCN, "T03_공격.jsonl"), "--config", p],
                       capture_output=True, text=True)
    check(r.returncode == 1 and key + ": out of range" in r.stderr, f"{name}: exit {r.returncode} {r.stderr}")

print("OK" if not failures else f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)
