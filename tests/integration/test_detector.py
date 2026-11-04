#!/usr/bin/env python3
"""실행 파일 통합 테스트 (4_ §4-2·§4-4, 3_ §9 T20) — ctest가 부른다.

인자: <detector 경로> <저장소 경로> <임시 폴더>
1) --replay 최대 속도: T05 → RAISE·CLEAR 로그, 증거 파일, 종료 코드 0
2) T20: 같은 파일을 --speed 50으로 재생해도 ALERT 줄이 똑같다 (T03·T05)
3) 소켓: detector --socket ← mock_producer.py, 결과가 재생과 같고 SIGTERM 뒤 소켓 파일이 지워진다
4) 사용법 오류 → 2, 설정 오류 → 1, 이미 떠 있는 엔진이 있으면 → 1
5) 2단계 설정 (10/29 이슈 #33): 저장소 설정 파일(2단계 키는 기본값)이면 WARN 없이 기본값과 같은 결과, 2단계 키가
   허용 범위를 벗어나면 → 1
6) 입력 침묵 T25·U-T31 (3_ §8·§9, 14_ §6.2·§10 — 10/29 Q-45 해결, 이슈 #50): input_silent_ms 1,000(하한)으로 띄운 소켓 모드에
   mock_producer가 RAISE 칸까지 보낸 뒤 2 s 멈추면 진단 input_silent 1회와 END reason=input_silent(t = 마지막 칸), 재개 뒤 세션 유지
   (session_reset·foreign_session 없음)와 이어지는 판정. 같은 파일을 --replay로 돌리면 END 없음. 1단계(T05)·2단계(L3-01-O) 각 1회
"""

import json
import os
import signal
import subprocess
import sys
import time

DET, REPO, TMP = sys.argv[1], sys.argv[2], sys.argv[3]
SCN = os.path.join(REPO, "tests", "data", "scenarios")
SCN2 = os.path.join(REPO, "tests", "data", "stage2_green")
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
# 설정 교차 제약 (4_ §1.2 — 11/05 W-31, 이슈 #92): 어기면 종료 코드 1. tomb 60 s < 기본 AN-04 창 300 s / short 400 s > 창 300 s
for name, text, key in [("bad_tomb", '{"ue_table":{"tomb_ms":60000}}', "ue_table.tomb_ms 60000 < rules.AN-04.window_ms"),
                        ("bad_short", '{"rules":{"AN-04":{"short_ms":400000}}}', "rules.AN-04.short_ms 400000 > rules.AN-04.window_ms")]:
    p = os.path.join(TMP, name + ".json")
    with open(p, "w") as f:
        f.write(text)
    r = subprocess.run([DET, "--replay", os.path.join(SCN, "T03_공격.jsonl"), "--config", p],
                       capture_output=True, text=True)
    check(r.returncode == 1 and key in r.stderr, f"{name}: exit {r.returncode} {r.stderr}")

# hello·설정 경계 (2_ §3, 3_ §3 — 11/05 W-31, 이슈 #92): 거대 noreply_timeout_ms는 hello를 버리고 계속 돈다(그전에는 bad_alloc 종료),
# window_ms가 period_ms의 배수가 아니면 진단 1회와 경보 없음(그전에는 무음)
huge = os.path.join(TMP, "huge_tnr.jsonl")
with open(huge, "w") as f:
    f.write('{"type":"hello","ver":1,"session":"h","seq":1,"cells":[{"cell_id":1,"max_conn":null}],"period_ms":100,'
            '"noreply_timeout_ms":1000000000000000000,"clock":"realtime"}\n')
    f.write('{"type":"kpm2","ver":1,"session":"h","seq":2,"cell_id":1,"t_start_ms":1792209000000,"t_end_ms":1792209000100,'
            '"cc":{"RRC.ConnEstabAtt":{"total":1},"RRC.ConnEstabSucc":{"total":1}}}\n')
r = subprocess.run([DET, "--replay", huge], capture_output=True, text=True)
check(r.returncode == 0 and "hello_rejected" in r.stderr and "kpm_before_hello" in r.stderr,
      f"huge T_nr: exit {r.returncode} {r.stderr[-400:]}")
mis = os.path.join(TMP, "misaligned.json")
with open(mis, "w") as f:
    f.write('{"rules":{"L3-01-V":{"window_ms":1050}}}')
r = subprocess.run([DET, "--replay", os.path.join(SCN, "T03_공격.jsonl"), "--config", mis], capture_output=True, text=True)
check(r.returncode == 0 and r.stderr.count("window_misaligned") == 1 and not alerts(r.stdout),
      f"misaligned window: exit {r.returncode} alerts {alerts(r.stdout)} {r.stderr[-400:]}")

# 6) 입력 침묵 — 소켓 모드 T25(1단계)·U-T31(2단계)와 재생 모드 대조
def silent_case(tag, scenario_path, rule):
    cfg_path = os.path.join(TMP, tag + "_silent.json")
    with open(cfg_path, "w") as f:
        json.dump({"input_silent_ms": 1000, "evidence": {"mode": "off"}}, f)
    # 재생: 같은 설정·같은 입력으로 END 없음 (벽시계 감시는 소켓 모드만). 첫 RAISE 시각을 여기서 읽는다
    rep = subprocess.run([DET, "--replay", scenario_path, "--config", cfg_path], capture_output=True, text=True, timeout=120)
    ra = [l for l in alerts(rep.stdout) if l.startswith("ALERT RAISE rule=" + rule + " ")]
    check(rep.returncode == 0 and ra, f"{tag}: replay RAISE {rep.returncode} {rep.stderr}")
    check(not any("reason=input_silent" in l for l in alerts(rep.stdout)) and "input_silent" not in rep.stderr,
          f"{tag}: replay must not watch silence: {alerts(rep.stdout)}")
    if not ra:
        return
    raise_t = int(ra[0].split(" t=")[1].split()[0])
    cell = int(ra[0].split(" cell=")[1].split()[0])
    with open(scenario_path, encoding="utf-8") as f:
        lines = f.read().splitlines()
    # RAISE가 난 kpm2 줄(그 셀, t_end_ms = RAISE t)까지 보내고 멈춘다
    n_pause = next(i + 1 for i, l in enumerate(lines)
                   if l.startswith('{"type":"kpm2"') and json.loads(l).get("cell_id") == cell
                   and json.loads(l).get("t_end_ms") == raise_t)
    sock = os.path.join(TMP, tag + "_silent.sock")
    if os.path.exists(sock):
        os.remove(sock)
    det = subprocess.Popen([DET, "--socket", sock, "--config", cfg_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True)
    for _ in range(50):
        if os.path.exists(sock):
            break
        time.sleep(0.05)
    m = subprocess.run([sys.executable, MOCK, "--socket", sock, "--file", scenario_path,
                        "--pause-after", str(n_pause), "--pause-sec", "2"], capture_output=True, text=True, timeout=60)
    check(m.returncode == 0, f"{tag}: mock_producer: {m.stderr}")
    time.sleep(0.5)
    det.send_signal(signal.SIGTERM)
    out, err = det.communicate(timeout=10)
    check(det.returncode == 0, f"{tag}: socket detector exit {det.returncode}: {err}")
    a = alerts(out)
    ends = [l for l in a if "reason=input_silent" in l]
    check(len(ends) == 1 and ends[0].startswith(f"ALERT END rule={rule} cell={cell} t={raise_t} "), f"{tag}: END {ends} all={a}")
    check(err.count("DIAG input_silent") == 1, f"{tag}: input_silent diag count: {err}")
    check("session_reset" not in err and "foreign_session" not in err and "input_lost" not in out,
          f"{tag}: state must survive the pause: {err} {a}")
    check(a and a[0] == ra[0] and a[1] == ends[0], f"{tag}: RAISE then END expected: {a}")
    return a, alerts(rep.stdout), raise_t


r6 = silent_case("t25", os.path.join(SCN, "T05_공격종료.jsonl"), "L3-01-V")
if r6:
    a, ra, raise_t = r6
    # 재개 뒤 버퍼·기준선이 그대로라 보류 없이 M = 3칸 성립에서 다시 RAISE(+300 ms), CLEAR는 재생과 같은 시각 (3_ §8)
    check(len(a) == 4 and a[2].startswith(f"ALERT RAISE rule=L3-01-V cell=1 t={raise_t + 300} ")
          and a[3].split(" duration_ms=")[0] == ra[-1].split(" duration_ms=")[0], f"T25 after resume: {a}")
silent_case("ut31", os.path.join(SCN2, "S01_L3-01-O_고착5_RAISE.jsonl"), "L3-01-O")

print("OK" if not failures else f"{len(failures)} failure(s)")
sys.exit(1 if failures else 0)
