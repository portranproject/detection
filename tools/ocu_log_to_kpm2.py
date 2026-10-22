#!/usr/bin/env python3
"""CU 로그(/tmp/ocu.log) → 탐지 엔진 입력(hello + kpm2) .jsonl 변환기.

명세: 4_ §4.1 'CU 로그를 정답으로 쓰기', 2_ §3·§4·§5. 실행:
    python3 tools/ocu_log_to_kpm2.py ocu.log -o out.jsonl [--utc-offset 9] [--cell 1]

쓰임 (4_ §4-3·§4-5): 분석 엔진이 없을 때 실제 스택 데이터로 탐지 엔진을 시험하고, 나중에 분석 엔진
카운터를 같은 시간대의 이 변환 결과와 대조한다(Q-08). 분석 엔진의 입력원으로 쓰지 않는다.

세는 규칙 (4_ §4.1 표):
- "RRC Setup Procedure" started            → Att
- "RRC Setup Procedure" finished successfully → Succ
- started 뒤 noreply_timeout(1000 ms) 안에 finished 없음 → 대기가 끝난 칸의 NoReply (2_ §5와 같은 기준)
- Unexpected UL-DCCH message type … in RRC Setup Procedure → 그 시각의 NoReply (대기 끝)
- "Sending rrcReject. Cause: DU is not able to serve the UE" → 바로 앞 UL-CCCH가 RRCSetupRequest일 때만 Att + NetworkReject
  (이때 CU는 "RRC Setup Procedure"를 시작하지 않으므로 started로는 이 시도가 빠진다)
- "Sending Connection Reject. Cause: RRC connections not allowed" → Att + NetworkReject
- "UE admission limit reached" → Att + NetworkReject
- 칸 안에서 새로 시도(started·거절)한 서로 다른 c-rnti 수 → ext.CrntiAlloc
- "timed out after 2000ms"는 OCUDU 자체 NoReply 시점(참고용)이라 세지 않는다

출력 (2_ 명세 그대로): hello 1줄 + 로그의 첫 줄 시각부터 마지막 줄 시각(대기 중 NoReply가 그 뒤면 그 시각)까지
period(100 ms) 칸을 빠짐없이(0건 칸 포함) 낸다. CU는 로그가 찍히는 동안 계속 관측하고 있었으므로 0건 칸도 실제
측정값이고, 분석 엔진도 접속이 없을 때 0건 kpm2를 보낸다 — 셀별 구간 연속성(2_ §4.1)을 지키기 위해서다. 원인별 세분은 넣지 않고 total만 낸다
(2_ §4.2 '원인을 세지 못하면 total만').
"""

import argparse
import datetime as dt
import json
import re
import sys
from collections import defaultdict

PERIOD_MS = 100
NOREPLY_MS = 1000

# 로그 한 줄 머리: 2026-10-17T14:45:14.341825 [RRC     ] [I] ...
TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s")
# ue=0 c-rnti=0x4601
UE_RE = re.compile(r"ue=(\d+)\s+c-rnti=(0x[0-9a-fA-F]+)")
CRNTI_RE = re.compile(r"c-rnti=(0x[0-9a-fA-F]+)")
# UL-CCCH 메시지 종류 — RRCSetupRequest JSON·요약 줄에 나오는 이름으로 가른다 (거절 문구가 어떤 요청에 대한 것인지)
CCCH_KINDS = (("rrcsetuprequest", "setup"), ("rrcreestablishmentrequest", "reestab"), ("rrcresumerequest", "resume"))


def parse_ts(s, utc_offset_h):
    t = dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone(dt.timedelta(hours=utc_offset_h)))
    return int(round(t.timestamp() * 1000))


def scan(lines, utc_offset_h, noreply_ms=NOREPLY_MS):
    """로그 줄들에서 사건 (시각 ms, 종류, c-rnti)을 뽑는다. 종류: att·succ·noreply·reject"""
    events = []
    span = [None, None]  # 로그의 첫·마지막 시각 — 출력 칸 범위
    pending = {}  # (ue, crnti) → started 시각 — 응답(Msg5) 대기 중
    last_ccch = None
    stats = defaultdict(int)

    def expire(now):
        # 대기 시간이 지난 것은 대기가 끝난 시각에 NoReply (2_ §5)
        for key, t0 in list(pending.items()):
            if now is None or now - t0 >= noreply_ms:
                events.append((t0 + noreply_ms, "noreply", key[1]))
                del pending[key]

    for raw in lines:
        m = TS_RE.match(raw)
        low = raw.lower()
        for name, kind in CCCH_KINDS:
            if name in low:
                last_ccch = kind
        if not m:
            continue  # 여러 줄 JSON의 이어진 줄 등
        t = parse_ts(m.group(1), utc_offset_h)
        span[0] = t if span[0] is None else span[0]
        span[1] = t
        expire(t)
        u = UE_RE.search(raw)
        key = (u.group(1), u.group(2).lower()) if u else None
        c = CRNTI_RE.search(raw)
        crnti = key[1] if key else (c.group(1).lower() if c else None)

        if '"RRC Setup Procedure" started' in raw and key:
            events.append((t, "att", key[1]))
            pending[key] = t
            stats["started"] += 1
        elif '"RRC Setup Procedure" finished successfully' in raw and key:
            events.append((t, "succ", key[1]))
            pending.pop(key, None)  # 1000 ms 뒤에 끝나도 Succ로 센다 — 분석 엔진과 같은 이중 계산 (2_ §5)
            stats["finished"] += 1
        elif "Unexpected UL-DCCH message type" in raw and "RRC Setup Procedure" in raw and key:
            if key in pending:
                del pending[key]
                events.append((t, "noreply", key[1]))
            stats["unexpected_ul_dcch"] += 1
        elif "Sending rrcReject. Cause: DU is not able to serve the UE" in raw:
            # 같은 문구가 재수립·재개 거절에도 나오므로 바로 앞 UL-CCCH가 RRCSetupRequest일 때만 (4_ §4.1)
            if last_ccch == "setup":
                events.append((t, "att", crnti))
                events.append((t, "reject", crnti))
                stats["reject_du"] += 1
            else:
                stats["reject_du_not_setup"] += 1
        elif "Sending Connection Reject. Cause: RRC connections not allowed" in raw:
            events.append((t, "att", crnti))
            events.append((t, "reject", crnti))
            stats["reject_not_allowed"] += 1
        elif "UE admission limit reached" in raw:
            events.append((t, "att", crnti))
            events.append((t, "reject", crnti))
            stats["reject_admission"] += 1
        elif "timed out after" in raw and "RRC Setup Procedure" in raw:
            stats["ocudu_timeout_ref"] += 1  # 참고용 — 세지 않음
    expire(None)  # 파일 끝: 남은 대기는 모두 NoReply
    events.sort(key=lambda e: e[0])
    stats["span_ms"] = tuple(span) if span[0] is not None else None
    return events, dict(stats)


def to_jsonl(events, session, cell_id, period_ms=PERIOD_MS, noreply_ms=NOREPLY_MS, span=None):
    """사건을 period 칸으로 묶어 hello + kpm2 줄들을 만든다 (2_ §3·§4)"""
    hello = {"type": "hello", "ver": 1, "session": session, "seq": 1, "producer": "ocu_log_to_kpm2",
             "node_id": "ocu-log", "cells": [{"cell_id": cell_id, "max_conn": None}],
             "period_ms": period_ms, "noreply_timeout_ms": noreply_ms, "si_sample_ms": period_ms,
             "clock": "realtime"}
    out = [hello]
    times = [e[0] for e in events] + [t for t in (span or ()) if t is not None]
    if not times:
        return out
    first = min(times) // period_ms * period_ms
    last = max(times) // period_ms * period_ms + period_ms
    bins = defaultdict(lambda: {"att": 0, "succ": 0, "noreply": 0, "reject": 0, "crnti": set()})
    for t, kind, crnti in events:
        b = bins[t // period_ms * period_ms]
        b[kind] += 1
        if kind == "att" and crnti:
            b["crnti"].add(crnti)
    seq = 1
    for ts in range(first, last, period_ms):
        b = bins.get(ts) or {"att": 0, "succ": 0, "noreply": 0, "reject": 0, "crnti": set()}
        seq += 1
        out.append({"type": "kpm2", "ver": 1, "session": session, "seq": seq, "cell_id": cell_id,
                    "t_start_ms": ts, "t_end_ms": ts + period_ms,
                    "cc": {"RRC.ConnEstabAtt": {"total": b["att"]},
                           "RRC.ConnEstabSucc": {"total": b["succ"]},
                           "RRC.ConnEstabFailCause": {"NetworkReject": b["reject"], "NoReply": b["noreply"],
                                                      "Other": 0}},
                    "ext": {"CrntiAlloc": len(b["crnti"])}})
    return out


def main():
    ap = argparse.ArgumentParser(description="CU 로그(/tmp/ocu.log) → hello + kpm2 .jsonl")
    ap.add_argument("log")
    ap.add_argument("-o", "--output", default="-")
    ap.add_argument("--utc-offset", type=float, default=0.0, help="로그 시각의 UTC 기준 시간대(시간). 기본 0 = UTC")
    ap.add_argument("--cell", type=int, default=1, help="cell_id (CU 로그에 셀 구분이 없으면 1)")
    ap.add_argument("--session", default=None, help="session 이름 (기본: 첫 사건 시각)")
    a = ap.parse_args()

    with open(a.log, encoding="utf-8", errors="replace") as f:
        events, stats = scan(f, a.utc_offset)
    session = a.session or (f"ocu-{events[0][0]}" if events else "ocu-empty")
    lines = to_jsonl(events, session, a.cell, span=stats.get("span_ms"))
    out = sys.stdout if a.output == "-" else open(a.output, "w", encoding="utf-8")
    for line in lines:
        out.write(json.dumps(line, ensure_ascii=False, separators=(",", ":")) + "\n")
    if out is not sys.stdout:
        out.close()
    kinds = defaultdict(int)
    for _, k, _ in events:
        kinds[k] += 1
    print(f"events: {dict(kinds)}  log lines: {stats}  kpm2 slots: {len(lines) - 1}", file=sys.stderr)


if __name__ == "__main__":
    main()
