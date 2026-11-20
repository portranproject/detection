#!/usr/bin/env python3
"""가짜 분석 엔진 — .jsonl을 Unix 도메인 소켓으로 보낸다 (4_ §2·§4-4, 2_ §1).

실행: python3 tools/mock_producer.py --socket /run/ran-detect/kpm.sock --file tests/data/scenarios/T05_공격종료.jsonl [--speed max|N]

- 탐지 엔진이 서버, 이 스크립트가 클라이언트다. 접속이 안 되면 1초 간격으로 다시 시도한다(2_ §1, 최대 --retry번).
- --speed max면 바로 보내고, N이면 kpm2의 t_end_ms 간격을 N으로 나눈 만큼 기다린다(탐지 엔진 --replay와 같은 규칙).
- --pause-after N --pause-sec S: N줄을 보낸 뒤 S초 동안 전송을 멈춘다 — 입력 침묵 시험(3_ §9 T25, 14_ §10 U-T31, 이슈 #50).
- 표준 라이브러리만 쓴다.
"""

import argparse
import json
import socket
import sys
import time


def connect(path, retry):
    for i in range(retry + 1):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.connect(path)
            return s
        except OSError as e:
            s.close()
            if i == retry:
                raise SystemExit(f"cannot connect {path}: {e}")
            time.sleep(1)


def t_end_ms(line):
    try:
        return json.loads(line).get("t_end_ms")
    except (ValueError, AttributeError):
        return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--socket", required=True)
    ap.add_argument("--file", required=True)
    ap.add_argument("--speed", default="max", help="max 또는 배속 N (1 = 실시간)")
    ap.add_argument("--retry", type=int, default=10)
    ap.add_argument("--pause-after", type=int, default=0, help="이 줄 수를 보낸 뒤 --pause-sec만큼 전송을 멈춘다 (0 = 안 멈춤)")
    ap.add_argument("--pause-sec", type=float, default=0.0)
    a = ap.parse_args()
    speed = 0.0 if a.speed == "max" else float(a.speed)
    if speed < 0:
        raise SystemExit("--speed must be max or > 0")

    s = connect(a.socket, a.retry)
    wall0 = time.monotonic()
    data0 = None
    n = 0
    with open(a.file, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if speed > 0:
                t = t_end_ms(line)
                if isinstance(t, int):
                    data0 = t if data0 is None else data0
                    wait = wall0 + (t - data0) / 1000.0 / speed - time.monotonic()
                    if wait > 0:
                        time.sleep(wait)
            s.sendall(line.encode("utf-8") + b"\n")
            n += 1
            if a.pause_after and n == a.pause_after and a.pause_sec > 0:
                time.sleep(a.pause_sec)
                wall0 += a.pause_sec  # 배속 재생이면 멈춘 만큼 기준을 미뤄 몰아 보내지 않는다
    s.close()
    print(f"sent {n} lines", file=sys.stderr)


if __name__ == "__main__":
    main()
