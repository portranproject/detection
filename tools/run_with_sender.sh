#!/usr/bin/env bash
# 실행 스크립트 — 전송기와 탐지 엔진을 함께 띄우고 정리한다 (19_ §2.1).
#
#   tools/run_with_sender.sh config/sender.json -- ./build/detector --socket /run/ran-detect/kpm.sock --config config/detector.json
#
# - '--' 앞은 전송기 설정 파일, 뒤는 탐지 엔진을 띄우는 명령 그대로다. 저장소 최상위에서 띄운다(p4에서는 setsid nohup으로).
# - 시작 전에 탐지 엔진 설정의 evidence.out_path와 전송기 입력 경로를 비교해 다르면 아무것도 띄우지 않는다(종료 코드 1).
# - 전송기가 오류로 끝나도 탐지 엔진은 그대로 둔다 — 대시보드 쪽 문제로 탐지가 멈추면 안 된다.
# - 탐지 엔진이 끝나거나 이 스크립트가 SIGINT·SIGTERM을 받으면: 탐지 엔진 SIGTERM → 전송기 SIGTERM →
#   'dashboard_sender.py --once'로 남은 줄을 보냄(최대 60초) → 탐지 엔진의 종료 코드로 끝난다.
# - 두 프로세스의 로그는 각자의 표준 오류 그대로 둔다(가로채지 않음). 파일로 남기려면 이 스크립트를 띄울 때 리다이렉트한다.
# - 전송기를 부를 Python은 환경 변수 PYTHON(기본 python3).
set -u

ONCE_TIMEOUT_S=60

ts() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
say() { echo "$(ts) $1 run_with_sender $2" >&2; }

usage() {
  echo "usage: $0 SENDER_CONFIG -- DETECTOR_COMMAND [ARGS...]" >&2
  exit 1
}

[ $# -ge 3 ] || usage
SENDER_CFG=$1
shift
[ "$1" = "--" ] || usage
shift

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PY=${PYTHON:-python3}
SENDER=("$PY" "$HERE/dashboard_sender.py" --config "$SENDER_CFG")

# 종료 코드의 뜻 (19_ §7)
meaning() {
  case $1 in
    0) echo "ok" ;;
    1) echo "config error" ;;
    2) echo "unexpected response from collector - check url, permissions, security group" ;;
    3) echo "TLS verification failed - check ca_file and url" ;;
    4) echo "state file save failed" ;;
    5) echo "another sender holds the state_path lock" ;;
    *) echo "unknown" ;;
  esac
}

# 시작 전 확인 (19_ §2.1 1~4): 탐지 엔진 명령에서 공백으로 띄운 '--config FILE'을 찾는다(없으면 탐지 엔진 기본값 '-').
# 경로 비교와 evidence.mode off 경고는 전송기가 한다 — 셸에서 JSON을 읽지 않는다
DET_CFG=-
ARGS=("$@")
for ((i = 0; i + 1 < ${#ARGS[@]}; i++)); do
  if [ "${ARGS[i]}" = "--config" ]; then
    DET_CFG=${ARGS[i + 1]}
  fi
done
if ! "${SENDER[@]}" --check-detector-config "$DET_CFG"; then
  say ERROR "not_started reason=path_check detector_config=$DET_CFG sender_config=$SENDER_CFG"
  exit 1
fi

# 프로세스가 끝날 때까지 기다리고 종료 코드를 RC에 남긴다. wait가 신호로 끊기면(>128) 다시 기다린다
RC=0
wait_pid() {
  local pid=$1 r
  wait "$pid"
  RC=$?
  while kill -0 "$pid" 2>/dev/null; do
    wait "$pid"
    RC=$?
  done
  # 끊긴 직후에 끝났으면 거두지 않은 종료 코드가 남아 있다 — 한 번 더 받아 본다(없으면 127)
  if [ "$RC" -gt 128 ]; then
    wait "$pid" 2>/dev/null
    r=$?
    [ "$r" -ne 127 ] && RC=$r
  fi
}

STOP=0
trap 'STOP=1' INT TERM

# 전송기를 먼저 백그라운드로, 이어서 탐지 엔진. 순서는 동작에 영향 없음 — 전송기는 파일이 생길 때까지 기다리고 처음부터 보낸다
"${SENDER[@]}" &
SENDER_PID=$!
"$@" &
DET_PID=$!
say INFO "started sender_pid=$SENDER_PID detector_pid=$DET_PID logs=stderr"

# 탐지 엔진이 끝나거나 신호가 올 때까지. 전송기가 먼저 끝나면 경고만 남기고 탐지 엔진은 계속 돈다
while :; do
  kill -0 "$DET_PID" 2>/dev/null || break
  if [ -n "$SENDER_PID" ] && ! kill -0 "$SENDER_PID" 2>/dev/null; then
    wait_pid "$SENDER_PID"
    SENDER_PID=
    say WARN "sender_exit code=$RC meaning=\"$(meaning "$RC")\" detector=running"
  fi
  [ "$STOP" -eq 1 ] && break
  sleep 0.2
done

# 정리 ① 탐지 엔진이 아직 돌면 SIGTERM
if kill -0 "$DET_PID" 2>/dev/null; then
  say INFO "stopping detector_pid=$DET_PID"
  kill -TERM "$DET_PID" 2>/dev/null
fi
wait_pid "$DET_PID"
DET_RC=$RC
say INFO "detector_exit code=$DET_RC"

# ② 전송기에 SIGTERM — 보낸 위치는 마지막 200 자리로 남는다
if [ -n "$SENDER_PID" ]; then
  kill -TERM "$SENDER_PID" 2>/dev/null
  wait_pid "$SENDER_PID"
  [ "$RC" -ne 0 ] && say WARN "sender_exit code=$RC meaning=\"$(meaning "$RC")\""
fi

# ③ 남은 줄을 한 번 더 — 그 안에 못 보낸 줄은 다음 실행 때 이어서 간다
"${SENDER[@]}" --once --once-timeout-s "$ONCE_TIMEOUT_S"
RC=$?
[ "$RC" -ne 0 ] && say WARN "final_once_exit code=$RC meaning=\"$(meaning "$RC")\""

# ④ 탐지 엔진의 종료 코드로 끝난다
exit "$DET_RC"
