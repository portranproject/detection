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
# - 로그: LOG_DIR(환경 변수)을 주지 않으면 두 프로세스의 로그는 각자의 표준 오류 그대로 둔다(가로채지 않음).
#   11/08 (이슈 #102, 29_ §5.2): LOG_DIR을 주면 그 폴더를 만들고 이어 쓰기(>>)로 남긴다 — detector.out(탐지 엔진 표준 출력),
#   detector.log(탐지 엔진 표준 오류), sender.log(전송기 표준 오류, 상주 + 마무리 --once), run_with_sender.log(이 스크립트와 정리 도구).
#   오래 돌릴 때: LOG_DIR=logs setsid nohup tools/run_with_sender.sh config/sender.json -- ./build/detector ... >/dev/null 2>&1 &
# - 11/08 (이슈 #102, 29_ §5.1·19_ §2.1): 시작 전 확인을 통과하면 두 프로세스를 띄우기 전에 정리 도구(tools/prune_outputs.py)를
#   한 번 부르고, 그 뒤 PRUNE_INTERVAL_S(환경 변수, 기본 3600초)마다 부른다. 0이면 정리 도구를 부르지 않는다(시작 때도).
#   보관 기간이 지난 회전 파일을 지우되 전송기 상태 파일에 적힌 파일은 남긴다. 정리 도구가 실패해도 경고만 — 탐지는 멈추지 않는다.
#   LOG_DIR이 있으면 네 로그를 --log로 넘겨 LOG_MAX_BYTES(기본 67108864 = 64 MiB)를 넘은 것을 복사 후 비우고,
#   복사본은 LOG_KEEP_S(기본 604800초 = 7일)가 지나면 지운다.
# - 전송기·정리 도구를 부를 Python은 환경 변수 PYTHON(기본 python3).
set -u

ONCE_TIMEOUT_S=60
PRUNE_INTERVAL_S=${PRUNE_INTERVAL_S:-3600}
LOG_DIR=${LOG_DIR:-}
LOG_MAX_BYTES=${LOG_MAX_BYTES:-67108864}
LOG_KEEP_S=${LOG_KEEP_S:-604800}

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

# 11/08 (이슈 #102, 29_ §5): 환경 변수는 0 이상의 정수만 — 틀리면 아무것도 띄우지 않는다(정리·로그 정리가 조용히 꺼지지 않게)
for v in PRUNE_INTERVAL_S LOG_MAX_BYTES LOG_KEEP_S; do
  if ! [[ ${!v} =~ ^(0|[1-9][0-9]{0,17})$ ]]; then  # 앞자리 0(8진수로 읽힘)·너무 큰 수는 받지 않는다
    say ERROR "not_started reason=bad_env $v=${!v} (must be a non-negative integer)"
    exit 1
  fi
done

# 로그 파일 (29_ §5.2): LOG_DIR이 있으면 이 스크립트의 표준 오류부터 run_with_sender.log에 이어 쓴다 — 이어 쓰기로 열어야
# 정리 도구의 copytruncate(복사 후 비우기) 뒤 다음 줄이 원본 처음에 간다. 폴더를 만들 수 없으면 아무것도 띄우지 않는다
PRUNE_LOG_ARGS=()
if [ -n "$LOG_DIR" ]; then
  if ! mkdir -p "$LOG_DIR" || ! : >>"$LOG_DIR/run_with_sender.log"; then
    say ERROR "not_started reason=log_dir LOG_DIR=$LOG_DIR"
    exit 1
  fi
  exec 2>>"$LOG_DIR/run_with_sender.log"
  PRUNE_LOG_ARGS=(--log "$LOG_DIR/detector.out" --log "$LOG_DIR/detector.log" --log "$LOG_DIR/sender.log"
                  --log "$LOG_DIR/run_with_sender.log" --log-max-bytes "$LOG_MAX_BYTES" --log-keep-s "$LOG_KEEP_S")
fi

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

# 정리 도구 (29_ §3·§5.1): 탐지 엔진 설정(시작 전 확인에서 찾은 --config)과 전송기 설정을 넘긴다.
# 실패해도(종료 코드 ≠ 0) 경고만 — 정리가 안 된다고 탐지를 멈추지 않는다 (29_ §3.3)
run_prune() {
  local rc
  "$PY" "$HERE/prune_outputs.py" --detector-config "$DET_CFG" --sender-config "$SENDER_CFG" \
    ${PRUNE_LOG_ARGS[@]+"${PRUNE_LOG_ARGS[@]}"}
  rc=$?
  [ "$rc" -ne 0 ] && say WARN "prune_exit code=$rc detail=\"prune failed - detector keeps running\""
  NEXT_PRUNE=$((SECONDS + PRUNE_INTERVAL_S))
}
NEXT_PRUNE=0
[ "$PRUNE_INTERVAL_S" -gt 0 ] && run_prune

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
# LOG_DIR이 있으면 전송기 표준 오류 → sender.log, 탐지 엔진 표준 출력 → detector.out·표준 오류 → detector.log (모두 이어 쓰기, 29_ §5.2)
if [ -n "$LOG_DIR" ]; then
  "${SENDER[@]}" 2>>"$LOG_DIR/sender.log" &
  SENDER_PID=$!
  "$@" >>"$LOG_DIR/detector.out" 2>>"$LOG_DIR/detector.log" &
  DET_PID=$!
  say INFO "started sender_pid=$SENDER_PID detector_pid=$DET_PID logs=$LOG_DIR"
else
  "${SENDER[@]}" &
  SENDER_PID=$!
  "$@" &
  DET_PID=$!
  say INFO "started sender_pid=$SENDER_PID detector_pid=$DET_PID logs=stderr"
fi

# 탐지 엔진이 끝나거나 신호가 올 때까지. 전송기가 먼저 끝나면 경고만 남기고 탐지 엔진은 계속 돈다.
# 기다리는 동안 PRUNE_INTERVAL_S마다 정리 도구를 부른다 (29_ §5.1 — bash SECONDS로 잰다)
while :; do
  kill -0 "$DET_PID" 2>/dev/null || break
  if [ -n "$SENDER_PID" ] && ! kill -0 "$SENDER_PID" 2>/dev/null; then
    wait_pid "$SENDER_PID"
    SENDER_PID=
    say WARN "sender_exit code=$RC meaning=\"$(meaning "$RC")\" detector=running"
  fi
  [ "$STOP" -eq 1 ] && break
  if [ "$PRUNE_INTERVAL_S" -gt 0 ] && [ "$SECONDS" -ge "$NEXT_PRUNE" ]; then
    run_prune
  fi
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
if [ -n "$LOG_DIR" ]; then
  "${SENDER[@]}" --once --once-timeout-s "$ONCE_TIMEOUT_S" 2>>"$LOG_DIR/sender.log"
else
  "${SENDER[@]}" --once --once-timeout-s "$ONCE_TIMEOUT_S"
fi
RC=$?
[ "$RC" -ne 0 ] && say WARN "final_once_exit code=$RC meaning=\"$(meaning "$RC")\""

# ④ 탐지 엔진의 종료 코드로 끝난다
exit "$DET_RC"
