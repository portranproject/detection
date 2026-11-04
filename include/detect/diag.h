#pragma once
// core가 내는 진단 레코드. core는 I/O를 하지 않으므로(4_ §2) 로그를 직접 찍지 않고
// 이 레코드를 돌려주고, 로그 출력은 app 쪽이 맡는다(1_ FR-6).

#include <cstdint>
#include <optional>
#include <string>

namespace detect {

enum class DiagKind {
  LineTooLong,         // 줄 길이 상한 초과 (2_ §1)
  FormatError,         // JSON·필드 형식 오류 (2_ §2·§4)
  UnsupportedVersion,  // ver를 모름 (2_ §3)
  Warning,             // 받아들이되 알릴 것 (total 불일치, clock 등)
  KpmBeforeHello,      // hello 전 kpm2 (2_ §3)
  ForeignSession,      // 현재 hello와 다른 session의 kpm2
  SeqGap,              // seq 건너뜀 — 로그용 (2_ §2)
  SeqRegress,          // seq 중복·역행
  SessionStarted,      // 첫 hello
  SessionReset,        // session 변경 또는 같은 session의 hello 파라미터 변경 (2_ §3)
  SessionResumed,      // 같은 session·같은 파라미터 hello (재연결)
  CellUnknown,         // hello cells에 없는 셀
  CellLimit,           // 셀 수 상한 초과
  CellGap,             // 셀 구간 끊김 (2_ §4.1, 3_ §8)
  CellOverlap,         // 셀 구간 겹침·역행
  PeriodMismatch,      // t_end - t_start != period_ms
  RuleInactive,        // 필수 키 A·S 누락이 연속 missing_key_slots칸 초과 (3_ §8)
  RuleResumed,         // 필수 키가 다시 들어옴 (3_ §8)
  ModeChanged,         // normal ↔ dl_missing 전환 (3_ §4.1·§8)
  BaselineLow,         // 웜업 종료 시 k × base < A_min — C3가 사실상 항상 참 (3_ §5)
  EvidenceDropped,     // 큐가 넘쳐 증거를 버림 — 경보마다 처음 1회, post 구간 몫은 post 끝에 (3_ §7.1, 결정 F3·F7)
  InputSilent,         // 벽시계로 마지막 kpm2 뒤 input_silent_ms 동안 kpm2가 없음 — 진행 중 경보를 END (3_ §8, 14_ §6.2, 이슈 #50)
  // 2단계 — UE 상태표·마감 목록 (14_)
  EvtBeforeHello,      // hello 전 ue_evt·f1_evt (2_ §6.5)
  UeEvtOff,            // hello에 ue_evt 표시가 없음 — 2단계 이상 룰을 끈다 (2_ §6.5)
  UeLate,              // 셀 워터마크보다 이른 ue_evt — 이력에는 넣고 판정은 바꾸지 않음 (2_ §6.5, 14_ §4.3)
  UeEvicted,           // 상태표 상한이 차서 항목을 밀어냄 (14_ §4.4)
  GhostPurge,          // 유령 정리 — 표의 CONNECTED 수가 셀 RRC 연결 수를 한참 넘어 오래된 항목을 닫음 (14_ §4.2, 이슈 #44)
  NgapUnlinked,        // F1AP UE에 잇지 못한 NGAP NAS 줄 — 셀별로 세고 셀마다 처음 1회만 (14_ §7, 2_ §6.6)
  UeEvtLostMissing,    // ue_evt_lost 없는 kpm2가 한 셀에서 연속 50칸 (14_ §6.2)
  DlUnobserved,        // ue_evt_lost에 "DL"이 한 셀에서 연속 50칸 (14_ §6.2, 15_ §2.7·§4.7)
  // 11/05 W-31 (이슈 #92) — hello·설정 경계 (2_ §3, 3_ §3·§8)
  HelloRejected,       // hello의 버퍼 칸 수(W/P + D + 1·pre_slots)가 max_slots를 넘음 — hello를 버림, 세션 유지
  WindowMisaligned,    // window_ms가 period_ms의 배수가 아님 — 창이 칸 경계에 걸려 이 세션 동안 1단계 룰 비활성
  InputLost,           // 보류가 H_hold를 넘어 그 셀 버퍼를 비움 (3_ §8) — 경보가 없어도 남긴다
};

const char* to_string(DiagKind kind);

struct Diag {
  DiagKind kind;
  std::optional<int64_t> cell_id;
  std::optional<int64_t> seq;
  std::string message;
};

}  // namespace detect
