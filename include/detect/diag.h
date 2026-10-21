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
};

const char* to_string(DiagKind kind);

struct Diag {
  DiagKind kind;
  std::optional<int64_t> cell_id;
  std::optional<int64_t> seq;
  std::string message;
};

}  // namespace detect
