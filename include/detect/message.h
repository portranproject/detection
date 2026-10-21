#pragma once
// 입력 메시지 구조체와 파서 (2_ 입력 인터페이스 명세).
// 줄 하나(JSON 객체 1개)를 Hello / Kpm2 / UeEvt로 바꾸고 형식을 검증한다.

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace detect {

inline constexpr int64_t kSupportedVersion = 1;            // 2_ §2 ver
inline constexpr std::size_t kDefaultMaxLineBytes = 65536;  // 2_ §1 줄 길이 상한 64 KiB

// 측정값 하나. nullopt = 측정하지 않음(키 없음 또는 null), 0 = 측정했고 0건 (2_ §4.5)
using Count = std::optional<int64_t>;

// 모든 메시지의 공통 필드 (2_ §2)
struct Common {
  std::string type;
  int64_t ver = 0;
  std::string session;
  int64_t seq = 0;
};

struct CellInfo {
  int64_t cell_id = 0;
  std::optional<int64_t> max_conn;  // null이면 탐지 엔진 설정 값을 쓴다 (3_ §4)
  bool operator==(const CellInfo& o) const { return cell_id == o.cell_id && max_conn == o.max_conn; }
};

// hello — 연결 직후 1회 (2_ §3)
struct Hello {
  std::string producer;
  std::string node_id;
  std::vector<CellInfo> cells;
  int64_t period_ms = 0;           // 필수 (3_ §2 P)
  int64_t noreply_timeout_ms = 0;  // 필수 (3_ §2 T_nr)
  int64_t si_sample_ms = 0;        // 없으면 period_ms로 간주
  std::string clock;
};

// 원인별 세분이 있는 CC 카운터 (2_ §4.2). total은 이 인터페이스의 필드이고 원인별 키는 0이 아닌 것만 올 수 있다
struct CauseCounter {
  Count total;
  std::map<std::string, int64_t> causes;
};

// kpm2 — 표 II, 셀마다 period_ms마다 1개 (2_ §4). cc 값은 구간 차분값(Δ)
struct Kpm2 {
  int64_t cell_id = 0;
  int64_t t_start_ms = 0;  // [t_start, t_end) (2_ §4.1)
  int64_t t_end_ms = 0;

  // cc (2_ §4.2)
  CauseCounter conn_estab_att;   // RRC.ConnEstabAtt  — 3_ §2 A
  CauseCounter conn_estab_succ;  // RRC.ConnEstabSucc — 3_ §2 S
  Count fail_no_reply;           // RRC.ConnEstabFailCause.NoReply       — 3_ §2 F
  Count fail_network_reject;     // RRC.ConnEstabFailCause.NetworkReject — 3_ §2 R
  Count fail_other;              // RRC.ConnEstabFailCause.Other
  Count rel_without_suspend_config;
  CauseCounter uecntx_estab_att;
  CauseCounter uecntx_estab_succ;
  Count reestab_att;
  Count reestab_succ_with_ue_context;
  CauseCounter resume_att;
  CauseCounter resume_succ;

  // si (2_ §4.3)
  std::optional<double> conn_mean;
  Count conn_max;
  std::optional<double> inactive_conn_mean;
  Count inactive_conn_max;

  // ext (2_ §4.4)
  Count crnti_alloc;
  Count ue_ctx_max;
  Count du_cannot_serve;

  // 받은 원본 줄 그대로 — 증거 raw는 다시 직렬화하지 않고 이것을 이어 붙인다 (3_ §7.1)
  std::string raw;
};

// ue_evt — 2단계부터. 룰 명세가 없으므로 종류만 인식하고 본문은 해석하지 않는다 (2_ §6, 1_ §3)
struct UeEvt {};

enum class ParseStatus {
  Ok,
  LineTooLong,         // 2_ §1
  FormatError,         // 2_ §2·§3·§4
  UnsupportedVersion,  // 2_ §3 — ver가 1이 아님
  UnknownType,         // 2_ §2 — 모르는 type은 무시
};

struct ParseResult {
  ParseStatus status = ParseStatus::FormatError;
  std::optional<Common> common;  // 공통 필드를 읽었으면 채움
  std::variant<std::monostate, Hello, Kpm2, UeEvt> msg;
  std::string error;                  // FormatError 등의 이유
  std::vector<std::string> warnings;  // Ok이지만 알릴 것
};

ParseResult parse_line(std::string_view line, std::size_t max_line_bytes = kDefaultMaxLineBytes);

}  // namespace detect
