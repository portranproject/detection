#pragma once
// 입력 메시지 구조체와 파서 (2_ 입력 인터페이스 명세).
// 줄 하나(JSON 객체 1개)를 Hello / Kpm2 / UeEvt / F1Evt로 바꾸고 형식을 검증한다.

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
  // 분석 엔진이 ue_evt를 보내는지 (2_ §6.5). 없거나 false면 2단계 이상 룰을 끈다
  bool ue_evt = false;
};

// 원인별 세분이 있는 CC 카운터 (2_ §4.2). total은 이 인터페이스의 필드이고 원인별 키는 0이 아닌 것만 올 수 있다
struct CauseCounter {
  Count total;
  std::map<std::string, int64_t> causes;
};

// 그 창의 ue_evt를 놓쳤을 수 있는 방향 (2_ §4.6 ue_evt_lost). [] = 둘 다 false
struct UeEvtLost {
  bool ul = false;
  bool dl = false;
  bool operator==(const UeEvtLost& o) const { return ul == o.ul && dl == o.dl; }
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

  // ue_evt 로스 표시 (2_ §4.6). nullopt = 키 없음·null — 알 수 없으므로 2단계는 양방향 로스로 본다 (14_ §6.2)
  std::optional<UeEvtLost> ue_evt_lost;

  // 받은 원본 줄 그대로 — 증거 raw는 다시 직렬화하지 않고 이것을 이어 붙인다 (3_ §7.1)
  std::string raw;
};

enum class Dir { UL, DL };
enum class Proto { RRC, NAS, F1AP };

// RRCSetupRequest의 ue_identity (2_ §6.3)
enum class UeIdentityType { Part1, RandomValue };

// ue_evt — UE별 메시지 이벤트 1줄 = 관측한 메시지 1개 (2_ §6.1·§6.2).
// 상태는 탐지 엔진이 메시지 순서로 만든다(14_ §5) — 여기서는 본 것을 그대로 옮긴다
struct UeEvt {
  int64_t t_ms = 0;                 // 관측 시각 (데이터 시각)
  int64_t cell_id = 0;
  std::optional<int64_t> du_ue_id;  // UE 키. null은 NGAP에서만 본 NAS 줄뿐 (2_ §6.5·§6.6)
  std::optional<int64_t> cu_ue_id;  // 알면
  std::optional<int64_t> crnti;     // 모르면 null
  Dir dir = Dir::UL;
  Proto proto = Proto::RRC;
  std::string msg;                  // 메시지 이름 (2_ §6.3 철자). 모르는 이름도 받는다
  std::string via;                  // NAS만: "F1" | "NGAP"
  std::optional<int64_t> sht;       // NAS만: 보안 헤더 유형 0~4

  // f에서 꺼낸 값 (2_ §6.3). 꺼내지 못했으면 nullopt. 어느 메시지의 값을 쓸지는 상태표·룰이 정한다
  std::optional<uint64_t> s_tmsi;        // 48비트 5G-S-TMSI ("0x…" → 정수, 14_ §3.1)
  std::optional<UeIdentityType> ue_identity;
  std::optional<uint64_t> s_tmsi_part1;  // ue_identity가 Part1이면 39비트 값
  std::optional<uint64_t> s_tmsi_part2;  // Part1과 합치지 못한 Part2 9비트 (2_ §7-14 폴백)
  std::optional<std::string> est_cause;
  std::optional<std::string> reg_type;
  std::optional<std::string> id_type;
  std::optional<std::string> cipher;
  std::optional<std::string> integrity;
  std::optional<bool> suspend;
  std::optional<bool> switch_off;
  std::optional<int64_t> cause;            // NAS 5GMM 원인값
  std::optional<std::string> f1ap_cause;   // F1AP cause ("radioNetwork:…")
  std::optional<int64_t> wait_time;

  // 받은 원본 줄 그대로 — UE 증거(recent)는 다시 직렬화하지 않고 이것을 쓴다 (14_ §2.3·§8.4)
  std::string raw;
};

// f1_evt — DU·CU 재시작 알림 (2_ §6.7). 그 셀의 열린 UE 항목을 du_reset으로 닫는 근거
struct F1Evt {
  int64_t t_ms = 0;
  std::string msg;                                 // "F1SetupRequest" | "F1Reset"
  std::optional<std::vector<int64_t>> cells;       // nullopt(null) = 모든 셀
  std::optional<std::vector<int64_t>> du_ue_ids;   // F1Reset이 일부 UE만이면 그 목록, 없으면 전체
};

enum class ParseStatus {
  Ok,
  LineTooLong,         // 2_ §1
  FormatError,         // 2_ §2·§3·§4·§6
  UnsupportedVersion,  // 2_ §3 — ver가 1이 아님
  UnknownType,         // 2_ §2 — 모르는 type은 무시
};

struct ParseResult {
  ParseStatus status = ParseStatus::FormatError;
  std::optional<Common> common;  // 공통 필드를 읽었으면 채움
  std::variant<std::monostate, Hello, Kpm2, UeEvt, F1Evt> msg;
  std::string error;                  // FormatError 등의 이유
  std::vector<std::string> warnings;  // Ok이지만 알릴 것
};

ParseResult parse_line(std::string_view line, std::size_t max_line_bytes = kDefaultMaxLineBytes);

}  // namespace detect
