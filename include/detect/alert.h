#pragma once
// 경보 상태기계와 경보 이벤트 (3_ §4 RAISE·CLEAR, §6.1 가 H_sat, §7 경보 로그, §8 보류).
// 경보 이벤트는 모든 룰이 같은 겉모양을 쓰고 룰마다 다른 값은 values·params·refs·ues·log_fields에만 둔다
// (14_ §8.1·§8.3, 4_ §6.1 #5).

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace detect {

enum class AlertEventKind { Raise, Clear, End, Update };
enum class AlertMode { Normal, DlMissing };  // 3_ §4.1 mode 필드
enum class Severity { Medium, High };       // 3_ §7 — C4 성립 시 high

// alert 레코드 형식 판 (14_ §8.3 fmt). 필드를 더할 때는 그대로 두고, 뜻을 바꾸거나 뺄 때만 올린다
inline constexpr int kAlertFmt = 1;

// UE 단위 경보(unit = "ue")에 걸린 UE 한 칸 (14_ §8.3 ues[]). 없는 식별 값은 nullopt → null
struct AlertUe {
  int64_t cell = 0;
  int64_t du_ue_id = 0;
  int64_t uid = 0;                      // 항목 인스턴스 번호 (14_ §2.1)
  std::optional<int64_t> cu_ue_id;
  std::optional<int64_t> crnti;
  std::optional<uint64_t> s_tmsi;       // 48비트 5G-S-TMSI — 레코드에는 "0x" + 소문자 16진 12자리
  std::vector<std::string> cond;        // 이 UE에서 성립한 조건 ID
  int64_t t_hit = 0;                    // 이 UE가 걸린 시각
  nlohmann::ordered_json values;        // 이 UE의 관측값 — 룰마다 다름
  std::vector<std::string> uncertain;   // 14_ §4.3 이유 목록
  std::vector<std::vector<int64_t>> peers;            // 함께 판정된 UE의 [cell, du_ue_id, uid] — 비면 키를 뺀다
  std::optional<std::pair<int64_t, int64_t>> seq_range;  // 이 UE 증거(recent)의 seq 범위
  bool evidence = false;                // 이 UE의 증거를 냈는지 (경보당 증거 UE 상한, 14_ §8.3)
};

// 경보 이벤트 하나. 로그 한 줄(format_log_line)과 증거 파일의 alert 레코드(alert_record_line)가 이것으로 만들어진다
struct AlertEvent {
  AlertEventKind kind = AlertEventKind::Raise;
  std::string rule;
  std::string alert_id;  // session-룰-셀-RAISE seq (3_ §7.1)
  int64_t cell_id = 0;
  int64_t t = 0;  // 상태가 바뀐 칸의 t_end_ms (데이터 시각, 3_ §3)
  AlertMode mode = AlertMode::Normal;
  Severity severity = Severity::Medium;

  // 공통 경보 형식의 겉모양 (14_ §8.3): 단계 1~4, 판정 단위 cell|ue, 공격 attack|이상 유형 anomaly
  int stage = 1;
  std::string unit = "cell";
  std::string alert_kind = "attack";
  std::optional<std::string> branch;  // 룰 안 갈래 (예: L3-21 "1"·"2"). 갈래가 없는 룰은 nullopt
  // RAISE 칸에서 성립한 조건 ID (14_ §8.3 cond, §8.5). 예: {"C1","C2","C3"}, {"C2a"}, dl_missing {"U","C3"}
  std::vector<std::string> cond;
  std::vector<std::string> candidates;

  // 룰마다 다른 값 (14_ §8.3) — 넣은 순서대로 레코드에 나간다(결정 F10). 비워 두면 레코드에서 뺀다
  nlohmann::ordered_json values;  // 판정에 쓴 관측값
  nlohmann::ordered_json params;  // 그때 쓴 파라미터 (RAISE)
  nlohmann::ordered_json refs;    // 근거 원본 seq 범위 {이름: [from, to]} — 셀 단위 룰용 (RAISE)

  // UE 단위 경보 (unit = "ue"): 걸린 UE 목록(update에는 새로 걸린 UE만)과 지금까지 걸린 UE 수 (14_ §8.3)
  std::vector<AlertUe> ues;
  int64_t ues_total = 0;

  // 로그 줄에 룰이 넣는 필드 — 사람이 읽는 형식 그대로, 넣은 순서대로 key=value (3_ §7, 15_ §2.6·§4.6·§5.6).
  // RAISE는 severity 앞에, UPDATE는 severity 뒤에 붙는다
  std::vector<std::pair<std::string, std::string>> log_fields;

  int64_t duration_ms = 0;  // CLEAR·END
  std::string reason;       // END: session_reset | input_lost | input_silent (3_ §7.1·§8, 14_ §8.2)
};

// 경보 로그 한 줄 (3_ §7, 15_ §2.6·§4.6·§5.6). 골격은 모든 룰이 같고 룰별 필드는 log_fields로 받는다
std::string format_log_line(const AlertEvent& e);

// 경보 상태기계 (3_ §4):
//  - 경보가 아닐 때 M칸 연속 성립 → RAISE
//  - 경보 중 K칸 연속 불성립 ∧ t − t_last ≥ H_sat → CLEAR (t_last = 마지막 성립 칸의 끝, 3_ §6.1 가)
//  - 보류 칸(3_ §8)은 on_slot을 부르지 않는다 → M·K·t_last가 그대로 유지된다
class AlertMachine {
 public:
  enum class Step { None, Raise, Clear };

  AlertMachine(int m_raise, int k_clear, int64_t h_sat_ms)
      : m_raise_(m_raise), k_clear_(k_clear), h_sat_ms_(h_sat_ms) {}

  Step on_slot(bool satisfied, int64_t t);
  // 강제 종료(session 변경·H_hold 초과) — 카운터까지 처음 상태로
  void reset();

  bool active() const { return active_; }
  int64_t raised_at() const { return raised_at_; }
  std::optional<int64_t> t_last() const { return t_last_; }

 private:
  int m_raise_;
  int k_clear_;
  int64_t h_sat_ms_;
  bool active_ = false;
  int ok_streak_ = 0;
  int ng_streak_ = 0;
  std::optional<int64_t> t_last_;
  int64_t raised_at_ = 0;
};

}  // namespace detect
