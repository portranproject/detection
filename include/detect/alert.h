#pragma once
// 경보 상태기계와 경보 이벤트 (3_ §4 RAISE·CLEAR, §6.1 가 H_sat, §7 경보 로그, §8 보류).

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace detect {

enum class AlertEventKind { Raise, Clear, End, Update };
enum class AlertMode { Normal, DlMissing };  // 3_ §4.1 mode 필드
enum class Severity { Medium, High };       // 3_ §7 — C4 성립 시 high

// 경보 이벤트 하나. 나중에 출력 명세가 정해지면 이 구조체를 그대로 직렬화한다 (3_ §7, Q-17)
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
  // RAISE 칸에서 성립한 조건 ID (14_ §8.3 cond, §8.5). 예: {"C1","C2","C3"}, {"C2a"}, dl_missing {"U","C3"}
  std::vector<std::string> cond;

  // 근거 값 (RAISE). normal이면 A_w·F_w·ratio, dl_missing이면 A_w(= A′_w)·U (결정 E5)
  int64_t a_w = 0;
  std::optional<int64_t> f_w;
  std::optional<double> ratio;
  std::optional<double> u;
  double base = 0;
  double k = 0;
  double theta = 0;
  std::optional<int64_t> f_abs;     // C2a 문턱 F_abs — normal 모드 RAISE에만 (3_ §7, 10/27 Q-41)
  std::optional<int64_t> uectx;     // ext.UeCtxMax (C4가 켜졌을 때만)
  std::optional<int64_t> max_conn;
  std::vector<std::string> candidates;
  // RAISE 근거 구간의 seq 범위 [첫 seq, 마지막 seq] — 대시보드가 집계값과 원본 줄을 맞춰 보게 (3_ §7.1).
  // dl_missing이면 a_seq = A′ 윈도우, f_seq 없음 (결정 F5)
  std::optional<std::pair<int64_t, int64_t>> a_seq;
  std::optional<std::pair<int64_t, int64_t>> f_seq;

  int64_t duration_ms = 0;  // CLEAR·END
  std::string reason;       // END: session_reset | input_lost (3_ §7.1)
};

// 3_ §7 형식의 로그 한 줄. UPDATE·END 형식은 결정 E2·E3
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
