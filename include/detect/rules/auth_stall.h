#pragma once
// 룰 L3-01-O — 인증 단계 고착 공격 (Kim'19 원형) 탐지 (15_ §4). 연결과 등록 요청까지 보낸 뒤 AMF의 AuthenticationRequest에
// 응답하지 않아 연결을 인증 단계에 묶어 두고, 이를 반복해 셀 연결 자원을 채우는 공격이다. 응답 대기 시간 안에 응답이 없는
// UE(고착)가 셀에서 창 W 안에 N건 이상이면 성립한다 — 정상 UE는 수십~수백 ms 안에 응답하고, 전파가 끊긴 UE 하나로는
// 문턱에 닿지 않는다(15_ §4.1·§4.9). 비율은 보지 않는다(10/29 사용자 결정, 15_ §4.3)

#include "detect/config.h"
#include "detect/ue_alert.h"
#include "detect/ue_rule.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace detect {

class AuthStallRule : public UeRule {
 public:
  static constexpr const char* kId = "L3-01-O";

  explicit AuthStallRule(AuthStallConfig cfg = {}, AlertConfig alert = {});

  const char* id() const override { return kId; }
  int64_t evidence_horizon_ms() const override;
  void on_ue_event(const UeEvt& evt, const UeState& before, const UeState& after, const UeRuleCtx& ctx,
                   RuleOutput& out) override;
  void on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput& out) override;
  void on_ue_close(const UeState& last, CloseReason reason, int64_t t, const UeRuleCtx& ctx, RuleOutput& out) override;
  void on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss& loss, bool input_lost, const UeRuleCtx& ctx,
                    RuleOutput& out) override;
  void on_session_reset(const UeRuleCtx& ctx, RuleOutput& out) override;
  void on_input_silent(const UeRuleCtx& ctx, RuleOutput& out) override;

  // 테스트용
  std::size_t waiting() const { return marks_.size(); }  // 기다리는 대기 표시 수
  int64_t stalls() const { return stalls_n_; }           // 지금까지 고착으로 센 수
  int64_t held() const { return held_n_; }               // 지금까지 보류한 판정 수

 private:
  using UeId = std::pair<UeKey, int64_t>;  // (키, uid)

  // 앞선 요청 (15_ §4.6 nas·id_type) — 상태표 cnt에는 순서·id_type이 없어 룰이 UE마다 들고 있는다(14_ §2.3)
  struct Request {
    std::string msg;
    std::optional<std::string> id_type;
  };
  // 대기 표시 (15_ §4.3, 14_ §2.4) — n의 (키, uid)로 둔다
  struct Mark {
    int64_t t_from = 0;              // t₀ — 기다림을 시작한 AuthenticationRequest
    int64_t deadline = 0;            // t₀ + auth_wait_ms
    int64_t auth_req_n = 1;          // 기다리는 동안 받은 AuthenticationRequest 수 — AMF 재전송 포함
    int64_t other_ul = 0;            // 기다리는 동안 온 응답 아닌 UL NAS 수 (15_ §4.3-3)
    std::optional<Request> req;      // 기다림을 시작할 때의 앞선 요청
    bool responded_late = false;     // 마감 뒤 응답이 마감 처리 전에 왔다 — 고착으로 세되 다음 요청은 새로 기다린다
    std::optional<UeState> closed;   // 마감 전에 닫혔으면 닫힐 때의 상태 (15_ §1)
    std::optional<int64_t> closed_at;
  };
  // 셀별 — 고착 창·심각도 창·경보 누적값 (15_ §4.3·§4.5·§4.6)
  struct CellState {
    std::vector<AlertUe> fresh;                 // 이번 kpm2의 마감 처리에서 정해진 고착 — on_cell_tick에서 성립을 본다
    std::deque<AlertUe> stalls;                 // 마지막 고착 시각 t 기준 (t − W, t] 안의 고착 — S_W와 RAISE의 ues
    std::optional<int64_t> t_last_stall;        // 마지막 고착 시각 — stalls_w·auth_req_w의 기준
    int64_t t_sat = 0;                          // 마지막으로 성립한 시각 — CLEAR 기준
    std::deque<std::pair<int64_t, std::optional<int64_t>>> uectx;  // (kpm2 t_end_ms, ext.UeCtxMax) — 최근 W
    std::deque<std::pair<int64_t, UeId>> auth_reqs;                // AuthenticationRequest (t_ms, UE) — auth_req_w
    int64_t held_open = 0;                      // 경보가 열린 뒤 보류된 판정 수
    std::deque<int64_t> held_times;             // 보류 시각 — raise의 held는 직전 clear_quiet_ms 동안 (이동 창)
    // 상태표 밀어내기 (15_ §4.5·§4.6, 14_ §6.3 — Q-56 해결, 이슈 #44): 직전 clear_quiet_ms 동안 밀어내기가 있으면 풀지 않는다
    int64_t evicted_seen = 0;
    int64_t evicted_open = 0;
    std::deque<int64_t> evict_times;
    // 불확실 경보 (14_ §6.2 — Q-58 해결, 이슈 #48): 창 W 안 보류 수가 N이면 kind anomaly
    std::vector<AlertUe> fresh_held;            // 이번 kpm2의 마감 처리에서 보류된 UE
    std::deque<AlertUe> held_ues;               // 마지막 보류 시각 기준 (t − W, t] 안의 보류 UE
    int64_t t_last_held = 0;
  };

  void start(const UeId& id, const UeEvt& evt, const UeRuleCtx& ctx);
  void decorate(int64_t cell, std::size_t from, std::optional<int64_t> cx, std::optional<int64_t> max_conn,
                RuleOutput& out);
  int64_t auth_req_w(const CellState& c) const;
  int64_t held_window(CellState& c, int64_t now) const;
  AlertUe held_ue(const UeState& n, int64_t t_hit) const;
  void held_tick(int64_t cell, CellState& c, int64_t t, bool input_lost, const UeRuleCtx& ctx, RuleOutput& out);
  void close_held(int64_t cell, int64_t t, RuleOutput& out);
  void decorate_held(std::size_t from, RuleOutput& out);
  int64_t evicted_window(CellState& c, int64_t now) const;
  void note_evictions(CellState& c, int64_t cell, int64_t t, const UeRuleCtx& ctx);

  AuthStallConfig cfg_;
  AlertConfig alert_;
  UeAlertBook book_;       // 공격 경보 (kind attack)
  UeAlertBook held_book_;  // 불확실 경보 (kind anomaly, 14_ §6.2 — 이슈 #48)
  std::map<UeId, Mark> marks_;
  std::map<UeId, Request> requests_;  // UE별 마지막 요청 — 닫히면 지운다
  std::set<UeId> stalled_;            // 고착으로 세고 아직 응답이 없는 열린 UE — 응답 전까지 다시 세지 않는다
  std::map<int64_t, CellState> cells_;
  int64_t stalls_n_ = 0;
  int64_t held_n_ = 0;
};

}  // namespace detect
