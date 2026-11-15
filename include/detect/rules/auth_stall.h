#pragma once
// 룰 L3-01-O — 인증 단계 고착 공격 (Kim'19 원형) 탐지 (15_ §4). 연결과 등록 요청까지 보낸 뒤 AMF의 AuthenticationRequest에
// 응답하지 않아 연결을 인증 단계에 묶어 두고, 이를 반복해 셀 연결 자원을 채우는 공격이다. 응답 대기 시간 안에 응답이 없는
// UE(고착)가 셀에서 창 W 안에 N건 이상이면 성립한다 — 정상 UE는 수십~수백 ms 안에 응답하고, 전파가 끊긴 UE 하나로는
// 문턱에 닿지 않는다(15_ §4.1·§4.9). 시도 대비 비율은 보지 않는다(10/29 사용자 결정, 15_ §4.3). N은 셀 한도에 비례한다 —
// max(n_stall, ⌈n_stall_frac × max_conn⌉), 기본 셀 한도 96이면 10 (15_ §1.2, 11/15 사용자 결정).
// (11/05 26_ R2, 이슈 #96) 고착의 셀 창 집계·RAISE·UPDATE·CLEAR·밀어내기 보류는 4단계와 같은 HitWindow 위에 둔다 — '대기 뒤 고착'
// 판정과 심각도·auth_req_w·UeCtxMax 창은 룰에 남는다

#include "detect/config.h"
#include "detect/ue_alert.h"
#include "detect/ue_held.h"
#include "detect/ue_hits.h"
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
  int64_t held() const { return held_.total(); }         // 지금까지 보류한 판정 수

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
  // 셀별 — 심각도 창·auth_req_w (15_ §4.3·§4.6). 고착 창·경보·밀어내기는 hits_, 보류·불확실 경보는 held_
  struct CellState {
    std::optional<int64_t> t_last_stall;        // 마지막 고착 시각 — auth_req_w의 기준 (걸림을 처리하는 decorate에서 갱신)
    std::deque<std::pair<int64_t, std::optional<int64_t>>> uectx;  // (kpm2 t_end_ms, ext.UeCtxMax) — 최근 W
    std::deque<std::pair<int64_t, UeId>> auth_reqs;                // AuthenticationRequest (t_ms, UE) — auth_req_w
  };

  void start(const UeId& id, const UeEvt& evt, const UeRuleCtx& ctx);
  void decorate(int64_t cell, std::size_t from, const AlertUe* hit, std::optional<int64_t> cx,
                std::optional<int64_t> max_conn, int64_t n_th, RuleOutput& out);
  int64_t auth_req_w(const CellState& c) const;
  AlertUe held_ue(const UeState& n, int64_t t_hit) const;

  AuthStallConfig cfg_;
  AlertConfig alert_;
  HitWindow hits_;  // 공격 경보 (kind attack, stage 2) — 고착 창 S_W·RAISE·UPDATE·CLEAR·밀어내기 보류 (R2, 이슈 #96)
  HeldBook held_;   // 불확실 경보 (kind anomaly, 14_ §6.2 — 이슈 #48; 공통 헬퍼 R1)
  std::map<UeId, Mark> marks_;
  std::map<UeId, Request> requests_;  // UE별 마지막 요청 — 닫히면 지운다
  std::set<UeId> stalled_;            // 고착으로 세고 아직 응답이 없는 열린 UE — 응답 전까지 다시 세지 않는다
  std::map<int64_t, CellState> cells_;
  int64_t stalls_n_ = 0;
};

}  // namespace detect
