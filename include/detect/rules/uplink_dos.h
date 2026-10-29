#pragma once
// 룰 L3-21 — 상향 DoS (위조 자격증명) 탐지 (15_ §5). 무효한 자격증명(SUCI·GUTI·MAC)을 담은 등록·서비스 요청을 코어로 올려
// 보내 인증 실패와 등록 거부를 되풀이하게 만드는 공격이다. 두 갈래로 잡는다:
//  ① 셀 단위 실패 급증(원형 L3-21-O) — 실패 뒤 수락 대기 시간 안에 망 수락이 없는 UE(실패 UE)가 셀에서 창 W 안에 N개 이상
//  ② 한 연결 안 반복 등록 + 실패(변형 L3-21-V) — 한 연결에 RegistrationRequest R번 이상과 실패가 함께 보이면 즉시
// 정상 단말은 거부 뒤 대기 타이머로 새 연결에서 다시 시도하고(10 s에 1번 안팎), 동기 실패는 재인증으로 곧 수락된다(15_ §5.1)

#include "detect/config.h"
#include "detect/ue_alert.h"
#include "detect/ue_rule.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace detect {

class UplinkDosRule : public UeRule {
 public:
  static constexpr const char* kId = "L3-21";

  explicit UplinkDosRule(UplinkDosConfig cfg = {}, AlertConfig alert = {});

  const char* id() const override { return kId; }
  int64_t evidence_horizon_ms() const override;
  void on_ue_event(const UeEvt& evt, const UeState& before, const UeState& after, const UeRuleCtx& ctx,
                   RuleOutput& out) override;
  void on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput& out) override;
  void on_ue_close(const UeState& last, CloseReason reason, int64_t t, const UeRuleCtx& ctx, RuleOutput& out) override;
  void on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss& loss, bool input_lost, const UeRuleCtx& ctx,
                    RuleOutput& out) override;
  void on_session_reset(const UeRuleCtx& ctx, RuleOutput& out) override;

  // 테스트용
  std::size_t waiting() const { return marks_.size(); }  // 갈래 ① 대기 표시 수
  int64_t failed_ues() const { return failed_n_; }      // 지금까지 실패 UE로 센 수 (갈래 ①)
  int64_t held() const { return held_n_; }              // 지금까지 보류한 판정 수

 private:
  using UeId = std::pair<UeKey, int64_t>;  // (키, uid)

  // 연결(UE 항목)별 기록 (15_ §5.2·§5.6) — 상태표 cnt에는 원인값이 없어 ignore_causes를 거를 수 없으므로 룰이 들고 있는다
  struct Conn {
    std::vector<std::string> fails;       // 실패로 센 메시지 이름, 본 순서
    std::vector<int64_t> causes;          // 그 가운데 원인값이 있는 것의 값
    std::optional<std::string> id_type;   // 마지막 RegistrationRequest의 f.id_type
    bool branch2 = false;                 // 갈래 ②로 걸렸다 — 연결당 한 번
    bool counted = false;                 // 실패 UE로 셌고 그 뒤 새 수락이 없다 — 새로 기다리지 않는다 (15_ §5.3-1)
  };
  // 갈래 ① 대기 표시 (15_ §5.3, 14_ §2.4) — n의 (키, uid)로 둔다
  struct Mark {
    int64_t t_from = 0;             // t_f — 기다림을 시작한 실패 메시지
    int64_t deadline = 0;           // t_f + fail_accept_wait_ms
    bool accepted_late = false;     // 마감 뒤 수락이 마감 처리 전에 왔다 — 실패 UE로 세되 다음 실패는 새로 기다린다
    std::optional<UeState> closed;  // 마감 전에 닫혔으면 닫힐 때의 상태와 연결 기록 (15_ §1)
    std::optional<Conn> closed_conn;
    std::optional<int64_t> closed_at;
  };
  // 창 안 실패 UE 하나 (갈래 ①)
  struct Failed {
    AlertUe ue;
    uint64_t loaded = 0;  // 이 실패 UE를 실은 경보 번호 — 갈래 ① 첫 성립 때 아직 안 실린 것을 함께 싣는다 (15_ §5.5)
  };
  // 셀별 — 창·경보 누적값·해제 기준 (15_ §5.3·§5.5·§5.6)
  struct CellState {
    std::vector<AlertUe> fresh;            // 이번 kpm2의 마감 처리에서 정해진 실패 UE — on_cell_tick에서 성립을 본다
    std::deque<Failed> failed;             // 마지막 실패 UE 시각 t 기준 (t − W, t] 안의 실패 UE — F_W와 RAISE의 ues
    std::deque<int64_t> fail_msgs;         // 실패 메시지 시각 (ignore_causes 제외) — fail_msgs_w
    std::optional<int64_t> t_last_hit;     // 가장 최근 걸림(갈래 ① 실패 UE 또는 갈래 ② UE) — 값 창의 기준
    int64_t t_active = 0;                  // 마지막 갈래 ① 성립과 마지막 갈래 ② 걸림 중 늦은 것 — CLEAR 기준
    uint64_t alert_no = 0;                 // 이 셀의 경보 번호 — RAISE마다 1씩
    bool sat1 = false;                     // 이 경보에서 갈래 ①이 성립했다 — branch "1"
    bool has2 = false;                     // 이 경보에 갈래 ② UE가 실렸다
    int64_t branch1_ues = 0;               // 이 경보에 실린 걸림 수 (갈래별)
    int64_t branch2_ues = 0;
    int64_t held_open = 0;                 // 경보가 열린 뒤 보류된 판정 수
    std::deque<int64_t> held_times;        // 보류 시각 — raise의 held는 직전 clear_quiet_ms 동안 (이동 창)
    // 상태표 밀어내기 (15_ §5.5·§5.6, 14_ §6.3 — Q-56 해결, 이슈 #44): 직전 clear_quiet_ms 동안 밀어내기가 있으면 풀지 않는다
    int64_t evicted_seen = 0;
    int64_t evicted_open = 0;
    std::deque<int64_t> evict_times;
  };

  bool is_failure(const UeEvt& evt) const;
  void start(const UeId& id, int64_t t_f, const UeRuleCtx& ctx);
  AlertUe make_ue(const UeState& n, const Conn* c, const char* branch, std::vector<std::string> cond, int64_t t_hit,
                  std::optional<int64_t> closed_ms) const;
  void hit2(const UeState& n, const Conn& c, int64_t t, const UeRuleCtx& ctx, RuleOutput& out);
  void new_alert(CellState& c) const;
  void decorate(std::size_t from, RuleOutput& out);
  int64_t in_window(const CellState& c, bool msgs) const;
  int64_t held_window(CellState& c, int64_t now) const;
  int64_t evicted_window(CellState& c, int64_t now) const;
  void note_evictions(CellState& c, int64_t cell, int64_t t, const UeRuleCtx& ctx);

  UplinkDosConfig cfg_;
  AlertConfig alert_;
  UeAlertBook book_;
  std::map<UeId, Mark> marks_;
  std::map<UeId, Conn> conns_;  // 실패·등록 요청을 본 열린 연결 — 닫히면 지운다
  std::map<int64_t, CellState> cells_;
  int64_t failed_n_ = 0;
  int64_t held_n_ = 0;
};

}  // namespace detect
