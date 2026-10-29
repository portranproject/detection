#pragma once
// 룰 L3-20 — Blind DoS (S-TMSI 재사용) 탐지 (15_ §2). CONNECTED형(L3-20-O·L3-20-V1)만 잡는다 — IDLE형(L3-20-V2)은
// 탐지하지 않는다(10/29 사용자 결정, 15_ §2.1). 피해자의 5G-S-TMSI로 연 새 연결이, 같은 S-TMSI의 다른 열린 연결(짝)이
// 있는 동안 수락 대기 시간 안에 망 수락(15_ §1.1)을 얻지 못하면 그 연결이 걸린다. 공격자는 피해자의 USIM 키가 없어
// 인증·무결성 검사를 통과하지 못하므로, 망 수락이 없다는 것이 정상(RLF 뒤 재접속)과 가르는 근거다

#include "detect/config.h"
#include "detect/ue_alert.h"
#include "detect/ue_rule.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace detect {

class BlindDosRule : public UeRule {
 public:
  static constexpr const char* kId = "L3-20";

  explicit BlindDosRule(BlindDosConfig cfg = {}, AlertConfig alert = {});

  const char* id() const override { return kId; }
  int64_t evidence_horizon_ms() const override;
  void on_ue_event(const UeEvt& evt, const UeState& before, const UeState& after, const UeRuleCtx& ctx,
                   RuleOutput& out) override;
  void on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput& out) override;
  void on_ue_close(const UeState& last, CloseReason reason, int64_t t, const UeRuleCtx& ctx, RuleOutput& out) override;
  void on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss& loss, bool input_lost, const UeRuleCtx& ctx,
                    RuleOutput& out) override;
  void on_session_reset(const UeRuleCtx& ctx, RuleOutput& out) override;

  std::size_t waiting() const { return marks_.size(); }  // 테스트용: 기다리는 대기 표시 수

 private:
  using UeId = std::pair<UeKey, int64_t>;  // (키, uid)

  // 대기 표시 (15_ §2.3, 14_ §2.4) — n의 (키, uid)로 둔다
  struct Mark {
    uint64_t s_tmsi = 0;
    int64_t t_from = 0;                // t₀ — n의 s_tmsi가 정해진 줄
    int64_t deadline = 0;              // t₀ + accept_wait_ms
    bool concurrent = false;           // 확실한 짝이 하나라도 있었다 — 아니면 peer_uncertain
    std::vector<UeId> peers;           // t₀ 때의 짝 — 같은 S-TMSI의 다른 열린 항목
    bool victim_released = false;      // 짝이 해제됨 — 피해 확정
    std::optional<UeState> closed;     // 마감 전에 닫혔으면 닫힐 때의 상태 (15_ §1)
    std::optional<int64_t> closed_at;
  };
  // 셀별 — 경보 누적값과 해제 기준 (15_ §2.5·§2.6)
  struct CellState {
    int64_t t_hit_last = 0;                  // 마지막으로 UE가 걸린 시각 — CLEAR 기준
    int64_t concurrent = 0;                  // 경보가 열린 뒤 표시 종류별 걸린 UE 수
    int64_t peer_uncertain = 0;
    std::map<uint64_t, int64_t> victims;     // 피해 S-TMSI → 이 경보에서 걸린 연결 수 (repeat)
    int64_t held_open = 0;                   // 경보가 열린 뒤 보류된 판정 수
    std::deque<int64_t> held_times;          // 보류 시각 — raise의 held는 직전 clear_quiet_ms 동안 (이동 창)
    // 상태표 밀어내기 (15_ §2.5·§2.6, 14_ §6.3 — Q-56 해결, 이슈 #44): 밀려난 UE는 판정되지 않아 조용해 보이므로
    // 직전 clear_quiet_ms 동안 밀어내기가 있으면 풀지 않는다. 시각은 그것을 본 kpm2의 t_end_ms
    int64_t evicted_seen = 0;                // 상태표 셀별 누적 evicted 중 이미 적은 수
    int64_t evicted_open = 0;                // 경보가 열린 뒤 밀어내기 수 — update의 values.evicted
    std::deque<int64_t> evict_times;         // 밀어내기 시각 — raise의 values.evicted·해제 보류 (이동 창)
  };

  void start(const UeState& n, int64_t t0, const UeRuleCtx& ctx);
  void drop(const UeId& id);
  void mark_victim(const UeId& peer);
  void hit(const Mark& m, const UeState& n, int64_t t_hit, int64_t now, const UeRuleCtx& ctx, RuleOutput& out);
  void decorate(std::size_t from, RuleOutput& out);
  int64_t held_window(CellState& c, int64_t now) const;
  int64_t evicted_window(CellState& c, int64_t now) const;
  void note_evictions(CellState& c, int64_t cell, int64_t t, const UeRuleCtx& ctx);

  BlindDosConfig cfg_;
  AlertConfig alert_;
  UeAlertBook book_;
  std::map<UeId, Mark> marks_;
  std::map<UeId, std::set<UeId>> by_peer_;  // 짝 → 그 짝을 가진 대기 표시 — 짝의 해제를 표시에 적으려고
  std::map<int64_t, CellState> cells_;
};

}  // namespace detect
