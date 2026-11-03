#pragma once
// 룰 L3-24 — 하향 IMSI 추출(Downlink IMSI Extractor) 탐지 (20_ §3). AS 보안이 서기 전 공중의 중간자가 피해 UE에 IdentityRequest를
// 주입하고 UE의 응답을 정상 기지국으로 넘기면, CU에는 주입한 요청은 보이지 않고 요청 없이 온 IdentityResponse만 보인다.
// 그 응답을 '요청 없는 응답'(20_ §1.2 — 공통 헬퍼 ue_lookback)으로 잡는다. 정상 망은 SUCI를 모를 때만 식별을 요청하고 그때는
// 요청·응답이 짝으로 보인다(5_ §15). 응답을 넘기지 않는 공격(순수 FBS)은 보이지 않으므로 경보에 전제 mitm_ul_relay를
// 싣는다(20_ §1.3). UE 하나가 걸리면 RAISE한다 — 표적 공격이라 셀 문턱을 두지 않는다(20_ §1.4)

#include "detect/config.h"
#include "detect/ue_alert.h"
#include "detect/ue_lookback.h"
#include "detect/ue_rule.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <vector>

namespace detect {

class ImsiExtractorRule : public UeRule {
 public:
  static constexpr const char* kId = "L3-24";

  explicit ImsiExtractorRule(ImsiExtractorConfig cfg = {}, AlertConfig alert = {});

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

  const LookbackMarks& marks() const { return marks_; }  // 테스트용: 표시(대기·결정됨)

 private:
  // 셀별 — 경보 누적값과 해제 기준 (20_ §3.5·§3.6). 밀어내기·불확실 경보는 L3-20과 같다(15_ §2.5·§2.6, 14_ §6.2)
  struct CellState {
    int64_t t_hit_last = 0;            // 마지막으로 UE가 걸린 시각(응답 t_r) — CLEAR 기준. extra는 늘리지 않는다
    int64_t extra_open = 0;            // 경보가 열린 뒤 걸린 연결에서 더 온 요청 없는 응답 수 (20_ §3.3-4)
    int64_t held_open = 0;             // 경보가 열린 뒤 보류된 판정 수
    std::deque<int64_t> held_times;    // 보류 시각 — raise의 held는 직전 clear_quiet_ms 동안 (이동 창)
    int64_t evicted_seen = 0;          // 상태표 셀별 누적 evicted 중 이미 적은 수
    int64_t evicted_open = 0;          // 경보가 열린 뒤 밀어내기 수 — update의 values.evicted
    std::deque<int64_t> evict_times;   // 밀어내기 시각 — raise의 values.evicted·해제 보류 (이동 창)
    std::vector<AlertUe> fresh_held;   // 이번 kpm2의 마감 처리에서 보류된 UE — held_tick에서 본다
    std::deque<AlertUe> held_ues;      // 마지막 보류 시각 기준 (t − clear_quiet_ms, t] 안의 보류 UE
    int64_t t_last_held = 0;           // 마지막 보류 시각 — 불확실 경보 CLEAR 기준
  };

  void hit(const LookbackMarks::Decision& dc, int64_t now, const UeRuleCtx& ctx, RuleOutput& out);
  void decorate(std::size_t from, RuleOutput& out);
  AlertUe held_ue(const LookbackMarks::Decision& dc, int64_t t_hit) const;
  void held_tick(int64_t cell, CellState& c, int64_t t, bool input_lost, const UeRuleCtx& ctx, RuleOutput& out);
  void close_held(int64_t cell, int64_t t, RuleOutput& out);
  void decorate_held(std::size_t from, RuleOutput& out);
  int64_t held_window(CellState& c, int64_t now) const;
  int64_t evicted_window(CellState& c, int64_t now) const;
  void note_evictions(CellState& c, int64_t cell, int64_t t, const UeRuleCtx& ctx);

  ImsiExtractorConfig cfg_;
  AlertConfig alert_;
  UeAlertBook book_;       // 공격 경보 (kind attack, stage 3)
  UeAlertBook held_book_;  // 불확실 경보 (kind anomaly, stage 3 — 14_ §6.2, 20_ §3.7)
  LookbackMarks marks_;
  std::map<int64_t, CellState> cells_;
};

}  // namespace detect
