#pragma once
// 룰 L3-24 — 하향 IMSI 추출(Downlink IMSI Extractor) 탐지 (20_ §3). AS 보안이 서기 전 공중의 중간자가 피해 UE에 IdentityRequest를
// 주입하고 UE의 응답을 정상 기지국으로 넘기면, CU에는 주입한 요청은 보이지 않고 요청 없이 온 IdentityResponse만 보인다.
// 그 응답을 '요청 없는 응답'(20_ §1.2 — 공통 헬퍼 ue_lookback)으로 잡는다. 정상 망은 SUCI를 모를 때만 식별을 요청하고 그때는
// 요청·응답이 짝으로 보인다(5_ §15). 응답을 넘기지 않는 공격(순수 FBS)은 보이지 않으므로 경보에 전제 mitm_ul_relay를
// 싣는다(20_ §1.3). UE 하나가 걸리면 RAISE한다 — 표적 공격이라 셀 문턱을 두지 않는다(20_ §1.4)

#include "detect/config.h"
#include "detect/ue_alert.h"
#include "detect/ue_held.h"
#include "detect/ue_lookback.h"
#include "detect/ue_rule.h"

#include <cstddef>
#include <cstdint>
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
  // 셀별 — 경보 누적값과 해제 기준 (20_ §3.5·§3.6). 밀어내기 창은 evict_, 불확실 경보는 held_ (15_ §2.5·§2.6, 14_ §6.2 — R1, 이슈 #96)
  struct CellState {
    int64_t t_hit_last = 0;            // 마지막으로 UE가 걸린 시각(응답 t_r) — CLEAR 기준. extra는 늘리지 않는다
    int64_t epoch = 0;                 // 경보 세대 — 새 경보마다 +1, 표시의 epoch과 대조 (11/05 W-34)
    int64_t extra_open = 0;            // 경보가 열린 뒤 걸린 연결에서 더 온 요청 없는 응답 수 (20_ §3.3-4)
  };

  void hit(const LookbackMarks::Decision& dc, int64_t now, const UeRuleCtx& ctx, RuleOutput& out);
  void decorate(std::size_t from, RuleOutput& out);
  AlertUe held_ue(const LookbackMarks::Decision& dc, int64_t t_hit) const;

  ImsiExtractorConfig cfg_;
  AlertConfig alert_;
  UeAlertBook book_;   // 공격 경보 (kind attack, stage 3)
  HeldBook held_;      // 불확실 경보 (kind anomaly, stage 3 — 14_ §6.2, 20_ §3.7; 공통 헬퍼 R1)
  EvictWindow evict_;  // 상태표 밀어내기 창 (14_ §6.3 — Q-56)
  LookbackMarks marks_;
  std::map<int64_t, CellState> cells_;
};

}  // namespace detect
