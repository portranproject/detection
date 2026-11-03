#pragma once
// 4단계 룰 AN-07 — 같은 S-TMSI의 Setup 반복·Complete 없음 (21_ §7). 같은 S-TMSI Part1의 RRCSetupRequest가 창 W 안에 N번 이상 오고
// 모두 RRCSetupComplete 없이 끝나면 이상 유형으로 걸린다. 중간자가 거절을 주입하고 UL을 중계하거나(#11 변형 L3-11-V1), waitTime
// 거절을 반복하면(5G 축소형 L3-11-V2) 같은 단말이 Part1을 바꾸지 않고 Setup만 되풀이하는 모양이 남는다 — 둘은 KPM으로 갈리지 않아
// 후보는 고정이다(§7.3-4). 1단계 L3-01-V와 표 II 모양은 같지만 그쪽은 무작위 식별자 다수, 이쪽은 같은 Part1의 반복이다(§7.1).
// 망이 거절한 연결(그 연결에서 RRCReject를 봄)은 세지 않는다 — 자원 부족·정상 거절이다(11/04 사용자 결정: 거절 뒤 CU의
// UEContextReleaseCommand가 rrc를 RELEASING으로 덮으므로 rrc_last가 아니라 '거절을 봤는지'로 본다, 14_ §3.2 rejected).
// 연결의 결과는 닫힐 때 정해지므로 닫힐 때 판정한다(§1.3). 걸림 키는 연결이 아니라 Part1이고, 회복 전 반복은 경보 values.extra로
// 센다(§7.3-2, 21_ §1.1 11/04 원칙 — AN-04와 같음). 골격은 4단계 공통 헬퍼 HitWindow(ue_hits)

#include "detect/config.h"
#include "detect/ue_hits.h"
#include "detect/ue_rule.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <tuple>

namespace detect {

class SetupRepeatRule : public UeRule {
 public:
  static constexpr const char* kId = "AN-07";

  explicit SetupRepeatRule(SetupRepeatConfig cfg = {}, AlertConfig alert = {});

  const char* id() const override { return kId; }
  int64_t evidence_horizon_ms() const override;
  void on_ue_event(const UeEvt&, const UeState&, const UeState&, const UeRuleCtx&, RuleOutput&) override {}
  void on_deadline(const Deadline&, const UeRuleCtx&, RuleOutput&) override {}  // 마감을 쓰지 않는다(§1.1)
  void on_ue_close(const UeState& last, CloseReason reason, int64_t t, const UeRuleCtx& ctx, RuleOutput& out) override;
  void on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss& loss, bool input_lost, const UeRuleCtx& ctx,
                    RuleOutput& out) override;
  void on_session_reset(const UeRuleCtx& ctx, RuleOutput& out) override;
  void on_input_silent(const UeRuleCtx& ctx, RuleOutput& out) override;

 private:
  using UeId = HitWindow::UeId;

  void decorate(std::size_t from, RuleOutput& out);

  SetupRepeatConfig cfg_;
  AlertConfig alert_;
  HitWindow hits_;
  std::map<UeId, int64_t> last_fail_;  // 걸린 Part1 키 → 마지막 미완료 연결이 닫힌 시각 — 창 W 동안 없으면 회복 (§7.3-2)
};

}  // namespace detect
