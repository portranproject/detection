#pragma once
// 4단계 룰 AN-08 — 기존 UE들의 재등록 급증 (21_ §8). 최근 이 망에서 본 UE들(S-TMSI 이력 표에 최근 연결 레코드가 있거나 이 망이
// 준 식별자 — 14_ §3.2)이 창 W 안에 N대 이상 이동 등록(mobility registration updating)을 요청하면 이상 유형으로 걸린다. 변조 SIB1의
// TAC를 보고 UE들이 TA가 바뀐 줄 알거나(#17 SIB TAC 조작 L3-17-OV), 가짜 기지국에 캠핑했다 정상망으로 돌아오면(#26 순수 FBS
// L3-26-O) 이 모양이 남는다 — 둘은 KPM으로 갈리지 않아 후보는 고정이다(§8.3-4). 등록 요청 줄에서 판정한다(§1.1).
// 창 안 수는 서로 다른 S-TMSI 수다(11/04 사용자 결정 — 연결마다 세면 이동 등록이 실패한 단말 한 대의 T3511 재시도로 RAISE).
// 그래서 걸림 키는 연결이 아니라 S-TMSI이고, 회복 전 재등록은 경보 values.extra로 센다(§8.3-1, 21_ §1.1 원칙). 골격은 4단계 공통
// 헬퍼 HitWindow(ue_hits) — 걸림은 열린 연결에서 생기므로 식별·uncertain은 그 연결(ref)에서 다시 채운다

#include "detect/config.h"
#include "detect/ue_hits.h"
#include "detect/ue_rule.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>

namespace detect {

class KnownRegBurstRule : public UeRule {
 public:
  static constexpr const char* kId = "AN-08";

  explicit KnownRegBurstRule(KnownRegBurstConfig cfg = {}, AlertConfig alert = {});

  const char* id() const override { return kId; }
  int64_t evidence_horizon_ms() const override;
  void on_ue_event(const UeEvt& evt, const UeState& before, const UeState& after, const UeRuleCtx& ctx,
                   RuleOutput& out) override;
  void on_deadline(const Deadline&, const UeRuleCtx&, RuleOutput&) override {}  // 마감을 쓰지 않는다(§1.1)
  void on_ue_close(const UeState& last, CloseReason reason, int64_t t, const UeRuleCtx& ctx, RuleOutput& out) override;
  void on_cell_tick(int64_t cell, const Kpm2& k, const CellLoss& loss, bool input_lost, const UeRuleCtx& ctx,
                    RuleOutput& out) override;
  void on_session_reset(const UeRuleCtx& ctx, RuleOutput& out) override;
  void on_input_silent(const UeRuleCtx& ctx, RuleOutput& out) override;

 private:
  using UeId = HitWindow::UeId;

  void decorate(std::size_t from, RuleOutput& out);

  KnownRegBurstConfig cfg_;
  AlertConfig alert_;
  HitWindow hits_;
  std::map<UeId, int64_t> last_reg_;  // 걸린 S-TMSI 키 → 마지막으로 걸리는 이동 등록을 한 시각 — 창 W 동안 없으면 회복 (§8.3-1)
  std::set<UeId> seen_;               // 이미 센 연결 (키, uid) — 같은 연결의 등록 요청 재전송은 다시 세지 않는다. 닫히면 지운다
};

}  // namespace detect
