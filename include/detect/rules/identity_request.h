#pragma once
// 4단계 룰 AN-02 — 식별 요청 증가 (21_ §5). 망의 IdentityRequest(보안 전)를 두 갈래로 본다.
//  - 갈래 ①: 이 망이 준 S-TMSI(RegistrationAccept로 할당 — S-TMSI 이력 표의 할당 기억)로 5G-GUTI 등록했는데 AMF가 식별을 요청 —
//    중간자가 등록 요청 안의 GUTI를 미지 값으로 바꿔 망의 식별 요청을 유도하면(#25 L3-25-OV) RRC의 S-TMSI는 원래 값이라 '준 적
//    있는 식별자인데 식별 요청'이 남는다. UE 하나로 RAISE
//  - 갈래 ②: 셀 창 W 안 식별 요청을 받은 연결 수 ≥ N — 여러 UE를 노릴 때, 또는 할당 기억이 없을 때(NAS 암호 망·늦게 뜸)
// AMF 재시작 뒤 정상 재등록도 같은 모양이라 공격이 아니라 이상 유형(kind anomaly)으로 경보한다(§5.1·§5.7).
// 판정 골격은 4단계 공통 헬퍼 HitWindow(ue_hits) — 갈래 ① 걸림은 force, 해제 기준은 마지막 성립(§5.5)

#include "detect/config.h"
#include "detect/ue_hits.h"
#include "detect/ue_rule.h"

#include <cstddef>
#include <cstdint>
#include <map>

namespace detect {

class IdentityRequestRule : public UeRule {
 public:
  static constexpr const char* kId = "AN-02";

  explicit IdentityRequestRule(IdentityRequestConfig cfg = {}, AlertConfig alert = {});

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
  void decorate(std::size_t from, RuleOutput& out, const AlertUe* hit = nullptr);  // hit = 이번 걸림 (이슈 #84)

  IdentityRequestConfig cfg_;
  AlertConfig alert_;
  HitWindow hits_;
  std::map<int64_t, bool> branch1_;  // 셀 → 지금 경보에 갈래 ① UE가 한 번이라도 실렸나 (branch "1", §5.3-3)
};

}  // namespace detect
