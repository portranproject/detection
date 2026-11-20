#pragma once
// 4단계 룰 AN-01 — 인증 동기 실패 재인증 (21_ §3). 한 연결에서 UE가 AuthenticationFailure(5GMM 원인값 #21 synch failure)를
// 보내면 '인증 동기 실패 재인증' 이상 유형으로 걸린다. 공격자가 피해자 명의 등록을 반복해 홈망 SQN을 앞당기면 피해자의 정상
// 인증이 동기 실패한다(#7 L3-07-OV) — 다만 한 건으로는 정상 SQN 어긋남과 가르지 못해 공격이 아니라 이상 유형(kind anomaly)으로
// 경보하고 후보만 싣는다(§3.1). 원인값이 이미 입력에 있어(2_ §6.3) MAC 실패(#20 — L3-21 몫)와 가른다. 줄에서 바로 성립하는
// '있는 것을 본 판정'이라 보류가 없고(§1.1), 셀 창 W 안 동기 실패 연결 수 ≥ N이면 RAISE한다(기본 N = 1 — 표적 공격, §3.3-3).
// 판정 골격은 4단계 공통 헬퍼 HitWindow(ue_hits)

#include "detect/config.h"
#include "detect/ue_hits.h"
#include "detect/ue_rule.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>

namespace detect {

class SyncFailureRule : public UeRule {
 public:
  static constexpr const char* kId = "AN-01";

  explicit SyncFailureRule(SyncFailureConfig cfg = {}, AlertConfig alert = {});

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

  void decorate(std::size_t from, RuleOutput& out, const AlertUe* hit = nullptr);  // hit = 이번 걸림 (이슈 #84)

  SyncFailureConfig cfg_;
  AlertConfig alert_;
  HitWindow hits_;
  // 앞선 RegistrationRequest의 f.id_type (21_ §3.2 — ues[].values.id_type). 상태표 cnt에는 id_type이 없어 룰이 연결마다
  // 들고 있는다(L3-01-O와 같은 방식, 15_ §4.6)
  std::map<UeId, std::optional<std::string>> id_type_;
  std::set<UeId> reauth_;  // 걸린 뒤 재인증(AuthenticationRequest)이 관측된 연결 — values.reauth는 연결당 1 (§3.3-2)
};

}  // namespace detect
