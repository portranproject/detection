#pragma once
// 4단계 룰 AN-06a — 보안 수립 뒤 재인증·SMC 재등장 (21_ §4). NAS 보안이 선 연결(갱신 전 nas_sec ON)에 망이 AuthenticationRequest
// 또는 NAS SecurityModeCommand를 다시 보내면 '보안 뒤 재등장'이다. 옛 보안 모드 명령·완료를 키 갱신 시점에 재전송해 NAS 카운터를
// 되돌리면 그 뒤 무결성 실패로 망이 재인증한다(#6 reset 원형 L3-06-O1). 이 테스트베드 AMF(Open5GS)는 같은 연결에서 보안이 선 뒤
// 재인증·키 갱신 명령을 보내지 않아(5_ §16) 1회로 이상이지만, 다른 AMF의 정상 키 갱신과 가르지 못해 이상 유형(kind anomaly)으로
// 경보한다(§4.1). AMF 재전송(T3560)은 응답이 없을 때라 nas_sec이 ON이 아니다. 보안 뒤 NAS라 평문(5G-EA0)일 때만 이름이 보인다.
// 줄에서 바로 성립하는 판정이고(§1.1) 셀 문턱 없이 UE 하나로 RAISE한다(§4.3-3) — 골격은 4단계 공통 헬퍼 HitWindow(ue_hits)

#include "detect/config.h"
#include "detect/ue_hits.h"
#include "detect/ue_rule.h"

#include <cstddef>
#include <cstdint>
#include <map>

namespace detect {

class SecReauthRule : public UeRule {
 public:
  static constexpr const char* kId = "AN-06a";

  explicit SecReauthRule(SecReauthConfig cfg = {}, AlertConfig alert = {});

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

  SecReauthConfig cfg_;
  AlertConfig alert_;
  HitWindow hits_;
  std::map<UeId, int64_t> reauth_n_;  // 걸리기 전 연결별 보안 뒤 재등장 수 — n_reauth에 닿으면 걸린다 (§4.3-2)
};

}  // namespace detect
