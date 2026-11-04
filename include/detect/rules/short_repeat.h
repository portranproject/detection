#pragma once
// 4단계 룰 AN-04 — 같은 UE의 짧은 연결 반복 (21_ §6). 같은 S-TMSI가 짧은 연결(CONNECTED에 닿고 short_ms 안에 끝남)을 창 W 안에
// N번 이상 반복하면 이상 유형으로 걸린다. 가짜 페이징으로 서비스 요청을 유발하거나(#2 페이징형 L3-02-Oa·#12 5G 변형 L3-12-V),
// 반복 호출로 페이징을 유발하거나(#34 TORPEDO L3-34-OV), 해제를 주입해 즉시 재접속시키면(#33 주입 변형 L3-33-V) 이 모양이 남는다.
// CU가 페이징했는지(F1AP PAGING)는 24종 밖이라 넷을 가르지 못하고, 설정 원인·DU 해제 요청 원인으로 후보만 좁힌다(§6.3-4).
// 연결의 길이·결과는 닫힐 때 정해지므로 닫힐 때 판정한다(§1.3) — 상태표가 S-TMSI 이력 표에 레코드를 먼저 넣으므로 history()에
// 이 연결이 들어 있다(14_ §7 ⑦). 걸림 키는 연결이 아니라 S-TMSI다 — 같은 S-TMSI는 회복 전까지 한 칸이고 그 뒤 반복은 경보
// values.extra로 센다(§6.3-2, 21_ §1.1 11/04 원칙). 골격은 4단계 공통 헬퍼 HitWindow(ue_hits)

#include "detect/config.h"
#include "detect/ue_hits.h"
#include "detect/ue_rule.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <tuple>

namespace detect {

class ShortRepeatRule : public UeRule {
 public:
  static constexpr const char* kId = "AN-04";

  explicit ShortRepeatRule(ShortRepeatConfig cfg = {}, AlertConfig alert = {});

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

  void decorate(std::size_t from, RuleOutput& out, const AlertUe* hit = nullptr);  // hit = 이번 걸림 (이슈 #84)

  ShortRepeatConfig cfg_;
  AlertConfig alert_;
  HitWindow hits_;
  std::map<UeId, int64_t> last_short_;  // 걸린 S-TMSI 키 → 마지막 짧은 연결이 닫힌 시각 — 창 W 동안 없으면 회복 (§6.3-2)
  // 로그 줄용 Part1 (48비트를 모를 때 s_tmsi= 대신 part1=) — 걸린 연결 (셀, du_ue_id, uid) → Part1. 경보에 실리면 지운다
  std::map<std::tuple<int64_t, int64_t, int64_t>, uint64_t> part1_of_;
};

}  // namespace detect
