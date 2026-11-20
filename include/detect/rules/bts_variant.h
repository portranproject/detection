#pragma once
// 룰 L3-01-V — UE 컨텍스트 고갈 공격(Msg5 미전송) 탐지 (3_ 1단계 룰 명세서).
// 모듈 이름 bts_variant는 영문 식별자라 개명 전 이름을 그대로 쓴다 (4_ §2).
// 입력 건전성(윈도우 합계·보류·H_hold·필수 키 누락)은 series가 FeedResult로 넘기고(Q-46), 여기서는 판정·경보만 한다.

#include "detect/alert.h"
#include "detect/baseline.h"
#include "detect/config.h"
#include "detect/rule.h"

#include <map>
#include <optional>
#include <string>

namespace detect {

class BtsVariantRule : public Rule {
 public:
  static constexpr const char* kId = "L3-01-V";

  explicit BtsVariantRule(BtsVariantConfig cfg = {});

  const char* id() const override { return kId; }
  void on_feed(const Series& series, const FeedResult& fed, RuleOutput& out) override;
  void on_input_silent(RuleOutput& out) override;

  // 테스트용: 셀의 현재 상태
  bool alert_active(int64_t cell_id) const;
  std::optional<AlertMode> mode(int64_t cell_id) const;
  std::optional<double> base(int64_t cell_id) const;

 private:
  // 셀마다 독립된 판정 상태 (3_ §4 '셀별로')
  struct CellState {
    CellState(const BtsVariantConfig& cfg, int64_t period_ms);
    AlertMachine machine;
    Baseline base;     // A_w의 기준선·표준편차 (3_ §5)
    Baseline base_dl;  // A′_w의 기준선 base′·표준편차 σ′ (3_ §4.1)
    std::optional<AlertMode> mode;
    bool warmup_done = false;
    bool c2a_off_logged = false;  // 셀 한도를 몰라 C2a를 끈 진단을 냈는지 — 셀마다 1회 (3_ §4, 11/12)
    // 진행 중 경보
    std::string alert_id;
    Severity severity = Severity::Medium;
    int64_t last_t = 0;
  };

  // 한 칸을 처리하는 동안 쓰는 값 묶음 (셀·시각·파라미터·그 칸의 입력)
  struct Ctx;
  // 한 칸의 판정 결과 (3_ §4·§4.1·§5)
  struct Verdict;

  // on_feed의 단계 — 순서대로 부른다 (3_ §4 처리 순서, 해설 §3). 모드(normal·dl_missing·보류)는 series가 FeedResult로 준다
  // (3_ §4.1 결정 E1 — 11/05 26_ R4, 이슈 #98)
  Verdict evaluate(const CellState& st, AlertMode mode, const WindowSums& w, bool was_active, bool warming,
                   std::optional<int64_t> f_abs) const;  // 3_ §4·§4.1
  void update_baseline(CellState& st, const Ctx& c, AlertMode mode, const WindowSums& w, const Verdict& v,
                       bool alert_slot, RuleOutput& out);                // 3_ §5
  void emit(CellState& st, const Ctx& c, AlertMode mode, const WindowSums& w, const Verdict& v,
            AlertMachine::Step step, RuleOutput& out);                   // 3_ §7·§6.1 다
  void end_alert(CellState& st, int64_t cell_id, int64_t t, const char* reason, RuleOutput& out,
                 const Ctx* c = nullptr);                                 // 3_ §7.1 end 레코드 — c가 있으면 그 칸의 uectx

  BtsVariantConfig cfg_;
  std::map<int64_t, CellState> cells_;
};

}  // namespace detect
