#pragma once
// 룰 L3-14 — UE 능력 탈취(Capability Hijacking) 탐지 (20_ §4). AS 보안이 서기 전 평문 구간에서 UE의 단말 능력(기기 지문)을
// 받아내는 공격이다. 길이 둘이고 경보의 뜻이 다르다(20_ §4.1).
//  - 갈래 ① (L3-14-O): 공중의 중간자가 보안 전 UECapabilityEnquiry를 주입하고 UE의 응답을 정상 기지국으로 넘김 →
//    요청 없는 UECapabilityInformation. '요청 없는 응답'(20_ §1.2, 공통 헬퍼 ue_lookback) — medium, 전제 mitm_ul_relay
//  - 갈래 ② (L3-14-V1): CU 자신이 AS 보안 전에 UECapabilityEnquiry를 보냄(설정 오류·침해) — '이 요청 앞에 보안이 섰는가'를
//    같은 되돌아보는 틀로 판정(20_ §4.3). 표준 위반이라 중간자 없이도 능력이 평문으로 나가므로 high, 전제 없음
// 두 갈래를 (룰, 셀) 경보 하나에 싣고 branch로 가른다(L3-21과 같은 방식). 표시는 (키, uid, 갈래)라 한 연결이 두 갈래에 다
// 걸릴 수 있다. 실린 UE들의 전제(conditions)가 바뀌면 바로 UPDATE한다(20_ §4.5)

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

class CapHijackRule : public UeRule {
 public:
  static constexpr const char* kId = "L3-14";
  static constexpr const char* kTagUnsolicited = "unsolicited";        // 갈래 ① 표시 tag
  static constexpr const char* kTagPreSecEnquiry = "pre_sec_enquiry";  // 갈래 ② 표시 tag (20_ §4.3-3)

  explicit CapHijackRule(CapHijackConfig cfg = {}, AlertConfig alert = {});

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

  const LookbackMarks& marks() const { return marks_; }  // 테스트용: 표시(대기·결정됨), 갈래별

 private:
  // 셀별 — 경보 누적값과 해제 기준 (20_ §4.5·§4.6). 밀어내기·불확실 경보는 L3-24·L3-20과 같다
  struct CellState {
    int64_t t_hit_last = 0;            // 마지막으로 UE가 걸린 시각(두 갈래 중 늦은 것) — CLEAR 기준
    int64_t branch1_ues = 0;           // 경보가 열린 뒤 갈래별 걸림 수 (values)
    int64_t branch2_ues = 0;
    bool branch2_seen = false;         // 갈래 ②가 한 번이라도 걸렸다 — branch "2" (심각도가 높은 쪽)
    bool premise_mitm = false;         // 실린 UE들의 전제 합 — 갈래 ① UE가 있으면 mitm_ul_relay (20_ §4.6)
    int64_t epoch = 0;                 // 경보 세대 — 새 경보마다 +1, 표시의 epoch과 대조 (11/05 W-34)
    int64_t extra_open = 0;            // 경보가 열린 뒤 걸린 연결에서 더 온 같은 갈래 신호 수
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
  void decorate(std::size_t from, RuleOutput& out, bool premise_changed = false);
  AlertUe held_ue(const LookbackMarks::Decision& dc, int64_t t_hit) const;
  void held_tick(int64_t cell, CellState& c, int64_t t, bool input_lost, const UeRuleCtx& ctx, RuleOutput& out);
  void close_held(int64_t cell, int64_t t, RuleOutput& out);
  void decorate_held(std::size_t from, RuleOutput& out);
  int64_t held_window(CellState& c, int64_t now) const;
  int64_t evicted_window(CellState& c, int64_t now) const;
  void note_evictions(CellState& c, int64_t cell, int64_t t, const UeRuleCtx& ctx);
  void count_extra(const UeState& n, const char* tag);

  CapHijackConfig cfg_;
  AlertConfig alert_;
  UeAlertBook book_;       // 공격 경보 (kind attack, stage 3)
  UeAlertBook held_book_;  // 불확실 경보 (kind anomaly, stage 3 — 14_ §6.2, 20_ §4.7)
  LookbackMarks marks_;
  std::map<int64_t, CellState> cells_;
};

}  // namespace detect
