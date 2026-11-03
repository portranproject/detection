#pragma once
// 룰 L3-06 — NAS 카운터 비동기화, 상향 desync 원형(L3-06-O2) 탐지 (20_ §5). AS 보안이 서기 전 평문 구간에서 중간자가 무효 NAS
// SecurityModeCommand를 UE에 주입하고 UE가 보내는 Security Mode Reject를 정상 망으로 넘기면, CU에는 주입한 명령은 보이지 않고
// 망이 보낸 적 없는 명령에 대한 Reject만 보인다. UE는 거부할 때마다 UL NAS COUNT를 올려 반복되면 망과 어긋난다.
// 그 Reject를 '요청 없는 응답'(20_ §1.2 — 공통 헬퍼 ue_lookback)으로 잡되, 보안 모드 명령의 정상 응답은 Complete와 Reject 둘이라
// 응답 수 A를 응답 집합(Complete ∪ Reject)으로 센다(20_ §5.3). 4단계 AN-06b였으나 판정·전제가 3단계와 같아 공격 경보로
// 올렸다(11/03 확인 지점 ②). 응답을 넘기지 않는 공격은 보이지 않으므로 전제 mitm_ul_relay를 싣고(20_ §1.3), UE 하나가 걸리면
// RAISE한다(20_ §1.4). 판정·경보 골격은 L3-24(imsi_extractor)와 같고 메시지·응답 집합·UE 값·후보만 다르다

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

class NasDesyncRule : public UeRule {
 public:
  static constexpr const char* kId = "L3-06";

  explicit NasDesyncRule(NasDesyncConfig cfg = {}, AlertConfig alert = {});

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
  // 셀별 — 경보 누적값과 해제 기준 (20_ §5.5·§5.6 — L3-24 §3.5·§3.6과 같음). 밀어내기·불확실 경보는 L3-20과 같다
  // (15_ §2.5·§2.6, 14_ §6.2)
  struct CellState {
    int64_t t_hit_last = 0;            // 마지막으로 UE가 걸린 시각(Reject t_r) — CLEAR 기준. extra는 늘리지 않는다
    int64_t extra_open = 0;            // 경보가 열린 뒤 걸린 연결에서 더 온 요청 없는 Reject 수 (20_ §5.3-4)
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

  NasDesyncConfig cfg_;
  AlertConfig alert_;
  UeAlertBook book_;       // 공격 경보 (kind attack, stage 3)
  UeAlertBook held_book_;  // 불확실 경보 (kind anomaly, stage 3 — 14_ §6.2, 20_ §5.7)
  LookbackMarks marks_;
  std::map<int64_t, CellState> cells_;
};

}  // namespace detect
