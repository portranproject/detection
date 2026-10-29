#pragma once
// 처리 흐름 (4_ §3, 14_ §7): 줄 → 파싱 → series → 1단계 룰(on_feed) → 2단계가 켜져 있으면 줄 유형별로
// UE 상태표·마감 목록·2단계 룰 → 경보 이벤트.
// I/O가 없어 테스트에서는 시나리오 재생기로, 나중에는 실행 파일(M4)이 소켓·파일 입력을 넣는다.

#include "detect/alert.h"
#include "detect/config.h"
#include "detect/deadline_queue.h"
#include "detect/diag.h"
#include "detect/rule.h"
#include "detect/series.h"
#include "detect/ue_rule.h"
#include "detect/ue_table.h"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace detect {

struct EngineOutput {
  std::vector<Diag> diags;         // series·상태표·룰 진단
  std::vector<AlertEvent> alerts;  // 경보 이벤트
  // 이번 줄을 series가 어떻게 처리했는지 — 증거 기록기가 '그 셀의 새 칸'과 끊김을 알려고 쓴다 (3_ §7.1)
  FeedOutcome outcome = FeedOutcome::Dropped;
  std::optional<int64_t> cell_id;
  std::optional<GapEvent> gap;
  // 이번 줄(ue_evt)이 반영된 UE — UE 증거 active용 (14_ §8.4)
  struct UeLine {
    UeKey key;
    int64_t uid = 0;
    int64_t seq = 0;
    std::string raw;  // 받은 원본 줄 그대로
  };
  std::optional<UeLine> ue_line;
};

class Engine {
 public:
  explicit Engine(SeriesConfig cfg = {}, std::size_t max_line_bytes = kDefaultMaxLineBytes, UeTableConfig ue_cfg = {});

  void add_rule(std::unique_ptr<Rule> rule);
  // 2단계 이상 룰 (14_ §1.1). hello에 ue_evt 표시가 있을 때만 불린다 (2_ §6.5).
  // 닫힌 항목 recent 보관 시간을 룰의 증거 지평에 맞춰 늘린다 (14_ §2.3)
  void add_ue_rule(std::unique_ptr<UeRule> rule);
  EngineOutput feed_line(std::string_view line);
  // 입력 침묵 (3_ §8, 14_ §6.2 — 10/29 Q-45 해결, 이슈 #50): 실행 파일이 벽시계로 마지막 kpm2 뒤 input_silent_ms 동안
  // kpm2가 없다고 알린다(core에는 시계가 없다). 진단 input_silent 1회와 모든 룰의 진행 중 경보 END(reason=input_silent).
  // 버퍼·기준선·세션·상태표·마감 목록·셀 시계는 그대로 — 판정은 데이터 시각이다. silent_ms = 침묵 길이(진단 문구용)
  EngineOutput on_input_silent(int64_t silent_ms);

  const Series& series() const { return series_; }
  const UeTable& ue_table() const { return table_; }
  const DeadlineQueue& deadlines() const { return deadlines_; }
  bool stage2() const { return stage2_; }  // 2단계 이상 룰이 켜져 있는지 — hello.ue_evt (2_ §6.5)

 private:
  void on_hello(FeedOutcome outcome, int64_t seq, EngineOutput& out);
  void on_ue_evt(UeEvt& e, int64_t seq, EngineOutput& out);  // e의 raw를 ue_line으로 옮겨 쓴다 (이슈 #54)
  void on_f1_evt(const F1Evt& f, int64_t seq, EngineOutput& out);
  void on_kpm2(const FeedResult& fed, int64_t seq, EngineOutput& out);
  void reset_stage2(int64_t seq, EngineOutput& out);
  void notify_close(const std::vector<UeTable::Closed>& closed, int64_t t, int64_t seq, EngineOutput& out);
  UeRuleCtx ctx(std::size_t owner, int64_t seq);

  Series series_;
  std::size_t max_line_bytes_;  // 2_ §1 줄 길이 상한 (설정 max_line_bytes)
  std::vector<std::unique_ptr<Rule>> rules_;
  std::vector<std::unique_ptr<UeRule>> ue_rules_;
  UeTable table_;
  DeadlineQueue deadlines_;
  bool stage2_ = false;
};

}  // namespace detect
