#pragma once
// 처리 흐름 (4_ §3): 줄 → 파싱 → series → 등록된 룰마다 on_feed → 경보 이벤트.
// I/O가 없어 테스트에서는 시나리오 재생기로, 나중에는 실행 파일(M4)이 소켓·파일 입력을 넣는다.

#include "detect/alert.h"
#include "detect/diag.h"
#include "detect/rule.h"
#include "detect/series.h"

#include <memory>
#include <string_view>
#include <vector>

namespace detect {

struct EngineOutput {
  std::vector<Diag> diags;         // series·룰 진단
  std::vector<AlertEvent> alerts;  // 경보 이벤트
  // 이번 줄을 series가 어떻게 처리했는지 — 증거 기록기가 '그 셀의 새 칸'과 끊김을 알려고 쓴다 (3_ §7.1)
  FeedOutcome outcome = FeedOutcome::Dropped;
  std::optional<int64_t> cell_id;
  std::optional<GapEvent> gap;
};

class Engine {
 public:
  explicit Engine(SeriesConfig cfg = {});

  void add_rule(std::unique_ptr<Rule> rule);
  EngineOutput feed_line(std::string_view line);

  const Series& series() const { return series_; }

 private:
  Series series_;
  std::vector<std::unique_ptr<Rule>> rules_;
};

}  // namespace detect
