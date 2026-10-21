#pragma once
// 룰 인터페이스 (1_ FR-4). 룰은 series가 갱신된 직후 그 결과(FeedResult)를 받아 경보 이벤트를 낸다.
// 룰 추가 = rules/에 파일 하나 + Engine::add_rule 한 줄 (4_ §2)

#include "detect/alert.h"
#include "detect/diag.h"
#include "detect/series.h"

#include <vector>

namespace detect {

struct RuleOutput {
  std::vector<AlertEvent> alerts;
  std::vector<Diag> diags;
};

class Rule {
 public:
  virtual ~Rule() = default;
  virtual const char* id() const = 0;
  // series는 H_hold 초과 시 버퍼를 비우려고(3_ §8) 쓰기 가능으로 받는다
  virtual void on_feed(Series& series, const FeedResult& fed, RuleOutput& out) = 0;
};

}  // namespace detect
