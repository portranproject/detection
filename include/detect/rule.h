#pragma once
// 룰 인터페이스 (1_ FR-4). 룰은 series가 갱신된 직후 그 결과(FeedResult)를 받아 경보 이벤트를 낸다.
// 룰은 series를 읽기만 한다 — 입력 건전성(보류·H_hold·버퍼 비움)은 series가 맡는다 (Q-46, 4_ §2).
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
  virtual void on_feed(const Series& series, const FeedResult& fed, RuleOutput& out) = 0;
};

}  // namespace detect
