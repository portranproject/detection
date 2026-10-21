#include "detect/engine.h"

#include <utility>

namespace detect {

Engine::Engine(SeriesConfig cfg) : series_(std::move(cfg)) {}

void Engine::add_rule(std::unique_ptr<Rule> rule) { rules_.push_back(std::move(rule)); }

// 한 줄 처리 (4_ §3): series를 먼저 갱신하고, 그 결과를 등록 순서대로 모든 룰에 넘긴다
EngineOutput Engine::feed_line(std::string_view line) {
  EngineOutput out;
  FeedResult fed = series_.feed(parse_line(line));
  out.diags = std::move(fed.diags);
  for (auto& rule : rules_) {
    RuleOutput ro;
    rule->on_feed(series_, fed, ro);
    out.diags.insert(out.diags.end(), ro.diags.begin(), ro.diags.end());
    out.alerts.insert(out.alerts.end(), ro.alerts.begin(), ro.alerts.end());
  }
  return out;
}

}  // namespace detect
