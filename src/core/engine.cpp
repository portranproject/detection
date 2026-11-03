#include "detect/engine.h"

#include <iterator>
#include <utility>

namespace detect {
namespace {

void append(RuleOutput& ro, EngineOutput& out) {
  out.diags.insert(out.diags.end(), std::make_move_iterator(ro.diags.begin()), std::make_move_iterator(ro.diags.end()));
  out.alerts.insert(out.alerts.end(), std::make_move_iterator(ro.alerts.begin()),
                    std::make_move_iterator(ro.alerts.end()));
}

}  // namespace

Engine::Engine(SeriesConfig cfg, std::size_t max_line_bytes, UeTableConfig ue_cfg)
    : series_(std::move(cfg)), max_line_bytes_(max_line_bytes), table_(ue_cfg) {
  deadlines_.set_diag_streak_ms(ue_cfg.dl_unobserved_ms);  // 14_ §6.2 진단 연속 시간 (16_ W-24)
}

void Engine::add_rule(std::unique_ptr<Rule> rule) { rules_.push_back(std::move(rule)); }

// 증거 지평에 더하는 여유 ue_table.recent_keep_margin_ms (14_ §2.3, 기본 1 s). 마감은 그 시각이 든 kpm2 창에서
// 처리되고 룰이 경보를 on_cell_tick에서 낼 수도 있어, 걸린 UE의 보관분이 경보와 같은 줄에서 먼저 지워지지 않게 더한다
void Engine::add_ue_rule(std::unique_ptr<UeRule> rule) {
  const int64_t keep = rule->evidence_horizon_ms() + table_.config().recent_keep_margin_ms;
  if (keep > table_.recent_keep_ms()) table_.set_recent_keep_ms(keep);
  // 늦은 줄 제외 길이 late_until은 증거 지평 최댓값(여유 없이) (14_ §4.3, 이슈 #46)
  if (rule->evidence_horizon_ms() > table_.late_horizon_ms()) table_.set_late_horizon_ms(rule->evidence_horizon_ms());
  ue_rules_.push_back(std::move(rule));
}

// 한 줄 처리 (4_ §3, 14_ §7): series를 먼저 갱신하고, 그 결과를 등록 순서대로 1단계 룰에 넘긴다.
// 2단계가 켜져 있으면 이어서 줄 유형별로 UE 상태표·마감 목록·2단계 룰에 넘긴다 — kpm2는 1단계 다음이다(14_ §7 kpm2 ①)
EngineOutput Engine::feed_line(std::string_view line) {
  EngineOutput out;
  ParseResult parsed = parse_line(line, max_line_bytes_);  // ue_evt의 raw는 on_ue_evt가 옮겨 간다
  FeedResult fed = series_.feed(parsed);
  out.diags = std::move(fed.diags);
  out.outcome = fed.outcome;
  out.cell_id = fed.cell_id;
  out.gap = fed.gap;
  for (auto& rule : rules_) {
    RuleOutput ro;
    rule->on_feed(series_, fed, ro);
    append(ro, out);
  }

  const int64_t seq = parsed.common ? parsed.common->seq : 0;
  switch (fed.outcome) {
    case FeedOutcome::SessionStarted:
    case FeedOutcome::SessionReset:
    case FeedOutcome::SessionResumed:
      on_hello(fed.outcome, seq, out);
      break;
    case FeedOutcome::Stored:
      if (stage2_) on_kpm2(fed, seq, out);
      break;
    case FeedOutcome::Passed:
      if (!stage2_) break;
      if (auto* e = std::get_if<UeEvt>(&parsed.msg)) on_ue_evt(*e, seq, out);
      if (const auto* f = std::get_if<F1Evt>(&parsed.msg)) on_f1_evt(*f, seq, out);
      break;
    case FeedOutcome::Dropped:
    case FeedOutcome::Ignored:
      break;
  }
  return out;
}

// 입력 침묵 (3_ §8, 14_ §6.2 — Q-45 해결, 이슈 #50): 진단 1회 → 1단계 룰 → 2단계 룰(켜져 있을 때만). 줄을 처리한 것이
// 아니므로 outcome은 Dropped — 증거 기록기는 out.alerts의 END만 보고 경보 track을 끝낸다(3_ §7.1). seq는 0 — END는
// alert_id를 새로 만들지 않는다. 반복(다시 kpm2가 올 때까지 1회)은 실행 파일이 막는다
EngineOutput Engine::on_input_silent(int64_t silent_ms) {
  EngineOutput out;
  out.diags.push_back(Diag{DiagKind::InputSilent, std::nullopt, std::nullopt,
                           "no kpm2 for " + std::to_string(silent_ms) + " ms: ending open alerts"});
  for (auto& rule : rules_) {
    RuleOutput ro;
    rule->on_input_silent(ro);
    append(ro, out);
  }
  if (!stage2_) return out;
  for (std::size_t i = 0; i < ue_rules_.size(); ++i) {
    RuleOutput ro;
    ue_rules_[i]->on_input_silent(ctx(i, 0), ro);
    append(ro, out);
  }
  return out;
}

// hello (14_ §7, 2_ §6.5): 새 세션이거나 2단계가 꺼지면 2단계 룰의 진행 중 경보를 END(session_reset)로 끝내고
// 상태표·마감 목록을 비운다. hello에 ue_evt 표시가 없으면 2단계 이상 룰을 끄고 진단을 1회 남긴다 —
// 이벤트를 안 보내는 것과 사건이 없어 안 오는 것을 가르기 위해서다
void Engine::on_hello(FeedOutcome outcome, int64_t seq, EngineOutput& out) {
  const bool was = stage2_;
  stage2_ = series_.hello()->ue_evt;
  if (was && (outcome == FeedOutcome::SessionReset || !stage2_)) reset_stage2(seq, out);
  if (!stage2_ && (outcome != FeedOutcome::SessionResumed || was))
    out.diags.push_back(Diag{DiagKind::UeEvtOff, std::nullopt, seq, "hello without ue_evt: stage 2+ rules off"});
}

// ue_evt (14_ §7): ② 항목 찾기·열기 → ③ 갱신 전 복사 → ④ 전이·횟수·최근 메시지·색인 → ⑤ 룰 on_ue_event →
// ⑥ superseded → ⑦ on_ue_close. 항목을 열면서 닫은 옛 항목(reused·evicted)은 ②의 일이라 새 항목의 ⑤보다 먼저 알린다.
// ⑤의 after는 복사본이 아니라 살아 있는 항목이다 — 룰은 표를 읽기만 하고 ⑥은 룰 뒤라 참조가 유효하다(16_ W-20, 이슈 #54).
// 원본 줄은 ④가 recent에 복사한 뒤이고 룰·⑥은 읽지 않으므로 UE 증거용 ue_line에는 옮겨 담는다(복사 1회 절약)
void Engine::on_ue_evt(UeEvt& e, int64_t seq, EngineOutput& out) {
  UeTable::Applied a = table_.apply(e, seq, deadlines_);
  out.diags.insert(out.diags.end(), a.diags.begin(), a.diags.end());
  if (!a.linked) return;
  notify_close(a.closed, e.t_ms, seq, out);
  const UeState& after = *table_.find(a.key);  // apply가 방금 넣거나 갱신한 항목 — 항상 있다
  for (std::size_t i = 0; i < ue_rules_.size(); ++i) {
    RuleOutput ro;
    ue_rules_[i]->on_ue_event(e, a.before, after, ctx(i, seq), ro);
    append(ro, out);
  }
  notify_close(table_.settle(a, deadlines_), e.t_ms, seq, out);
  out.ue_line = EngineOutput::UeLine{a.key, a.uid, seq, std::move(e.raw)};
}

// f1_evt (14_ §7, 2_ §6.7): 그 셀의 열린 항목(일부 Reset이면 그 UE만)을 du_reset으로 닫는다. 세션·kpm2·1단계 상태는 그대로
void Engine::on_f1_evt(const F1Evt& f, int64_t seq, EngineOutput& out) { notify_close(table_.close_du(f, deadlines_), f.t_ms, seq, out); }

// kpm2 (14_ §7): ① series·1단계 룰은 이미 지났다 → ② 로스 기록과 그 셀 열린 항목의 loss 표시 — 마감 처리보다 먼저다.
// 마감이 든 창이 로스 창이면 그 창에서 꺼낸 마감도 보류돼야 하기 때문이다(14_ §6.2) → ②′ 유령 정리 → ③ 셀 시계를 t_end_ms로 올리고
// 마감이 지난 것을 넣은 순서대로 주인(상태표·룰)에게 넘긴다 → ④ 2단계 룰 on_cell_tick
void Engine::on_kpm2(const FeedResult& fed, int64_t seq, EngineOutput& out) {
  const int64_t cell = *fed.cell_id;
  const Kpm2& k = series_.cell(cell)->back().kpm;
  DeadlineQueue::LossResult lr = deadlines_.record_loss(k, fed.gap.has_value(), seq);
  out.diags.insert(out.diags.end(), lr.diags.begin(), lr.diags.end());
  if (lr.loss.any()) table_.mark_loss(cell, k.t_end_ms);

  // ②′ 유령 정리 (14_ §4.2 ghost_purge — 10/29 Q-56 해결, 이슈 #44): 로스 기록 뒤·마감 처리 앞. 닫힌 항목은 룰에 알린다
  UeTable::Purged purged = table_.purge_ghosts(k, seq, deadlines_);
  out.diags.insert(out.diags.end(), purged.diags.begin(), purged.diags.end());
  notify_close(purged.closed, k.t_end_ms, seq, out);

  deadlines_.set_clock(cell, k.t_end_ms);
  while (std::optional<Deadline> d = deadlines_.pop_due(cell)) {
    if (d->owner == DeadlineQueue::kTableOwner) {
      if (std::optional<UeTable::Closed> c = table_.on_deadline(*d, deadlines_)) {
        std::vector<UeTable::Closed> closed;
        closed.push_back(std::move(*c));
        notify_close(closed, d->at, seq, out);
      }
      continue;
    }
    RuleOutput ro;
    ue_rules_[static_cast<std::size_t>(d->owner)]->on_deadline(*d, ctx(static_cast<std::size_t>(d->owner), seq), ro);
    append(ro, out);
  }

  for (std::size_t i = 0; i < ue_rules_.size(); ++i) {
    RuleOutput ro;
    ue_rules_[i]->on_cell_tick(cell, k, lr.loss, fed.input_lost, ctx(i, seq), ro);
    append(ro, out);
  }
}

// 2단계 초기화 (14_ §7 hello): 룰이 진행 중 경보를 END로 끝내고 대기 표시를 버린 뒤 상태표·색인·마감 목록을 비운다
void Engine::reset_stage2(int64_t seq, EngineOutput& out) {
  for (std::size_t i = 0; i < ue_rules_.size(); ++i) {
    RuleOutput ro;
    ue_rules_[i]->on_session_reset(ctx(i, seq), ro);
    append(ro, out);
  }
  table_.clear();
  deadlines_.clear();
}

// 닫힌 항목을 모든 2단계 룰에 알린다 (14_ §7 ⑦, §1.1 on_ue_close)
void Engine::notify_close(const std::vector<UeTable::Closed>& closed, int64_t t, int64_t seq, EngineOutput& out) {
  for (const UeTable::Closed& c : closed) {
    for (std::size_t i = 0; i < ue_rules_.size(); ++i) {
      RuleOutput ro;
      ue_rules_[i]->on_ue_close(c.last, c.reason, t, ctx(i, seq), ro);
      append(ro, out);
    }
  }
}

UeRuleCtx Engine::ctx(std::size_t owner, int64_t seq) {
  return UeRuleCtx(table_, deadlines_, *series_.hello(), series_.session(), seq, static_cast<int>(owner));
}

}  // namespace detect
