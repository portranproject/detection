#include "detect/rules/bts_variant.h"

#include <algorithm>
#include <cmath>
#include <utility>

namespace detect {
namespace {

Count get_att(const Kpm2& k) { return k.conn_estab_att.total; }
Count get_succ(const Kpm2& k) { return k.conn_estab_succ.total; }
Count get_noreply(const Kpm2& k) { return k.fail_no_reply; }

Diag diag(DiagKind kind, int64_t cell, std::string msg) { return Diag{kind, cell, std::nullopt, std::move(msg)}; }

const char* mode_name(AlertMode m) { return m == AlertMode::Normal ? "normal" : "dl_missing"; }

// C4의 max_conn: hello cells[].max_conn이 있으면 그 값, 없으면 설정 값 (3_ §4 max_conn 행)
std::optional<int64_t> max_conn_for(const Hello& h, int64_t cell_id, const BtsVariantConfig& cfg) {
  for (const auto& c : h.cells)
    if (c.cell_id == cell_id && c.max_conn) return c.max_conn;
  return cfg.max_conn;
}

}  // namespace

BtsVariantRule::CellState::CellState(const BtsVariantConfig& cfg, int64_t period_ms)
    : machine(cfg.m_raise, cfg.k_clear, cfg.h_sat_ms),
      base(cfg.warmup_ms, cfg.baseline_tau_s, period_ms),
      base_dl(cfg.warmup_ms, cfg.baseline_tau_s, period_ms) {}

BtsVariantRule::BtsVariantRule(BtsVariantConfig cfg) : cfg_(std::move(cfg)) {}

bool BtsVariantRule::alert_active(int64_t cell_id) const {
  auto it = cells_.find(cell_id);
  return it != cells_.end() && it->second.machine.active();
}

std::optional<AlertMode> BtsVariantRule::mode(int64_t cell_id) const {
  auto it = cells_.find(cell_id);
  return it == cells_.end() ? std::nullopt : it->second.mode;
}

std::optional<double> BtsVariantRule::base(int64_t cell_id) const {
  auto it = cells_.find(cell_id);
  if (it == cells_.end()) return std::nullopt;
  return it->second.base.value();
}

// 진행 중 경보 강제 종료 — session 변경·H_hold 초과 (3_ §7.1 end 레코드, §8, 결정 E3)
void BtsVariantRule::end_alert(CellState& st, int64_t cell_id, int64_t t, const char* reason, RuleOutput& out) {
  if (st.machine.active()) {
    AlertEvent e;
    e.kind = AlertEventKind::End;
    e.rule = kId;
    e.alert_id = st.alert_id;
    e.cell_id = cell_id;
    e.t = t;
    e.severity = st.severity;
    e.mode = st.mode.value_or(AlertMode::Normal);
    e.duration_ms = t - st.machine.raised_at();
    e.reason = reason;
    out.alerts.push_back(std::move(e));
  }
  st.machine.reset();
}

void BtsVariantRule::on_feed(Series& series, const FeedResult& fed, RuleOutput& out) {
  // session 변경(또는 같은 session의 hello 파라미터 변경) — 진행 중 경보를 end로 끝내고
  // 버퍼·기준선·경보 상태를 모두 초기화, 웜업 다시 시작 (3_ §8)
  if (fed.outcome == FeedOutcome::SessionReset) {
    for (auto& [cell_id, st] : cells_) end_alert(st, cell_id, st.last_t, "session_reset", out);
    cells_.clear();
    return;
  }
  if (fed.outcome != FeedOutcome::Stored || !fed.cell_id) return;

  const int64_t cell_id = *fed.cell_id;
  CellSeries* cs = series.cell(cell_id);
  const Hello* hello = series.hello();
  if (!cs || !hello || cs->size() == 0) return;

  const Slot& slot = cs->back();
  const Kpm2& k = slot.kpm;
  const int64_t t = k.t_end_ms;
  const int64_t P = hello->period_ms;
  const int64_t D = (hello->noreply_timeout_ms + P - 1) / P;  // 시차 D = ⌈T_nr / P⌉칸 (3_ §3)
  const int64_t W = cfg_.window_ms;

  auto it = cells_.find(cell_id);
  if (it == cells_.end()) it = cells_.emplace(cell_id, CellState(cfg_, P)).first;
  CellState& st = it->second;
  st.last_t = t;

  // 구간 끊김이 있으면 보류가 그 끊김의 시작부터 시작된 것으로 본다 (3_ §8, 결정 E9)
  if (fed.gap) st.hold_start = st.hold_start ? std::min(*st.hold_start, fed.gap->t_from) : fed.gap->t_from;

  // 필수 키 A·S 누락 추적 — 연속 missing_key_slots칸을 넘으면 '룰 비활성', 다시 들어오면 재개 로그 (3_ §8)
  if (!get_att(k) || !get_succ(k)) {
    if (++st.missing_streak > cfg_.missing_key_slots && !st.inactive) {
      st.inactive = true;
      out.diags.push_back(diag(DiagKind::RuleInactive, cell_id, "L3-01-V inactive: A/S missing"));
    }
  } else {
    if (st.inactive) out.diags.push_back(diag(DiagKind::RuleResumed, cell_id, "L3-01-V resumed"));
    st.inactive = false;
    st.missing_streak = 0;
  }

  // 윈도우 합계 (3_ §3): A 윈도우는 T_nr(= D칸)만큼 과거, F·A′·S′는 시차 없음
  const std::optional<int64_t> a_w = cs->window_sum(t - W - D * P, t - D * P, get_att);
  const std::optional<int64_t> f_w = cs->window_sum(t - W, t, get_noreply);
  const std::optional<int64_t> a2_w = cs->window_sum(t - W, t, get_att);
  const std::optional<int64_t> s2_w = cs->window_sum(t - W, t, get_succ);

  // 모드 결정 (결정 E1): F만 본다.
  //  - [t−W, t)의 A′·S′가 불완전하면(끊김·A/S 누락) 보류
  //  - F 윈도우가 다 있으면 normal — 단 A 윈도우가 불완전하면 보류
  //  - F 윈도우가 불완전한데 같은 구간 A′는 다 있으면 F가 null인 것 → dl_missing (3_ §4.1)
  std::optional<AlertMode> mode;
  if (a2_w && s2_w) {
    if (f_w) {
      if (a_w) mode = AlertMode::Normal;
    } else {
      mode = AlertMode::DlMissing;
    }
  }

  // 보류 (3_ §8): 성립·불성립 어느 쪽으로도 세지 않는다 — M·K·t_last 유지
  if (!mode) {
    if (!st.hold_start) st.hold_start = k.t_start_ms;
    // 보류가 H_hold보다 길면 진행 중 경보를 input_lost로 끝내고 이 칸 이전 버퍼를 비운다. 기준선은 유지 (3_ §8)
    if (k.t_start_ms - *st.hold_start > cfg_.h_hold_ms) {
      end_alert(st, cell_id, t, "input_lost", out);
      cs->drop_before(k.t_start_ms);
      st.hold_start = k.t_start_ms;
    }
    return;
  }
  st.hold_start.reset();

  if (st.mode && *st.mode != *mode)
    out.diags.push_back(diag(DiagKind::ModeChanged, cell_id, std::string("mode -> ") + mode_name(*mode)));
  st.mode = mode;

  // 판정 (3_ §4). 비율은 분모가 0보다 클 때만, 분모 0이면 그 조건은 거짓
  const bool was_active = st.machine.active();
  const double a2 = static_cast<double>(*a2_w);
  const std::optional<double> u =
      *a2_w > 0 ? std::optional<double>((a2 - static_cast<double>(*s2_w)) / a2) : std::nullopt;
  const bool u_ok = *a2_w >= cfg_.a_min && u && *u >= cfg_.theta;  // A′_w ≥ A_min ∧ U ≥ θ

  st.base.tick(t);
  st.base_dl.tick(t);
  const bool warming = st.base.in_warmup(t);

  bool satisfied = false;
  bool suspicious = false;     // base 갱신 제외 (3_ §5)
  bool suspicious_dl = u && *u >= cfg_.theta;  // base′ 갱신 제외 — DL 미관측은 U로 (결정 E7)
  std::optional<double> ratio;
  double base_used = 0;

  if (*mode == AlertMode::Normal) {
    const double aw = static_cast<double>(*a_w);
    if (*a_w > 0) ratio = static_cast<double>(*f_w) / aw;
    const bool c1 = *a_w >= cfg_.a_min;
    const bool c2 = ratio && *ratio >= cfg_.theta;
    base_used = st.base.value();  // 갱신 전 base로 판정 (결정 E8)
    const bool c3 = warming || aw >= cfg_.k * base_used;  // 웜업 중엔 참 (3_ §4·§5)
    // 경보가 아닐 때 C1∧C2∧C3, 경보 중 (C1∧C2) ∨ (A′_w ≥ A_min ∧ U ≥ θ) — 뒤쪽은 거절로 바뀐 포화 ② (3_ §6.1 나)
    satisfied = was_active ? ((c1 && c2) || u_ok) : (c1 && c2 && c3);
    suspicious = *a_w > 0 && c2;
  } else {
    // DL 미관측 모드 (3_ §4.1): ratio 대신 U, base′는 A′_w의 기준선
    base_used = st.base_dl.value();
    const bool c3 = warming || a2 >= cfg_.k * base_used;
    satisfied = was_active ? u_ok : (u_ok && c3);
  }

  const AlertMachine::Step step = st.machine.on_slot(satisfied, t);
  const bool now_active = st.machine.active();

  // 기준선 갱신 (3_ §5): 경보 중인 칸과 의심 칸은 뺀다. 판정 뒤에 갱신 (결정 E8)
  const bool alert_slot = was_active || now_active;
  if (a_w && f_w && !alert_slot && !suspicious) st.base.add(t, static_cast<double>(*a_w));
  if (!alert_slot && !suspicious_dl) st.base_dl.add(t, a2);

  // 웜업이 끝났을 때 k × base < A_min이면 C3가 C1보다 약해 사실상 항상 참 — 1회 로그 (3_ §5, 결정 E6)
  if (!st.warmup_done && !warming) {
    st.warmup_done = true;
    const double b = *mode == AlertMode::Normal ? st.base.value() : st.base_dl.value();
    if (cfg_.k * b < static_cast<double>(cfg_.a_min))
      out.diags.push_back(diag(DiagKind::BaselineLow, cell_id,
                               "baseline low after warmup: base=" + std::to_string(b)));
  }

  // C4 (보조, 3_ §4): Cx ≥ 0.9 × max_conn이면 severity high. Cx나 max_conn이 없으면 끔 (결정 E4)
  const std::optional<int64_t> max_conn = max_conn_for(*hello, cell_id, cfg_);
  const bool c4 = max_conn && k.ue_ctx_max &&
                  static_cast<double>(*k.ue_ctx_max) >= 0.9 * static_cast<double>(*max_conn);

  auto make_event = [&](AlertEventKind kind) {
    AlertEvent e;
    e.kind = kind;
    e.rule = kId;
    e.alert_id = st.alert_id;
    e.cell_id = cell_id;
    e.t = t;
    e.mode = *mode;
    e.severity = st.severity;
    if (max_conn && k.ue_ctx_max) {
      e.uectx = k.ue_ctx_max;
      e.max_conn = max_conn;
    }
    return e;
  };

  if (step == AlertMachine::Step::Raise) {
    // RAISE (3_ §7): 근거 값·severity·mode·candidates. alert_id = session-룰-셀-seq (3_ §7.1)
    st.alert_id = series.session() + "-" + kId + "-" + std::to_string(cell_id) + "-" + std::to_string(slot.seq);
    st.severity = c4 ? Severity::High : Severity::Medium;
    AlertEvent e = make_event(AlertEventKind::Raise);
    // 근거 구간의 seq 범위 (3_ §7.1). dl_missing이면 A′ 윈도우만 (결정 F5)
    if (*mode == AlertMode::Normal) {
      e.a_w = *a_w;
      e.f_w = f_w;
      e.ratio = ratio;
      e.a_seq = cs->seq_range(t - W - D * P, t - D * P);
      e.f_seq = cs->seq_range(t - W, t);
    } else {
      e.a_w = *a2_w;
      e.u = u;
      e.a_seq = cs->seq_range(t - W, t);
    }
    e.base = base_used;
    e.k = cfg_.k;
    e.theta = cfg_.theta;
    e.candidates = {"L3-11"};  // 같은 표 II 모양인 #11 중간자 변형 (3_ §7)
    out.alerts.push_back(std::move(e));
  } else if (step == AlertMachine::Step::Clear) {
    AlertEvent e = make_event(AlertEventKind::Clear);
    e.duration_ms = t - st.machine.raised_at();
    out.alerts.push_back(std::move(e));
  } else if (now_active && c4 && st.severity == Severity::Medium) {
    // 경보 중 포화 확인 → severity high로 올림, 1회 UPDATE (3_ §6.1 다, 결정 E2)
    st.severity = Severity::High;
    out.alerts.push_back(make_event(AlertEventKind::Update));
  }
}

}  // namespace detect
