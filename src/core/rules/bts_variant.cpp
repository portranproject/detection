#include "detect/rules/bts_variant.h"

#include <algorithm>
#include <cmath>
#include <utility>

namespace detect {
namespace {

Diag diag(DiagKind kind, int64_t cell, std::string msg) { return Diag{kind, cell, std::nullopt, std::move(msg)}; }

const char* mode_name(AlertMode m) { return m == AlertMode::Normal ? "normal" : "dl_missing"; }

// C4의 max_conn: hello cells[].max_conn이 있으면 그 값, 없으면 설정 값 (3_ §4 max_conn 행)
std::optional<int64_t> max_conn_for(const Hello& h, int64_t cell_id, const BtsVariantConfig& cfg) {
  for (const auto& c : h.cells)
    if (c.cell_id == cell_id && c.max_conn) return c.max_conn;
  return cfg.max_conn;
}

}  // namespace

struct BtsVariantRule::Ctx {
  int64_t cell_id;
  const Slot& slot;      // 이번 칸
  const Kpm2& k;         // = slot.kpm
  int64_t t;             // 이번 칸의 t_end_ms — 룰의 시간 기준 (3_ §3)
  int64_t P;             // hello.period_ms
  int64_t D;             // 시차 D = ⌈T_nr / P⌉칸 (3_ §3)
  int64_t W;             // window_ms
  const CellSeries& cs;  // 읽기만 — seq 범위용 (3_ §7.1)
  const Hello& hello;
  const std::string& session;
};

struct BtsVariantRule::Verdict {
  bool satisfied = false;
  bool suspicious = false;     // base 갱신 제외 (3_ §5)
  bool suspicious_dl = false;  // base′ 갱신 제외 — DL 미관측은 U로 (결정 E7)
  std::optional<double> ratio;
  std::optional<double> u;
  double base_used = 0;        // 판정에 쓴(갱신 전) 기준선 (결정 E8)
  std::vector<std::string> cond;  // 이 칸에서 참인 조건 ID — RAISE 칸이면 경보의 cond가 된다 (14_ §8.5)
};

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
    e.stage = 1;
    e.unit = "cell";
    e.alert_kind = "attack";
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

// 모드 결정 (결정 E1): F만 본다. 합계는 series가 낸 표준 윈도우 합계(3_ §3)다.
//  - [t−W, t)의 A′·S′가 불완전하면(끊김·A/S 누락) 보류(nullopt) — series가 이미 hold로 표시한 경우
//  - F 윈도우가 다 있으면 normal — 단 A 윈도우가 불완전하면 보류
//  - F 윈도우가 불완전한데 같은 구간 A′는 다 있으면 F가 null인 것 → dl_missing (3_ §4.1)
std::optional<AlertMode> BtsVariantRule::decide_mode(const WindowSums& w) {
  if (!w.a2_w || !w.s2_w) return std::nullopt;
  if (!w.f_w) return AlertMode::DlMissing;
  if (!w.a_w) return std::nullopt;
  return AlertMode::Normal;
}

// 판정 (3_ §4·§4.1). 비율은 분모가 0보다 클 때만, 분모 0이면 그 조건은 거짓
BtsVariantRule::Verdict BtsVariantRule::evaluate(const CellState& st, AlertMode mode, const WindowSums& w,
                                                 bool was_active, bool warming) const {
  Verdict v;
  const double a2 = static_cast<double>(*w.a2_w);
  if (*w.a2_w > 0) v.u = (a2 - static_cast<double>(*w.s2_w)) / a2;
  const bool u_ok = *w.a2_w >= cfg_.a_min && v.u && *v.u >= cfg_.theta;  // A′_w ≥ A_min ∧ U ≥ θ
  v.suspicious_dl = v.u && *v.u >= cfg_.theta;

  if (mode == AlertMode::Normal) {
    const double aw = static_cast<double>(*w.a_w);
    if (*w.a_w > 0) v.ratio = static_cast<double>(*w.f_w) / aw;
    const bool c1 = *w.a_w >= cfg_.a_min;
    const bool c2 = v.ratio && *v.ratio >= cfg_.theta;
    v.base_used = st.base.value();  // 갱신 전 base로 판정 (결정 E8)
    const bool c3 = warming || aw >= cfg_.k * v.base_used;  // 웜업 중엔 참 (3_ §4·§5)
    // C2a 절대 실패 수 (3_ §4, 10/27 Q-41 해결): 정상 시도가 많아 ratio < θ여도 1초 NoReply가 F_abs 이상이면
    // 컨텍스트가 그만큼 잡혀 있는 것이므로 C1·C3 없이 단독 성립. dl_missing 모드에는 없다(F가 없음)
    const bool c2a = *w.f_w >= cfg_.f_abs;
    // 경보가 아닐 때 (C1∧C2∧C3) ∨ C2a, 경보 중 (C1∧C2) ∨ C2a ∨ (A′_w ≥ A_min ∧ U ≥ θ) — 마지막은 거절로 바뀐 포화 ② (3_ §6.1 나)
    v.satisfied = was_active ? ((c1 && c2) || c2a || u_ok) : ((c1 && c2 && c3) || c2a);
    v.suspicious = *w.a_w > 0 && (c2 || c2a);  // 의심 칸 (3_ §5): 비율이 높거나 절대 실패 수가 큰 칸
    // 성립한 조건 ID (14_ §8.5, 결정 J2): RAISE는 경보가 아닐 때 성립한 칸에서만 나므로 그때만 모은다.
    // 웜업 중의 C3는 확인한 값이 아니라 참으로 둔 것이라 넣지 않는다 (3_ §5)
    if (!was_active && v.satisfied) {
      if (c1) v.cond.emplace_back("C1");
      if (c2) v.cond.emplace_back("C2");
      if (!warming && c3) v.cond.emplace_back("C3");
      if (c2a) v.cond.emplace_back("C2a");
    }
  } else {
    // DL 미관측 모드 (3_ §4.1): ratio 대신 U, base′는 A′_w의 기준선
    v.base_used = st.base_dl.value();
    const bool c3 = warming || a2 >= cfg_.k * v.base_used;
    v.satisfied = was_active ? u_ok : (u_ok && c3);
    // U = (A′_w ≥ A_min ∧ U ≥ θ), 웜업 뒤면 base′ 기준 C3도 (결정 J3)
    if (!was_active && v.satisfied) {
      v.cond.emplace_back("U");
      if (!warming) v.cond.emplace_back("C3");
    }
  }
  return v;
}

// 기준선 갱신 (3_ §5): 경보 중인 칸과 의심 칸은 뺀다. 판정 뒤에 갱신 (결정 E8).
// 웜업이 끝났을 때 k × base < A_min이면 C3가 C1보다 약해 사실상 항상 참 — 1회 로그 (결정 E6)
void BtsVariantRule::update_baseline(CellState& st, const Ctx& c, AlertMode mode, const WindowSums& w, const Verdict& v,
                                     bool alert_slot, RuleOutput& out) {
  const bool warming = st.base.in_warmup(c.t);
  if (w.a_w && w.f_w && !alert_slot && !v.suspicious) st.base.add(c.t, static_cast<double>(*w.a_w));
  if (!alert_slot && !v.suspicious_dl) st.base_dl.add(c.t, static_cast<double>(*w.a2_w));

  if (!st.warmup_done && !warming) {
    st.warmup_done = true;
    const double b = mode == AlertMode::Normal ? st.base.value() : st.base_dl.value();
    if (cfg_.k * b < static_cast<double>(cfg_.a_min))
      out.diags.push_back(diag(DiagKind::BaselineLow, c.cell_id,
                               "baseline low after warmup: base=" + std::to_string(b)));
  }
}

// 경보 이벤트 (3_ §7): RAISE는 근거 값·severity·mode·candidates·seq 범위, CLEAR는 duration,
// 경보 중 C4가 처음 참이 되면 severity high로 올리고 UPDATE 1회 (3_ §6.1 다, 결정 E2)
void BtsVariantRule::emit(CellState& st, const Ctx& c, AlertMode mode, const WindowSums& w, const Verdict& v,
                          AlertMachine::Step step, RuleOutput& out) {
  // C4 (보조, 3_ §4): Cx ≥ 0.9 × max_conn이면 severity high. Cx나 max_conn이 없으면 끔 (결정 E4)
  const std::optional<int64_t> max_conn = max_conn_for(c.hello, c.cell_id, cfg_);
  const bool c4 = max_conn && c.k.ue_ctx_max &&
                  static_cast<double>(*c.k.ue_ctx_max) >= 0.9 * static_cast<double>(*max_conn);
  const bool now_active = st.machine.active();

  auto make_event = [&](AlertEventKind kind) {
    AlertEvent e;
    e.kind = kind;
    e.rule = kId;
    e.stage = 1;  // 1단계 셀 단위 공격 룰 (14_ §8.5)
    e.unit = "cell";
    e.alert_kind = "attack";
    e.alert_id = st.alert_id;
    e.cell_id = c.cell_id;
    e.t = c.t;
    e.mode = mode;
    e.severity = st.severity;
    if (max_conn && c.k.ue_ctx_max) {
      e.uectx = c.k.ue_ctx_max;
      e.max_conn = max_conn;
    }
    return e;
  };

  if (step == AlertMachine::Step::Raise) {
    // alert_id = session-룰-셀-seq (3_ §7.1)
    st.alert_id = c.session + "-" + kId + "-" + std::to_string(c.cell_id) + "-" + std::to_string(c.slot.seq);
    st.severity = c4 ? Severity::High : Severity::Medium;
    AlertEvent e = make_event(AlertEventKind::Raise);
    // 근거 구간의 seq 범위 (3_ §7.1). dl_missing이면 A′ 윈도우만 (결정 F5)
    if (mode == AlertMode::Normal) {
      e.a_w = *w.a_w;
      e.f_w = w.f_w;
      e.ratio = v.ratio;
      e.a_seq = c.cs.seq_range(c.t - c.W - c.D * c.P, c.t - c.D * c.P);
      e.f_seq = c.cs.seq_range(c.t - c.W, c.t);
      e.f_abs = cfg_.f_abs;  // normal 모드만 (3_ §7)
    } else {
      e.a_w = *w.a2_w;
      e.u = v.u;
      e.a_seq = c.cs.seq_range(c.t - c.W, c.t);
    }
    e.base = v.base_used;
    e.k = cfg_.k;
    e.theta = cfg_.theta;
    e.candidates = {"L3-11"};  // 같은 표 II 모양인 #11 중간자 변형 (3_ §7)
    e.cond = v.cond;
    out.alerts.push_back(std::move(e));
  } else if (step == AlertMachine::Step::Clear) {
    AlertEvent e = make_event(AlertEventKind::Clear);
    e.duration_ms = c.t - st.machine.raised_at();
    out.alerts.push_back(std::move(e));
  } else if (now_active && c4 && st.severity == Severity::Medium) {
    st.severity = Severity::High;
    out.alerts.push_back(make_event(AlertEventKind::Update));
  }
}

// 칸 하나 처리 (3_ §4 '매 kpm2 수신마다 셀별로'): 입력 건전성(series) → 모드 → 판정 → 상태기계 → 기준선 → 이벤트
void BtsVariantRule::on_feed(const Series& series, const FeedResult& fed, RuleOutput& out) {
  // session 변경(또는 같은 session의 hello 파라미터 변경) — 진행 중 경보를 end로 끝내고
  // 버퍼·기준선·경보 상태를 모두 초기화, 웜업 다시 시작 (3_ §8)
  if (fed.outcome == FeedOutcome::SessionReset) {
    for (auto& [cell_id, st] : cells_) end_alert(st, cell_id, st.last_t, "session_reset", out);
    cells_.clear();
    return;
  }
  if (fed.outcome != FeedOutcome::Stored || !fed.cell_id) return;

  const int64_t cell_id = *fed.cell_id;
  const CellSeries* cs = series.cell(cell_id);
  const Hello* hello = series.hello();
  if (!cs || !hello || cs->size() == 0) return;

  const Slot& slot = cs->back();
  const int64_t P = hello->period_ms;
  const Ctx c{cell_id, slot, slot.kpm, slot.kpm.t_end_ms, P, (hello->noreply_timeout_ms + P - 1) / P,
              cfg_.window_ms, *cs, *hello, series.session()};

  auto it = cells_.find(cell_id);
  if (it == cells_.end()) it = cells_.emplace(cell_id, CellState(cfg_, P)).first;
  CellState& st = it->second;
  st.last_t = c.t;

  // 보류 (3_ §8) — series가 판단한다. 보류가 H_hold를 넘었으면(input_lost) 진행 중 경보를 끝낸다.
  // 보류 칸은 성립·불성립 어느 쪽으로도 세지 않는다 — M·K·t_last 유지, 기준선도 그대로
  if (fed.input_lost) end_alert(st, cell_id, c.t, "input_lost", out);
  if (fed.hold) return;
  const WindowSums& w = fed.sums;
  const std::optional<AlertMode> mode = decide_mode(w);
  if (!mode) return;

  if (st.mode && *st.mode != *mode)
    out.diags.push_back(diag(DiagKind::ModeChanged, cell_id, std::string("mode -> ") + mode_name(*mode)));
  st.mode = mode;

  // 웜업은 그 셀에서 처음 판정한 칸부터 데이터 시각으로 잰다 (3_ §5)
  st.base.tick(c.t);
  st.base_dl.tick(c.t);
  const bool was_active = st.machine.active();
  const Verdict v = evaluate(st, *mode, w, was_active, st.base.in_warmup(c.t));

  const AlertMachine::Step step = st.machine.on_slot(v.satisfied, c.t);
  const bool now_active = st.machine.active();
  update_baseline(st, c, *mode, w, v, was_active || now_active, out);
  emit(st, c, *mode, w, v, step, out);
}

}  // namespace detect
