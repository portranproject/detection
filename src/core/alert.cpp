#include "detect/alert.h"

#include <cstdio>

namespace detect {

AlertMachine::Step AlertMachine::on_slot(bool satisfied, int64_t t) {
  if (!active_) {
    // 경보가 아닐 때: M칸 연속 성립이면 RAISE (3_ §4)
    ok_streak_ = satisfied ? ok_streak_ + 1 : 0;
    if (ok_streak_ >= m_raise_) {
      active_ = true;
      ok_streak_ = 0;
      ng_streak_ = 0;
      t_last_ = t;
      raised_at_ = t;
      return Step::Raise;
    }
    return Step::None;
  }
  // 경보 중: 성립하면 t_last 갱신, 불성립이 K칸 이어지고 H_sat도 지나야 CLEAR (3_ §4·§6.1 가)
  if (satisfied) {
    ng_streak_ = 0;
    t_last_ = t;
    return Step::None;
  }
  ++ng_streak_;
  if (ng_streak_ >= k_clear_ && t_last_ && t - *t_last_ >= h_sat_ms_) {
    reset();
    return Step::Clear;
  }
  return Step::None;
}

void AlertMachine::reset() {
  active_ = false;
  ok_streak_ = 0;
  ng_streak_ = 0;
  t_last_.reset();
}

namespace {

std::string fmt(const char* f, double v) {
  char buf[64];
  std::snprintf(buf, sizeof(buf), f, v);
  return buf;
}

const char* mode_str(AlertMode m) { return m == AlertMode::Normal ? "normal" : "dl_missing"; }
const char* severity_str(Severity s) { return s == Severity::High ? "high" : "medium"; }

std::string head(const char* kind, const AlertEvent& e) {
  return std::string("ALERT ") + kind + " rule=" + e.rule + " cell=" + std::to_string(e.cell_id) +
         " t=" + std::to_string(e.t);
}

std::string uectx_str(const AlertEvent& e) {
  if (!e.uectx || !e.max_conn) return "";
  return " uectx=" + std::to_string(*e.uectx) + "/" + std::to_string(*e.max_conn);
}

}  // namespace

// 경보 로그 한 줄 (3_ §7 예시 형식). 예:
// ALERT RAISE rule=L3-01-V cell=1 t=… A_w=48 F_w=45 ratio=0.94 base=3.1 k=3 theta=0.5 f_abs=10 uectx=93/96 severity=high mode=normal candidates=L3-11
std::string format_log_line(const AlertEvent& e) {
  switch (e.kind) {
    case AlertEventKind::Raise: {
      std::string s = head("RAISE", e) + " A_w=" + std::to_string(e.a_w);
      if (e.mode == AlertMode::Normal) {
        s += " F_w=" + std::to_string(e.f_w.value_or(0)) + " ratio=" + fmt("%.2f", e.ratio.value_or(0));
      } else {
        s += " U=" + fmt("%.2f", e.u.value_or(0));  // 결정 E5
      }
      s += " base=" + fmt("%.1f", e.base) + " k=" + fmt("%g", e.k) + " theta=" + fmt("%g", e.theta);
      if (e.f_abs) s += " f_abs=" + std::to_string(*e.f_abs);  // normal 모드만 (3_ §7, 10/27 Q-41)
      s += uectx_str(e);
      s += std::string(" severity=") + severity_str(e.severity) + " mode=" + mode_str(e.mode);
      if (!e.candidates.empty()) {
        s += " candidates=";
        for (std::size_t i = 0; i < e.candidates.size(); ++i) s += (i ? "," : "") + e.candidates[i];
      }
      return s;
    }
    case AlertEventKind::Clear:
      return head("CLEAR", e) + " duration_ms=" + std::to_string(e.duration_ms);
    case AlertEventKind::End:  // 결정 E3
      return head("END", e) + " duration_ms=" + std::to_string(e.duration_ms) + " reason=" + e.reason;
    case AlertEventKind::Update:  // 결정 E2
      return head("UPDATE", e) + std::string(" severity=") + severity_str(e.severity) + uectx_str(e);
  }
  return {};
}

}  // namespace detect
