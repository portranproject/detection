#include "detect/alert.h"

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

const char* mode_str(AlertMode m) { return m == AlertMode::Normal ? "normal" : "dl_missing"; }
const char* severity_str(Severity s) { return s == Severity::High ? "high" : "medium"; }

std::string head(const char* kind, const AlertEvent& e) {
  return std::string("ALERT ") + kind + " rule=" + e.rule + " cell=" + std::to_string(e.cell_id) +
         " t=" + std::to_string(e.t);
}

std::string fields_str(const AlertEvent& e) {
  std::string s;
  for (const auto& [k, v] : e.log_fields) s += " " + k + "=" + v;
  return s;
}

}  // namespace

// 경보 로그 한 줄 (3_ §7, 15_ §2.6·§4.6·§5.6 예시 형식). 골격은 모든 룰이 같고, 룰마다 다른 필드는 룰이
// 사람이 읽는 형식으로 log_fields에 넣는다 (4_ §6.1 #5 '룰별 포맷터'). 예:
//   ALERT RAISE rule=L3-01-V cell=1 t=… A_w=48 … uectx=93/96 severity=high mode=normal candidates=L3-11
//   ALERT UPDATE rule=L3-21 cell=1 t=… ues_new=2 ues_total=7 branch=1 severity=high
//   ALERT CLEAR rule=L3-20 cell=1 t=… duration_ms=… ues_total=3
// candidates는 비어 있어도 'candidates='를 찍는다 (15_ §2.6 L3-20 예)
std::string format_log_line(const AlertEvent& e) {
  const bool ue = e.unit == "ue";
  switch (e.kind) {
    case AlertEventKind::Raise: {
      std::string s = head("RAISE", e) + fields_str(e);
      s += std::string(" severity=") + severity_str(e.severity) + " mode=" + mode_str(e.mode) + " candidates=";
      for (std::size_t i = 0; i < e.candidates.size(); ++i) s += (i ? "," : "") + e.candidates[i];
      return s;
    }
    case AlertEventKind::Clear: {
      std::string s = head("CLEAR", e) + " duration_ms=" + std::to_string(e.duration_ms);
      if (ue) s += " ues_total=" + std::to_string(e.ues_total);
      return s;
    }
    case AlertEventKind::End:  // 결정 E3
      return head("END", e) + " duration_ms=" + std::to_string(e.duration_ms) + " reason=" + e.reason;
    case AlertEventKind::Update: {  // 결정 E2. UE 단위면 새로 걸린 UE 수·누적 수 (14_ §8.2)
      std::string s = head("UPDATE", e);
      if (ue) s += " ues_new=" + std::to_string(e.ues.size()) + " ues_total=" + std::to_string(e.ues_total);
      if (e.branch) s += " branch=" + *e.branch;
      return s + " severity=" + severity_str(e.severity) + fields_str(e);
    }
  }
  return {};
}

}  // namespace detect
