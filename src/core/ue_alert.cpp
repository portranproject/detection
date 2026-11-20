#include "detect/ue_alert.h"

#include <algorithm>
#include <utility>

namespace detect {

AlertUe alert_ue(const UeState& s) {
  AlertUe u;
  u.cell = s.key.cell_id;
  u.du_ue_id = s.key.du_ue_id;
  u.uid = s.uid;
  u.cu_ue_id = s.cu_ue_id;
  u.crnti = s.crnti;
  u.s_tmsi = s.s_tmsi;
  if (s.mid_join) u.uncertain.emplace_back("mid_join");
  if (s.loss) u.uncertain.emplace_back("loss");
  if (s.late) u.uncertain.emplace_back("late");
  return u;
}

UeAlertBook::UeAlertBook(std::string rule, AlertConfig cfg, std::string kind, int stage)
    : rule_(std::move(rule)), cfg_(cfg), kind_(std::move(kind)), stage_(stage) {}

std::optional<Severity> UeAlertBook::severity(int64_t cell) const {
  auto it = open_.find(cell);
  return it == open_.end() ? std::nullopt : std::optional<Severity>(it->second.severity);
}

int64_t UeAlertBook::ues_total(int64_t cell) const {
  auto it = open_.find(cell);
  return it == open_.end() ? 0 : it->second.ues_total;
}

// 공통 겉모양 (14_ §8.3): UE 단위 경보(공격 attack 또는 불확실 anomaly — §6.2), 단계는 생성자에서 받은 값(2단계 2·3단계 3,
// 4_ §6.2 #1), mode normal (15_ §1)
AlertEvent UeAlertBook::event(AlertEventKind kind, int64_t cell, const Open& o, int64_t t) const {
  AlertEvent e;
  e.kind = kind;
  e.rule = rule_;
  e.alert_id = o.alert_id;
  e.cell_id = cell;
  e.t = t;
  e.stage = stage_;
  e.unit = "ue";
  e.alert_kind = kind_;
  e.mode = AlertMode::Normal;
  e.severity = o.severity;
  e.ues_total = o.ues_total;
  return e;
}

// 한 레코드의 ues는 ues_max칸까지 — 넘는 UE는 싣지 않고 ues_total로만 센다 (14_ §8.3)
std::vector<AlertUe> UeAlertBook::take(std::vector<AlertUe>& ues) const {
  std::vector<AlertUe> out = std::move(ues);
  ues.clear();
  if (out.size() > cfg_.ues_max) out.resize(cfg_.ues_max);
  return out;
}

void UeAlertBook::emit_update(int64_t cell, Open& o, int64_t t, std::vector<AlertEvent>& out) {
  AlertEvent e = event(AlertEventKind::Update, cell, o, t);
  e.ues = take(o.pending);
  o.last_emit = t;
  out.push_back(std::move(e));
}

// 걸린 UE (14_ §8.2): 경보가 없으면 RAISE. 있으면 모았다가 RAISE·UPDATE 뒤 update_min_ms가 지났을 때 UPDATE로
// 한꺼번에 낸다 — 새 UE마다 내면 홍수 공격 때 경보 레코드가 쏟아진다. 심각도가 오르면 그것을 바로 알린다
void UeAlertBook::add(int64_t cell, std::vector<AlertUe> ues, Severity sev, int64_t t, const std::string& session,
                      int64_t seq, std::vector<AlertEvent>& out) {
  auto it = open_.find(cell);
  if (it == open_.end()) {
    Open o;
    o.alert_id = session + "-" + rule_ + "-" + std::to_string(cell) + "-" + std::to_string(seq);
    o.raised_at = t;
    o.last_emit = t;
    o.t_last = t;
    o.severity = sev;
    o.ues_total = static_cast<int64_t>(ues.size());
    AlertEvent e = event(AlertEventKind::Raise, cell, o, t);
    e.ues = take(ues);
    open_.emplace(cell, std::move(o));
    out.push_back(std::move(e));
    return;
  }
  Open& o = it->second;
  o.t_last = std::max(o.t_last, t);
  o.ues_total += static_cast<int64_t>(ues.size());
  for (AlertUe& u : ues) o.pending.push_back(std::move(u));
  if (sev > o.severity) {
    o.severity = sev;
    emit_update(cell, o, t, out);
  } else if (t - o.last_emit >= cfg_.update_min_ms) {
    emit_update(cell, o, t, out);
  }
}

void UeAlertBook::flush(int64_t cell, int64_t t, std::vector<AlertEvent>& out) {
  auto it = open_.find(cell);
  if (it == open_.end()) return;
  Open& o = it->second;
  o.t_last = std::max(o.t_last, t);
  if (!o.pending.empty() && t - o.last_emit >= cfg_.update_min_ms) emit_update(cell, o, t, out);
}

void UeAlertBook::update(int64_t cell, Severity sev, int64_t t, std::vector<AlertEvent>& out) {
  auto it = open_.find(cell);
  if (it == open_.end()) return;
  Open& o = it->second;
  o.t_last = std::max(o.t_last, t);
  if (sev > o.severity) o.severity = sev;
  emit_update(cell, o, t, out);
}

void UeAlertBook::clear(int64_t cell, int64_t t, std::vector<AlertEvent>& out) {
  auto it = open_.find(cell);
  if (it == open_.end()) return;
  Open& o = it->second;
  if (!o.pending.empty()) emit_update(cell, o, t, out);
  AlertEvent e = event(AlertEventKind::Clear, cell, o, t);
  e.duration_ms = t - o.raised_at;
  out.push_back(std::move(e));
  open_.erase(it);
}

void UeAlertBook::end(int64_t cell, int64_t t, const std::string& reason, std::vector<AlertEvent>& out) {
  auto it = open_.find(cell);
  if (it == open_.end()) return;
  AlertEvent e = event(AlertEventKind::End, cell, it->second, t);
  e.duration_ms = t - it->second.raised_at;
  e.reason = reason;
  out.push_back(std::move(e));
  open_.erase(it);
}

void UeAlertBook::end_all(const std::string& reason, std::vector<AlertEvent>& out) {
  for (const auto& [cell, o] : open_) {
    AlertEvent e = event(AlertEventKind::End, cell, o, o.t_last);
    e.duration_ms = o.t_last - o.raised_at;
    e.reason = reason;
    out.push_back(std::move(e));
  }
  open_.clear();
}

}  // namespace detect
