#include "detect/evidence.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <utility>

namespace detect {
namespace {

// 넣은 순서대로 키를 내보내 사람이 읽기 쉽게 한다 (결정 F10)
using ojson = nlohmann::ordered_json;

const char* event_name(AlertEventKind k) {
  switch (k) {
    case AlertEventKind::Raise: return "raise";
    case AlertEventKind::Clear: return "clear";
    case AlertEventKind::End: return "end";
    case AlertEventKind::Update: return "update";  // 결정 F4
  }
  return "?";
}

ojson seq_pair(const std::pair<int64_t, int64_t>& p) { return ojson::array({p.first, p.second}); }

}  // namespace

// alert 레코드 — 공통 경보 형식 (14_ §8.3·§8.5, 4_ §6.1 #3): 겉모양(룰·단계·단위·종류·셀·시각·심각도·모드)은
// 모든 룰이 같고, 룰마다 다른 것은 values(관측값)·params(파라미터)·refs(근거 seq 범위) 안에만 둔다.
// raise면 cond·candidates·values·params·refs, clear·end면 duration_ms와 내보낸·버린 증거 수, end면 reason.
// uectx·max_conn은 C4가 켜져 값이 있을 때만 어느 이벤트든 values에 (결정 J5)
std::string alert_record_line(const AlertEvent& e, int64_t sent, int64_t dropped) {
  ojson j;
  j["type"] = "alert";
  j["alert_id"] = e.alert_id;
  j["event"] = event_name(e.kind);
  j["rule"] = e.rule;
  j["stage"] = e.stage;
  j["unit"] = e.unit;
  j["kind"] = e.alert_kind;
  j["cell"] = e.cell_id;
  j["t"] = e.t;
  j["severity"] = e.severity == Severity::High ? "high" : "medium";
  j["mode"] = e.mode == AlertMode::Normal ? "normal" : "dl_missing";
  const bool raise = e.kind == AlertEventKind::Raise;
  if (raise) {
    j["cond"] = e.cond;
    j["candidates"] = e.candidates;
  }
  ojson values = ojson::object();
  if (raise) {
    values["a_w"] = e.a_w;
    if (e.f_w) values["f_w"] = *e.f_w;
    if (e.ratio) values["ratio"] = *e.ratio;
    if (e.u) values["u"] = *e.u;
    values["base"] = e.base;
  }
  if (e.uectx && e.max_conn) {
    values["uectx"] = *e.uectx;
    values["max_conn"] = *e.max_conn;
  }
  if (!values.empty()) j["values"] = std::move(values);
  if (raise) {
    ojson params;
    params["k"] = e.k;
    params["theta"] = e.theta;
    if (e.f_abs) params["f_abs"] = *e.f_abs;  // normal 모드만 (3_ §7.1, 10/27 Q-41)
    j["params"] = std::move(params);
    ojson refs = ojson::object();
    if (e.a_seq) refs["a"] = seq_pair(*e.a_seq);
    if (e.f_seq) refs["f"] = seq_pair(*e.f_seq);
    j["refs"] = std::move(refs);
  }
  if (e.kind == AlertEventKind::Clear || e.kind == AlertEventKind::End) {
    j["duration_ms"] = e.duration_ms;
    j["evidence_sent"] = sent;
    j["evidence_dropped"] = dropped;
  }
  if (e.kind == AlertEventKind::End) j["reason"] = e.reason;
  return j.dump();
}

// evidence 레코드 (3_ §7.1): 나머지 필드를 직렬화한 뒤 닫는 '}' 앞에 "raw": + 원본 줄을 그대로 붙인다.
// 원본 줄은 파싱에 성공한 한 줄짜리 JSON 객체이므로 결과도 올바른 JSON이다
std::string evidence_record_line(const std::string& alert_id, const char* phase, int64_t seq, const std::string& raw) {
  ojson j;
  j["type"] = "evidence";
  j["alert_id"] = alert_id;
  j["phase"] = phase;
  j["seq"] = seq;
  std::string s = j.dump();
  s.pop_back();  // '}'
  s += ",\"raw\":";
  s += raw;
  s += '}';
  return s;
}

// gap 레코드 (3_ §7.1): 경보 중 그 셀의 빠진 시각 범위와 참고용 seq 범위
std::string gap_record_line(const std::string& alert_id, const GapEvent& g) {
  ojson j;
  j["type"] = "gap";
  j["alert_id"] = alert_id;
  j["cell"] = g.cell_id;
  j["t_from"] = g.t_from;
  j["t_to"] = g.t_to;
  j["seq_from"] = g.seq_before;
  j["seq_to"] = g.seq_after;
  return j.dump();
}

EvidenceRecorder::EvidenceRecorder(EvidenceConfig cfg, EvidenceQueue& queue) : cfg_(std::move(cfg)), queue_(queue) {}

EvidenceRecorder::Counts EvidenceRecorder::counts(const std::string& alert_id) const {
  if (auto it = tracks_.find(alert_id); it != tracks_.end()) return it->second.counts;
  if (auto it = finished_.find(alert_id); it != finished_.end()) return it->second;
  return {};
}

// 큐에 넣고 버린 수를 경보별로 센다 (3_ §7.1 '버린 수는 경보별로'). 버린 것은 넣은 레코드와
// 다른 경보의 evidence일 수 있으므로 push 결과의 alert_id 몫으로 센다
void EvidenceRecorder::push(RecordKind kind, const std::string& alert_id, std::string line, std::vector<Diag>& diags) {
  EvidenceQueue::PushResult r = queue_.push(EvidenceRecord{kind, alert_id, std::move(line)});
  if (kind == RecordKind::Evidence && r.accepted) {
    if (auto it = tracks_.find(alert_id); it != tracks_.end()) ++it->second.counts.sent;
  }
  if (!r.dropped_alert) return;
  const std::string& victim = *r.dropped_alert;
  Counts* c = nullptr;
  Track* tr = nullptr;
  if (auto it = tracks_.find(victim); it != tracks_.end()) {
    tr = &it->second;
    c = &tr->counts;
  } else if (auto it2 = finished_.find(victim); it2 != finished_.end()) {
    c = &it2->second;
  }
  if (!c) return;
  ++c->dropped;
  if (r.accepted || victim != alert_id) --c->sent;  // 큐 안에 있던 것을 버렸으면 '보낸 수'에서 뺀다
  if (tr) {
    if (tr->phase == Phase::Post) ++tr->post_dropped;
    // 경보마다 처음 버릴 때 1회 진단 (결정 F7)
    if (!tr->drop_logged) {
      tr->drop_logged = true;
      diags.push_back(Diag{DiagKind::EvidenceDropped, tr->cell_id, std::nullopt,
                           "evidence queue full, dropping evidence of " + victim});
    }
  }
}

void EvidenceRecorder::push_evidence(const std::string& alert_id, const char* phase, const Slot& slot,
                                     std::vector<Diag>& diags) {
  // 버퍼 칸의 값(seq·raw)을 복사해 레코드를 만든다 — 덮어쓰기와 무관 (3_ §7.1)
  push(RecordKind::Evidence, alert_id, evidence_record_line(alert_id, phase, slot.seq, slot.kpm.raw), diags);
}

// post 구간 끝: post 몫의 버린 수가 있으면 진단으로 남기고 집계를 finished로 옮긴다 (결정 F3)
void EvidenceRecorder::finish_post(const std::string& alert_id, std::vector<Diag>& diags) {
  auto it = tracks_.find(alert_id);
  if (it == tracks_.end()) return;
  if (it->second.post_dropped > 0)
    diags.push_back(Diag{DiagKind::EvidenceDropped, it->second.cell_id, std::nullopt,
                         "post evidence dropped for " + alert_id + ": " + std::to_string(it->second.post_dropped)});
  // 끝난 경보 집계는 kFinishedMax까지만 — 오래된 것부터 지운다 (10/27 이슈 #13 W-2)
  if (finished_.insert_or_assign(alert_id, it->second.counts).second) finished_order_.push_back(alert_id);
  while (finished_order_.size() > kFinishedMax) {
    finished_.erase(finished_order_.front());
    finished_order_.pop_front();
  }
  by_rule_cell_.erase({it->second.rule, it->second.cell_id});
  tracks_.erase(it);
}

// 줄 하나 처리 뒤의 증거 처리 순서 (결정 F2):
//  1) 이번 줄 전부터 경보 중이던 그 셀의 경보: 끊김이면 gap → 이번 칸 active (post 중이면 post)
//  2) 이번 줄의 경보 이벤트: raise(alert + pre 스냅샷 — 이번 칸 포함) / clear(alert, 다음 칸부터 post) / end / update
std::vector<Diag> EvidenceRecorder::on_feed(const Series& series, const EngineOutput& out) {
  std::vector<Diag> diags;
  if (cfg_.mode == EvidenceMode::Off) return diags;
  const bool full = cfg_.mode == EvidenceMode::Full;

  // 1) 이번에 저장된 칸 — 그 셀의 진행 중 경보마다 evidence (ref 모드는 alert만, 결정 F6)
  if (full && out.outcome == FeedOutcome::Stored && out.cell_id) {
    const CellSeries* cs = series.cell(*out.cell_id);
    if (cs && cs->size() > 0) {
      const Slot& slot = cs->back();
      std::vector<std::string> ids;
      for (const auto& [id, tr] : tracks_)
        if (tr.cell_id == *out.cell_id) ids.push_back(id);
      for (const auto& id : ids) {
        Track& tr = tracks_.at(id);
        if (tr.phase == Phase::Active) {
          if (out.gap) push(RecordKind::Gap, id, gap_record_line(id, *out.gap), diags);
          push_evidence(id, "active", slot, diags);
        } else {
          push_evidence(id, "post", slot, diags);
          if (--tracks_.at(id).post_left == 0) finish_post(id, diags);
        }
      }
    }
  }

  // 2) 경보 이벤트
  for (const AlertEvent& e : out.alerts) {
    const auto key = std::make_pair(e.rule, e.cell_id);
    switch (e.kind) {
      case AlertEventKind::Raise: {
        // post 중 같은 셀·룰이 다시 RAISE하면 이전 post를 끝내고 새 경보 시작 (3_ §7.1)
        if (auto it = by_rule_cell_.find(key); it != by_rule_cell_.end()) finish_post(it->second, diags);
        Track tr;
        tr.rule = e.rule;
        tr.cell_id = e.cell_id;
        tracks_[e.alert_id] = tr;
        by_rule_cell_[key] = e.alert_id;
        push(RecordKind::Alert, e.alert_id, alert_record_line(e, 0, 0), diags);
        if (full) {
          // pre 스냅샷: 버퍼의 마지막 pre_slots칸 (null이면 버퍼 전체, 결정 F1)
          if (const CellSeries* cs = series.cell(e.cell_id)) {
            const std::size_t n = std::min(cs->size(), cfg_.pre_slots.value_or(cs->capacity()));
            for (std::size_t i = cs->size() - n; i < cs->size(); ++i) push_evidence(e.alert_id, "pre", cs->at(i), diags);
          }
        }
        break;
      }
      case AlertEventKind::Clear: {
        auto it = tracks_.find(e.alert_id);
        const Counts c = it != tracks_.end() ? it->second.counts : Counts{};
        push(RecordKind::Alert, e.alert_id, alert_record_line(e, c.sent, c.dropped), diags);  // 그 순간까지의 수 (결정 F3)
        if (it == tracks_.end()) break;
        if (full && cfg_.post_slots > 0) {
          it->second.phase = Phase::Post;
          it->second.post_left = cfg_.post_slots;
        } else {
          finish_post(e.alert_id, diags);
        }
        break;
      }
      case AlertEventKind::End: {
        auto it = tracks_.find(e.alert_id);
        const Counts c = it != tracks_.end() ? it->second.counts : Counts{};
        push(RecordKind::Alert, e.alert_id, alert_record_line(e, c.sent, c.dropped), diags);
        finish_post(e.alert_id, diags);  // END 뒤에는 post 없음
        break;
      }
      case AlertEventKind::Update:
        push(RecordKind::Alert, e.alert_id, alert_record_line(e, 0, 0), diags);
        break;
    }
  }
  return diags;
}

}  // namespace detect
