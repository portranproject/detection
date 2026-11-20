#include "detect/ue_evidence.h"

#include <nlohmann/json.hpp>

namespace detect {

UeEvidence::UeEvidence(EvidenceMode mode, std::size_t ue_evidence_max) : mode_(mode), max_(ue_evidence_max) {}

// RAISE·UPDATE에 새로 실린 UE (14_ §8.3·§8.4). 경보당 증거 UE 상한이 경보 전체(이어지는 update)에 걸려 있어 여기서 센다.
//  - seq_range = 그 UE recent의 [첫 seq, 마지막 seq]. 모드와 관계없이 채운다 — ref 모드에서 대시보드가 원본을 찾는 근거다.
//    recent가 없으면(닫힌 뒤 보관이 끝남, 14_ §2.3) null
//  - full 모드이고 상한 안이고 recent가 있으면 evidence = true, recent 전부를 pre로 낸다(값 복사 — 고리 버퍼 칸을 공유하지 않음).
//    상한을 넘거나 recent가 없거나 ref 모드면 false. 이미 증거를 내는 UE가 다시 실리면 pre를 다시 내지 않는다
std::vector<UeEvidence::Record> UeEvidence::on_alert(AlertEvent& e, const UeTable& table) {
  std::vector<Record> out;
  std::set<UeId>& mine = by_alert_[e.alert_id];
  for (AlertUe& u : e.ues) {
    const UeId id{UeKey{u.cell, u.du_ue_id}, u.uid};
    const std::deque<RecentLine>* recent = table.recent(id.first, id.second);
    const bool have = recent && !recent->empty();
    u.seq_range = have ? std::optional<std::pair<int64_t, int64_t>>({recent->front().seq, recent->back().seq})
                       : std::nullopt;
    if (mine.count(id)) {
      u.evidence = true;
      continue;
    }
    u.evidence = mode_ == EvidenceMode::Full && have && mine.size() < max_;
    if (!u.evidence) continue;
    mine.insert(id);
    by_ue_[id].insert(e.alert_id);
    for (const RecentLine& r : *recent)
      out.push_back(Record{e.alert_id, ue_evidence_record_line(e.alert_id, "pre", r.seq, id.first, id.second, r.raw)});
  }
  return out;
}

// 경보 중 새 줄 (14_ §8.4 active). 이 줄로 RAISE·UPDATE된 UE는 아직 여기 없으므로 그 줄은 pre에만 들어간다
std::vector<UeEvidence::Record> UeEvidence::on_line(const EngineOutput::UeLine& line) const {
  std::vector<Record> out;
  auto it = by_ue_.find({line.key, line.uid});
  if (it == by_ue_.end()) return out;
  for (const std::string& id : it->second)
    out.push_back(Record{id, ue_evidence_record_line(id, "active", line.seq, line.key, line.uid, line.raw)});
  return out;
}

void UeEvidence::finish(const std::string& alert_id) {
  auto it = by_alert_.find(alert_id);
  if (it == by_alert_.end()) return;
  for (const UeId& id : it->second) {
    auto u = by_ue_.find(id);
    if (u == by_ue_.end()) continue;
    u->second.erase(alert_id);
    if (u->second.empty()) by_ue_.erase(u);
  }
  by_alert_.erase(it);
}

// UE 증거 레코드 (14_ §8.4): 나머지 필드를 직렬화한 뒤 닫는 '}' 앞에 "raw": + 원본 줄을 그대로 붙인다.
// 원본 줄은 파싱에 성공한 한 줄짜리 JSON 객체이므로 결과도 올바른 JSON이다
std::string ue_evidence_record_line(const std::string& alert_id, const char* phase, int64_t seq, const UeKey& key,
                                    int64_t uid, const std::string& raw) {
  nlohmann::ordered_json j;
  j["type"] = "evidence";
  j["alert_id"] = alert_id;
  j["phase"] = phase;
  j["seq"] = seq;
  j["ue"] = nlohmann::ordered_json::array({key.cell_id, key.du_ue_id, uid});
  std::string s = j.dump();
  s.pop_back();  // '}'
  s += ",\"raw\":";
  s += raw;
  s += '}';
  return s;
}

}  // namespace detect
