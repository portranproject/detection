#include "detect/ue_lookback.h"

#include <algorithm>
#include <cctype>
#include <utility>

namespace detect {

// AS 무결성 (20_ §1.2-1): ON이고 무결성이 nia0이 아니면 그 뒤 주입은 PDCP에서 걸러진다. CMD(보안 모드 명령 뒤 완료 전)·FAILED·OFF는
// 판정하고, 무결성 nia0은 연결 내내 주입할 수 있어 판정한다. 값 없음·모르는 값은 nia0이 아닌 것으로 본다(보수적)
bool as_integrity_on(const UeState& b) {
  if (b.rrc_sec != RrcSecState::On) return false;
  if (!b.rrc_alg) return true;
  std::string v = b.rrc_alg->integrity;
  std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return v != "nia0";
}

bool unsolicited(const UeState& b, Proto proto, const std::string& req, const std::string& resp) {
  return unsolicited(b, proto, req, std::vector<std::string>{resp});
}

int64_t count_any(const UeState& n, Proto proto, const std::vector<std::string>& msgs) {
  int64_t a = 0;
  for (const std::string& m : msgs) a += n.count(proto, m);
  return a;
}

bool unsolicited(const UeState& b, Proto proto, const std::string& req, const std::vector<std::string>& resps) {
  return !b.mid_join && !as_integrity_on(b) && b.count(proto, req) <= count_any(b, proto, resps);
}

const LookbackMarks::Mark* LookbackMarks::find(const UeKey& key, int64_t uid, const std::string& tag) const {
  auto it = marks_.find(Id{key, uid, tag});
  return it == marks_.end() ? nullptr : &it->second;
}

// 후보 (20_ §1.2-2·3): 응답 줄에서 바로 판정하지 않고 마감 t + 1을 넣는다 — 같은 창에서 요청 줄을 로스로 놓쳤다면 그 표시
// (ue_evt_lost)는 그 창의 kpm2에 실려 응답 줄보다 나중에 온다(2_ §4.6·§6.1). 마감을 t + 1로 두면 t를 품은 창(t_end_ms > t)의
// kpm2에서 꺼내진다 — t가 창 경계와 같아도 앞 창에서 꺼내지지 않는다
bool LookbackMarks::start(const UeState& n, const std::string& tag, int64_t t, nlohmann::ordered_json snap,
                          const UeRuleCtx& ctx) {
  const Id id{n.key, n.uid, tag};
  if (auto it = marks_.find(id); it != marks_.end()) {
    ++it->second.extra;
    return false;
  }
  Mark m;
  m.key = n.key;
  m.uid = n.uid;
  m.tag = tag;
  m.t_from = t;
  m.snap = std::move(snap);
  ctx.add_deadline(t + 1, n.key, n.uid, tag, Dir::DL, t);  // 놓쳤을 수 있는 것은 DL 줄(요청·보안 모드 명령)
  marks_.emplace(id, std::move(m));
  return true;
}

// 마감 처리 (20_ §1.2-4): 표시가 그대로(대기, t_from 같음)이면 n을 판정한다. n은 열린 항목, 마감 전에 닫혔으면 복사본(§1.2-5).
//  - 보류: 그 연결이 시작된 뒤(t_s = t_start) 그 셀에 DL 로스 창이 있었으면 그때 요청(보안 모드 명령)을 놓쳤을 수 있다 —
//    14_ §6.2 보류에서 기준 시각만 t_from → t_s로 바꾼 것. 항목의 loss 표시는 방향을 가리지 않아 보지 않는다
//  - late: 늦은 줄 제외 기간(late_until)이 마감을 덮으면 판정하지 않고 표시를 지운다 — 뒤에 온 줄은 다시 후보가 될 수 있다(14_ §4.3)
//  - 걸림·보류는 표시를 '결정됨'으로 둔다. 복사본으로 판정했으면 항목이 이미 닫혔으므로 지운다
LookbackMarks::Decision LookbackMarks::on_deadline(const Deadline& d, const UeRuleCtx& ctx) {
  Decision r;
  auto it = marks_.find(Id{d.key, d.uid, d.tag});
  if (it == marks_.end() || it->second.phase != Phase::Waiting || it->second.t_from != d.t_from) return r;
  Mark& m = it->second;
  const UeState* live = ctx.table.find(d.key);
  const bool open = live && live->uid == d.uid;
  if (!open && !m.closed) {  // 닫힘 알림 없이 사라진 항목 — 일어나지 않지만 표시만 남지 않게
    marks_.erase(it);
    return r;
  }
  r.n = open ? *live : *m.closed;
  if (ctx.deadlines.held(d.key.cell_id, Dir::DL, r.n.t_start)) {
    m.phase = Phase::Held;
    r.verdict = Verdict::Held;
  } else if (r.n.late_blocks(d.at)) {
    r.verdict = Verdict::Skip;
    r.mark = std::move(m);
    marks_.erase(it);
    return r;
  } else {
    m.phase = Phase::Hit;
    r.verdict = Verdict::Hit;
  }
  r.mark = m;
  if (!open) marks_.erase(it);
  return r;
}

void LookbackMarks::included(const UeKey& key, int64_t uid, const std::string& tag, int64_t epoch) {
  if (auto it = marks_.find(Id{key, uid, tag}); it != marks_.end()) it->second.epoch = epoch;
}

void LookbackMarks::on_close(const UeState& last, CloseReason reason) {
  const bool keep = reason == CloseReason::Released || reason == CloseReason::Reused || reason == CloseReason::StaleSetup;
  for (auto it = marks_.lower_bound(Id{last.key, last.uid, std::string()});
       it != marks_.end() && std::get<0>(it->first) == last.key && std::get<1>(it->first) == last.uid;) {
    if (keep && it->second.phase == Phase::Waiting) {
      it->second.closed = last;
      ++it;
    } else {
      it = marks_.erase(it);
    }
  }
}

}  // namespace detect
