#include "detect/ue_table.h"

#include "detect/deadline_queue.h"

#include <algorithm>
#include <limits>
#include <tuple>
#include <utility>

namespace detect {

const char* to_string(CloseReason r) {
  switch (r) {
    case CloseReason::Released: return "released";
    case CloseReason::Reused: return "reused";
    case CloseReason::StaleSetup: return "stale_setup";
    case CloseReason::Superseded: return "superseded";
    case CloseReason::DuReset: return "du_reset";
    case CloseReason::Evicted: return "evicted";
    case CloseReason::SessionReset: return "session_reset";
  }
  return "?";
}

int64_t UeState::count(Proto proto, const std::string& msg) const {
  auto it = cnt.find({proto, msg});
  return it == cnt.end() ? 0 : it->second;
}

namespace {

constexpr uint64_t kPart1Mask = (uint64_t{1} << 39) - 1;

// Part1 색인 값 (14_ §3.1): Part1 = 48비트 S-TMSI의 하위 39비트. 48비트를 알면 거기서, 아니면 RRCSetupRequest의 Part1
std::optional<uint64_t> part1_of(const UeState& s) {
  if (s.s_tmsi) return *s.s_tmsi & kPart1Mask;
  return s.s_tmsi_part1;
}

// 망에 받아들여짐 — superseded 기준 (14_ §4.2): nas REGISTERED 또는 rrc_sec ON.
// 15_ §1.1 '망 수락'(RRC SecurityModeCommand의 CMD 포함)보다 엄격하다 — 유령 항목을 치우는 용도라서
bool admitted(const UeState& s) { return s.nas == NasState::Registered || s.rrc_sec == RrcSecState::On; }

bool is(const UeEvt& e, Proto proto, Dir dir, const char* msg) {
  return e.proto == proto && e.dir == dir && e.msg == msg;
}

// 항목 열기 (14_ §4.1): RRCSetupRequest면 정상 시작, 그 밖의 메시지면 mid_join(탐지 엔진이 켜지기 전 접속,
// INACTIVE 재개, 로스로 시작을 놓침) — 상태를 모르므로 UNKNOWN에서 시작한다 (14_ §5.1·§5.3·§5.4)
UeState open_state(const UeKey& key, int64_t uid, const UeEvt& e) {
  UeState s;
  s.key = key;
  s.uid = uid;
  s.t_start = e.t_ms;
  s.t_last = e.t_ms;
  if (is(e, Proto::RRC, Dir::UL, "RRCSetupRequest")) {
    s.rrc = RrcState::Setup;
    s.rrc_sec = RrcSecState::Off;
    s.nas_sec = NasSecState::None;
    if (e.ue_identity == UeIdentityType::Part1) s.s_tmsi_part1 = e.s_tmsi_part1;
  } else {
    s.mid_join = true;
    s.rrc = RrcState::Unknown;
    s.rrc_sec = RrcSecState::Unknown;
    s.nas_sec = NasSecState::Unknown;
  }
  return s;
}

// 상태 전이 (14_ §5). 표에 없는 메시지와 방향이 표와 다른 메시지는 상태를 바꾸지 않는다. 순서가 맞지 않는 메시지도
// 표대로 바꾼다 — 갱신 전 상태가 룰에 함께 가므로 룰이 순서 위반을 판정할 수 있다
void transition(UeState& s, const UeEvt& e) {
  using P = Proto;
  using D = Dir;
  // §5.1 rrc
  if (is(e, P::RRC, D::DL, "RRCSetup")) {
    if (s.rrc == RrcState::Setup) s.t_rrc_setup = e.t_ms;
  } else if (is(e, P::RRC, D::DL, "RRCReject")) {
    if (s.rrc == RrcState::Setup) s.rrc = RrcState::Rejected;
  } else if (is(e, P::RRC, D::UL, "RRCSetupComplete")) {
    if (s.rrc == RrcState::Setup || s.rrc == RrcState::Unknown) s.rrc = RrcState::Connected;
  } else if (is(e, P::RRC, D::DL, "RRCRelease")) {
    s.rrc = e.suspend.value_or(false) ? RrcState::Inactive : RrcState::Releasing;
  } else if (is(e, P::F1AP, D::DL, "UEContextReleaseCommand")) {
    if (s.rrc != RrcState::Inactive) s.rrc = RrcState::Releasing;
  }
  // 'UNKNOWN 항목이 보안을 쓰는 메시지를 보내면 CONNECTED' — 보안 헤더가 있는 NAS 줄(sht ≥ 1)로 본다 (14_ §5.1)
  if (s.rrc == RrcState::Unknown && e.proto == P::NAS && e.sht && *e.sht >= 1) s.rrc = RrcState::Connected;
  if (s.rrc == RrcState::Connected) s.ever_connected = true;

  // §5.3 rrc_sec
  if (is(e, P::RRC, D::DL, "SecurityModeCommand")) {
    if (s.rrc_sec == RrcSecState::Off || s.rrc_sec == RrcSecState::Unknown) {
      s.rrc_sec = RrcSecState::Cmd;
      s.rrc_alg = SecAlg{e.cipher.value_or(""), e.integrity.value_or("")};
    }
  } else if (is(e, P::RRC, D::UL, "SecurityModeComplete")) {
    if (s.rrc_sec == RrcSecState::Cmd) s.rrc_sec = RrcSecState::On;
  } else if (is(e, P::RRC, D::UL, "SecurityModeFailure")) {
    if (s.rrc_sec == RrcSecState::Cmd) s.rrc_sec = RrcSecState::Failed;
  }

  // §5.2 nas — Accept는 요청 줄을 로스로 놓쳤어도 수락 자체가 근거라 어느 상태에서든 REGISTERED (10/29 검수 B11)
  if (is(e, P::NAS, D::UL, "RegistrationRequest")) {
    s.nas = NasState::RegInitiated;
  } else if (is(e, P::NAS, D::DL, "RegistrationAccept")) {
    s.nas = NasState::Registered;
  } else if (is(e, P::NAS, D::DL, "RegistrationReject")) {
    if (s.nas == NasState::RegInitiated) s.nas = NasState::Deregistered;
  } else if (is(e, P::NAS, D::UL, "RegistrationComplete")) {
    if (s.nas == NasState::Registered) s.t_reg_complete = e.t_ms;
  } else if (is(e, P::NAS, D::UL, "ServiceRequest")) {
    s.nas = NasState::SrInitiated;
  } else if (is(e, P::NAS, D::DL, "ServiceAccept")) {
    s.nas = NasState::Registered;
  } else if (is(e, P::NAS, D::DL, "ServiceReject")) {
    if (s.nas == NasState::SrInitiated) s.nas = NasState::Deregistered;
  } else if (e.proto == P::NAS && e.msg == "DeregistrationRequest") {  // UL·DL 모두
    s.nas = NasState::DeregInitiated;
  } else if (is(e, P::NAS, D::DL, "AuthenticationReject")) {
    s.nas = NasState::Deregistered;
  }

  // §5.4 nas_sec — UL NAS의 sht는 UE가 적는 값이라(공격자도 꾸밈) 상태를 바꾸지 않는다. DL과 그 응답 순서로만
  if (is(e, P::NAS, D::DL, "AuthenticationRequest")) {
    s.nas_sec = NasSecState::Auth;
  } else if (is(e, P::NAS, D::UL, "AuthenticationResponse")) {
    if (s.nas_sec == NasSecState::Auth) s.nas_sec = NasSecState::AuthOk;
  } else if (is(e, P::NAS, D::UL, "AuthenticationFailure")) {
    if (s.nas_sec == NasSecState::Auth) s.nas_sec = NasSecState::AuthFail;
  } else if (is(e, P::NAS, D::DL, "SecurityModeCommand")) {
    s.nas_sec = NasSecState::Cmd;
    s.nas_alg = SecAlg{e.cipher.value_or(""), e.integrity.value_or("")};
  } else if (is(e, P::NAS, D::UL, "SecurityModeComplete")) {
    if (s.nas_sec == NasSecState::Cmd) s.nas_sec = NasSecState::On;
  } else if (is(e, P::NAS, D::UL, "SecurityModeReject")) {
    if (s.nas_sec == NasSecState::Cmd) s.nas_sec = NasSecState::Rejected;
  }
}

// 식별 값 (14_ §2.1): cu_ue_id는 알게 되면 채우고, crnti는 첫 값을 쓴다. 48비트 S-TMSI는 RRCSetupComplete·
// RegistrationRequest·ServiceRequest·RegistrationAccept(망이 준 새 5G-GUTI, 10/29 검수 A3)의 f.s_tmsi로 채우고 바뀌면
// 마지막 값을 쓴다. RRCSetupComplete에 Part2만 오면 RRCSetupRequest의 Part1과 합친다 (2_ §7-14 폴백, Part2 = 상위 9비트)
void update_ids(UeState& s, const UeEvt& e) {
  if (e.cu_ue_id) s.cu_ue_id = e.cu_ue_id;
  if (!s.crnti && e.crnti) s.crnti = e.crnti;
  const bool setup_complete = is(e, Proto::RRC, Dir::UL, "RRCSetupComplete");
  const bool carries = setup_complete || is(e, Proto::NAS, Dir::UL, "RegistrationRequest") ||
                       is(e, Proto::NAS, Dir::UL, "ServiceRequest") || is(e, Proto::NAS, Dir::DL, "RegistrationAccept");
  if (!carries) return;
  if (e.s_tmsi) {
    s.s_tmsi = e.s_tmsi;
  } else if (setup_complete && e.s_tmsi_part2 && s.s_tmsi_part1) {
    s.s_tmsi = (*e.s_tmsi_part2 << 39) | *s.s_tmsi_part1;
  }
}

void index_erase(std::map<uint64_t, std::set<UeKey>>& index, uint64_t v, const UeKey& key) {
  auto it = index.find(v);
  if (it == index.end()) return;
  it->second.erase(key);
  if (it->second.empty()) index.erase(it);
}

}  // namespace

UeTable::UeTable(UeTableConfig cfg) : cfg_(cfg) {}

// ue_evt 한 줄의 ②~④ (14_ §7)
UeTable::Applied UeTable::apply(const UeEvt& e, int64_t seq, DeadlineQueue& dq) {
  Applied a;
  // ② du_ue_id가 null(F1AP UE에 잇지 못한 NGAP NAS)이면 항목에 붙이지 않고 셀별 수만 센다 (14_ §7, 2_ §6.6)
  if (!e.du_ue_id) {
    a.linked = false;
    if (++counts_[e.cell_id].ngap_unlinked == 1)
      a.diags.push_back(Diag{DiagKind::NgapUnlinked, e.cell_id, seq,
                             "NAS via NGAP without du_ue_id: counted per cell, not kept in UE table"});
    return a;
  }
  a.key = UeKey{e.cell_id, *e.du_ue_id};
  auto it = entries_.find(a.key);
  // 열린 키에 RRCSetupRequest — UEContextReleaseComplete를 놓쳐 F1AP ID가 재사용됐다. 옛 항목을 reused로 닫고 새로 연다 (14_ §4.1)
  if (it != entries_.end() && is(e, Proto::RRC, Dir::UL, "RRCSetupRequest")) {
    a.closed.push_back(close(it, CloseReason::Reused, e.t_ms, &dq));
    it = entries_.end();
  }
  if (it == entries_.end()) {
    // 상한 (14_ §4.4): 꽉 찼으면 밀어낼 순서대로 닫는다. 밀려남 자체가 이상 신호라 진단·셀별 수를 남긴다
    while (!entries_.empty() && entries_.size() >= cfg_.max_ues) {
      Iter victim = pick_victim();
      const UeState& v = victim->second.st;
      const int64_t n = ++counts_[v.key.cell_id].evicted;
      a.diags.push_back(Diag{DiagKind::UeEvicted, v.key.cell_id, seq,
                             "UE table full (" + std::to_string(cfg_.max_ues) + "): evicted du_ue_id=" +
                                 std::to_string(v.key.du_ue_id) + " uid=" + std::to_string(v.uid) +
                                 " (cell total " + std::to_string(n) + ")"});
      a.closed.push_back(close(victim, CloseReason::Evicted, e.t_ms, nullptr));
    }
    it = entries_.emplace(a.key, Entry{open_state(a.key, next_uid_++, e), {}}).first;
    a.opened = true;
    // 표 몫 마감 stale_setup (14_ §4.2·§6.1 표). mid_join은 이미 붙어 있던 UE일 수 있어 시간으로 닫지 않는다
    if (!it->second.st.mid_join) dq.add(stale_deadline(it->second.st));
  }

  UeState& s = it->second.st;
  a.before = s;  // ③
  const std::optional<uint64_t> old_s = a.opened ? std::nullopt : s.s_tmsi;
  const std::optional<uint64_t> old_p1 = a.opened ? std::nullopt : part1_of(s);

  // ④ 늦은 줄 (2_ §6.5, 14_ §4.3): 그 셀 워터마크(시계)보다 이른 t_ms — 이력에는 넣고, 이미 내린 판정은 룰이 바꾸지 않는다
  if (const std::optional<int64_t> clock = dq.clock(e.cell_id); clock && e.t_ms < *clock) {
    s.late = true;
    const int64_t n = ++counts_[e.cell_id].late;
    a.diags.push_back(Diag{DiagKind::UeLate, e.cell_id, seq,
                           "ue_evt " + e.msg + " t_ms=" + std::to_string(e.t_ms) + " < watermark " +
                               std::to_string(*clock) + " (cell total " + std::to_string(n) + ")"});
  }
  transition(s, e);
  update_ids(s, e);
  ++s.cnt[{e.proto, e.msg}];
  s.last = LastMsg{e.proto, e.dir, e.msg, e.t_ms, seq};
  s.t_last = std::max(s.t_last, e.t_ms);
  // 최근 메시지 N개 고리 버퍼 — 원본 줄을 복사해 둔다 (14_ §2.3, 증거용)
  if (cfg_.recent_n > 0) {
    std::deque<RecentLine>& r = it->second.recent;
    r.push_back(RecentLine{seq, e.t_ms, e.raw});
    while (r.size() > cfg_.recent_n) r.pop_front();
  }
  reindex(a.key, old_s, old_p1, s);
  a.released = is(e, Proto::F1AP, Dir::UL, "UEContextReleaseComplete");
  a.after = s;
  return a;
}

// ⑥·⑦ (14_ §7): 이 줄로 망에 받아들여진 항목이 있으면 같은 S-TMSI의 불확실한(loss·mid_join) 옛 열린 항목을
// superseded로 닫는다 — 해제 줄을 로스로 놓친 유령을 치운다. 불확실하지 않은 옛 항목은 남겨 룰(L3-20)이 본다(14_ §4.2).
// 받아들여진 순간(또는 받아들여진 뒤 S-TMSI가 바뀐 순간)에만 본다. UEContextReleaseComplete면 그 항목을 released로 닫는다
std::vector<UeTable::Closed> UeTable::settle(const Applied& a, DeadlineQueue& dq) {
  std::vector<Closed> out;
  if (!a.linked) return out;
  auto it = entries_.find(a.key);
  if (it == entries_.end() || it->second.st.uid != a.after.uid) return out;
  const UeState& n = it->second.st;
  const int64_t t = a.after.last.t_ms;
  if (admitted(n) && n.s_tmsi && (!admitted(a.before) || a.before.s_tmsi != n.s_tmsi)) {
    std::vector<UeKey> ghosts;
    if (auto ix = by_s_tmsi_.find(*n.s_tmsi); ix != by_s_tmsi_.end()) {
      for (const UeKey& k : ix->second) {
        if (k == n.key) continue;
        const UeState& o = entries_.at(k).st;
        if (o.uid < n.uid && (o.mid_join || o.loss)) ghosts.push_back(k);
      }
    }
    for (const UeKey& k : ghosts) out.push_back(close(entries_.find(k), CloseReason::Superseded, t, &dq));
  }
  if (a.released) out.push_back(close(entries_.find(a.key), CloseReason::Released, t, &dq));
  return out;
}

// 상태표 몫 마감 (14_ §6.1 표).
//  - closed_recent: 닫힌 항목 recent 보관이 끝났다 — 그 보관분이 아직 있고 같은 것이면 지운다 (14_ §2.3)
//  - stale_setup: CONNECTED 전인 항목이 stale_setup_ms 동안 새 줄이 없으면 닫는다(14_ §4.2). t_last가 바뀌었으면
//    새 마감으로 다시 넣고, CONNECTED가 됐거나 닫힌 항목(uid가 다름)이면 버린다
std::optional<UeTable::Closed> UeTable::on_deadline(const Deadline& d, DeadlineQueue& dq) {
  if (d.tag == kKeptTag) {
    auto k = kept_.find({d.key, d.uid});
    if (k != kept_.end() && k->second.closed_at == d.t_from) {
      kept_order_.erase(k->second.order);
      kept_.erase(k);
    }
    return std::nullopt;
  }
  auto it = entries_.find(d.key);
  if (it == entries_.end() || it->second.st.uid != d.uid) return std::nullopt;
  const UeState& s = it->second.st;
  if (s.ever_connected) return std::nullopt;
  if (s.t_last != d.t_from) {
    dq.add(stale_deadline(s));
    return std::nullopt;
  }
  return close(it, CloseReason::StaleSetup, d.at, &dq);
}

// 로스 창이 난 셀의 열린 항목에 loss와 마지막 로스 시각 (14_ §4.3, §7 kpm2 ②)
void UeTable::mark_loss(int64_t cell, int64_t t_loss) {
  for (auto it = entries_.lower_bound(UeKey{cell, std::numeric_limits<int64_t>::min()});
       it != entries_.end() && it->first.cell_id == cell; ++it) {
    it->second.st.loss = true;
    it->second.st.t_loss = t_loss;
  }
}

// f1_evt (14_ §4.2 du_reset, 2_ §6.7): cells(null = 모든 셀)의 열린 항목, du_ue_ids가 있으면 그 UE만 닫는다.
// 이때 UE별 해제 줄은 오지 않는다
std::vector<UeTable::Closed> UeTable::close_du(const F1Evt& f) {
  auto listed = [](const std::optional<std::vector<int64_t>>& v, int64_t x) {
    return !v || std::find(v->begin(), v->end(), x) != v->end();
  };
  std::vector<Closed> out;
  for (auto it = entries_.begin(); it != entries_.end();) {
    Iter cur = it++;
    if (listed(f.cells, cur->first.cell_id) && listed(f.du_ue_ids, cur->first.du_ue_id))
      out.push_back(close(cur, CloseReason::DuReset, f.t_ms, nullptr));
  }
  return out;
}

void UeTable::clear() {
  entries_.clear();
  by_s_tmsi_.clear();
  by_part1_.clear();
  counts_.clear();
  next_uid_ = 1;
  kept_.clear();
  kept_order_.clear();
  next_kept_ = 0;
}

const UeState* UeTable::find(const UeKey& key) const {
  auto it = entries_.find(key);
  return it == entries_.end() ? nullptr : &it->second.st;
}

std::vector<const UeState*> UeTable::by_s_tmsi(uint64_t s_tmsi) const { return lookup(by_s_tmsi_, s_tmsi); }

std::vector<const UeState*> UeTable::by_part1(uint64_t part1) const { return lookup(by_part1_, part1); }

const std::deque<RecentLine>* UeTable::recent(const UeKey& key) const {
  auto it = entries_.find(key);
  return it == entries_.end() ? nullptr : &it->second.recent;
}

const std::deque<RecentLine>* UeTable::recent(const UeKey& key, int64_t uid) const {
  if (auto it = entries_.find(key); it != entries_.end() && it->second.st.uid == uid) return &it->second.recent;
  auto k = kept_.find({key, uid});
  return k == kept_.end() ? nullptr : &k->second.recent;
}

UeTable::CellCounts UeTable::counts(int64_t cell) const {
  auto it = counts_.find(cell);
  return it == counts_.end() ? CellCounts{} : it->second;
}

// 닫기 (14_ §4.2): 색인에서 빼고 표에서 지운 뒤 마지막 상태를 돌려준다. released·reused·stale_setup·superseded면
// 최근 메시지를 보관한다 — 경보를 낼 때 걸린 UE가 이미 닫혀 있을 수 있어서다(14_ §2.3). du_reset·evicted는 룰도
// 대기 표시를 지우므로(15_ §1) 보관하지 않는다
UeTable::Closed UeTable::close(Iter it, CloseReason reason, int64_t t, DeadlineQueue* dq) {
  Closed c{std::move(it->second.st), reason};
  if (c.last.s_tmsi) index_erase(by_s_tmsi_, *c.last.s_tmsi, c.last.key);
  if (const std::optional<uint64_t> p1 = part1_of(c.last)) index_erase(by_part1_, *p1, c.last.key);
  const bool keep = reason == CloseReason::Released || reason == CloseReason::Reused ||
                    reason == CloseReason::StaleSetup || reason == CloseReason::Superseded;
  if (keep && dq) keep_recent(c.last, std::move(it->second.recent), t, *dq);
  entries_.erase(it);
  return c;
}

// 닫힌 항목 recent 보관 (14_ §2.3·§6.1 표 closed_recent): 닫힌 시각 + 보관 시간에 표 몫 마감으로 지우고,
// 개수 상한 closed_recent_max를 넘으면 오래된 것부터 버린다. 증거에만 쓰고 판정에는 쓰지 않는다
void UeTable::keep_recent(const UeState& last, std::deque<RecentLine> recent, int64_t t, DeadlineQueue& dq) {
  if (keep_ms_ <= 0 || cfg_.closed_recent_max == 0 || recent.empty()) return;
  const UeId id{last.key, last.uid};
  const uint64_t order = next_kept_++;
  kept_[id] = Kept{std::move(recent), order, t};
  kept_order_[order] = id;
  while (kept_.size() > cfg_.closed_recent_max) {
    auto oldest = kept_order_.begin();
    kept_.erase(oldest->second);
    kept_order_.erase(oldest);
  }
  Deadline d;
  d.at = t + keep_ms_;
  d.key = last.key;
  d.uid = last.uid;
  d.owner = DeadlineQueue::kTableOwner;
  d.tag = kKeptTag;
  d.t_from = t;  // 닫힌 시각 — 꺼낼 때 보관분의 closed_at과 대조
  dq.add(std::move(d));
}

// 밀어낼 순서 (14_ §4.4): ① rrc가 CONNECTED가 아닌 항목 → ② CONNECTED이지만 불확실한 항목 → ③ 나머지.
// 같은 무리 안에서는 t_last가 가장 오래된 것부터(같으면 먼저 연 것). t_last만 보면 조용히 데이터만 쓰는 정상 연결
// (Blind DoS 피해자 후보)이 먼저 밀려나기 때문이다. 꽉 찼을 때만 훑는다 — 상한이 4,096이라 비용이 작다
UeTable::Iter UeTable::pick_victim() {
  auto rank = [](const UeState& s) { return s.rrc != RrcState::Connected ? 0 : (s.uncertain() ? 1 : 2); };
  Iter best = entries_.begin();
  for (Iter it = std::next(entries_.begin()); it != entries_.end(); ++it) {
    const UeState& x = it->second.st;
    const UeState& b = best->second.st;
    if (std::make_tuple(rank(x), x.t_last, x.uid) < std::make_tuple(rank(b), b.t_last, b.uid)) best = it;
  }
  return best;
}

// S-TMSI 색인 갱신 (14_ §3.1): 48비트 색인에는 48비트를 아는 항목만, Part1 색인에는 Part1만 받은 항목과 48비트를 아는
// 항목(그 하위 39비트)을 함께 넣는다. 값이 바뀌면 옮긴다
void UeTable::reindex(const UeKey& key, std::optional<uint64_t> old_s, std::optional<uint64_t> old_p1,
                      const UeState& s) {
  if (old_s != s.s_tmsi) {
    if (old_s) index_erase(by_s_tmsi_, *old_s, key);
    if (s.s_tmsi) by_s_tmsi_[*s.s_tmsi].insert(key);
  }
  const std::optional<uint64_t> p1 = part1_of(s);
  if (old_p1 != p1) {
    if (old_p1) index_erase(by_part1_, *old_p1, key);
    if (p1) by_part1_[*p1].insert(key);
  }
}

Deadline UeTable::stale_deadline(const UeState& s) const {
  Deadline d;
  d.at = s.t_last + cfg_.stale_setup_ms;
  d.key = s.key;
  d.uid = s.uid;
  d.owner = DeadlineQueue::kTableOwner;
  d.tag = kStaleTag;
  d.t_from = s.t_last;  // 마감을 넣을 때의 t_last — 꺼낼 때 그대로면 그동안 새 줄이 없었다
  return d;
}

std::vector<const UeState*> UeTable::lookup(const std::map<uint64_t, std::set<UeKey>>& index, uint64_t v) const {
  std::vector<const UeState*> out;
  auto it = index.find(v);
  if (it == index.end()) return out;
  for (const UeKey& k : it->second) out.push_back(&entries_.at(k).st);
  return out;
}

}  // namespace detect
