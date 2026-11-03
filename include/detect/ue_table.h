#pragma once
// UE 상태표 (14_ §2~§5) — ue_evt 한 줄을 받아 UE 항목의 현재 상태·횟수·최근 메시지를 이 한 곳에서 갱신한다(14_ §1).
// 룰은 읽기만 한다. 판정에는 메시지 이력이 아니라 현재 상태·횟수를 쓰고, 최근 메시지(recent)는 증거용이다(14_ §0 결정 1·2).
// 닫힌 S-TMSI 기억(14_ §3.2)은 쓰는 룰이 없어(IDLE형 제외, 15_ §2.1) 두지 않는다.

#include "detect/config.h"
#include "detect/diag.h"
#include "detect/message.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace detect {

class DeadlineQueue;
struct Deadline;

// UE 키 (14_ §2.1, 2_ §6.2) — 셀이 다른 DU에 속해도 겹치지 않게 셀을 붙인다
struct UeKey {
  int64_t cell_id = 0;
  int64_t du_ue_id = 0;
  bool operator<(const UeKey& o) const {
    return cell_id != o.cell_id ? cell_id < o.cell_id : du_ue_id < o.du_ue_id;
  }
  bool operator==(const UeKey& o) const { return cell_id == o.cell_id && du_ue_id == o.du_ue_id; }
};

// 상태 값 (14_ §5.1~§5.4)
enum class RrcState { Setup, Unknown, Rejected, Connected, Releasing, Inactive };
enum class NasState { Unknown, RegInitiated, Registered, Deregistered, SrInitiated, DeregInitiated };
enum class RrcSecState { Off, Unknown, Cmd, On, Failed };
enum class NasSecState { None, Unknown, Auth, AuthOk, AuthFail, Cmd, On, Rejected };
// 보안 상태 이름 — 14_ §5.3·§5.4 철자(대문자). 3단계 경보 ues[].values의 rrc_sec·nas_sec (20_ §3.6·§4.6, 4_ §6.2)
const char* to_string(RrcSecState s);
const char* to_string(NasSecState s);

// 항목이 닫힌 이유 (14_ §4.2). GhostPurge = 유령 정리(10/29 Q-56 해결, 이슈 #44) — 처리는 Evicted와 같다
enum class CloseReason { Released, Reused, StaleSetup, Superseded, DuReset, Evicted, SessionReset, GhostPurge };
const char* to_string(CloseReason r);

// 보안 알고리즘 (14_ §2.2 rrc_alg·nas_alg)
struct SecAlg {
  std::string cipher;
  std::string integrity;
};

// 마지막 메시지 (14_ §2.2 last)
struct LastMsg {
  Proto proto = Proto::RRC;
  Dir dir = Dir::UL;
  std::string msg;
  int64_t t_ms = 0;
  int64_t seq = 0;
};

// UE 항목의 상태 — 룰에 갱신 전·후로 넘기는 값 (14_ §1·§2.1~§2.3). 최근 메시지는 커서 따로 둔다
struct UeState {
  UeKey key;
  int64_t uid = 0;                        // 세션 안 항목 인스턴스 번호 — 같은 키의 재사용을 가른다 (14_ §2.1)
  std::optional<int64_t> cu_ue_id;
  std::optional<int64_t> crnti;
  std::optional<uint64_t> s_tmsi;         // 48비트 5G-S-TMSI (14_ §2.1)
  std::optional<uint64_t> s_tmsi_part1;   // RRCSetupRequest의 Part1 39비트

  RrcState rrc = RrcState::Setup;
  NasState nas = NasState::Unknown;
  RrcSecState rrc_sec = RrcSecState::Off;
  NasSecState nas_sec = NasSecState::None;
  std::optional<SecAlg> rrc_alg;
  std::optional<SecAlg> nas_alg;
  LastMsg last;
  int64_t t_start = 0;                    // 항목을 연 줄의 t_ms
  int64_t t_last = 0;                     // 마지막 줄의 t_ms
  std::optional<int64_t> t_rrc_setup;     // RRCSetup 시각 (14_ §5.1 '응답 시각만 기록')
  std::optional<int64_t> t_reg_complete;  // RegistrationComplete 시각 (14_ §5.2 '완료 시각 기록')
  bool ever_connected = false;            // CONNECTED에 한 번이라도 닿았는지 — stale_setup 대상 판단 (14_ §4.2)
  // 망 수락을 한 번이라도 얻었나 (15_ §1.1 — RegistrationAccept·ServiceAccept·RRC SecurityModeCommand, 모두 DL). 닫힐 때
  // S-TMSI 이력 표 레코드의 accepted로 옮긴다 (14_ §3.2, 11/04 이슈 #74)
  bool ever_accepted = false;
  // S-TMSI를 어디서 알았나 (14_ §3.2 src): UE가 냄(RRCSetupRequest Part1·RRCSetupComplete·RegistrationRequest·ServiceRequest) /
  // 망이 줌(RegistrationAccept)
  bool s_tmsi_from_ue = false;
  bool s_tmsi_from_net = false;
  // 4단계가 쓰는 값 (14_ §2.2, 11/03) — 닫힐 때 이력 표 레코드로 옮긴다. 판정에는 룰이 쓴다(AN-04·AN-08)
  std::optional<std::string> est_cause;      // RRCSetupRequest의 f.est_cause
  std::optional<std::string> reg_type;       // 마지막 RegistrationRequest의 f.reg_type
  std::optional<std::string> id_type;        // 마지막 RegistrationRequest의 f.id_type
  std::optional<std::string> rel_req_cause;  // UEContextReleaseRequest(DU가 먼저 해제 요청)의 f.cause

  // 불확실 (14_ §4.3) — 한 번 붙으면 항목이 닫힐 때까지 남는다
  bool mid_join = false;
  bool loss = false;
  bool late = false;
  std::optional<int64_t> t_loss;          // 마지막 로스 창의 t_end_ms
  // 늦은 줄의 '없음' 판정 제외는 이때까지만 (14_ §4.3, 10/29 Q-57 해결 — 이슈 #46): 늦은 줄 t_ms + 등록된 2단계 룰의
  // 증거 지평 최댓값. 늦은 줄이 또 오면 늘어난다. 표시 late 자체는 닫힐 때까지 남는다(경보 ues[].uncertain)
  std::optional<int64_t> late_until;

  std::map<std::pair<Proto, std::string>, int64_t> cnt;  // (proto, msg)별 횟수 — 이 연결 안 (14_ §2.3)

  bool uncertain() const { return mid_join || loss || late; }
  // 마감 at의 '없음' 판정을 늦은 줄이 막는가 — 마감 < late_until일 때만 (14_ §4.3). 늦은 줄이 기다리던 응답 자체면 룰이
  // 이미 대기를 풀므로, 이것이 막는 것은 '마감을 처리한 뒤 늦게 온 응답'뿐이다
  bool late_blocks(int64_t at) const { return late && late_until && at < *late_until; }
  int64_t count(Proto proto, const std::string& msg) const;
};

// S-TMSI 이력 표의 연결 레코드 (14_ §3.2, 11/04 이슈 #74) — UE 항목이 닫힐 때 연결 1건 = 레코드 1개. 4단계 룰(AN-02·AN-04·
// AN-07·AN-08)이 '같은 S-TMSI의 지난 연결'을 읽는다. 열린 연결은 상태표·S-TMSI 색인(§3.1)에 있다
struct ConnRecord {
  std::optional<uint64_t> s_tmsi;   // 48비트 (알면)
  std::optional<uint64_t> part1;    // 39비트 — 48비트를 알면 그 하위 39비트, 아니면 RRCSetupRequest의 Part1
  bool src_ue = false;              // S-TMSI를 UE가 냈다
  bool src_net = false;             // 망이 RegistrationAccept로 줬다 — 둘 다면 src "both"
  UeKey key;                        // 닫힌 항목의 키 — 셀은 key.cell_id
  int64_t uid = 0;
  int64_t t_start = 0;              // 연 줄의 t_ms
  int64_t t_end = 0;                // 닫힌 데이터 시각
  CloseReason reason = CloseReason::Released;
  bool connected = false;           // CONNECTED에 닿았나 (ever_connected)
  RrcState rrc_last = RrcState::Unknown;  // 닫히기 직전 rrc·nas (INACTIVE였는지 포함)
  NasState nas_last = NasState::Unknown;
  bool accepted = false;            // 망 수락을 얻었나 (15_ §1.1)
  std::optional<std::string> est_cause;
  std::optional<std::string> reg_type;
  std::optional<std::string> id_type;
  std::optional<std::string> rel_req_cause;
  bool mid_join = false;            // 닫힐 때의 불확실 표시 — 불확실 연결도 넣되 표시를 남긴다 (§3.2, 결정 ④)
  bool loss = false;
  bool late = false;
  const char* src() const { return src_ue && src_net ? "both" : (src_net ? "net" : "ue"); }
};

// 최근 메시지 한 칸 (14_ §2.3 recent) — 받은 원본 줄 그대로, 증거용
struct RecentLine {
  int64_t seq = 0;
  int64_t t_ms = 0;
  std::string raw;
};

class UeTable {
 public:
  explicit UeTable(UeTableConfig cfg = {});

  // 닫힌 항목 하나 — 닫히기 직전의 상태와 이유. 최근 메시지는 상태표가 보관한다(recent(key, uid), 14_ §2.3)
  struct Closed {
    UeState last;
    CloseReason reason = CloseReason::Released;
  };

  // ue_evt 한 줄의 반영 결과 (14_ §7 ②~④). 갱신 후 상태(④)는 복사하지 않는다 — 살아 있는 항목 find(key)가 그 값이고,
  // 룰이 읽는 동안 표는 바뀌지 않으며 settle은 룰 뒤에 돈다(16_ W-20 — 이슈 #54). 갱신 전(③)만 1회 복사한다
  struct Applied {
    bool linked = true;          // false = du_ue_id가 null인 NGAP NAS 줄 — 항목에 붙이지 않았다
    bool opened = false;         // 이 줄로 새 항목을 열었다
    bool released = false;       // UEContextReleaseComplete — settle에서 released로 닫는다
    UeKey key;
    int64_t uid = 0;             // ④ 갱신된 항목의 uid — settle이 같은 항목인지 대조한다
    int64_t t_ms = 0;            // 이 줄의 t_ms — settle이 닫는 시각
    UeState before;              // ③ 갱신 전 (새 항목이면 연 직후의 처음 상태)
    std::vector<Closed> closed;  // ② 열면서 닫은 옛 항목 (reused·evicted)
    std::vector<Diag> diags;
  };

  // ②~④: 항목 찾기·열기 → 갱신 전 복사 → 전이·횟수·최근 메시지·색인. 새 항목이면 stale_setup 마감을 넣는다
  Applied apply(const UeEvt& e, int64_t seq, DeadlineQueue& dq);
  // ⑥·⑦: 룰이 이 줄을 본 뒤에 부른다 — superseded, UEContextReleaseComplete면 released
  std::vector<Closed> settle(const Applied& a, DeadlineQueue& dq);
  // 상태표 몫 마감(stale_setup·closed_recent)을 꺼냈을 때. 항목을 닫았으면 그 항목, 아니면 nullopt
  std::optional<Closed> on_deadline(const Deadline& d, DeadlineQueue& dq);
  // 그 셀에 로스 창이 났다 — 열린 항목에 loss와 마지막 로스 시각 (14_ §4.3)
  void mark_loss(int64_t cell, int64_t t_loss);
  // 유령 정리 (14_ §4.2 ghost_purge — 10/29 Q-56 해결, 이슈 #44). 그 셀 kpm2마다 로스 기록 뒤·마감 처리 앞에 부른다(§7).
  // M = si.RRC.ConnMax(없으면 ext.UeCtxMax, 둘 다 없으면 하지 않음), C = 그 셀 열린 항목 중 rrc가 CONNECTED·RELEASING인 수.
  // C > ⌊ghost_k × M⌋ + ghost_margin이 ghost_hold_ms 이상 이어지면 넘는 수만큼, 룰 몫 마감이 없는 항목을 t_last 오래된
  // 것부터 ghost_purge로 닫는다(recent 보관 안 함). 해제 줄을 로스로 놓친 유령은 이것 말고는 superseded·du_reset·
  // session_reset으로만 닫히고(du_ue_id가 재사용되지 않아 reused는 안 옴, Q-55), 표가 차면 새 항목부터 밀려 2단계가
  // 보이지 않게 되기 때문이다(16_ §3.1-1)
  struct Purged {
    std::vector<Closed> closed;
    std::vector<Diag> diags;
  };
  Purged purge_ghosts(const Kpm2& k, int64_t seq, DeadlineQueue& dq);
  // f1_evt — DU·CU 재시작으로 그 셀 항목(일부 Reset이면 그 UE만)을 du_reset으로 닫는다 (14_ §4.2). 이력 표 레코드의 만료
  // 마감을 넣으려고 마감 목록을 받는다 (14_ §3.2)
  std::vector<Closed> close_du(const F1Evt& f, DeadlineQueue& dq);
  // 새 세션 — 표·색인·셀별 수·S-TMSI 이력 표(연결 레코드·할당 기억)를 모두 비우고 uid를 1부터 다시 센다 (14_ §7 hello)
  void clear();

  // 읽기 — 룰과 테스트용
  const UeState* find(const UeKey& key) const;
  std::vector<const UeState*> by_s_tmsi(uint64_t s_tmsi) const;  // 48비트 색인 (14_ §3.1)
  std::vector<const UeState*> by_part1(uint64_t part1) const;    // Part1(하위 39비트) 색인 (14_ §3.1)
  const std::deque<RecentLine>* recent(const UeKey& key) const;
  // 그 UE (키, uid)의 최근 메시지 — 열린 항목이면 지금 것, 닫혔으면 보관분(14_ §2.3). 없거나 보관이 끝났으면 nullptr
  const std::deque<RecentLine>* recent(const UeKey& key, int64_t uid) const;
  std::size_t size() const { return entries_.size(); }
  std::size_t kept_size() const { return kept_.size(); }  // 보관 중인 닫힌 항목 recent 수

  // S-TMSI 이력 표 읽기 (14_ §3.2) — 룰은 읽기만 한다. history·history_part1: t_end ≥ since인 연결 레코드를 t_end 순으로
  // (같으면 넣은 순서). Part1 색인에는 48비트를 아는 레코드(그 하위 39비트)와 Part1만 아는 레코드가 함께 있다(§3.1과 같음).
  // allocated: 이 망이 RegistrationAccept로 그 S-TMSI를 준 마지막 시각 — 없으면 nullopt
  std::vector<const ConnRecord*> history(uint64_t s_tmsi, int64_t since) const;
  std::vector<const ConnRecord*> history_part1(uint64_t part1, int64_t since) const;
  std::optional<int64_t> allocated(uint64_t s_tmsi) const;
  std::size_t history_size() const { return records_.size(); }
  std::size_t alloc_size() const { return allocs_.size(); }

  // 닫힌 항목 recent 보관 시간 (14_ §1.1·§2.3) — Engine이 등록된 2단계 룰의 증거 지평 최댓값 + 여유로 정한다. 0이면 보관하지 않는다
  void set_recent_keep_ms(int64_t ms) { keep_ms_ = ms; }
  int64_t recent_keep_ms() const { return keep_ms_; }
  // 늦은 줄 제외 길이 (14_ §4.3 late_until) — Engine이 등록된 2단계 룰의 증거 지평 최댓값(여유 없이)으로 정한다 (이슈 #46)
  void set_late_horizon_ms(int64_t ms) { late_horizon_ms_ = ms; }
  int64_t late_horizon_ms() const { return late_horizon_ms_; }

  const UeTableConfig& config() const { return cfg_; }

  // 셀별 수 (진단·테스트용)
  struct CellCounts {
    int64_t evicted = 0;        // 14_ §4.4 ue_evicted — 룰이 창 안 증가분을 해제 보류·values.evicted에 쓴다(§6.3)
    int64_t ghost_purged = 0;   // 14_ §4.2 ghost_purge (이슈 #44)
    int64_t late = 0;           // 2_ §6.5 늦은 줄
    int64_t ngap_unlinked = 0;  // 14_ §7 잇지 못한 NGAP NAS
  };
  CellCounts counts(int64_t cell) const;

  static constexpr const char* kStaleTag = "stale_setup";
  static constexpr const char* kKeptTag = "closed_recent";
  static constexpr const char* kTombTag = "tomb";    // 연결 레코드 만료 (14_ §3.2·§6.1 표)
  static constexpr const char* kAllocTag = "alloc";  // 할당 기억 만료 (14_ §3.2)

 private:
  struct Entry {
    UeState st;
    std::deque<RecentLine> recent;
  };
  // 닫힌 항목의 recent 보관분 (14_ §2.3)
  struct Kept {
    std::deque<RecentLine> recent;
    uint64_t order = 0;     // 넣은 순서 — 상한을 넘으면 오래된 것부터 버린다
    int64_t closed_at = 0;  // 닫힌 데이터 시각 — 보관 끝 마감과 대조
  };
  using Iter = std::map<UeKey, Entry>::iterator;
  using UeId = std::pair<UeKey, int64_t>;  // (키, uid)

  // 닫기. t = 닫힌 데이터 시각. S-TMSI 이력 표에 연결 레코드를 넣고(만료 마감 포함), 보관 대상 이유면 recent를 보관한다
  Closed close(Iter it, CloseReason reason, int64_t t, DeadlineQueue& dq);
  // S-TMSI 이력 표 (14_ §3.2)
  void add_record(const UeState& last, CloseReason reason, int64_t t, DeadlineQueue& dq);
  void erase_record(uint64_t order);
  void add_alloc(uint64_t s_tmsi, const UeState& s, int64_t t, DeadlineQueue& dq);
  std::vector<const ConnRecord*> select(const std::map<uint64_t, std::vector<uint64_t>>& index, uint64_t v,
                                        int64_t since) const;
  void keep_recent(const UeState& last, std::deque<RecentLine> recent, int64_t t, DeadlineQueue& dq);
  // 밀어내기 후보 색인 (14_ §4.4, 이슈 #44): 무리 ①(CONNECTED 아님)·②(CONNECTED·불확실)·③(나머지)마다 (t_last, uid, 키) 순.
  // 보호 무리(룰 몫 마감·최근 줄)는 시각·마감에 따라 바뀌므로 색인에 넣지 않고 고를 때 건너뛴다
  using RankKey = std::tuple<int64_t, int64_t, UeKey>;
  static int rank_of(const UeState& s);
  void rank_insert(const UeState& s);
  void rank_erase(const UeState& s);
  Iter pick_victim(int64_t now, const DeadlineQueue& dq);
  void reindex(const UeKey& key, std::optional<uint64_t> old_s, std::optional<uint64_t> old_p1, const UeState& s);
  Deadline stale_deadline(const UeState& s) const;
  std::vector<const UeState*> lookup(const std::map<uint64_t, std::set<UeKey>>& index, uint64_t v) const;

  UeTableConfig cfg_;
  std::map<UeKey, Entry> entries_;
  std::map<uint64_t, std::set<UeKey>> by_s_tmsi_;  // 48비트 → 열린 키 (gNB 전체, 14_ §3.1)
  std::map<uint64_t, std::set<UeKey>> by_part1_;   // Part1 → 열린 키
  std::map<int64_t, CellCounts> counts_;
  int64_t next_uid_ = 1;
  std::map<UeId, Kept> kept_;
  std::map<uint64_t, UeId> kept_order_;  // 넣은 순서 → (키, uid)
  uint64_t next_kept_ = 0;
  int64_t keep_ms_ = 0;
  int64_t late_horizon_ms_ = 0;
  std::set<RankKey> ranks_[3];                  // 밀어내기 후보 색인 (14_ §4.4)
  std::map<int64_t, int64_t> ghost_over_since_;  // 셀 → CONNECTED 수가 문턱을 처음 넘은 kpm2의 t_start_ms (§4.2)

  // S-TMSI 이력 표 (14_ §3.2). 연결 레코드는 넣은 순서 번호로 두고, 48비트·Part1 색인은 (t_end, 순서)로 정렬한 번호 목록이다.
  // 할당 기억은 S-TMSI → 마지막 할당 시각·셀, 만료 마감에 S-TMSI를 실을 수 없어 (키, uid, 시각) → S-TMSI로 찾는다
  struct Alloc {
    int64_t t = 0;
    int64_t cell = 0;
    uint64_t order = 0;
  };
  std::map<uint64_t, ConnRecord> records_;                     // 순서 번호 → 레코드 (상한을 넘으면 앞에서부터 버린다)
  std::map<UeId, uint64_t> record_of_;                         // (키, uid) → 순서 번호 — 만료 마감과 대조
  std::map<uint64_t, std::vector<uint64_t>> hist_s_tmsi_;      // 48비트 → 레코드 번호 (t_end 순)
  std::map<uint64_t, std::vector<uint64_t>> hist_part1_;       // Part1 → 레코드 번호 (t_end 순)
  uint64_t next_record_ = 0;
  std::map<uint64_t, Alloc> allocs_;                           // S-TMSI → 마지막 할당
  std::map<uint64_t, uint64_t> alloc_order_;                   // 할당 순서 → S-TMSI (상한)
  std::map<std::tuple<UeKey, int64_t, int64_t>, uint64_t> alloc_due_;  // (키, uid, 할당 시각) → S-TMSI (만료 마감과 대조)
  uint64_t next_alloc_ = 0;
};

}  // namespace detect
