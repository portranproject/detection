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

  // 불확실 (14_ §4.3) — 한 번 붙으면 항목이 닫힐 때까지 남는다
  bool mid_join = false;
  bool loss = false;
  bool late = false;
  std::optional<int64_t> t_loss;          // 마지막 로스 창의 t_end_ms

  std::map<std::pair<Proto, std::string>, int64_t> cnt;  // (proto, msg)별 횟수 — 이 연결 안 (14_ §2.3)

  bool uncertain() const { return mid_join || loss || late; }
  int64_t count(Proto proto, const std::string& msg) const;
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

  // ue_evt 한 줄의 반영 결과 (14_ §7 ②~④)
  struct Applied {
    bool linked = true;          // false = du_ue_id가 null인 NGAP NAS 줄 — 항목에 붙이지 않았다
    bool opened = false;         // 이 줄로 새 항목을 열었다
    bool released = false;       // UEContextReleaseComplete — settle에서 released로 닫는다
    UeKey key;
    UeState before;              // ③ 갱신 전 (새 항목이면 연 직후의 처음 상태)
    UeState after;               // ④ 갱신 후
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
  Purged purge_ghosts(const Kpm2& k, int64_t seq, const DeadlineQueue& dq);
  // f1_evt — DU·CU 재시작으로 그 셀 항목(일부 Reset이면 그 UE만)을 du_reset으로 닫는다 (14_ §4.2)
  std::vector<Closed> close_du(const F1Evt& f);
  // 새 세션 — 표·색인·셀별 수를 모두 비우고 uid를 1부터 다시 센다 (14_ §7 hello)
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

  // 닫힌 항목 recent 보관 시간 (14_ §1.1·§2.3) — Engine이 등록된 2단계 룰의 증거 지평 최댓값 + 여유로 정한다. 0이면 보관하지 않는다
  void set_recent_keep_ms(int64_t ms) { keep_ms_ = ms; }
  int64_t recent_keep_ms() const { return keep_ms_; }

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

  // 닫기. t = 닫힌 데이터 시각, dq가 있으면 보관 대상 이유의 recent를 보관한다
  Closed close(Iter it, CloseReason reason, int64_t t, DeadlineQueue* dq);
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
  std::set<RankKey> ranks_[3];                  // 밀어내기 후보 색인 (14_ §4.4)
  std::map<int64_t, int64_t> ghost_over_since_;  // 셀 → CONNECTED 수가 문턱을 처음 넘은 kpm2의 t_start_ms (§4.2)
};

}  // namespace detect
