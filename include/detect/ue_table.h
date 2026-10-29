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

// 항목이 닫힌 이유 (14_ §4.2)
enum class CloseReason { Released, Reused, StaleSetup, Superseded, DuReset, Evicted, SessionReset };
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

  // 닫힌 항목 하나 — 닫히기 직전의 상태·최근 메시지와 이유
  struct Closed {
    UeState last;
    std::deque<RecentLine> recent;
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
  std::vector<Closed> settle(const Applied& a);
  // 상태표 몫 마감(stale_setup)을 꺼냈을 때. 닫았으면 그 항목, 아니면 nullopt(필요하면 마감을 다시 넣는다)
  std::optional<Closed> on_deadline(const Deadline& d, DeadlineQueue& dq);
  // 그 셀에 로스 창이 났다 — 열린 항목에 loss와 마지막 로스 시각 (14_ §4.3)
  void mark_loss(int64_t cell, int64_t t_loss);
  // f1_evt — DU·CU 재시작으로 그 셀 항목(일부 Reset이면 그 UE만)을 du_reset으로 닫는다 (14_ §4.2)
  std::vector<Closed> close_du(const F1Evt& f);
  // 새 세션 — 표·색인·셀별 수를 모두 비우고 uid를 1부터 다시 센다 (14_ §7 hello)
  void clear();

  // 읽기 — 룰과 테스트용
  const UeState* find(const UeKey& key) const;
  std::vector<const UeState*> by_s_tmsi(uint64_t s_tmsi) const;  // 48비트 색인 (14_ §3.1)
  std::vector<const UeState*> by_part1(uint64_t part1) const;    // Part1(하위 39비트) 색인 (14_ §3.1)
  const std::deque<RecentLine>* recent(const UeKey& key) const;
  std::size_t size() const { return entries_.size(); }

  // 셀별 수 (진단·테스트용)
  struct CellCounts {
    int64_t evicted = 0;        // 14_ §4.4 ue_evicted
    int64_t late = 0;           // 2_ §6.5 늦은 줄
    int64_t ngap_unlinked = 0;  // 14_ §7 잇지 못한 NGAP NAS
  };
  CellCounts counts(int64_t cell) const;

  static constexpr const char* kStaleTag = "stale_setup";

 private:
  struct Entry {
    UeState st;
    std::deque<RecentLine> recent;
  };
  using Iter = std::map<UeKey, Entry>::iterator;

  Closed close(Iter it, CloseReason reason);
  Iter pick_victim();
  void reindex(const UeKey& key, std::optional<uint64_t> old_s, std::optional<uint64_t> old_p1, const UeState& s);
  Deadline stale_deadline(const UeState& s) const;
  std::vector<const UeState*> lookup(const std::map<uint64_t, std::set<UeKey>>& index, uint64_t v) const;

  UeTableConfig cfg_;
  std::map<UeKey, Entry> entries_;
  std::map<uint64_t, std::set<UeKey>> by_s_tmsi_;  // 48비트 → 열린 키 (gNB 전체, 14_ §3.1)
  std::map<uint64_t, std::set<UeKey>> by_part1_;   // Part1 → 열린 키
  std::map<int64_t, CellCounts> counts_;
  int64_t next_uid_ = 1;
};

}  // namespace detect
