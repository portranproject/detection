#pragma once
// S-TMSI 이력 표 (14_ §3.2 — 연결 레코드·할당 기억, 11/03 확인 지점 ⑤ 사용자 확정, 11/04 M9 이슈 #74). UE 상태표(ue_table)에서
// 파일만 분리했다 (11/05 26_ R5, 이슈 #98) — 상태표가 항목을 닫을 때 레코드를 넣고(record), RegistrationAccept 때 할당을 적으며
// (allocate), 표 몫 마감(tomb·alloc)으로 지운다. 4단계 룰(AN-02·AN-04·AN-07·AN-08)은 UeTable의 history()·allocated()로 읽기만
// 한다 — 공개 API는 UeTable이 그대로 내주므로 룰·테스트는 이 헤더를 모른다

#include "detect/ue_table.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <tuple>
#include <utility>
#include <vector>

namespace detect {

// Part1 = 48비트 S-TMSI의 하위 39비트 (14_ §3.1)
inline constexpr uint64_t kStmsiPart1Mask = (uint64_t{1} << 39) - 1;

class StmsiHistory {
 public:
  static constexpr const char* kTombTag = "tomb";    // 연결 레코드 만료 (14_ §3.2·§6.1 표)
  static constexpr const char* kAllocTag = "alloc";  // 할당 기억 만료 (14_ §3.2)

  // tomb_ms·tomb_max = 연결 레코드 보관 시간·상한, alloc_ms·alloc_max = 할당 기억 보관 시간·상한 (14_ §9 ue_table.tomb_*·alloc_*)
  StmsiHistory(int64_t tomb_ms, std::size_t tomb_max, int64_t alloc_ms, std::size_t alloc_max);

  // 연결 레코드 (14_ §3.2): 항목이 닫힐 때 연결 1건 = 레코드 1개. part1 = 그 항목의 Part1(48비트를 알면 그 하위 39비트, 아니면
  // RRCSetupRequest의 Part1) — 둘 다 모르면 넣지 않는다. 닫힌 시각 t + tomb_ms에 표 몫 마감 tomb으로 지운다
  void record(const UeState& last, std::optional<uint64_t> part1, CloseReason reason, int64_t t, DeadlineQueue& dq);
  // 할당 기억 (14_ §3.2): RegistrationAccept의 f.s_tmsi → 마지막 할당 시각·셀. t + alloc_ms에 표 몫 마감 alloc으로 지운다
  void allocate(uint64_t s_tmsi, const UeState& s, int64_t t, DeadlineQueue& dq);
  // 표 몫 마감 (14_ §6.1 표): tomb·alloc이면 처리하고 true, 아니면 false(상태표의 다른 마감)
  bool on_deadline(const Deadline& d);
  void clear();  // 새 hello·session_reset (14_ §3.2 — du_reset은 비우지 않는다)

  // 읽기 (14_ §3.2) — history·history_part1: t_end ≥ since인 연결 레코드를 t_end 순으로(같으면 넣은 순서). Part1 색인에는 48비트를
  // 아는 레코드(그 하위 39비트)와 Part1만 아는 레코드가 함께 있다(§3.1과 같음). allocated: 이 망이 그 S-TMSI를 준 마지막 시각
  std::vector<const ConnRecord*> history(uint64_t s_tmsi, int64_t since) const;
  std::vector<const ConnRecord*> history_part1(uint64_t part1, int64_t since) const;
  std::optional<int64_t> allocated(uint64_t s_tmsi) const;
  // Part1만 아는 연결용 — 하위 39비트가 같은 할당 가운데 가장 최근 시각. 식별 요청 줄에서만 불려 선형으로 찾는다
  std::optional<int64_t> allocated_part1(uint64_t part1) const;
  std::size_t history_size() const { return records_.size(); }
  std::size_t alloc_size() const { return allocs_.size(); }

 private:
  using UeId = std::pair<UeKey, int64_t>;  // (키, uid)
  // 할당 기억 한 칸 — S-TMSI → 마지막 할당 시각·셀. 만료 마감에 S-TMSI를 실을 수 없어 (키, uid, 시각) → S-TMSI로 찾는다
  struct Alloc {
    int64_t t = 0;
    int64_t cell = 0;
    uint64_t order = 0;
  };

  void erase_record(uint64_t order);
  std::vector<const ConnRecord*> select(const std::map<uint64_t, std::vector<uint64_t>>& index, uint64_t v,
                                        int64_t since) const;

  int64_t tomb_ms_;
  std::size_t tomb_max_;
  int64_t alloc_ms_;
  std::size_t alloc_max_;
  // 연결 레코드는 넣은 순서 번호로 두고, 48비트·Part1 색인은 (t_end, 순서)로 정렬한 번호 목록이다
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
