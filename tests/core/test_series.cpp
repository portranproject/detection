// series 단위 테스트 (4_ §4-1) — 세션·seq·hello 규칙(2_ §2·§3), 셀별 연속성(2_ §4.1, 3_ §8), 윈도우(3_ §3)
#include "detect/series.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <string>

using namespace detect;

namespace {

constexpr int64_t kT0 = 1792209000000;  // 구간 시작 기준 시각
constexpr int64_t kP = 100;

std::string hello_line(const std::string& session, int64_t seq, int64_t period = kP, int64_t t_nr = 1000,
                       const std::string& cells = R"([{"cell_id":1,"max_conn":null}])") {
  return R"({"type":"hello","ver":1,"session":")" + session + R"(","seq":)" + std::to_string(seq) +
         R"(,"cells":)" + cells + R"(,"period_ms":)" + std::to_string(period) +
         R"(,"noreply_timeout_ms":)" + std::to_string(t_nr) + R"(,"si_sample_ms":)" + std::to_string(period) +
         R"(,"clock":"realtime"})";
}

// 칸 번호 n(0부터)의 kpm2 한 줄: [kT0 + n·P, kT0 + (n+1)·P)
std::string kpm_line(const std::string& session, int64_t seq, int64_t cell, int64_t n, int64_t att, int64_t succ,
                     int64_t noreply, int64_t len = kP) {
  const int64_t ts = kT0 + n * kP;
  return R"({"type":"kpm2","ver":1,"session":")" + session + R"(","seq":)" + std::to_string(seq) +
         R"(,"cell_id":)" + std::to_string(cell) + R"(,"t_start_ms":)" + std::to_string(ts) +
         R"(,"t_end_ms":)" + std::to_string(ts + len) + R"(,"cc":{"RRC.ConnEstabAtt":{"total":)" +
         std::to_string(att) + R"(},"RRC.ConnEstabSucc":{"total":)" + std::to_string(succ) +
         R"(},"RRC.ConnEstabFailCause":{"NetworkReject":0,"NoReply":)" + std::to_string(noreply) +
         R"(,"Other":0}}})";
}

FeedResult feed(Series& s, const std::string& line) { return s.feed(parse_line(line)); }

bool has_diag(const FeedResult& r, DiagKind k) {
  return std::any_of(r.diags.begin(), r.diags.end(), [&](const Diag& d) { return d.kind == k; });
}

Count get_att(const Kpm2& k) { return k.conn_estab_att.total; }
Count get_succ(const Kpm2& k) { return k.conn_estab_succ.total; }
Count get_noreply(const Kpm2& k) { return k.fail_no_reply; }

// hello 후 셀 1에 칸 0..n-1을 넣는다. seq는 2부터. 반환값 = 다음 seq
int64_t fill(Series& s, int64_t n, int64_t att = 1, int64_t succ = 1, int64_t noreply = 0, int64_t cell = 1,
             int64_t seq = 2, int64_t first = 0) {
  for (int64_t i = first; i < first + n; ++i) {
    auto r = feed(s, kpm_line("s1", seq++, cell, i, att, succ, noreply));
    EXPECT_EQ(r.outcome, FeedOutcome::Stored);
  }
  return seq;
}

}  // namespace

// ---- 버퍼 크기 (3_ §3·§7.1) ----

TEST(Series, BufferSlots) {
  EXPECT_EQ(buffer_slots(1000, 100, 1000), 21u);  // W/P 10 + D 10 + 1
  EXPECT_EQ(buffer_slots(1000, 100, 1000, 300), 300u);
  EXPECT_EQ(buffer_slots(1000, 100, 1000, 5), 21u);
  EXPECT_EQ(buffer_slots(1000, 100, 1050), 22u);  // D = ⌈1050/100⌉ = 11
}

// ---- hello 규칙·session (2_ §3) ----

TEST(Series, KpmBeforeHelloDropped) {
  Series s;
  auto r = feed(s, kpm_line("s1", 1, 1, 0, 1, 1, 0));
  EXPECT_EQ(r.outcome, FeedOutcome::Dropped);
  EXPECT_TRUE(has_diag(r, DiagKind::KpmBeforeHello));
  EXPECT_FALSE(s.active());
}

TEST(Series, FirstHelloStartsSession) {
  Series s;
  auto r = feed(s, hello_line("s1", 1));
  EXPECT_EQ(r.outcome, FeedOutcome::SessionStarted);
  EXPECT_TRUE(s.active());
  EXPECT_EQ(s.session(), "s1");
  EXPECT_EQ(s.slot_capacity(), 21u);
  fill(s, 3);
  ASSERT_NE(s.cell(1), nullptr);
  EXPECT_EQ(s.cell(1)->size(), 3u);
}

TEST(Series, NewSessionResets) {
  Series s;
  feed(s, hello_line("s1", 1));
  fill(s, 5);
  auto r = feed(s, hello_line("s2", 1));
  EXPECT_EQ(r.outcome, FeedOutcome::SessionReset);
  EXPECT_TRUE(has_diag(r, DiagKind::SessionReset));
  EXPECT_EQ(s.session(), "s2");
  EXPECT_EQ(s.cell(1), nullptr);  // 버퍼 초기화
  // 새 session은 seq가 1부터 다시 시작해도 된다
  EXPECT_EQ(feed(s, kpm_line("s2", 2, 1, 50, 1, 1, 0)).outcome, FeedOutcome::Stored);
}

TEST(Series, SameSessionSameParamsKeepsState) {
  Series s;
  feed(s, hello_line("s1", 1));
  int64_t seq = fill(s, 5);
  auto r = feed(s, hello_line("s1", seq++));
  EXPECT_EQ(r.outcome, FeedOutcome::SessionResumed);
  ASSERT_NE(s.cell(1), nullptr);
  EXPECT_EQ(s.cell(1)->size(), 5u);
  EXPECT_EQ(feed(s, kpm_line("s1", seq, 1, 5, 1, 1, 0)).outcome, FeedOutcome::Stored);
}

TEST(Series, SameSessionCellOrderDoesNotMatter) {
  Series s;
  const std::string a = R"([{"cell_id":1,"max_conn":null},{"cell_id":2,"max_conn":96}])";
  const std::string b = R"([{"cell_id":2,"max_conn":96},{"cell_id":1,"max_conn":null}])";
  feed(s, hello_line("s1", 1, kP, 1000, a));
  EXPECT_EQ(feed(s, hello_line("s1", 2, kP, 1000, b)).outcome, FeedOutcome::SessionResumed);
}

TEST(Series, SameSessionChangedParamsResets) {
  struct Case {
    std::string hello;
  };
  const Case cases[] = {
      {hello_line("s1", 7, 200)},                                   // period_ms
      {hello_line("s1", 7, kP, 2000)},                              // noreply_timeout_ms
      {hello_line("s1", 7, kP, 1000, R"([{"cell_id":1,"max_conn":96}])")},  // cells
      {R"({"type":"hello","ver":1,"session":"s1","seq":7,"cells":[{"cell_id":1,"max_conn":null}],"period_ms":100,"noreply_timeout_ms":1000,"si_sample_ms":10,"clock":"realtime"})"},  // si_sample_ms
  };
  for (const auto& c : cases) {
    Series s;
    feed(s, hello_line("s1", 1));
    fill(s, 5);
    auto r = feed(s, c.hello);
    EXPECT_EQ(r.outcome, FeedOutcome::SessionReset) << c.hello;
    EXPECT_EQ(s.cell(1), nullptr) << c.hello;
  }
}

// 결정 D4: 다른 session의 kpm2는 버리고, 초기화는 하지 않는다
TEST(Series, ForeignSessionKpmDropped) {
  Series s;
  feed(s, hello_line("s1", 1));
  fill(s, 3);
  auto r = feed(s, kpm_line("other", 10, 1, 3, 1, 1, 0));
  EXPECT_EQ(r.outcome, FeedOutcome::Dropped);
  EXPECT_TRUE(has_diag(r, DiagKind::ForeignSession));
  EXPECT_EQ(s.session(), "s1");
  EXPECT_EQ(s.cell(1)->size(), 3u);
}

TEST(Series, BadLinesProduceDiagnostics) {
  Series s;
  feed(s, hello_line("s1", 1));
  EXPECT_TRUE(has_diag(feed(s, "garbage"), DiagKind::FormatError));
  auto v2 = feed(s, R"({"type":"kpm2","ver":2,"session":"s1","seq":2,"cell_id":1})");
  EXPECT_EQ(v2.outcome, FeedOutcome::Dropped);
  EXPECT_TRUE(has_diag(v2, DiagKind::UnsupportedVersion));
  auto u = feed(s, R"({"type":"future","ver":1,"session":"s1","seq":3})");  // ver=2 줄이 seq 2를 소비했다 (W-1)
  EXPECT_EQ(u.outcome, FeedOutcome::Ignored);
  EXPECT_TRUE(u.diags.empty());
}

// ---- seq (2_ §2) ----

// ver 불일치 줄도 같은 session이면 seq를 소비한다 — 다음 줄에서 거짓 seq 건너뜀 로그가 나지 않게 (2_ §2, 10/27 이슈 #13 W-1)
TEST(Series, UnsupportedVersionConsumesSeq) {
  Series s;
  feed(s, hello_line("s1", 1));
  auto v2 = feed(s, R"({"type":"kpm2","ver":2,"session":"s1","seq":2,"cell_id":1})");
  EXPECT_EQ(v2.outcome, FeedOutcome::Dropped);
  EXPECT_TRUE(has_diag(v2, DiagKind::UnsupportedVersion));
  auto r = feed(s, kpm_line("s1", 3, 1, 0, 1, 1, 0));
  EXPECT_EQ(r.outcome, FeedOutcome::Stored);
  EXPECT_FALSE(has_diag(r, DiagKind::SeqGap));
  // 다른 session의 ver 불일치 줄은 번호열에 넣지 않는다
  feed(s, R"({"type":"kpm2","ver":2,"session":"other","seq":99,"cell_id":1})");
  auto r2 = feed(s, kpm_line("s1", 4, 1, 1, 1, 1, 0));
  EXPECT_FALSE(has_diag(r2, DiagKind::SeqGap));
  EXPECT_FALSE(has_diag(r2, DiagKind::SeqRegress));
}


TEST(Series, SeqGapIsLoggedButProcessed) {
  Series s;
  feed(s, hello_line("s1", 1));
  feed(s, kpm_line("s1", 2, 1, 0, 1, 1, 0));
  auto r = feed(s, kpm_line("s1", 5, 1, 1, 1, 1, 0));
  EXPECT_EQ(r.outcome, FeedOutcome::Stored);
  EXPECT_TRUE(has_diag(r, DiagKind::SeqGap));
  EXPECT_FALSE(r.gap);  // seq 건너뜀만으로는 셀 끊김이 아니다
}

// 모르는 type·ue_evt도 seq 번호열을 함께 쓰므로 건너뜀으로 잡히면 안 된다
TEST(Series, SeqSharedAcrossTypes) {
  Series s;
  feed(s, hello_line("s1", 1));
  feed(s, kpm_line("s1", 2, 1, 0, 1, 1, 0));
  EXPECT_EQ(feed(s, R"({"type":"ue_evt","ver":1,"session":"s1","seq":3})").outcome, FeedOutcome::Ignored);
  auto r = feed(s, kpm_line("s1", 4, 1, 1, 1, 1, 0));
  EXPECT_FALSE(has_diag(r, DiagKind::SeqGap));
}

// 결정 D5: seq 중복·역행은 버림
TEST(Series, SeqRegressDropped) {
  Series s;
  feed(s, hello_line("s1", 1));
  feed(s, kpm_line("s1", 2, 1, 0, 1, 1, 0));
  feed(s, kpm_line("s1", 3, 1, 1, 1, 1, 0));
  auto dup = feed(s, kpm_line("s1", 3, 1, 2, 1, 1, 0));
  EXPECT_EQ(dup.outcome, FeedOutcome::Dropped);
  EXPECT_TRUE(has_diag(dup, DiagKind::SeqRegress));
  auto back = feed(s, kpm_line("s1", 2, 1, 2, 1, 1, 0));
  EXPECT_EQ(back.outcome, FeedOutcome::Dropped);
  EXPECT_EQ(s.cell(1)->size(), 2u);
}

// ---- 셀 연속성 (2_ §4.1, 3_ §8) ----

TEST(Series, ContinuousSlotsNoGap) {
  Series s;
  feed(s, hello_line("s1", 1));
  for (int64_t i = 0; i < 5; ++i) {
    auto r = feed(s, kpm_line("s1", 2 + i, 1, i, 1, 1, 0));
    EXPECT_FALSE(r.gap);
    EXPECT_FALSE(has_diag(r, DiagKind::CellGap));
  }
}

TEST(Series, GapDetected) {
  Series s;
  feed(s, hello_line("s1", 1));
  fill(s, 3);  // 칸 0..2, seq 2..4
  auto r = feed(s, kpm_line("s1", 5, 1, 5, 1, 1, 0));  // 칸 3·4 빠짐
  EXPECT_EQ(r.outcome, FeedOutcome::Stored);
  ASSERT_TRUE(r.gap);
  EXPECT_EQ(r.gap->cell_id, 1);
  EXPECT_EQ(r.gap->t_from, kT0 + 3 * kP);
  EXPECT_EQ(r.gap->t_to, kT0 + 5 * kP);
  EXPECT_EQ(r.gap->seq_before, 4);
  EXPECT_EQ(r.gap->seq_after, 5);
  EXPECT_TRUE(has_diag(r, DiagKind::CellGap));
}

// 결정 D6: 겹침·역행은 버림
TEST(Series, OverlapDropped) {
  Series s;
  feed(s, hello_line("s1", 1));
  fill(s, 3);
  auto r = feed(s, kpm_line("s1", 5, 1, 1, 1, 1, 0));
  EXPECT_EQ(r.outcome, FeedOutcome::Dropped);
  EXPECT_TRUE(has_diag(r, DiagKind::CellOverlap));
  EXPECT_EQ(s.cell(1)->size(), 3u);
}

TEST(Series, PeriodMismatchWarnsButStores) {
  Series s;
  feed(s, hello_line("s1", 1));
  auto r = feed(s, kpm_line("s1", 2, 1, 0, 1, 1, 0, 150));
  EXPECT_EQ(r.outcome, FeedOutcome::Stored);
  EXPECT_TRUE(has_diag(r, DiagKind::PeriodMismatch));
}

// 결정 D7: hello에 없는 셀은 받되 경고, 상한을 넘으면 버림
TEST(Series, UnknownCellAndCellLimit) {
  SeriesConfig cfg;
  cfg.max_cells = 2;
  Series s(cfg);
  feed(s, hello_line("s1", 1));
  EXPECT_FALSE(has_diag(feed(s, kpm_line("s1", 2, 1, 0, 1, 1, 0)), DiagKind::CellUnknown));
  auto r2 = feed(s, kpm_line("s1", 3, 2, 0, 1, 1, 0));
  EXPECT_EQ(r2.outcome, FeedOutcome::Stored);
  EXPECT_TRUE(has_diag(r2, DiagKind::CellUnknown));
  EXPECT_FALSE(has_diag(feed(s, kpm_line("s1", 4, 2, 1, 1, 1, 0)), DiagKind::CellUnknown));  // 셀마다 1회
  auto r3 = feed(s, kpm_line("s1", 5, 3, 0, 1, 1, 0));
  EXPECT_EQ(r3.outcome, FeedOutcome::Dropped);
  EXPECT_TRUE(has_diag(r3, DiagKind::CellLimit));
  EXPECT_EQ(s.cell_ids().size(), 2u);
}

// ---- 링버퍼·윈도우 (3_ §3) ----

TEST(Series, RingBufferOverwritesOldest) {
  Series s;
  feed(s, hello_line("s1", 1));
  fill(s, 30);  // 용량 21
  const CellSeries* c = s.cell(1);
  EXPECT_EQ(c->size(), 21u);
  EXPECT_EQ(c->at(0).kpm.t_start_ms, kT0 + 9 * kP);  // 칸 0..8은 덮어써짐
  EXPECT_EQ(c->back().kpm.t_start_ms, kT0 + 29 * kP);
  // 버퍼보다 오래된 윈도우는 불완전
  EXPECT_FALSE(c->window_sum(kT0, kT0 + 10 * kP, get_att));
  EXPECT_TRUE(c->window_sum(kT0 + 20 * kP, kT0 + 30 * kP, get_att));
}

// 3_ §3의 A·F 윈도우: A = [t−W−D·P, t−D·P), F = [t−W, t)
TEST(Series, ShiftedWindows) {
  Series s;
  feed(s, hello_line("s1", 1));
  int64_t seq = fill(s, 10, /*att=*/3, /*succ=*/0, /*noreply=*/0);                    // 칸 0..9: 공격 시도
  fill(s, 10, /*att=*/0, /*succ=*/0, /*noreply=*/3, 1, seq, /*first=*/10);           // 칸 10..19: NoReply 확정
  const CellSeries* c = s.cell(1);
  const int64_t t = kT0 + 20 * kP;  // 현재 구간 끝
  const int64_t W = 1000, D = 10;
  EXPECT_EQ(c->window_sum(t - W - D * kP, t - D * kP, get_att), 30);
  EXPECT_EQ(c->window_sum(t - W, t, get_noreply), 30);
  EXPECT_EQ(c->window_sum(t - W, t, get_att), 0);  // A′ (시차 없음)
}

// 2_ §4.5·3_ §8: 한 칸에 A만 없으면 A 합만 불완전
TEST(Series, MissingFieldMakesOnlyThatSumIncomplete) {
  Series s;
  feed(s, hello_line("s1", 1));
  int64_t seq = fill(s, 4);
  feed(s, R"({"type":"kpm2","ver":1,"session":"s1","seq":)" + std::to_string(seq++) +
              R"(,"cell_id":1,"t_start_ms":)" + std::to_string(kT0 + 4 * kP) + R"(,"t_end_ms":)" +
              std::to_string(kT0 + 5 * kP) + R"(,"cc":{"RRC.ConnEstabSucc":{"total":1}}})");
  fill(s, 5, 1, 1, 0, 1, seq, 5);
  const CellSeries* c = s.cell(1);
  EXPECT_FALSE(c->window_sum(kT0, kT0 + 10 * kP, get_att));
  EXPECT_EQ(c->window_sum(kT0, kT0 + 10 * kP, get_succ), 10);
  EXPECT_EQ(c->window_sum(kT0 + 5 * kP, kT0 + 10 * kP, get_att), 5);
}

// 3_ §8: 끊김이 걸린 동안 불완전, W/P + D칸이 지나면 다시 완전
TEST(Series, GapWindowRecovers) {
  Series s;
  feed(s, hello_line("s1", 1));
  int64_t seq = fill(s, 10);               // 칸 0..9
  seq = fill(s, 19, 1, 1, 0, 1, seq, 11);  // 칸 10 빠짐, 칸 11..29
  const CellSeries* c = s.cell(1);
  // 현재 구간 끝 t에서 [t−W−D·P, t) = A·F·A′ 윈도우를 모두 덮는 범위(20칸)
  auto window_ok = [&]() {
    const int64_t t = c->back().kpm.t_end_ms;
    return c->window_sum(t - 2000, t, get_att).has_value();
  };
  EXPECT_FALSE(window_ok());        // 칸 [10, 30) — 빠진 칸 10 포함
  fill(s, 1, 1, 1, 0, 1, seq, 30);  // 칸 30 → 칸 [11, 31)
  EXPECT_TRUE(window_ok());
}

// D8: 칸이 윈도우 경계에 일부만 걸리면 불완전
TEST(Series, PartialOverlapIncomplete) {
  Series s;
  feed(s, hello_line("s1", 1));
  fill(s, 5);
  const CellSeries* c = s.cell(1);
  EXPECT_FALSE(c->window_sum(kT0 + 50, kT0 + 300, get_att));
  EXPECT_EQ(c->window_sum(kT0 + 100, kT0 + 300, get_att), 2);
}

// T21 바탕: 한 셀의 끊김은 다른 셀에 영향 없음
TEST(Series, GapIsPerCell) {
  Series s;
  feed(s, hello_line("s1", 1, kP, 1000, R"([{"cell_id":1},{"cell_id":2}])"));
  int64_t seq = 2;
  for (int64_t i = 0; i < 20; ++i) {
    feed(s, kpm_line("s1", seq++, 1, i, 1, 1, 0));
    if (i != 7) {
      auto r = feed(s, kpm_line("s1", seq++, 2, i, 1, 1, 0));
      if (i == 8) {
        EXPECT_TRUE(r.gap);
      }
    }
  }
  const int64_t t = kT0 + 20 * kP;
  EXPECT_EQ(s.cell(1)->window_sum(t - 2000, t, get_att), 20);
  EXPECT_FALSE(s.cell(2)->window_sum(t - 2000, t, get_att));
}

// 3_ §7.1: 버퍼 칸은 받은 원본 줄을 그대로 보관
TEST(Series, SlotKeepsRawLine) {
  Series s;
  feed(s, hello_line("s1", 1));
  const std::string line = kpm_line("s1", 2, 1, 0, 4, 1, 0);
  feed(s, line);
  EXPECT_EQ(s.cell(1)->back().kpm.raw, line);
  EXPECT_EQ(s.cell(1)->back().seq, 2);
}

// ---- 입력 건전성 (Q-46 — 룰에서 옮겨 옴, 3_ §3·§8) ----

// 3_ §8 H_hold: 보류가 H_hold를 넘으면 input_lost, 이 칸 이전 버퍼를 비우고 연속성 기준은 남는다
TEST(Series, InputLostAfterHholdDropsBuffer) {
  Series s;
  feed(s, hello_line("s1", 1));
  int64_t seq = fill(s, 5);
  auto r = feed(s, kpm_line("s1", seq++, 1, 200, 1, 1, 0));  // 19.5 s 끊김 > H_hold 10 s
  ASSERT_TRUE(r.gap);
  EXPECT_TRUE(r.hold);
  EXPECT_TRUE(r.input_lost);
  EXPECT_EQ(s.cell(1)->size(), 1u);
  auto n = feed(s, kpm_line("s1", seq, 1, 201, 1, 1, 0));
  EXPECT_FALSE(n.gap);
  EXPECT_TRUE(n.hold);  // 윈도우가 다시 찰 때까지 보류
  EXPECT_FALSE(n.input_lost);
}

// 짧은 끊김(< H_hold)은 보류만 — input_lost 아님, 버퍼 유지
TEST(Series, ShortGapHoldsWithoutInputLost) {
  Series s;
  feed(s, hello_line("s1", 1));
  int64_t seq = fill(s, 25);  // 윈도우가 찬 상태
  EXPECT_FALSE(feed(s, kpm_line("s1", seq++, 1, 25, 1, 1, 0)).hold);
  auto r = feed(s, kpm_line("s1", seq++, 1, 27, 1, 1, 0));  // 칸 26 유실 (0.1 s)
  EXPECT_TRUE(r.gap);
  EXPECT_TRUE(r.hold);
  EXPECT_FALSE(r.input_lost);
  EXPECT_GT(s.cell(1)->size(), 1u);
}

// 윈도우가 다 차기 전(W/P + D칸)은 보류, 20칸째부터 표준 합계가 채워진다 (3_ §3·§8)
TEST(Series, HoldUntilStandardWindowsFull) {
  Series s;
  feed(s, hello_line("s1", 1));
  int64_t seq = 2;
  for (int64_t i = 0; i < 19; ++i) EXPECT_TRUE(feed(s, kpm_line("s1", seq++, 1, i, 2, 1, 1)).hold);
  auto r = feed(s, kpm_line("s1", seq++, 1, 19, 2, 1, 1));
  EXPECT_FALSE(r.hold);
  EXPECT_EQ(r.sums.a_w, 20);  // A 윈도우 [0, 1000) = 칸 0..9
  EXPECT_EQ(r.sums.f_w, 10);  // F 윈도우 [1000, 2000) = 칸 10..19
  EXPECT_EQ(r.sums.a2_w, 20);
  EXPECT_EQ(r.sums.s2_w, 10);
}

// 필수 키 A·S 누락 (3_ §8): 연속 10칸을 넘으면 비활성 진단, 다시 들어오면 재개 진단. 누락 칸은 보류
TEST(Series, MissingRequiredKeysStreakDiag) {
  Series s;
  feed(s, hello_line("s1", 1));
  int64_t seq = fill(s, 25);
  auto null_line = [&](int64_t n) {
    const int64_t ts = kT0 + n * kP;
    return R"({"type":"kpm2","ver":1,"session":"s1","seq":)" + std::to_string(seq++) +
           R"(,"cell_id":1,"t_start_ms":)" + std::to_string(ts) + R"(,"t_end_ms":)" + std::to_string(ts + kP) +
           R"(,"cc":{"RRC.ConnEstabAtt":null,"RRC.ConnEstabSucc":null}})";
  };
  for (int64_t i = 25; i < 35; ++i) {
    auto r = feed(s, null_line(i));
    EXPECT_TRUE(r.hold);
    EXPECT_FALSE(has_diag(r, DiagKind::RuleInactive));
  }
  EXPECT_TRUE(has_diag(feed(s, null_line(35)), DiagKind::RuleInactive));  // 11칸째
  EXPECT_TRUE(has_diag(feed(s, kpm_line("s1", seq++, 1, 36, 1, 1, 0)), DiagKind::RuleResumed));
}
