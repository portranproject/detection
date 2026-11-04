// 2·3단계 공통 헬퍼 테스트 (26_ R1, 이슈 #96 — 11/05): 불확실 경보 묶음 HeldBook(14_ §6.2 — Q-58 ② 해결, 이슈 #48)과 셀별 밀어내기 창
// EvictWindow(14_ §6.3, 15_ §2.5 — Q-56 해결, 이슈 #44·W-32). 룰을 통한 판정(2단계 U-T29·U-T30, 3단계 보류 시험)은 룰 테스트가 엔진으로 본다 —
// 여기서는 룰마다 같던 보류 기록·창·RAISE/UPDATE/CLEAR·END·값 채우기를 헬퍼 수준에서 고정한다
#include "detect/ue_held.h"

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

using namespace detect;

namespace {

// 상태표·마감 목록을 직접 쥔 문맥 — 상태표는 비어 있어 밀어내기는 0이다
struct Ctx {
  UeTable table;
  DeadlineQueue dq;
  Hello hello;
  std::string session = "S";
  UeRuleCtx ctx() { return UeRuleCtx(table, dq, hello, session, 7, 0); }
};

AlertUe held(int64_t du, int64_t t_hit) {
  AlertUe a;
  a.cell = 1;
  a.du_ue_id = du;
  a.uid = 1;
  a.cond = {"held"};
  a.t_hit = t_hit;
  a.uncertain = {"loss"};
  a.values["wait_ms"] = 2000;
  a.values["dir"] = "UL";
  return a;
}

// L3-01-O 모양 (창 W, 문턱 N, raise의 params·로그 필드)
HeldBook::Spec spec(int64_t n = 1, int64_t window_ms = 60000, int64_t clear_quiet_ms = 60000) {
  HeldBook::Spec s;
  s.rule = "L3-xx";
  s.stage = 2;
  s.window_ms = window_ms;
  s.n = n;
  s.clear_quiet_ms = clear_quiet_ms;
  s.params["auth_wait_ms"] = 2000;
  s.params["n_stall"] = n;
  s.log_fields = {{"n_stall", std::to_string(n)}};
  return s;
}

struct H {
  explicit H(HeldBook::Spec s = spec(), AlertConfig alert = {}) : b(std::move(s), alert) {}
  void tick(int64_t t, bool attack_open = false, bool input_lost = false) {
    b.tick(1, t, input_lost, attack_open, c.ctx(), out);
  }
  Ctx c;
  HeldBook b;
  std::vector<AlertEvent> out;
};

}  // namespace

// 보류 기록 (14_ §6.2): 공격 경보가 열려 있으면 held_open으로만(불확실 경보 후보 아님), raise의 held는 직전 clear_quiet_ms 이동 창
TEST(HeldBook, HoldCountsAndWindow) {
  H h;
  h.b.hold(1, 1000, true, held(3, 1000));
  h.b.hold(1, 2000, true, std::nullopt);
  EXPECT_EQ(h.b.total(), 2);
  EXPECT_EQ(h.b.held(1, false, 2000), 2);  // update — 경보가 열린 뒤 누적
  EXPECT_EQ(h.b.held(1, true, 2000), 2);   // raise — 이동 창
  EXPECT_EQ(h.b.held(1, true, 61000), 1);  // 1000은 창(60 s) 밖
  h.tick(2100, true);
  EXPECT_TRUE(h.out.empty());              // 공격 경보 중의 보류는 불확실 경보가 아니다
  h.b.new_attack_alert(1);
  EXPECT_EQ(h.b.held(1, false, 2100), 0);
}

// 불확실 RAISE (14_ §6.2): 문턱 1 — 보류 하나로 kind anomaly·stage 2·severity medium, ues 1칸, values.held_w, cond held_count,
// candidates [룰], params는 넘긴 것, 로그 필드는 kind=anomaly held_w= 뒤에 룰 필드. alert_id는 session-룰-셀-seq
TEST(HeldBook, RaiseAtThresholdWithDecoration) {
  H h;
  h.b.hold(1, 1000, false, held(3, 1000));
  h.tick(1100);
  ASSERT_EQ(h.out.size(), 1u);
  const AlertEvent& e = h.out[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.rule, "L3-xx");
  EXPECT_EQ(e.alert_kind, "anomaly");
  EXPECT_EQ(e.stage, 2);
  EXPECT_EQ(e.severity, Severity::Medium);
  EXPECT_EQ(e.t, 1100);
  EXPECT_EQ(e.alert_id, "S-L3-xx-1-7");
  ASSERT_EQ(e.ues.size(), 1u);
  EXPECT_EQ(e.ues[0].du_ue_id, 3);
  EXPECT_EQ(e.values.dump(), R"({"held_w":1})");
  EXPECT_EQ(e.cond, (std::vector<std::string>{"held_count"}));
  EXPECT_EQ(e.candidates, (std::vector<std::string>{"L3-xx"}));
  EXPECT_EQ(e.params.dump(), R"({"auth_wait_ms":2000,"n_stall":1})");
  EXPECT_EQ(e.log_fields, (std::vector<std::pair<std::string, std::string>>{
                              {"kind", "anomaly"}, {"held_w", "1"}, {"n_stall", "1"}}));
  EXPECT_TRUE(h.b.open(1));
  EXPECT_EQ(h.b.held_w(1), 1);
}

// 문턱 N과 창 (t_hit − W, t_hit] (14_ §6.2 — L3-01-O·L3-21은 창 W, 문턱 N): 창 밖 보류는 세지 않고, 창 안이 N이 되면 창 안 보류 UE 전부로 RAISE
TEST(HeldBook, WindowAndThreshold) {
  H h(spec(2, 1000));
  h.b.hold(1, 100, false, held(1, 100));
  h.tick(200);
  EXPECT_TRUE(h.out.empty());
  h.b.hold(1, 1500, false, held(2, 1500));  // 100은 창 밖(≤ 1500 − 1000)
  h.tick(1600);
  EXPECT_TRUE(h.out.empty());
  EXPECT_EQ(h.b.held_w(1), 1);
  h.b.hold(1, 1600, false, held(3, 1600));
  h.tick(1700);
  ASSERT_EQ(h.out.size(), 1u);
  EXPECT_EQ(h.out[0].kind, AlertEventKind::Raise);
  ASSERT_EQ(h.out[0].ues.size(), 2u);
  EXPECT_EQ(h.out[0].ues[0].du_ue_id, 2);
  EXPECT_EQ(h.out[0].ues[1].du_ue_id, 3);
  EXPECT_EQ(h.out[0].values.at("held_w"), 2);
}

// 경보 중 새 보류는 UPDATE로 모은다(alert.update_min_ms), update에도 values.held_w·로그 kind=anomaly. 마지막 보류 뒤 clear_quiet_ms면 CLEAR,
// CLEAR 뒤 창 밖 보류 UE는 정리된다
TEST(HeldBook, UpdateThenClear) {
  H h;
  h.b.hold(1, 1000, false, held(1, 1000));
  h.tick(1100);
  h.b.hold(1, 1500, false, held(2, 1500));
  h.tick(1600);
  ASSERT_EQ(h.out.size(), 1u);  // 1 s 안 — 모아 둔다
  h.tick(2100);
  ASSERT_EQ(h.out.size(), 2u);
  EXPECT_EQ(h.out[1].kind, AlertEventKind::Update);
  EXPECT_EQ(h.out[1].values.dump(), R"({"held_w":2})");
  EXPECT_EQ(h.out[1].log_fields, (std::vector<std::pair<std::string, std::string>>{{"kind", "anomaly"}}));
  h.tick(61400);
  EXPECT_EQ(h.out.size(), 2u);  // 1500 + 60000 > 61400
  h.tick(61500);
  ASSERT_EQ(h.out.size(), 3u);
  EXPECT_EQ(h.out[2].kind, AlertEventKind::Clear);
  EXPECT_FALSE(h.b.open(1));
  h.tick(62000);
  EXPECT_EQ(h.b.held_w(1), 0);  // 창(60 s) 밖 정리
}

// 공격 RAISE 직전 (14_ §8.2): close는 열린 불확실 경보를 그 시각에 CLEAR한다. 열려 있지 않으면 무동작
TEST(HeldBook, CloseBeforeAttackRaise) {
  H h;
  h.b.close(1, 500, h.out);
  EXPECT_TRUE(h.out.empty());
  h.b.hold(1, 1000, false, held(1, 1000));
  h.tick(1100);
  ASSERT_EQ(h.out.size(), 1u);
  h.b.close(1, 1300, h.out);
  ASSERT_EQ(h.out.size(), 2u);
  EXPECT_EQ(h.out[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.out[1].t, 1300);
  EXPECT_FALSE(h.b.open(1));
}

// 공격 경보가 이 칸에서 열렸으면 모아 둔 보류 UE는 held_open으로만 센다 (14_ §6.2)
TEST(HeldBook, AttackOpenAtTickCountsOnly) {
  H h;
  h.b.hold(1, 1000, false, held(1, 1000));
  h.tick(1100, true);
  EXPECT_TRUE(h.out.empty());
  EXPECT_EQ(h.b.held(1, false, 1100), 1);
}

// alert.held_alert가 꺼져 있으면 보류는 세기만 하고 불확실 경보는 내지 않는다 (14_ §9)
TEST(HeldBook, HeldAlertOff) {
  AlertConfig a;
  a.held_alert = false;
  H h(spec(), a);
  h.b.hold(1, 1000, false, held(1, 1000));
  h.tick(1100);
  EXPECT_TRUE(h.out.empty());
  EXPECT_EQ(h.b.total(), 1);
  EXPECT_EQ(h.b.held(1, true, 1100), 1);
}

// END (14_ §8.2): input_lost면 그 셀, end_all이면 모든 셀. reset은 셀 기록을 버린다 — 같은 보류가 다시 세어진다
TEST(HeldBook, EndAndReset) {
  H h;
  h.b.hold(1, 1000, false, held(1, 1000));
  h.tick(1100);
  h.tick(1200, false, true);
  ASSERT_EQ(h.out.size(), 2u);
  EXPECT_EQ(h.out[1].kind, AlertEventKind::End);
  EXPECT_EQ(h.out[1].reason, "input_lost");
  EXPECT_FALSE(h.b.open(1));
  h.b.hold(1, 1300, false, held(2, 1300));
  h.tick(1400);
  ASSERT_EQ(h.out.size(), 3u);
  EXPECT_EQ(h.out[2].kind, AlertEventKind::Raise);
  h.b.end_all("input_silent", h.out);
  ASSERT_EQ(h.out.size(), 4u);
  EXPECT_EQ(h.out[3].reason, "input_silent");
  h.b.reset();
  EXPECT_EQ(h.b.held_w(1), 0);
  EXPECT_EQ(h.b.held(1, true, 1400), 0);
}

// 밀어내기 창 (14_ §6.3, 15_ §2.5 — Q-56): 상태표 셀별 누적 evicted의 증가분을 그 칸 시각으로 적고, 직전 clear_quiet_ms 안 수와 경보가 열린 뒤
// 누적을 따로 센다. 창 밖 시각은 경보가 없어도 버린다(W-32)
TEST(EvictWindow, NoteWindowAndOpen) {
  UeTableConfig tc;
  tc.max_ues = 100;
  UeTable table(tc);
  DeadlineQueue dq;
  Hello hello;
  std::string session = "S";
  UeRuleCtx ctx(table, dq, hello, session, 1, 0);
  auto connect = [&](int64_t du) {
    UeEvt e;
    e.t_ms = 1000 + du;
    e.cell_id = 1;
    e.du_ue_id = du;
    e.crnti = du;
    e.dir = Dir::UL;
    e.proto = Proto::RRC;
    e.msg = "RRCSetupRequest";
    table.apply(e, du, dq);
  };
  for (int64_t du = 1; du <= 120; ++du) connect(du);  // 상한 100 → 20건 밀어내기
  ASSERT_EQ(table.counts(1).evicted, 20);
  EvictWindow w(60000);
  w.note(1, 2000, false, ctx);
  EXPECT_EQ(w.window(1, 2000), 20);
  EXPECT_EQ(w.open(1), 0);
  EXPECT_EQ(w.times_size(1), 20u);
  for (int64_t du = 121; du <= 125; ++du) connect(du);  // 5건 더 — 경보가 열린 뒤
  w.note(1, 3000, true, ctx);
  EXPECT_EQ(w.window(1, 3000), 25);
  EXPECT_EQ(w.open(1), 5);
  w.reset_open(1);
  EXPECT_EQ(w.open(1), 0);
  EXPECT_EQ(w.window(1, 62000), 5);   // 2000의 20건은 창 밖
  w.note(1, 63000, false, ctx);       // 창 밖 시각은 경보 없이도 버린다
  EXPECT_EQ(w.times_size(1), 0u);
  EXPECT_EQ(w.window(1, 63000), 0);
  w.reset();
  EXPECT_EQ(w.window(1, 63000), 0);
}
