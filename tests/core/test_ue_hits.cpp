// 4단계 공통 헬퍼 HitWindow 테스트 (21_ §1.1·§1.3) — 연결당 한 번, 셀 창 (t − W, t]와 문턱 N, 경보에 실리기 전·뒤 누적 수,
// 새 경보의 누적 수 초기화, 해제·END·초기화, 닫힌 연결의 식별·uncertain. 룰을 통한 판정은 test_sync_failure.cpp가 엔진으로 본다
#include "detect/ue_hits.h"

#include <gtest/gtest.h>

#include <optional>
#include <string>
#include <vector>

using namespace detect;

namespace {

// 상태표·마감 목록을 직접 쥔 문맥 — 상태표는 비어 있어 걸림은 적어 둔 값 그대로 실린다
struct Ctx {
  UeTable table;
  DeadlineQueue dq;
  Hello hello;
  std::string session = "S";
  UeRuleCtx ctx() { return UeRuleCtx(table, dq, hello, session, 1, 0); }
};

HitWindow::UeId uid(int64_t du, int64_t u = 1) { return {UeKey{1, du}, u}; }

AlertUe ue(int64_t du, int64_t t_hit, int64_t u = 1) {
  AlertUe a;
  a.cell = 1;
  a.du_ue_id = du;
  a.uid = u;
  a.cond = {"hit"};
  a.t_hit = t_hit;
  return a;
}

// 엔진 없이 헬퍼만 — tick마다 낸 이벤트와 decorate 호출을 모은다
struct H {
  explicit H(int64_t n, int64_t window_ms = 1000, int64_t clear_quiet_ms = 60000, AlertConfig alert = {})
      : w("AN-xx", alert, window_ms, n, clear_quiet_ms) {}
  void tick(int64_t t, bool input_lost = false) {
    w.tick(1, t, input_lost, c.ctx(), out, [&](std::size_t from, const AlertUe* hit) {
      froms.push_back(from);
      hits.push_back(hit ? std::optional<int64_t>(hit->du_ue_id) : std::nullopt);  // 이번 걸림의 du (이슈 #84)
    });
  }
  Ctx c;
  HitWindow w;
  std::vector<AlertEvent> out;
  std::vector<std::size_t> froms;
  std::vector<std::optional<int64_t>> hits;
};

}  // namespace

// 연결당 한 번 (§1.1): 같은 (키, uid)는 다시 걸리지 않는다. 같은 키의 다른 항목(uid)은 따로
TEST(HitWindow, OncePerConnection) {
  H h(1);
  EXPECT_TRUE(h.w.hit(uid(3), ue(3, 100)));
  EXPECT_FALSE(h.w.hit(uid(3), ue(3, 150)));
  EXPECT_TRUE(h.w.hit_before(uid(3)));
  EXPECT_FALSE(h.w.hit_before(uid(3, 2)));
  EXPECT_TRUE(h.w.hit(uid(3, 2), ue(3, 160, 2)));
}

// 셀 창 (t − W, t]·문턱 N (21_ §3.3-3): N 2, W 1,000 — 100의 걸림은 1,100 걸림 때 창에서 빠진다(경계 t − W는 밖). 1,500에서
// 창 안 2(1,100·1,500)로 RAISE, ues는 창 안 걸림 전부, kind anomaly·stage 4
TEST(HitWindow, WindowAndThreshold) {
  H h(2);
  h.w.hit(uid(1), ue(1, 100));
  h.tick(200);
  EXPECT_TRUE(h.out.empty());
  EXPECT_EQ(h.w.window(1), 1);
  h.w.hit(uid(2), ue(2, 1100));
  h.tick(1200);
  EXPECT_TRUE(h.out.empty());
  EXPECT_EQ(h.w.window(1), 1);
  h.w.hit(uid(3), ue(3, 1500));
  h.tick(1600);
  ASSERT_EQ(h.out.size(), 1u);
  const AlertEvent& e = h.out[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  EXPECT_EQ(e.alert_kind, "anomaly");
  EXPECT_EQ(e.stage, 4);
  EXPECT_EQ(e.severity, Severity::Medium);
  EXPECT_EQ(e.t, 1600);
  ASSERT_EQ(e.ues.size(), 2u);
  EXPECT_EQ(e.ues[0].du_ue_id, 2);
  EXPECT_EQ(e.ues[1].du_ue_id, 3);
  EXPECT_EQ(h.w.window(1), 2);
}

// 누적 수 (§1.1): 경보에 실리기 전 쌓인 것은 실릴 때 더하고, 실린 뒤 것은 바로 더한다. 실리지 않은 연결·모르는 연결은 무시.
// 경보 중 새 걸림은 UPDATE로 모은다(update_min_ms) — 그 걸림의 누적 수도 함께
TEST(HitWindow, CountsBeforeAndAfterInclude) {
  H h(1);
  h.w.hit(uid(1), ue(1, 100));
  h.w.add(uid(1), "extra");
  h.w.add(uid(1), "reauth");
  h.w.add(uid(9), "extra");  // 걸리지 않은 연결
  h.tick(200);
  ASSERT_EQ(h.out.size(), 1u);
  EXPECT_EQ(h.w.count(1, "extra"), 1);
  EXPECT_EQ(h.w.count(1, "reauth"), 1);
  h.w.add(uid(1), "extra");
  EXPECT_EQ(h.w.count(1, "extra"), 2);
  h.w.hit(uid(2), ue(2, 500));
  h.w.add(uid(2), "reauth");
  h.tick(600);
  EXPECT_EQ(h.out.size(), 1u);  // RAISE 뒤 1 s 전 — 모아 둔다
  EXPECT_EQ(h.w.count(1, "reauth"), 2);
  h.tick(1200);
  ASSERT_EQ(h.out.size(), 2u);
  EXPECT_EQ(h.out[1].kind, AlertEventKind::Update);
  ASSERT_EQ(h.out[1].ues.size(), 1u);
  EXPECT_EQ(h.out[1].ues[0].du_ue_id, 2);
  EXPECT_EQ(h.out[1].ues_total, 2);
}

// 해제 (21_ §3.5): 경보에 실린 마지막 걸림 + clear_quiet_ms 이상인 첫 칸에 CLEAR. 새 경보는 누적 수를 처음부터 센다
TEST(HitWindow, ClearAndNewAlertResetsCounts) {
  H h(1, 1000, 60000);
  h.w.hit(uid(1), ue(1, 100));
  h.w.add(uid(1), "extra");
  h.tick(200);
  h.tick(60000);
  EXPECT_EQ(h.out.size(), 1u);
  h.tick(60100);
  ASSERT_EQ(h.out.size(), 2u);
  EXPECT_EQ(h.out[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.out[1].t, 60100);
  h.w.hit(uid(2), ue(2, 70000));
  h.tick(70100);
  ASSERT_EQ(h.out.size(), 3u);
  EXPECT_EQ(h.out[2].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.w.count(1, "extra"), 0);
}

// END·초기화: input_lost면 그 셀 END, reset이면 걸림·연결 기록을 버린다 — 같은 연결이 다시 걸릴 수 있다
TEST(HitWindow, EndAndReset) {
  H h(1);
  h.w.hit(uid(1), ue(1, 100));
  h.tick(200);
  h.tick(300, true);
  ASSERT_EQ(h.out.size(), 2u);
  EXPECT_EQ(h.out[1].kind, AlertEventKind::End);
  EXPECT_EQ(h.out[1].reason, "input_lost");
  EXPECT_TRUE(h.w.hit_before(uid(1)));
  h.w.reset();
  EXPECT_FALSE(h.w.hit_before(uid(1)));
  EXPECT_EQ(h.w.window(1), 0);
}

// 닫힌 연결: kpm2 전에 닫힌 걸림은 마지막 상태로 식별·uncertain을 채우고(cond·t_hit·values는 그대로), 연결 기록을 지운다
TEST(HitWindow, CloseRefreshesIdentity) {
  H h(1);
  AlertUe u = ue(3, 100);
  u.values["cause"] = 21;
  h.w.hit(uid(3), u);
  UeState last;
  last.key = UeKey{1, 3};
  last.uid = 1;
  last.crnti = 17003;
  last.loss = true;
  h.w.on_close(last);
  EXPECT_FALSE(h.w.hit_before(uid(3)));
  h.tick(200);
  ASSERT_EQ(h.out.size(), 1u);
  const AlertUe& r = h.out[0].ues[0];
  EXPECT_EQ(r.crnti, 17003);
  EXPECT_EQ(r.uncertain, (std::vector<std::string>{"loss"}));
  EXPECT_EQ(r.cond, (std::vector<std::string>{"hit"}));
  EXPECT_EQ(r.t_hit, 100);
  EXPECT_EQ(r.values.dump(), R"({"cause":21})");
}

// force 걸림 (21_ §5.3 — AN-02 갈래 ①): 창 안 수가 N 미만이어도 이 걸림으로 RAISE하고, 그때 창 안 걸림을 모두 싣는다.
// 조건별 수 window_with는 창 안 걸림 가운데 그 cond를 가진 수
TEST(HitWindow, ForceHitRaisesWithWindow) {
  H h(5);
  h.w.hit(uid(1), ue(1, 100));
  h.tick(200);
  EXPECT_TRUE(h.out.empty());
  AlertUe k = ue(2, 300);
  k.cond = {"known"};
  h.w.hit(uid(2), k, true);
  h.tick(400);
  ASSERT_EQ(h.out.size(), 1u);
  EXPECT_EQ(h.out[0].kind, AlertEventKind::Raise);
  EXPECT_EQ(h.out[0].ues.size(), 2u);
  EXPECT_EQ(h.w.window(1), 2);
  EXPECT_EQ(h.w.window_with(1, "known"), 1);
  EXPECT_EQ(h.w.window_with(1, "hit"), 1);
}

// 해제 기준 (21_ §5.5): clear_on_satisfied면 성립하지 않은 걸림(창 안 수 < N, force 아님)은 경보에 실려도 해제를 늦추지 않는다 /
// 기본(마지막 걸림)이면 늦춘다
TEST(HitWindow, ClearOnSatisfiedIgnoresUnsatisfiedHits) {
  for (bool on : {true, false}) {
    H h(5, 1000, 60000);
    h.w.set_clear_on_satisfied(on);
    h.w.hit(uid(1), ue(1, 100), true);  // 성립 — RAISE
    h.tick(200);
    h.w.hit(uid(2), ue(2, 30000));      // 창(1 s) 안 1개 — 성립 아님, 경보에 UPDATE로 실림
    h.tick(30100);
    h.tick(60100);
    const bool cleared = h.out.back().kind == AlertEventKind::Clear;
    EXPECT_EQ(cleared, on) << on;  // on이면 첫 걸림 + 60 s에 CLEAR, 아니면 둘째 걸림 + 60 s까지 열림
  }
}

// CLEAR 뒤 창 (23_ §3.1-2, 이슈 #84): 창 W(300 s)가 해제(60 s)보다 길어도 CLEAR된 경보의 걸림은 새 경보에 싣지 않는다 — 창·창 안 수·
// 누적 수가 새로 시작한다. 그전에는 옛 걸림이 창에 남아 둘째 RAISE의 ues가 2였다
TEST(HitWindow, ClearForgetsWindow) {
  H h(1, 300000, 60000);
  h.w.hit(uid(1), ue(1, 100));
  h.w.add(uid(1), "extra");
  h.tick(200);
  ASSERT_EQ(h.out.size(), 1u);
  EXPECT_EQ(h.w.count(1, "extra"), 1);
  h.tick(60100);
  ASSERT_EQ(h.out.size(), 2u);
  EXPECT_EQ(h.out[1].kind, AlertEventKind::Clear);
  EXPECT_EQ(h.w.window(1), 0);
  h.w.hit(uid(2), ue(2, 70000));  // 첫 걸림 뒤 69.9 s — 창 300 s 안
  h.tick(70100);
  ASSERT_EQ(h.out.size(), 3u);
  const AlertEvent& e = h.out[2];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  ASSERT_EQ(e.ues.size(), 1u);
  EXPECT_EQ(e.ues[0].du_ue_id, 2);
  EXPECT_EQ(e.ues_total, 1);
  EXPECT_EQ(h.w.window(1), 1);
  EXPECT_EQ(h.w.count(1, "extra"), 0);
}

// END 뒤 창 (이슈 #84): input_lost END·end_all(input_silent) 뒤에도 같다. 경보가 없던 셀의 걸림(성립 전)은 END가 건드리지 않는다
TEST(HitWindow, EndForgetsWindow) {
  {
    H h(1, 300000);
    h.w.hit(uid(1), ue(1, 100));
    h.tick(200);
    h.tick(300, true);
    ASSERT_EQ(h.out.size(), 2u);
    EXPECT_EQ(h.out[1].kind, AlertEventKind::End);
    EXPECT_EQ(h.w.window(1), 0);
    h.w.hit(uid(2), ue(2, 1000));
    h.tick(1100);
    ASSERT_EQ(h.out.size(), 3u);
    EXPECT_EQ(h.out[2].ues.size(), 1u);
    EXPECT_EQ(h.out[2].ues_total, 1);
  }
  {
    H h(1, 300000);
    h.w.hit(uid(1), ue(1, 100));
    h.tick(200);
    h.w.end_all("input_silent", h.out);
    ASSERT_EQ(h.out.size(), 2u);
    EXPECT_EQ(h.w.window(1), 0);
    h.w.hit(uid(2), ue(2, 1000));
    h.tick(1100);
    ASSERT_EQ(h.out.size(), 3u);
    EXPECT_EQ(h.out[2].ues.size(), 1u);
  }
  {
    H h(2, 300000);  // 성립 전(창 안 1 < N 2) — 경보가 없어 END는 아무것도 하지 않고 창도 그대로
    h.w.hit(uid(1), ue(1, 100));
    h.tick(200);
    h.tick(300, true);
    EXPECT_TRUE(h.out.empty());
    EXPECT_EQ(h.w.window(1), 1);
  }
}

// 이번 걸림 전달 (이슈 #84): decorate는 걸림을 처리하는 구간(RAISE·그 걸림의 UPDATE)에 그 걸림을 받고, END·모아 둔 UPDATE·CLEAR 구간은 nullptr
TEST(HitWindow, DecorateGetsTriggeringHit) {
  H h(1);
  h.w.hit(uid(1), ue(1, 100));
  h.tick(200);
  EXPECT_EQ(h.hits, (std::vector<std::optional<int64_t>>{std::nullopt, 1, std::nullopt}));
  h.hits.clear();
  h.w.hit(uid(2), ue(2, 500));
  h.tick(600);  // 경보 중 — 모아 둔다(UPDATE는 뒤), 그래도 그 걸림을 넘긴다
  EXPECT_EQ(h.hits, (std::vector<std::optional<int64_t>>{std::nullopt, 2, std::nullopt}));
  h.hits.clear();
  h.tick(1200);  // 모아 둔 UPDATE
  EXPECT_EQ(h.hits, (std::vector<std::optional<int64_t>>{std::nullopt, std::nullopt}));
  ASSERT_EQ(h.out.size(), 2u);
  EXPECT_EQ(h.out[1].kind, AlertEventKind::Update);
}

// ues_max 잘림 (23_ §3.2-1, 이슈 #84): 레코드의 ues가 alert.ues_max로 잘려도 넘겨받은 이번 걸림은 RAISE를 일으킨 걸림이다 —
// e.ues.back()은 잘린 목록의 마지막 칸(다른 UE)
TEST(HitWindow, TriggeringHitUnderUesMax) {
  AlertConfig a;
  a.ues_max = 2;
  H h(3, 1000, 60000, a);
  h.w.hit(uid(1), ue(1, 100));
  h.w.hit(uid(2), ue(2, 200));
  h.w.hit(uid(3), ue(3, 300));
  h.tick(400);
  ASSERT_EQ(h.out.size(), 1u);
  const AlertEvent& e = h.out[0];
  EXPECT_EQ(e.kind, AlertEventKind::Raise);
  ASSERT_EQ(e.ues.size(), 2u);
  EXPECT_EQ(e.ues_total, 3);
  EXPECT_EQ(e.ues.back().du_ue_id, 2);
  ASSERT_EQ(h.hits.size(), 5u);  // 시작·걸림 3·끝
  EXPECT_EQ(h.hits[3], std::optional<int64_t>(3));
}
