// UE 증거 테스트 (14_ §8.3·§8.4, §10 U-T20) — 걸린 UE의 최근 메시지(pre), 경보 중 새 줄(active), 경보당 증거 UE 상한,
// 닫힌 UE의 recent 보관(14_ §2.3). 2단계 룰은 다음 이슈부터라 줄로 경보를 조종하는 테스트용 룰(ScriptRule)로 한다
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace detect;
using nlohmann::json;

namespace {

constexpr int64_t kT0 = 1793005200000;
const std::string kCc =
    R"({"RRC.ConnEstabAtt":{"total":0},"RRC.ConnEstabSucc":{"total":0},"RRC.ConnEstabFailCause":{"NetworkReject":0,"NoReply":0,"Other":0}})";

// 테스트용 2단계 룰 — 줄 이름으로 UE 단위 경보를 조종한다
//  - TestHit: 그 UE를 바로 경보에 싣는다(그 셀 경보가 없으면 RAISE, 있으면 UPDATE)
//  - TestWait: wait_ms 뒤 마감에 그 UE를 싣는다. 마감 전에 released로 닫혀도 표시를 남긴다 (15_ §1)
//  - TestClear: 그 셀 경보를 CLEAR
class ScriptRule : public UeRule {
 public:
  ScriptRule(std::string id, int64_t wait_ms, int64_t horizon_ms)
      : id_(std::move(id)), wait_ms_(wait_ms), horizon_ms_(horizon_ms) {}

  const char* id() const override { return id_.c_str(); }
  int64_t evidence_horizon_ms() const override { return horizon_ms_; }

  void on_ue_event(const UeEvt& e, const UeState&, const UeState& after, const UeRuleCtx& ctx,
                   RuleOutput& out) override {
    if (e.msg == "TestHit") {
      hit(after, e.t_ms, ctx, out);
    } else if (e.msg == "TestWait") {
      waits_[{after.key, after.uid}] = after;
      ctx.add_deadline(e.t_ms + wait_ms_, after.key, after.uid, "test", Dir::UL, e.t_ms);
    } else if (e.msg == "TestClear") {
      clear(after.key.cell_id, e.t_ms, out);
    }
  }
  void on_deadline(const Deadline& d, const UeRuleCtx& ctx, RuleOutput& out) override {
    auto it = waits_.find({d.key, d.uid});
    if (it == waits_.end()) return;
    const UeState s = it->second;
    waits_.erase(it);
    hit(s, d.at, ctx, out);
  }
  void on_ue_close(const UeState& last, CloseReason reason, int64_t, const UeRuleCtx&, RuleOutput&) override {
    auto it = waits_.find({last.key, last.uid});
    if (it == waits_.end()) return;
    if (reason == CloseReason::Released || reason == CloseReason::Reused || reason == CloseReason::StaleSetup)
      it->second = last;
    else
      waits_.erase(it);
  }
  void on_cell_tick(int64_t, const Kpm2&, const CellLoss&, bool, const UeRuleCtx&, RuleOutput&) override {}
  void on_session_reset(const UeRuleCtx&, RuleOutput& out) override {
    for (const auto& [cell, a] : open_) {
      AlertEvent e = event(AlertEventKind::End, a.alert_id, cell, a.t_last);
      e.reason = "session_reset";
      out.alerts.push_back(std::move(e));
    }
    open_.clear();
    waits_.clear();
  }

 private:
  struct Open {
    std::string alert_id;
    int64_t raised_at = 0;
    int64_t total = 0;
    int64_t t_last = 0;
  };

  AlertEvent event(AlertEventKind kind, const std::string& alert_id, int64_t cell, int64_t t) const {
    AlertEvent e;
    e.kind = kind;
    e.rule = id_;
    e.alert_id = alert_id;
    e.cell_id = cell;
    e.t = t;
    e.stage = 2;
    e.unit = "ue";
    return e;
  }
  void hit(const UeState& s, int64_t t, const UeRuleCtx& ctx, RuleOutput& out) {
    const int64_t cell = s.key.cell_id;
    auto it = open_.find(cell);
    AlertEvent e;
    if (it == open_.end()) {
      const std::string id = ctx.session + "-" + id_ + "-" + std::to_string(cell) + "-" + std::to_string(ctx.seq);
      it = open_.emplace(cell, Open{id, t, 0, t}).first;
      e = event(AlertEventKind::Raise, id, cell, t);
      e.cond = {"test"};
    } else {
      e = event(AlertEventKind::Update, it->second.alert_id, cell, t);
    }
    AlertUe u;
    u.cell = cell;
    u.du_ue_id = s.key.du_ue_id;
    u.uid = s.uid;
    u.crnti = s.crnti;
    u.cond = {"test"};
    u.t_hit = t;
    e.ues = {u};
    e.ues_total = ++it->second.total;
    it->second.t_last = t;
    out.alerts.push_back(std::move(e));
  }
  void clear(int64_t cell, int64_t t, RuleOutput& out) {
    auto it = open_.find(cell);
    if (it == open_.end()) return;
    AlertEvent e = event(AlertEventKind::Clear, it->second.alert_id, cell, t);
    e.duration_ms = t - it->second.raised_at;
    e.ues_total = it->second.total;
    out.alerts.push_back(std::move(e));
    open_.erase(it);
  }

  std::string id_;
  int64_t wait_ms_;
  int64_t horizon_ms_;
  std::map<int64_t, Open> open_;
  std::map<std::pair<UeKey, int64_t>, UeState> waits_;
};

using RuleSpec = std::tuple<std::string, int64_t, int64_t>;  // (룰 ID, 대기 ms, 증거 지평 ms)

// 엔진 + 테스트용 룰 + 증거 기록기·큐. 시각은 kT0 기준 ms
class Harness {
 public:
  explicit Harness(EvidenceConfig ecfg = {}, std::size_t queue_max = 100000, AlertConfig acfg = {},
                   UeTableConfig ucfg = {}, std::vector<RuleSpec> rules = {RuleSpec{"TEST", 1000, 1000}})
      : engine(SeriesConfig{}, kDefaultMaxLineBytes, ucfg), queue(queue_max), rec(ecfg, queue, acfg) {
    for (const auto& [id, wait, horizon] : rules) engine.add_ue_rule(std::make_unique<ScriptRule>(id, wait, horizon));
    feed(R"({"type":"hello","ver":1,"session":"S","seq":)" + std::to_string(++seq_) +
         R"(,"cells":[{"cell_id":1,"max_conn":null}],"period_ms":100,"noreply_timeout_ms":1000,"clock":"realtime","ue_evt":true})");
  }

  int64_t rrc(int64_t t, int64_t du, const std::string& dir, const std::string& msg) {
    return ue(t, du, dir, "RRC", msg);
  }
  int64_t test(int64_t t, int64_t du, const std::string& msg) { return ue(t, du, "UL", "RRC", msg); }
  int64_t f1ap(int64_t t, int64_t du, const std::string& dir, const std::string& msg) {
    return ue(t, du, dir, "F1AP", msg);
  }
  // ue_evt 한 줄을 넣고 그 seq를 돌려준다
  int64_t ue(int64_t t, int64_t du, const std::string& dir, const std::string& proto, const std::string& msg) {
    const int64_t seq = ++seq_;
    feed(R"({"type":"ue_evt","ver":1,"session":"S","seq":)" + std::to_string(seq) + R"(,"t_ms":)" +
         std::to_string(kT0 + t) + R"(,"cell_id":1,"du_ue_id":)" + std::to_string(du) + R"(,"crnti":)" +
         std::to_string(17000 + du) + R"(,"dir":")" + dir + R"(","proto":")" + proto + R"(","msg":")" + msg + "\"}");
    return seq;
  }
  void f1(int64_t t, const std::string& cells) {
    feed(R"({"type":"f1_evt","ver":1,"session":"S","seq":)" + std::to_string(++seq_) + R"(,"t_ms":)" +
         std::to_string(kT0 + t) + R"(,"msg":"F1SetupRequest","cells":)" + cells + "}");
  }
  void kpm(int64_t t) {
    next_t_ = t + 100;
    feed(R"({"type":"kpm2","ver":1,"session":"S","seq":)" + std::to_string(++seq_) + R"(,"cell_id":1,"t_start_ms":)" +
         std::to_string(kT0 + t) + R"(,"t_end_ms":)" + std::to_string(kT0 + t + 100) + R"(,"cc":)" + kCc +
         R"(,"ue_evt_lost":[]})");
  }
  void tick_to(int64_t t) {
    while (next_t_ < t) kpm(next_t_);
  }

  void feed(const std::string& line) {
    if (const auto j = json::parse(line); j.contains("seq")) lines[j["seq"].get<int64_t>()] = line;
    EngineOutput out = engine.feed_line(line);
    diags.insert(diags.end(), out.diags.begin(), out.diags.end());
    for (const auto& d : rec.on_feed(engine.series(), engine.ue_table(), out)) diags.push_back(d);
  }
  // 큐를 닫고 레코드를 모두 꺼낸다 — 시험 끝에 한 번
  std::vector<std::string> drain() {
    queue.close();
    std::vector<std::string> out;
    EvidenceRecord r;
    while (queue.pop(r)) out.push_back(r.line);
    return out;
  }

  Engine engine;
  EvidenceQueue queue;
  EvidenceRecorder rec;
  std::map<int64_t, std::string> lines;  // seq → 넣은 줄
  std::vector<Diag> diags;

 private:
  int64_t seq_ = 0;
  int64_t next_t_ = 0;
};

std::vector<json> parse_all(const std::vector<std::string>& lines) {
  std::vector<json> v;
  for (const auto& l : lines) v.push_back(json::parse(l));
  return v;
}

std::vector<json> select(const std::vector<json>& recs, const std::string& type, const std::string& phase = "") {
  std::vector<json> v;
  for (const auto& r : recs)
    if (r["type"] == type && (phase.empty() || r["phase"] == phase)) v.push_back(r);
  return v;
}

}  // namespace

// pre (14_ §8.4): 걸린 UE의 recent 전부를 seq 순으로, ue = [cell, du_ue_id, uid], raw는 받은 줄 그대로.
// alert 레코드의 ues[]에는 evidence·seq_range를 기록기가 채운다(14_ §8.3). RAISE를 일으킨 줄은 pre에만 들어간다
TEST(UeEvidence, PreCopiesRecentWithUeKey) {
  Harness h;
  const int64_t s1 = h.rrc(0, 3, "UL", "RRCSetupRequest");
  h.rrc(0, 3, "DL", "RRCSetup");
  h.rrc(50, 3, "UL", "RRCSetupComplete");
  const int64_t hit = h.test(60, 3, "TestHit");
  const std::vector<std::string> raw = h.drain();
  const std::vector<json> recs = parse_all(raw);
  ASSERT_EQ(recs.size(), 5u);
  EXPECT_EQ(recs[0]["type"], "alert");
  EXPECT_EQ(recs[0]["event"], "raise");
  ASSERT_EQ(recs[0]["ues"].size(), 1u);
  EXPECT_EQ(recs[0]["ues"][0]["evidence"], true);
  EXPECT_EQ(recs[0]["ues"][0]["seq_range"], json::array({s1, hit}));
  const std::string id = "S-TEST-1-" + std::to_string(hit);
  EXPECT_EQ(raw[1], R"({"type":"evidence","alert_id":")" + id + R"(","phase":"pre","seq":)" + std::to_string(s1) +
                        R"(,"ue":[1,3,1],"raw":)" + h.lines[s1] + "}");
  for (std::size_t i = 1; i < recs.size(); ++i) {
    EXPECT_EQ(recs[i]["phase"], "pre");
    EXPECT_EQ(recs[i]["seq"], s1 + static_cast<int64_t>(i) - 1);
    EXPECT_EQ(recs[i]["raw"], json::parse(h.lines[s1 + static_cast<int64_t>(i) - 1]));
  }
  EXPECT_TRUE(select(recs, "evidence", "active").empty());
  EXPECT_EQ(h.rec.counts(id).sent, 4);
}

// recent는 최근 N개(기본 16)만 — pre도 그만큼 (14_ §2.3)
TEST(UeEvidence, PreKeepsLastRecentN) {
  Harness h;
  const int64_t first = h.rrc(0, 3, "UL", "RRCSetupRequest");
  for (int i = 0; i < 19; ++i) h.test(10 + i, 3, "TestNoop");
  const int64_t hit = h.test(40, 3, "TestHit");
  const std::vector<json> pre = select(parse_all(h.drain()), "evidence", "pre");
  ASSERT_EQ(pre.size(), 16u);
  EXPECT_EQ(pre.front()["seq"], hit - 15);
  EXPECT_EQ(pre.back()["seq"], hit);
  EXPECT_GT(hit - 15, first);
}

// active (14_ §8.4): 경보가 열려 있는 동안 증거를 내는 UE의 새 줄만 — 다른 UE의 줄, CLEAR 뒤의 줄은 내지 않는다
TEST(UeEvidence, ActiveOnlyWhileOpenForEvidenceUe) {
  Harness h;
  h.rrc(0, 3, "UL", "RRCSetupRequest");
  h.rrc(0, 4, "UL", "RRCSetupRequest");
  h.test(10, 3, "TestHit");
  const int64_t mine = h.rrc(20, 3, "UL", "RRCSetupComplete");
  h.rrc(20, 4, "UL", "RRCSetupComplete");
  h.test(30, 4, "TestClear");
  h.rrc(40, 3, "DL", "RRCRelease");
  const std::vector<json> recs = parse_all(h.drain());
  const std::vector<json> active = select(recs, "evidence", "active");
  ASSERT_EQ(active.size(), 1u);
  EXPECT_EQ(active[0]["seq"], mine);
  EXPECT_EQ(active[0]["ue"], json::array({1, 3, 1}));
  const std::vector<json> alerts = select(recs, "alert");
  ASSERT_EQ(alerts.size(), 2u);
  EXPECT_EQ(alerts[1]["event"], "clear");
  EXPECT_EQ(alerts[1]["evidence_sent"], 3);  // pre 2 + active 1
  EXPECT_EQ(alerts[1]["ues_total"], 1);
}

// U-T20 (14_ §8.3): 경보 하나에 UE 51개 — 51번째부터 evidence: false, 그 UE의 증거 레코드 없음. UPDATE에는 새 UE만
TEST(UeEvidence, UT20EvidenceUeCap) {
  Harness h;
  for (int64_t du = 1; du <= 51; ++du) {
    h.rrc(du, du, "UL", "RRCSetupRequest");
    h.test(du, du, "TestHit");
  }
  h.rrc(100, 51, "UL", "RRCSetupComplete");
  const int64_t first_active = h.rrc(100, 1, "UL", "RRCSetupComplete");
  const std::vector<json> recs = parse_all(h.drain());
  const std::vector<json> alerts = select(recs, "alert");
  ASSERT_EQ(alerts.size(), 51u);
  EXPECT_EQ(alerts[0]["event"], "raise");
  for (std::size_t i = 0; i < alerts.size(); ++i) {
    ASSERT_EQ(alerts[i]["ues"].size(), 1u) << i;
    EXPECT_EQ(alerts[i]["ues"][0]["du_ue_id"], static_cast<int64_t>(i) + 1);
    EXPECT_EQ(alerts[i]["ues"][0]["evidence"], i < 50) << i;
    EXPECT_FALSE(alerts[i]["ues"][0]["seq_range"].is_null()) << i;  // seq_range는 상한과 관계없이
  }
  EXPECT_EQ(alerts[50]["ues_total"], 51);
  const std::vector<json> pre = select(recs, "evidence", "pre");
  EXPECT_EQ(pre.size(), 100u);  // UE 50개 × (RRCSetupRequest, TestHit)
  for (const auto& r : select(recs, "evidence")) EXPECT_NE(r["ue"][1], 51);
  const std::vector<json> active = select(recs, "evidence", "active");
  ASSERT_EQ(active.size(), 1u);
  EXPECT_EQ(active[0]["seq"], first_active);
}

// 한 UE가 두 룰의 경보에 걸리면 active를 경보마다 낸다 (14_ §8.4)
TEST(UeEvidence, ActivePerAlertWhenUeInTwoAlerts) {
  Harness h({}, 100000, {}, {}, {RuleSpec{"TA", 1000, 1000}, RuleSpec{"TB", 1000, 1000}});
  h.rrc(0, 3, "UL", "RRCSetupRequest");
  const int64_t hit = h.test(10, 3, "TestHit");
  h.rrc(20, 3, "UL", "RRCSetupComplete");
  const std::vector<json> active = select(parse_all(h.drain()), "evidence", "active");
  ASSERT_EQ(active.size(), 2u);
  EXPECT_EQ(active[0]["alert_id"], "S-TA-1-" + std::to_string(hit));
  EXPECT_EQ(active[1]["alert_id"], "S-TB-1-" + std::to_string(hit));
}

// 닫힌 UE (14_ §2.3): 마감 전에 released된 UE가 경보에 실리면 보관된 recent로 pre — 닫는 줄까지 들어 있다
TEST(UeEvidence, ClosedUeUsesKeptRecent) {
  Harness h;
  const int64_t s1 = h.rrc(0, 3, "UL", "RRCSetupRequest");
  h.test(100, 3, "TestWait");  // 마감 kT0+1100
  const int64_t rel = h.f1ap(300, 3, "UL", "UEContextReleaseComplete");
  EXPECT_FALSE(h.engine.ue_table().find(UeKey{1, 3}));
  EXPECT_EQ(h.engine.ue_table().kept_size(), 1u);
  h.tick_to(1200);
  const std::vector<json> recs = parse_all(h.drain());
  const std::vector<json> alerts = select(recs, "alert");
  ASSERT_EQ(alerts.size(), 1u);
  EXPECT_EQ(alerts[0]["ues"][0]["evidence"], true);
  EXPECT_EQ(alerts[0]["ues"][0]["seq_range"], json::array({s1, rel}));
  const std::vector<json> pre = select(recs, "evidence", "pre");
  ASSERT_EQ(pre.size(), 3u);
  EXPECT_EQ(pre.back()["seq"], rel);
}

// 보관 시간 = 등록된 룰의 증거 지평 최댓값 + 1 s (14_ §1.1·§2.3). 그보다 늦게 실리면 evidence false, seq_range null
TEST(UeEvidence, KeptRecentExpires) {
  Harness h({}, 100000, {}, {}, {RuleSpec{"TEST", 5000, 0}});
  EXPECT_EQ(h.engine.ue_table().recent_keep_ms(), 1000);
  h.rrc(0, 3, "UL", "RRCSetupRequest");
  h.test(100, 3, "TestWait");  // 마감 kT0+5100
  h.f1ap(300, 3, "UL", "UEContextReleaseComplete");
  h.tick_to(1400);  // 보관 끝 kT0+1300
  EXPECT_EQ(h.engine.ue_table().kept_size(), 0u);
  h.tick_to(5200);
  const std::vector<json> recs = parse_all(h.drain());
  const std::vector<json> alerts = select(recs, "alert");
  ASSERT_EQ(alerts.size(), 1u);
  EXPECT_EQ(alerts[0]["ues"][0]["evidence"], false);
  EXPECT_TRUE(alerts[0]["ues"][0]["seq_range"].is_null());
  EXPECT_TRUE(select(recs, "evidence").empty());
}

// 보관은 released·reused·stale_setup·superseded만, 개수 상한을 넘으면 오래된 것부터 (14_ §2.3).
// 룰의 증거 지평이 가장 긴 것을 따른다
TEST(UeEvidence, KeptOnlyForKeepReasonsAndCapped) {
  UeTableConfig ucfg;
  ucfg.closed_recent_max = 2;
  Harness h({}, 100000, {}, ucfg, {RuleSpec{"TA", 1000, 1000}, RuleSpec{"TB", 1000, 7000}});
  EXPECT_EQ(h.engine.ue_table().recent_keep_ms(), 8000);
  for (int64_t du : {1, 2, 3}) h.rrc(du, du, "UL", "RRCSetupRequest");
  for (int64_t du : {1, 2, 3}) h.f1ap(10 + du, du, "UL", "UEContextReleaseComplete");
  const UeTable& t = h.engine.ue_table();
  EXPECT_EQ(t.kept_size(), 2u);
  EXPECT_FALSE(t.recent(UeKey{1, 1}, 1));
  EXPECT_TRUE(t.recent(UeKey{1, 2}, 2));
  EXPECT_TRUE(t.recent(UeKey{1, 3}, 3));
  EXPECT_FALSE(t.recent(UeKey{1, 3}, 99));  // 다른 uid는 다른 UE
  h.rrc(20, 4, "UL", "RRCSetupRequest");
  h.f1(30, "[1]");  // du_reset — 보관하지 않음
  EXPECT_EQ(t.kept_size(), 2u);
  EXPECT_FALSE(t.recent(UeKey{1, 4}, 4));
}

// ref 모드 (14_ §8.3·§8.4): alert 레코드만 — evidence는 false, seq_range는 채운다(대시보드가 원본을 찾는 근거)
TEST(UeEvidence, RefModeSeqRangeOnly) {
  EvidenceConfig ecfg;
  ecfg.mode = EvidenceMode::Ref;
  Harness h(ecfg);
  const int64_t s1 = h.rrc(0, 3, "UL", "RRCSetupRequest");
  const int64_t hit = h.test(10, 3, "TestHit");
  h.rrc(20, 3, "UL", "RRCSetupComplete");
  const std::vector<json> recs = parse_all(h.drain());
  ASSERT_EQ(recs.size(), 1u);
  EXPECT_EQ(recs[0]["ues"][0]["evidence"], false);
  EXPECT_EQ(recs[0]["ues"][0]["seq_range"], json::array({s1, hit}));
}

TEST(UeEvidence, OffModeNothing) {
  EvidenceConfig ecfg;
  ecfg.mode = EvidenceMode::Off;
  Harness h(ecfg);
  h.rrc(0, 3, "UL", "RRCSetupRequest");
  h.test(10, 3, "TestHit");
  h.rrc(20, 3, "UL", "RRCSetupComplete");
  EXPECT_TRUE(h.drain().empty());
}

// 큐는 1단계와 함께 쓰고 넘치면 가장 오래된 evidence부터 버린다. 경보별 보낸·버린 수가 clear 레코드와 맞는다 (3_ §7.1, 10/29 검수 B12)
TEST(UeEvidence, QueueOverflowCountedPerAlert) {
  Harness h({}, 3);
  h.rrc(0, 3, "UL", "RRCSetupRequest");
  h.rrc(0, 4, "UL", "RRCSetupRequest");
  for (int i = 0; i < 4; ++i) h.test(10 + i, 3, "TestNoop");
  const int64_t hit = h.test(20, 3, "TestHit");  // recent 6줄 → pre 6건, 큐 상한 3
  h.test(30, 4, "TestClear");
  const std::vector<json> recs = parse_all(h.drain());
  const std::vector<json> pre = select(recs, "evidence", "pre");
  ASSERT_EQ(pre.size(), 3u);
  EXPECT_EQ(pre.back()["seq"], hit);  // 오래된 것부터 버렸다
  const std::vector<json> alerts = select(recs, "alert");
  ASSERT_EQ(alerts.size(), 2u);
  EXPECT_EQ(alerts[1]["evidence_sent"], 3);
  EXPECT_EQ(alerts[1]["evidence_dropped"], 3);
  EXPECT_EQ(std::count_if(h.diags.begin(), h.diags.end(),
                          [](const Diag& d) { return d.kind == DiagKind::EvidenceDropped; }),
            1);
}

// UE 단위 경보도 열려 있는 동안 그 셀 kpm2 구간이 끊기면 gap (14_ §8.4). kpm2 칸 증거는 내지 않는다
TEST(UeEvidence, GapRecordForUeAlert) {
  Harness h;
  h.rrc(0, 3, "UL", "RRCSetupRequest");
  h.kpm(0);
  const int64_t hit = h.test(100, 3, "TestHit");
  h.kpm(100);
  h.kpm(300);  // 끊김 [200, 300)
  const std::vector<json> recs = parse_all(h.drain());
  const std::vector<json> gaps = select(recs, "gap");
  ASSERT_EQ(gaps.size(), 1u);
  EXPECT_EQ(gaps[0]["alert_id"], "S-TEST-1-" + std::to_string(hit));
  EXPECT_EQ(gaps[0]["t_from"], kT0 + 200);
  EXPECT_EQ(gaps[0]["t_to"], kT0 + 300);
  for (const auto& r : select(recs, "evidence")) EXPECT_TRUE(r.contains("ue"));  // kpm2 칸 증거 없음
}
