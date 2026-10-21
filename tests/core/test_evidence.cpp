// 증거 내보내기 테스트 (3_ §7.1, §9 T9~T12·T16) — 큐·기록기·전달 스레드
#include "detect/engine.h"
#include "detect/evidence.h"
#include "detect/evidence_queue.h"
#include "detect/io/evidence_sink.h"
#include "detect/rules/bts_variant.h"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

using namespace detect;
using nlohmann::json;

namespace {

std::string scenario(const std::string& name) { return std::string(DETECT_SCENARIO_DIR) + "/" + name + ".jsonl"; }

std::vector<std::string> read_lines(const std::string& path) {
  std::ifstream in(path);
  std::vector<std::string> lines;
  std::string l;
  while (std::getline(in, l)) lines.push_back(l);
  return lines;
}

// seq → 입력 줄 (kpm2만)
std::map<int64_t, std::string> kpm2_by_seq(const std::vector<std::string>& lines, const std::string& session = "S1") {
  std::map<int64_t, std::string> m;
  for (const auto& l : lines) {
    auto j = json::parse(l);
    if (j["type"] == "kpm2" && j["session"] == session) m[j["seq"].get<int64_t>()] = l;
  }
  return m;
}

// 시나리오 하나를 엔진 + 기록기로 돌린다. 큐 소비자는 없음 — 끝난 뒤 큐를 비워 레코드를 모은다
struct RunResult {
  std::vector<AlertEvent> alerts;
  std::vector<json> records;
  std::vector<std::string> record_lines;
  std::vector<Diag> diags;
};

RunResult run_scenario(const std::string& path, EvidenceConfig ecfg, std::size_t queue_max = 100000) {
  BtsVariantConfig cfg;
  SeriesConfig scfg;
  scfg.window_ms = cfg.window_ms;
  scfg.pre_slots = ecfg.pre_slots;
  Engine engine(scfg);
  engine.add_rule(std::make_unique<BtsVariantRule>(cfg));
  EvidenceQueue q(queue_max);
  EvidenceRecorder rec(ecfg, q);
  RunResult r;
  for (const auto& line : read_lines(path)) {
    auto out = engine.feed_line(line);
    r.alerts.insert(r.alerts.end(), out.alerts.begin(), out.alerts.end());
    auto d = rec.on_feed(engine.series(), out);
    r.diags.insert(r.diags.end(), d.begin(), d.end());
  }
  q.close();
  EvidenceRecord x;
  while (q.pop(x)) {
    r.record_lines.push_back(x.line);
    r.records.push_back(json::parse(x.line));  // 모든 레코드가 올바른 JSON이어야 한다
  }
  return r;
}

std::vector<json> of_type(const RunResult& r, const std::string& type) {
  std::vector<json> v;
  for (const auto& j : r.records)
    if (j["type"] == type) v.push_back(j);
  return v;
}

EvidenceRecord ev(const std::string& id, const std::string& line = "{}") {
  return EvidenceRecord{RecordKind::Evidence, id, line};
}

}  // namespace

// ---- 큐 (3_ §7.1 생산자 측 드롭) ----

TEST(EvidenceQueue, DropsOldestEvidenceKeepsAlerts) {
  EvidenceQueue q(2);
  q.push(EvidenceRecord{RecordKind::Alert, "a", "A1"});
  q.push(ev("a", "E1"));
  q.push(ev("a", "E2"));
  auto r = q.push(ev("b", "E3"));  // 상한 2 → 가장 오래된 evidence(E1) 버림
  EXPECT_TRUE(r.accepted);
  ASSERT_TRUE(r.dropped_alert);
  EXPECT_EQ(*r.dropped_alert, "a");
  q.push(EvidenceRecord{RecordKind::Gap, "a", "G1"});  // gap은 상한과 무관
  EXPECT_EQ(q.evidence_count(), 2u);
  q.close();
  std::vector<std::string> got;
  EvidenceRecord x;
  while (q.pop(x)) got.push_back(x.line);
  EXPECT_EQ(got, (std::vector<std::string>{"A1", "E2", "E3", "G1"}));
}

// 버릴 evidence가 없으면(상한 0) 새로 넣으려는 evidence를 버린다
TEST(EvidenceQueue, DropsNewWhenNoEvidenceToDrop) {
  EvidenceQueue q(0);
  q.push(EvidenceRecord{RecordKind::Alert, "a", "A1"});
  auto r = q.push(ev("a"));
  EXPECT_FALSE(r.accepted);
  EXPECT_EQ(*r.dropped_alert, "a");
  EXPECT_EQ(q.size(), 1u);
}

// 생산자·소비자 두 스레드 — 넣은 것 = 꺼낸 것 + 버린 것
TEST(EvidenceQueue, ProducerConsumerThreads) {
  EvidenceQueue q(64);
  std::size_t popped = 0;
  std::thread consumer([&] {
    EvidenceRecord x;
    while (q.pop(x)) ++popped;
  });
  std::size_t dropped = 0;
  for (int i = 0; i < 20000; ++i)
    if (q.push(ev("a")).dropped_alert) ++dropped;
  q.close();
  consumer.join();
  EXPECT_EQ(popped + dropped, 20000u);
}

// ---- 레코드 형식 ----

// raw는 받은 문자열을 바이트 그대로 이어 붙인다 (3_ §7.1)
TEST(EvidenceRecord, RawIsVerbatim) {
  const std::string raw = R"({"type":"kpm2","z":1,"a":2.50})";
  const std::string line = evidence_record_line("id", "pre", 7, raw);
  EXPECT_EQ(line, R"({"type":"evidence","alert_id":"id","phase":"pre","seq":7,"raw":{"type":"kpm2","z":1,"a":2.50}})");
  EXPECT_NO_THROW({ auto parsed = json::parse(line); (void)parsed; });
}

// ---- T9: RAISE pre 스냅샷에 a_seq·f_seq 범위 칸이 모두 있음 ----

TEST(Evidence, T09PreSnapshotCoversWindows) {
  const auto path = scenario("T03_공격");
  RunResult r = run_scenario(path, {});
  auto alerts = of_type(r, "alert");
  ASSERT_EQ(alerts.size(), 1u);
  const json& raise = alerts[0];
  EXPECT_EQ(raise["event"], "raise");
  const int64_t a0 = raise["a_seq"][0], f1 = raise["f_seq"][1];
  std::set<int64_t> pre;
  for (const auto& e : of_type(r, "evidence"))
    if (e["phase"] == "pre") pre.insert(e["seq"].get<int64_t>());
  EXPECT_EQ(pre.size(), 21u);  // 버퍼 전체 = W/P + D + 1
  for (const auto& [seq, line] : kpm2_by_seq(read_lines(path)))
    if (seq >= a0 && seq <= f1) {
      EXPECT_TRUE(pre.count(seq)) << seq;
    }
  // 레코드 순서: alert(raise)가 pre보다 먼저
  EXPECT_EQ(r.records.front()["type"], "alert");
}

// ---- T10: RAISE ~ CLEAR + post까지 그 셀 칸이 시각 순으로 빠짐없이 한 번씩 ----

TEST(Evidence, T10LongAttackEveryCellSlotOnce) {
  const auto path = scenario("T10_긴공격");
  RunResult r = run_scenario(path, {});
  auto evs = of_type(r, "evidence");
  ASSERT_FALSE(evs.empty());
  std::vector<int64_t> seqs;
  std::map<std::string, int> phases;
  for (const auto& e : evs) {
    seqs.push_back(e["seq"].get<int64_t>());
    ++phases[e["phase"].get<std::string>()];
  }
  EXPECT_EQ(phases["pre"], 21);
  EXPECT_EQ(phases["post"], 10);
  // 겹침 없이 증가 (pre 다음 active는 RAISE 다음 칸부터)
  for (std::size_t i = 1; i < seqs.size(); ++i) EXPECT_GT(seqs[i], seqs[i - 1]) << i;
  // 첫 증거부터 마지막 증거까지 입력의 kpm2 칸이 모두 있다
  std::set<int64_t> got(seqs.begin(), seqs.end());
  for (const auto& [seq, line] : kpm2_by_seq(read_lines(path)))
    if (seq >= seqs.front() && seq <= seqs.back()) {
      EXPECT_TRUE(got.count(seq)) << seq;
    }
  // clear 레코드의 집계 = pre + active
  auto alerts = of_type(r, "alert");
  ASSERT_EQ(alerts.size(), 2u);
  EXPECT_EQ(alerts[1]["event"], "clear");
  EXPECT_EQ(alerts[1]["evidence_sent"].get<int>(), phases["pre"] + phases["active"]);
  EXPECT_EQ(alerts[1]["evidence_dropped"].get<int>(), 0);
}

// ---- T11: 전송이 막혀도(소비자 없음, 작은 큐) 판정 시각은 같고, 버린 수가 clear에 남는다 ----

TEST(Evidence, T11BlockedSinkDoesNotDelayAlerts) {
  const auto path = scenario("T05_공격종료");
  EvidenceConfig off;
  off.mode = EvidenceMode::Off;
  RunResult base = run_scenario(path, off);
  RunResult small = run_scenario(path, {}, 8);
  ASSERT_EQ(base.alerts.size(), small.alerts.size());
  for (std::size_t i = 0; i < base.alerts.size(); ++i) EXPECT_EQ(base.alerts[i].t, small.alerts[i].t);
  auto alerts = of_type(small, "alert");
  ASSERT_EQ(alerts.size(), 2u);
  EXPECT_GT(alerts[1]["evidence_dropped"].get<int>(), 0);
  EXPECT_EQ(of_type(small, "evidence").size(), 8u);  // 큐에 남은 것은 상한만큼
  bool logged = false;
  for (const auto& d : small.diags) logged |= d.kind == DiagKind::EvidenceDropped;
  EXPECT_TRUE(logged);
}

// ---- T12: 경보 중 끊김 → gap, session 변경 → end(session_reset) ----

TEST(Evidence, T12GapRecord) {
  RunResult r = run_scenario(scenario("T06_공격중끊김"), {});
  auto gaps = of_type(r, "gap");
  ASSERT_EQ(gaps.size(), 1u);
  EXPECT_EQ(gaps[0]["t_to"].get<int64_t>() - gaps[0]["t_from"].get<int64_t>(), 100);
  EXPECT_EQ(gaps[0]["t_from"].get<int64_t>(), 1792209000000 + 12000);
}

TEST(Evidence, T12SessionResetEndRecord) {
  RunResult r = run_scenario(scenario("T07_세션변경"), {});
  auto alerts = of_type(r, "alert");
  ASSERT_EQ(alerts.size(), 3u);
  EXPECT_EQ(alerts[1]["event"], "end");
  EXPECT_EQ(alerts[1]["reason"], "session_reset");
  EXPECT_GT(alerts[1]["evidence_sent"].get<int>(), 0);
  EXPECT_EQ(alerts[2]["event"], "raise");
  EXPECT_NE(alerts[2]["alert_id"], alerts[0]["alert_id"]);
}

// ---- T16: 느린 전달로 버퍼가 여러 바퀴 덮어써져도 전달된 raw·seq는 입력과 1:1 ----

TEST(Evidence, T16SlowConsumerSeesExactInput) {
  const auto path = scenario("T10_긴공격");
  const auto lines = read_lines(path);
  const auto by_seq = kpm2_by_seq(lines);

  BtsVariantConfig cfg;
  SeriesConfig scfg;
  Engine engine(scfg);
  engine.add_rule(std::make_unique<BtsVariantRule>(cfg));
  EvidenceQueue q(4096);
  EvidenceRecorder rec({}, q);
  std::vector<std::string> got;
  std::thread consumer([&] {  // 스레드 B: 레코드마다 늦게 꺼낸다
    EvidenceRecord x;
    while (q.pop(x)) {
      std::this_thread::sleep_for(std::chrono::microseconds(200));
      got.push_back(x.line);
    }
  });
  for (const auto& line : lines) rec.on_feed(engine.series(), engine.feed_line(line));
  q.close();
  consumer.join();

  int n = 0;
  for (const auto& l : got) {
    auto j = json::parse(l);
    if (j["type"] != "evidence") continue;
    ++n;
    const int64_t seq = j["seq"];
    ASSERT_TRUE(by_seq.count(seq)) << seq;
    // 레코드 안 raw가 입력 줄과 바이트 단위로 같다
    const std::string tail = ",\"raw\":" + by_seq.at(seq) + "}";
    ASSERT_GE(l.size(), tail.size());
    EXPECT_EQ(l.substr(l.size() - tail.size()), tail) << seq;
  }
  EXPECT_GT(n, 21 * 5);  // 버퍼(21칸)가 여러 바퀴 돈 만큼
}

// ---- 그 밖 ----

// post 구간 중 같은 셀·룰이 다시 RAISE하면 이전 post를 끝내고 새 경보 (3_ §7.1)
TEST(Evidence, ReRaiseDuringPostEndsPost) {
  // T05(5~15 s 공격, CLEAR 19.8 s)에 22 s부터 공격을 다시 붙인다
  auto lines = read_lines(scenario("T05_공격종료"));
  std::vector<std::string> mod;
  for (auto l : lines) {
    auto j = json::parse(l);
    if (j["type"] == "kpm2") {
      const int64_t rel = j["t_start_ms"].get<int64_t>() - 1792209000000;
      if (rel >= 22000) j["cc"]["RRC.ConnEstabAtt"]["total"] = j["cc"]["RRC.ConnEstabAtt"]["total"].get<int>() + 3;
      if (rel >= 23000) j["cc"]["RRC.ConnEstabFailCause"]["NoReply"] = 3;
      l = j.dump();
    }
    mod.push_back(l);
  }
  const std::string tmp = std::string(DETECT_TMP_DIR) + "/reraise_tmp.jsonl";
  {
    std::ofstream o(tmp);
    for (const auto& l : mod) o << l << "\n";
  }
  EvidenceConfig ecfg;
  ecfg.post_slots = 100;  // post(10 s)가 두 번째 RAISE까지 이어지게
  RunResult r = run_scenario(tmp, ecfg);
  std::remove(tmp.c_str());

  auto alerts = of_type(r, "alert");
  ASSERT_EQ(alerts.size(), 3u);  // raise, clear, raise
  EXPECT_EQ(alerts[2]["event"], "raise");
  const std::string first = alerts[0]["alert_id"];
  int post = 0;
  for (const auto& e : of_type(r, "evidence"))
    if (e["alert_id"] == first && e["phase"] == "post") ++post;
  EXPECT_GT(post, 0);
  EXPECT_LT(post, 100);  // 두 번째 RAISE에서 끝남
}

// ref 모드는 alert만, off는 아무것도 (3_ §7.1 모드, 결정 F6)
TEST(Evidence, RefAndOffModes) {
  EvidenceConfig ref;
  ref.mode = EvidenceMode::Ref;
  RunResult r = run_scenario(scenario("T06_공격중끊김"), ref);
  ASSERT_FALSE(r.records.empty());
  for (const auto& j : r.records) EXPECT_EQ(j["type"], "alert");
  EXPECT_TRUE(r.records[0].contains("a_seq"));

  EvidenceConfig off;
  off.mode = EvidenceMode::Off;
  EXPECT_TRUE(run_scenario(scenario("T06_공격중끊김"), off).records.empty());
}

// 전달 스레드: 파일에 이어 쓰고, stop 때 남은 것을 다 쓴다 (결정 F8)
TEST(EvidenceSink, WritesAndDrainsOnStop) {
  const std::string path = std::string(DETECT_TMP_DIR) + "/sink_tmp.jsonl";
  std::remove(path.c_str());
  {
    std::ofstream o(path);
    o << "old\n";
  }
  EvidenceQueue q(100);
  EvidenceSink sink(q, path);
  ASSERT_TRUE(sink.start());
  for (int i = 0; i < 50; ++i) q.push(ev("a", "{\"n\":" + std::to_string(i) + "}"));
  sink.stop();
  EXPECT_EQ(sink.written(), 50u);
  auto lines = read_lines(path);
  std::remove(path.c_str());
  ASSERT_EQ(lines.size(), 51u);
  EXPECT_EQ(lines[0], "old");  // 이어 쓰기
  EXPECT_EQ(lines[50], "{\"n\":49}");
}
