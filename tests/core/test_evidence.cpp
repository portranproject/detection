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
    auto d = rec.on_feed(engine.series(), engine.ue_table(), out);
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

// alert 레코드는 공통 경보 형식 — 겉모양 + values·params·refs (14_ §8.3·§8.5, 4_ §6.1 #3), type 뒤에 fmt (4_ §6.1 #4)
TEST(EvidenceRecord, AlertRaiseCommonFormat) {
  AlertEvent e;
  e.kind = AlertEventKind::Raise;
  e.rule = "L3-01-V";
  e.alert_id = "S-L3-01-V-1-5310";
  e.cell_id = 1;
  e.t = 1792209001200;
  e.severity = Severity::High;
  e.cond = {"C1", "C2", "C3"};
  e.candidates = {"L3-11"};
  e.values["a_w"] = 48;
  e.values["f_w"] = 45;
  e.values["ratio"] = 0.94;
  e.values["base"] = 3.1;
  e.values["sigma"] = 1.2;
  e.values["uectx"] = 93;
  e.values["max_conn"] = 96;
  e.params["z"] = 3.0;
  e.params["theta"] = 0.5;
  e.params["f_abs_frac"] = 0.1;
  e.params["f_abs"] = 10;
  e.refs["a"] = {5280, 5300};
  e.refs["f"] = {5290, 5310};
  EXPECT_EQ(alert_record_line(e, 0, 0),
            R"({"type":"alert","fmt":1,"alert_id":"S-L3-01-V-1-5310","event":"raise","rule":"L3-01-V","stage":1,)"
            R"("unit":"cell","kind":"attack","cell":1,"t":1792209001200,"severity":"high","mode":"normal",)"
            R"("cond":["C1","C2","C3"],"candidates":["L3-11"],)"
            R"("values":{"a_w":48,"f_w":45,"ratio":0.94,"base":3.1,"sigma":1.2,"uectx":93,"max_conn":96},)"
            R"("params":{"z":3.0,"theta":0.5,"f_abs_frac":0.1,"f_abs":10},"refs":{"a":[5280,5300],"f":[5290,5310]}})");
}

// clear·end는 겉모양 + duration·증거 수(+ reason). C4 값이 없으면 values도 없다 (결정 J5)
TEST(EvidenceRecord, AlertEndCommonFormat) {
  AlertEvent e;
  e.kind = AlertEventKind::End;
  e.rule = "L3-01-V";
  e.alert_id = "S-L3-01-V-1-25";
  e.cell_id = 1;
  e.t = 1000;
  e.mode = AlertMode::DlMissing;
  e.duration_ms = 5600;
  e.reason = "input_lost";
  EXPECT_EQ(alert_record_line(e, 7, 2),
            R"({"type":"alert","fmt":1,"alert_id":"S-L3-01-V-1-25","event":"end","rule":"L3-01-V","stage":1,)"
            R"("unit":"cell","kind":"attack","cell":1,"t":1000,"severity":"medium","mode":"dl_missing",)"
            R"("duration_ms":5600,"evidence_sent":7,"evidence_dropped":2,"reason":"input_lost"})");
}

// UE 단위 경보 — 15_ §2.6 L3-20 alert 레코드 예를 바이트 그대로 (14_ §8.3 ues[] 칸 순서, refs 없음, branch 없음)
TEST(EvidenceRecord, AlertUeUnitMatchesL320Example) {
  AlertEvent e;
  e.kind = AlertEventKind::Raise;
  e.rule = "L3-20";
  e.stage = 2;
  e.unit = "ue";
  e.alert_id = "20261026T090000Z-L3-20-1-8890";
  e.cell_id = 1;
  e.t = 1793005265500;
  e.severity = Severity::High;
  e.cond = {"same_stmsi", "concurrent", "not_accepted"};
  e.values["concurrent"] = 1;
  e.values["peer_uncertain"] = 0;
  e.values["victims"] = 1;
  e.values["held"] = 0;
  e.params["accept_wait_ms"] = 3000;  // 15_ §2.6 예 — 11/15 기본값 3,000
  e.params["clear_quiet_ms"] = 60000;
  AlertUe u;
  u.cell = 1;
  u.du_ue_id = 7;
  u.uid = 58;
  u.cu_ue_id = 12;
  u.crnti = 18050;
  u.s_tmsi = 0x0123456789abULL;
  u.cond = e.cond;
  u.t_hit = 1793005265410;
  u.values["peer"] = "concurrent";
  u.values["nas"] = "ServiceRequest";
  u.values["wait_ms"] = 3000;
  u.values["closed_ms"] = nullptr;
  u.values["victim_released"] = true;
  u.values["repeat"] = 1;
  u.peers = {{1, 3, 41}};
  u.seq_range = {{8790, 8812}};
  u.evidence = true;
  e.ues = {u};
  e.ues_total = 1;
  EXPECT_EQ(alert_record_line(e, 0, 0),
            R"({"type":"alert","fmt":1,"alert_id":"20261026T090000Z-L3-20-1-8890","event":"raise","rule":"L3-20",)"
            R"("stage":2,"unit":"ue","kind":"attack","cell":1,"t":1793005265500,"severity":"high","mode":"normal",)"
            R"("cond":["same_stmsi","concurrent","not_accepted"],"candidates":[],)"
            R"("values":{"concurrent":1,"peer_uncertain":0,"victims":1,"held":0},)"
            R"("params":{"accept_wait_ms":3000,"clear_quiet_ms":60000},)"
            R"("ues":[{"cell":1,"du_ue_id":7,"uid":58,"cu_ue_id":12,"crnti":18050,"s_tmsi":"0x0123456789ab",)"
            R"("cond":["same_stmsi","concurrent","not_accepted"],"t_hit":1793005265410,)"
            R"("values":{"peer":"concurrent","nas":"ServiceRequest","wait_ms":3000,"closed_ms":null,)"
            R"("victim_released":true,"repeat":1},"uncertain":[],"peers":[[1,3,41]],"seq_range":[8790,8812],)"
            R"("evidence":true}],"ues_total":1})");
}

// UE 단위 경보의 그 밖 모양: 갈래(branch)는 mode 뒤, 식별 값이 없으면 null·peers는 뺌·values는 {},
// clear에는 ues 없이 ues_total만 (14_ §8.3)
TEST(EvidenceRecord, AlertUeUnitBranchNullsAndClear) {
  AlertEvent e;
  e.kind = AlertEventKind::Update;
  e.rule = "L3-21";
  e.stage = 2;
  e.unit = "ue";
  e.alert_id = "S-L3-21-1-9";
  e.cell_id = 1;
  e.t = 10;
  e.branch = "2";
  AlertUe u;
  u.cell = 1;
  u.du_ue_id = 9;
  u.uid = 77;
  u.uncertain = {"mid_join"};
  e.ues = {u};
  e.ues_total = 3;
  EXPECT_EQ(alert_record_line(e, 0, 0),
            R"({"type":"alert","fmt":1,"alert_id":"S-L3-21-1-9","event":"update","rule":"L3-21","stage":2,"unit":"ue",)"
            R"("kind":"attack","cell":1,"t":10,"severity":"medium","mode":"normal","branch":"2",)"
            R"("ues":[{"cell":1,"du_ue_id":9,"uid":77,"cu_ue_id":null,"crnti":null,"s_tmsi":null,"cond":[],"t_hit":0,)"
            R"("values":{},"uncertain":["mid_join"],"seq_range":null,"evidence":false}],"ues_total":3})");

  e.kind = AlertEventKind::Clear;
  e.duration_ms = 60000;
  EXPECT_EQ(alert_record_line(e, 0, 0),
            R"({"type":"alert","fmt":1,"alert_id":"S-L3-21-1-9","event":"clear","rule":"L3-21","stage":2,"unit":"ue",)"
            R"("kind":"attack","cell":1,"t":10,"severity":"medium","mode":"normal","branch":"2","ues_total":3,)"
            R"("duration_ms":60000,"evidence_sent":0,"evidence_dropped":0})");
}

// ---- T9: RAISE pre 스냅샷에 refs.a·refs.f(A·F 윈도우 seq 범위) 칸이 모두 있음 ----

TEST(Evidence, T09PreSnapshotCoversWindows) {
  const auto path = scenario("T03_공격");
  RunResult r = run_scenario(path, {});
  auto alerts = of_type(r, "alert");
  ASSERT_EQ(alerts.size(), 1u);
  const json& raise = alerts[0];
  EXPECT_EQ(raise["event"], "raise");
  const int64_t a0 = raise["refs"]["a"][0], f1 = raise["refs"]["f"][1];
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
  for (const auto& line : lines) rec.on_feed(engine.series(), engine.ue_table(), engine.feed_line(line));
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
  EXPECT_TRUE(r.records[0]["refs"].contains("a"));

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

// 11/05 W-33 (이슈 #92, 25_ §3.1-6): 쓰기 오류면 전달을 멈추고 그 뒤 레코드를 버린 수로 센다 — /dev/full. 열지 못하면 start false + 이유
TEST(EvidenceSink, WriteErrorStopsAndCounts) {
  if (!std::ifstream("/dev/full")) GTEST_SKIP() << "/dev/full not available";
  EvidenceQueue q(100);
  EvidenceSink sink(q, "/dev/full");
  ASSERT_TRUE(sink.start());
  for (int i = 0; i < 5; ++i) q.push(ev("a", "{\"n\":" + std::to_string(i) + "}"));
  sink.stop();
  EXPECT_TRUE(sink.failed());
  EXPECT_EQ(sink.written(), 0u);
  EXPECT_EQ(sink.dropped(), 5u);
  EXPECT_NE(sink.error().find("No space"), std::string::npos);
  EvidenceQueue q2(10);
  EvidenceSink bad(q2, std::string(DETECT_TMP_DIR) + "/no_such_dir/x.jsonl");
  EXPECT_FALSE(bad.start());
  EXPECT_FALSE(bad.error().empty());
}

// 11/05 W-33 (25_ §3.5): 같은 룰·셀의 공격·불확실 track이 동시에 열려도 둘째 RAISE가 첫째를 끝내지 않는다 — (룰, 종류, 셀)로 찾는다
TEST(Evidence, AttackAndAnomalyTracksCoexist) {
  EvidenceQueue q(1000);
  EvidenceRecorder rec({}, q);
  Engine engine;
  auto mk = [](AlertEventKind kind, const char* akind, const char* id, int64_t cell) {
    AlertEvent e;
    e.kind = kind;
    e.rule = "L3-20";
    e.stage = 2;
    e.unit = "ue";
    e.alert_kind = akind;
    e.cell_id = cell;
    e.alert_id = id;
    return e;
  };
  int stored = 0;
  for (const auto& line : read_lines(scenario("T01_평상시"))) {
    auto out = engine.feed_line(line);
    if (out.outcome == FeedOutcome::Stored && out.cell_id) {
      ++stored;
      if (stored == 10) out.alerts.push_back(mk(AlertEventKind::Raise, "attack", "A", *out.cell_id));
      if (stored == 11) out.alerts.push_back(mk(AlertEventKind::Raise, "anomaly", "B", *out.cell_id));
      if (stored == 12) {
        EXPECT_EQ(rec.finished_count(), 0u);  // 둘 다 진행 중 — 그전에는 B의 RAISE가 A를 끝냈다
      }
      if (stored == 20) out.alerts.push_back(mk(AlertEventKind::Clear, "attack", "A", *out.cell_id));
      if (stored == 21) out.alerts.push_back(mk(AlertEventKind::Clear, "anomaly", "B", *out.cell_id));
    }
    rec.on_feed(engine.series(), engine.ue_table(), out);
  }
  EXPECT_EQ(rec.finished_count(), 2u);
}

// 끝난 경보의 집계는 상한(kFinishedMax)까지만 보관하고 오래된 것부터 지운다 (3_ §7.1, 10/27 이슈 #13 W-2)
TEST(Evidence, FinishedCountsAreBounded) {
  EvidenceQueue q(100000);
  EvidenceConfig ecfg;
  ecfg.mode = EvidenceMode::Ref;  // alert만 — pre 스냅샷이 없어 셀 버퍼 없이 돌릴 수 있다
  EvidenceRecorder rec(ecfg, q);
  Series s;
  UeTable t;
  const std::size_t n = EvidenceRecorder::kFinishedMax + 100;
  for (std::size_t i = 0; i < n; ++i) {
    EngineOutput out;
    AlertEvent e;
    e.rule = "L3-01-V";
    e.cell_id = 1;
    e.alert_id = "S-L3-01-V-1-" + std::to_string(i);
    e.kind = AlertEventKind::Raise;
    out.alerts.push_back(e);
    e.kind = AlertEventKind::End;
    e.reason = "session_reset";
    out.alerts.push_back(e);
    rec.on_feed(s, t, out);
  }
  EXPECT_EQ(rec.finished_count(), EvidenceRecorder::kFinishedMax);
  EXPECT_EQ(q.size(), 2 * n);  // alert 레코드는 버리지 않는다
}

// UE 단위 경보(unit = "ue")는 kpm2 칸 증거(pre·active·post)를 내지 않는다. UE 증거는 ues[]에 실린 UE의 최근 메시지라
// (14_ §8.4, test_ue_evidence.cpp) ues가 빈 이 경보는 alert 레코드만 낸다
TEST(Evidence, UeUnitAlertHasNoKpm2Evidence) {
  EvidenceQueue q(100000);
  EvidenceRecorder rec({}, q);
  Engine engine;  // 룰 없이 series만 — 셀 버퍼에 칸이 쌓인다
  const std::string id = "S-L3-20-1-x";
  int stored = 0;
  for (const auto& line : read_lines(scenario("T01_평상시"))) {
    auto out = engine.feed_line(line);
    if (out.outcome == FeedOutcome::Stored && out.cell_id) {
      ++stored;
      AlertEvent e;
      e.rule = "L3-20";
      e.stage = 2;
      e.unit = "ue";
      e.cell_id = *out.cell_id;
      e.alert_id = id;
      if (stored == 30) {
        e.kind = AlertEventKind::Raise;
        out.alerts.push_back(e);
      } else if (stored == 60) {
        e.kind = AlertEventKind::Clear;
        out.alerts.push_back(e);
      }
    }
    rec.on_feed(engine.series(), engine.ue_table(), out);
  }
  ASSERT_GT(stored, 60 + 10);  // CLEAR 뒤에도 post_slots(10)칸 넘게 칸이 온다
  q.close();
  std::vector<json> mine;
  EvidenceRecord x;
  while (q.pop(x))
    if (x.alert_id == id) mine.push_back(json::parse(x.line));
  ASSERT_EQ(mine.size(), 2u);
  EXPECT_EQ(mine[0]["type"], "alert");
  EXPECT_EQ(mine[0]["event"], "raise");
  EXPECT_EQ(mine[1]["type"], "alert");
  EXPECT_EQ(mine[1]["event"], "clear");
  EXPECT_EQ(mine[1]["evidence_sent"], 0);
  EXPECT_EQ(rec.counts(id).sent, 0);
}

// 3단계 alert 레코드 (20_ §3.6·§4.6, 14_ §8.3, 4_ §6.2 #1·#2): stage 3, 경보 conditions는 candidates 뒤·values 앞,
// ues[] 칸 conditions는 peers 뒤·seq_range 앞. 값이 없으면 키를 뺀다(L3-24 ues[] 칸)
TEST(EvidenceRecord, AlertConditionsMatchStage3Examples) {
  AlertEvent e;
  e.kind = AlertEventKind::Raise;
  e.rule = "L3-24";
  e.stage = 3;
  e.unit = "ue";
  e.alert_id = "20261026T090000Z-L3-24-1-2007";
  e.cell_id = 1;
  e.t = 1793005200100;
  e.cond = {"unsolicited"};
  e.conditions = std::vector<std::string>{"mitm_ul_relay"};
  e.values["extra"] = 0;
  e.values["held"] = 0;
  e.values["evicted"] = 0;
  e.params["clear_quiet_ms"] = 60000;
  AlertUe u;
  u.cell = 1;
  u.du_ue_id = 3;
  u.uid = 12;
  u.cu_ue_id = 3;
  u.crnti = 17922;
  u.cond = {"unsolicited"};
  u.t_hit = 1793005200098;
  u.values["req"] = 0;
  u.values["resp"] = 1;
  u.values["rrc_sec"] = "OFF";
  u.values["nas_sec"] = "NONE";
  u.seq_range = {{2001, 2006}};
  u.evidence = true;
  e.ues = {u};
  e.ues_total = 1;
  EXPECT_EQ(alert_record_line(e, 0, 0),
            R"({"type":"alert","fmt":1,"alert_id":"20261026T090000Z-L3-24-1-2007","event":"raise","rule":"L3-24",)"
            R"("stage":3,"unit":"ue","kind":"attack","cell":1,"t":1793005200100,"severity":"medium","mode":"normal",)"
            R"("cond":["unsolicited"],"candidates":[],"conditions":["mitm_ul_relay"],)"
            R"("values":{"extra":0,"held":0,"evicted":0},"params":{"clear_quiet_ms":60000},)"
            R"("ues":[{"cell":1,"du_ue_id":3,"uid":12,"cu_ue_id":3,"crnti":17922,"s_tmsi":null,"cond":["unsolicited"],)"
            R"("t_hit":1793005200098,"values":{"req":0,"resp":1,"rrc_sec":"OFF","nas_sec":"NONE"},"uncertain":[],)"
            R"("seq_range":[2001,2006],"evidence":true}],"ues_total":1})");

  // L3-14 갈래 ② — 경보·UE 칸 모두 빈 conditions (20_ §4.6 예)
  AlertEvent b;
  b.kind = AlertEventKind::Raise;
  b.rule = "L3-14";
  b.stage = 3;
  b.unit = "ue";
  b.alert_id = "20261026T090000Z-L3-14-1-2009";
  b.cell_id = 1;
  b.t = 1793005200200;
  b.severity = Severity::High;
  b.branch = "2";
  b.cond = {"enquiry_before_as_sec"};
  b.conditions = std::vector<std::string>{};
  b.values["branch1_ues"] = 0;
  b.values["branch2_ues"] = 1;
  b.values["extra"] = 0;
  b.values["held"] = 0;
  b.values["evicted"] = 0;
  b.params["clear_quiet_ms"] = 60000;
  AlertUe v;
  v.cell = 1;
  v.du_ue_id = 3;
  v.uid = 12;
  v.cu_ue_id = 3;
  v.crnti = 17922;
  v.cond = {"enquiry_before_as_sec"};
  v.t_hit = 1793005200120;
  v.values["branch"] = "2";
  v.values["req"] = 1;
  v.values["resp"] = 0;
  v.values["rrc_sec"] = "OFF";
  v.conditions = std::vector<std::string>{};
  v.seq_range = {{2001, 2008}};
  v.evidence = true;
  b.ues = {v};
  b.ues_total = 1;
  EXPECT_EQ(alert_record_line(b, 0, 0),
            R"({"type":"alert","fmt":1,"alert_id":"20261026T090000Z-L3-14-1-2009","event":"raise","rule":"L3-14",)"
            R"("stage":3,"unit":"ue","kind":"attack","cell":1,"t":1793005200200,"severity":"high","mode":"normal",)"
            R"("branch":"2","cond":["enquiry_before_as_sec"],"candidates":[],"conditions":[],)"
            R"("values":{"branch1_ues":0,"branch2_ues":1,"extra":0,"held":0,"evicted":0},)"
            R"("params":{"clear_quiet_ms":60000},)"
            R"("ues":[{"cell":1,"du_ue_id":3,"uid":12,"cu_ue_id":3,"crnti":17922,"s_tmsi":null,)"
            R"("cond":["enquiry_before_as_sec"],"t_hit":1793005200120,)"
            R"("values":{"branch":"2","req":1,"resp":0,"rrc_sec":"OFF"},"uncertain":[],"conditions":[],)"
            R"("seq_range":[2001,2008],"evidence":true}],"ues_total":1})");

  // 전제가 바뀐 update — cond·candidates 없이 branch 뒤·values 앞 (20_ §4.5)
  b.kind = AlertEventKind::Update;
  b.conditions = std::vector<std::string>{"mitm_ul_relay"};
  b.values = nlohmann::ordered_json();
  b.ues.clear();
  b.ues_total = 2;
  EXPECT_EQ(alert_record_line(b, 0, 0),
            R"({"type":"alert","fmt":1,"alert_id":"20261026T090000Z-L3-14-1-2009","event":"update","rule":"L3-14",)"
            R"("stage":3,"unit":"ue","kind":"attack","cell":1,"t":1793005200200,"severity":"high","mode":"normal",)"
            R"("branch":"2","conditions":["mitm_ul_relay"],"ues":[],"ues_total":2})");
}
