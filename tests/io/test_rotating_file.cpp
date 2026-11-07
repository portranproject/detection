// 출력 파일 회전 시험 (29_ §8.1 RT-T1~RT-T10 — 11/08 이슈 #102). 시계와 파일 연산(열기·이름 바꾸기·쓰기)을 주입한다 — 벽시계를
// 기다리지 않고, /dev/full 같은 실제 장치 경로를 회전시키지 않는다(실패는 주입으로 만든다). 파일은 시험 폴더(DETECT_TMP_DIR)
// 아래 시험마다 새 폴더에 만든다. RT-T11은 tests/core/test_config.cpp, RT-T12·T13은 tests/integration/
#include "detect/evidence_queue.h"
#include "detect/io/evidence_sink.h"
#include "detect/io/input_recorder.h"
#include "detect/io/rotating_file.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace detect;
namespace fs = std::filesystem;

namespace {

using Kind = RotateEvent::Kind;

// 시험마다 비운 폴더
std::string fresh_dir(const std::string& name) {
  const fs::path d = fs::path(DETECT_TMP_DIR) / ("rot_" + name);
  std::error_code ec;
  fs::remove_all(d, ec);
  fs::create_directories(d);
  return d.string();
}

std::string read_all(const std::string& p) {
  std::ifstream in(p, std::ios::binary);
  std::stringstream ss;
  ss << in.rdbuf();
  return ss.str();
}

void write_file(const std::string& p, const std::string& s) {
  std::ofstream out(p, std::ios::binary);
  out << s;
}

// UTC 시각 → epoch ms
int64_t utc_ms(int y, int mo, int d, int h, int mi, int s) {
  std::tm tm{};
  tm.tm_year = y - 1900;
  tm.tm_mon = mo - 1;
  tm.tm_mday = d;
  tm.tm_hour = h;
  tm.tm_min = mi;
  tm.tm_sec = s;
  return static_cast<int64_t>(timegm(&tm)) * 1000;
}

// 회전 파일 목록 — 이름 규칙 ^<기준 이름>\.(\d{8}-\d{6})(?:\.(\d{1,2}))?$, 시각 → 번호 순(없는 것이 먼저) (29_ §2.3)
std::vector<std::string> rotated_files(const std::string& path) {
  const fs::path p(path);
  const std::string base = p.filename().string();
  const std::regex rx(std::regex_replace(base, std::regex(R"([.^$|()\[\]{}*+?\\])"), R"(\$&)") +
                      R"(\.(\d{8}-\d{6})(?:\.(\d{1,2}))?)");
  std::vector<std::tuple<std::string, int, std::string>> found;
  for (const auto& e : fs::directory_iterator(p.parent_path())) {
    const std::string n = e.path().filename().string();
    std::smatch m;
    if (std::regex_match(n, m, rx)) found.emplace_back(m[1].str(), m[2].matched ? std::stoi(m[2].str()) : 0, e.path().string());
  }
  std::sort(found.begin(), found.end());
  std::vector<std::string> out;
  for (const auto& f : found) out.push_back(std::get<2>(f));
  return out;
}

std::size_t dir_entries(const std::string& dir) {
  return static_cast<std::size_t>(std::distance(fs::directory_iterator(dir), fs::directory_iterator()));
}

// 조건이 참이 될 때까지 기다린다(최대 2 s) — 쓰기 스레드가 처리하는 것을 기다릴 때
template <typename F>
bool wait_for(F cond) {
  for (int i = 0; i < 200; ++i) {
    if (cond()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return cond();
}

std::size_t count_kind(const std::vector<RotateEvent>& evs, Kind k) {
  return static_cast<std::size_t>(std::count_if(evs.begin(), evs.end(), [k](const RotateEvent& e) { return e.kind == k; }));
}

// 주입 시계 — 쓰기 스레드와 시험 스레드가 함께 본다
struct Clock {
  std::atomic<int64_t> now{0};
};

FileOps ops_with(Clock& c) {
  FileOps o = FileOps::system();
  o.now_ms = [&c] { return c.now.load(); };
  return o;
}

EvidenceRecord rec(const std::string& line) { return EvidenceRecord{RecordKind::Evidence, "a", line}; }

}  // namespace

// RT-T1: 증거 — 주기 경계를 넘긴 뒤 레코드. 넘기기 전 레코드는 회전 파일, 뒤 레코드는 새 파일. 이으면 쓴 순서 그대로, 회전 파일
// 끝은 \n. 경계는 파일을 연 뒤의 rotate_s 배수(3,600이면 매시 정각)이고 이름은 회전한 시각(UTC)
TEST(RotatingFile, RT01_EvidenceRotatesAtPeriodBoundary) {
  const std::string dir = fresh_dir("t1");
  const std::string path = dir + "/ev.jsonl";
  Clock c;
  c.now = utc_ms(2026, 11, 8, 9, 59, 59);
  EvidenceQueue q(100);
  EvidenceSink sink(q, path, RotateOptions{3600, 0}, ops_with(c));
  ASSERT_TRUE(sink.start());
  q.push(rec("A"));
  q.push(rec("B"));
  ASSERT_TRUE(wait_for([&] { return sink.written() == 2; }));
  c.now = utc_ms(2026, 11, 8, 9, 59, 59) + 999;  // 경계 1 ms 전 — 회전 없음
  q.push(rec("C"));
  ASSERT_TRUE(wait_for([&] { return sink.written() == 3; }));
  EXPECT_TRUE(rotated_files(path).empty());
  c.now = utc_ms(2026, 11, 8, 10, 0, 0) + 500;
  q.push(rec("D"));
  q.push(rec("E"));
  sink.stop();
  const auto rot = rotated_files(path);
  ASSERT_EQ(rot.size(), 1u);
  EXPECT_EQ(rot[0], path + ".20261108-100000");
  EXPECT_EQ(read_all(rot[0]), "A\nB\nC\n");
  EXPECT_EQ(read_all(path), "D\nE\n");
  EXPECT_EQ(read_all(rot[0]) + read_all(path), "A\nB\nC\nD\nE\n");
  EXPECT_EQ(sink.written(), 5u);
  EXPECT_EQ(sink.dropped(), 0u);
  EXPECT_EQ(sink.rotated(), 1u);
  const auto evs = sink.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, Kind::Rotate);
  EXPECT_EQ(evs[0].reason, "time");
  EXPECT_EQ(evs[0].to, rot[0]);
  EXPECT_EQ(evs[0].bytes, 6u);
}

// RT-T2: 증거 — 경계를 넘겼지만 레코드가 없으면 회전하지 않고 빈 파일도 생기지 않는다 (29_ §2.1 — 스레드 B는 레코드를 기다린다)
TEST(RotatingFile, RT02_EvidenceNoRecordNoRotation) {
  const std::string dir = fresh_dir("t2");
  const std::string path = dir + "/ev.jsonl";
  Clock c;
  c.now = utc_ms(2026, 11, 8, 10, 0, 30);
  EvidenceQueue q(100);
  EvidenceSink sink(q, path, RotateOptions{60, 1048576}, ops_with(c));
  ASSERT_TRUE(sink.start());
  q.push(rec("A"));
  ASSERT_TRUE(wait_for([&] { return sink.written() == 1; }));
  c.now = utc_ms(2026, 11, 8, 11, 0, 0);  // 경계 여러 개를 넘김
  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  sink.stop();
  EXPECT_TRUE(rotated_files(path).empty());
  EXPECT_EQ(dir_entries(dir), 1u);  // 빈 회전 파일 없음
  EXPECT_EQ(read_all(path), "A\n");
  EXPECT_EQ(sink.rotated(), 0u);
  EXPECT_TRUE(sink.take_events().empty());
}

// RT-T2 보충 (11/08 이슈 #102): 빈 파일은 주기 경계를 넘겨도 회전하지 않고 경계만 다시 센다 — 경보가 몇 시간 없다가 처음 날 때
// 빈 회전 파일이 생기지 않게. 내용이 생긴 뒤 다음 경계에서는 회전한다
TEST(RotatingFile, RT02_EmptyFileNotRotatedAtBoundary) {
  const std::string dir = fresh_dir("t2e");
  const std::string path = dir + "/ev.jsonl";
  Clock c;
  c.now = utc_ms(2026, 11, 8, 10, 0, 30);
  RotatingFile f(path, RotateOptions{60, 0}, ops_with(c));
  ASSERT_TRUE(f.open());
  c.now = utc_ms(2026, 11, 8, 13, 0, 10);  // 경계 여러 개를 넘긴 뒤 첫 쓰기 — 파일은 비어 있다
  EXPECT_EQ(f.write("a\n").err, 0);
  EXPECT_TRUE(rotated_files(path).empty());
  EXPECT_EQ(f.rotated(), 0u);
  c.now = utc_ms(2026, 11, 8, 13, 0, 50);  // 다시 센 경계(13:01:00) 전 — 회전 없음
  EXPECT_EQ(f.write("b\n").err, 0);
  EXPECT_TRUE(rotated_files(path).empty());
  c.now = utc_ms(2026, 11, 8, 13, 1, 0);  // 경계 — 내용이 있으므로 회전
  EXPECT_EQ(f.write("c\n").err, 0);
  f.close();
  const auto rot = rotated_files(path);
  ASSERT_EQ(rot.size(), 1u);
  EXPECT_EQ(read_all(rot[0]), "a\nb\n");
  EXPECT_EQ(read_all(path), "c\n");
  EXPECT_EQ(f.rotated(), 1u);
  EXPECT_TRUE(f.take_events().size() == 1u);
}

// RT-T3: 입력 기록 — 크기 상한. 묶음 사이에서만 회전(파일마다 쓰기 호출이 통째로 들어감), 파일은 상한 + 묶음 하나를 넘지 않음
// (묶음 하나뿐인 파일만 상한을 넘을 수 있음), 회전 파일 + 지금 파일을 이으면 넣은 줄 그대로, written·dropped는 실행 전체 합
TEST(RotatingFile, RT03_InputRecorderSizeRotatesBetweenBatches) {
  const std::string dir = fresh_dir("t3s");
  const std::string path = dir + "/input.jsonl";
  Clock c;
  const int64_t t0 = utc_ms(2026, 11, 8, 10, 0, 0);
  c.now = t0;
  FileOps ops = ops_with(c);
  std::vector<std::string> calls;  // 스레드 C의 쓰기 호출 — stop(join) 뒤에 읽는다
  ops.write = [&calls](int fd, const void* b, std::size_t n) {
    const ssize_t w = ::write(fd, b, n);
    if (w > 0) calls.emplace_back(static_cast<const char*>(b), static_cast<std::size_t>(w));
    return w;
  };
  const uint64_t kMax = 64;
  InputRecorder r(path, 1 << 20, RotateOptions{0, kMax}, ops);
  std::string expect;
  for (int i = 0; i < 5; ++i) {  // 시작 전에 넣은 줄은 첫 묶음 하나
    const std::string l = "pre" + std::to_string(i);
    ASSERT_EQ(r.push(l), InputRecorder::Push::Queued);
    expect += l + "\n";
  }
  ASSERT_TRUE(r.start());
  for (int i = 0; i < 200; ++i) {
    c.now = t0 + i * 1000;  // 회전 이름이 대부분 다른 초가 되게
    const std::string l = "line" + std::to_string(1000 + i);
    ASSERT_EQ(r.push(l), InputRecorder::Push::Queued);
    expect += l + "\n";
    if (i % 7 == 0) std::this_thread::sleep_for(std::chrono::milliseconds(1));  // 묶음 크기를 섞는다
  }
  const std::string big(100, 'x');  // 상한보다 긴 줄 — 빈 새 파일에 묶음 하나로
  ASSERT_TRUE(wait_for([&] { return r.queued_bytes() == 0; }));
  ASSERT_EQ(r.push(big), InputRecorder::Push::Queued);
  expect += big + "\n";
  r.stop();

  std::vector<std::string> files = rotated_files(path);
  ASSERT_GE(files.size(), 2u);
  EXPECT_EQ(r.rotated(), files.size());
  files.push_back(path);
  std::string all;
  std::size_t ci = 0;
  for (const std::string& f : files) {
    const std::string body = read_all(f);
    all += body;
    // 이 파일은 쓰기 호출 몇 개가 통째로 이어진 것 — 묶음 중간에서 회전하지 않았다
    std::string acc;
    std::size_t n_calls = 0;
    while (acc.size() < body.size() && ci < calls.size()) {
      acc += calls[ci++];
      ++n_calls;
    }
    EXPECT_EQ(acc, body) << f;
    EXPECT_TRUE(n_calls == 1 || body.size() <= kMax) << f << " size " << body.size() << " calls " << n_calls;
    EXPECT_TRUE(body.empty() || body.back() == '\n') << f;
  }
  EXPECT_EQ(ci, calls.size());
  EXPECT_EQ(all, expect);
  EXPECT_EQ(read_all(path), big + "\n");  // 마지막 긴 줄은 새 파일에 혼자
  EXPECT_EQ(r.written(), 206u);
  EXPECT_EQ(r.dropped(), 0u);
  const auto evs = r.take_events();
  EXPECT_EQ(count_kind(evs, Kind::Rotate), files.size() - 1);
  for (const auto& e : evs) EXPECT_EQ(e.reason, "size");
}

// RT-T3: 입력 기록 — 주기 경계. 경계를 넘긴 뒤 묶음 앞에서 회전한다
TEST(RotatingFile, RT03_InputRecorderTimeRotatesBeforeBatch) {
  const std::string dir = fresh_dir("t3t");
  const std::string path = dir + "/input.jsonl";
  Clock c;
  c.now = utc_ms(2026, 11, 8, 10, 0, 30);
  InputRecorder r(path, 1 << 20, RotateOptions{60, 0}, ops_with(c));
  r.push("a");
  r.push("b");
  ASSERT_TRUE(r.start());
  ASSERT_TRUE(wait_for([&] { return r.written() == 2; }));
  c.now = utc_ms(2026, 11, 8, 10, 1, 0);
  r.push("c");
  ASSERT_TRUE(wait_for([&] { return r.written() == 3; }));
  c.now = utc_ms(2026, 11, 8, 10, 1, 59);  // 같은 주기 안 — 회전 없음
  r.push("d");
  r.stop();
  const auto rot = rotated_files(path);
  ASSERT_EQ(rot.size(), 1u);
  EXPECT_EQ(rot[0], path + ".20261108-100100");
  EXPECT_EQ(read_all(rot[0]), "a\nb\n");
  EXPECT_EQ(read_all(path), "c\nd\n");
  EXPECT_EQ(r.written(), 4u);
  EXPECT_EQ(r.rotated(), 1u);
  const auto evs = r.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].reason, "time");
}

// RT-T4: 이름 충돌 — 같은 초에 여러 번 회전하면 .1, .2가 붙고 이름 순서 = 쓴 순서. .99까지 다 있으면 회전 실패(step=name)이고
// 지금 파일에 계속 쓴다 (29_ §2.3)
TEST(RotatingFile, RT04_NameCollisionSameSecond) {
  const std::string dir = fresh_dir("t4");
  const std::string path = dir + "/ev.jsonl";
  Clock c;
  c.now = utc_ms(2026, 11, 8, 10, 0, 0) + 123;
  RotatingFile f(path, RotateOptions{0, 10}, ops_with(c));
  ASSERT_TRUE(f.open());
  for (const char* l : {"aaaaaaaa\n", "bbbbbbbb\n", "cccccccc\n", "dddddddd\n"}) {
    const auto r = f.write(l);
    EXPECT_EQ(r.err, 0);
    EXPECT_FALSE(r.skipped);
  }
  f.close();
  const std::string ts = path + ".20261108-100000";
  const auto rot = rotated_files(path);
  ASSERT_EQ(rot.size(), 3u);
  EXPECT_EQ(rot[0], ts);
  EXPECT_EQ(rot[1], ts + ".1");
  EXPECT_EQ(rot[2], ts + ".2");
  EXPECT_EQ(read_all(rot[0]) + read_all(rot[1]) + read_all(rot[2]) + read_all(path),
            "aaaaaaaa\nbbbbbbbb\ncccccccc\ndddddddd\n");
  EXPECT_EQ(f.rotated(), 3u);

  // .99까지 다 있으면 실패 — 지금 파일에 계속 씀, 경고 1번, 이름은 그대로
  const std::string dir2 = fresh_dir("t4b");
  const std::string path2 = dir2 + "/ev.jsonl";
  const std::string ts2 = path2 + ".20261108-100000";
  write_file(ts2, "x\n");
  for (int i = 1; i <= 99; ++i) write_file(ts2 + "." + std::to_string(i), "x\n");
  RotatingFile g(path2, RotateOptions{0, 10}, ops_with(c));
  ASSERT_TRUE(g.open());
  g.write("aaaaaaaa\n");
  g.write("bbbbbbbb\n");
  g.close();
  EXPECT_EQ(read_all(path2), "aaaaaaaa\nbbbbbbbb\n");
  EXPECT_EQ(g.rotated(), 0u);
  const auto evs = g.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, Kind::RotateFailed);
  EXPECT_EQ(evs[0].step, "name");
  EXPECT_EQ(dir_entries(dir2), 101u);
}

// RT-T5: 새 파일 열기 실패(주입) — 이름을 되돌리고 옛 파일에 계속 씀, 60초 동안 다시 시도하지 않음, 경고 1번. 60초 뒤 첫 쓰기 때
// 다시 해서 되면 회전 (29_ §2.2)
TEST(RotatingFile, RT05_OpenFailureRenamesBackAndWaits60s) {
  const std::string dir = fresh_dir("t5");
  const std::string path = dir + "/ev.jsonl";
  Clock c;
  c.now = utc_ms(2026, 11, 8, 10, 0, 30);
  FileOps ops = ops_with(c);
  const FileOps sys = FileOps::system();
  bool fail_open = false;
  int renames = 0;
  ops.open_append = [&](const std::string& p) {
    if (fail_open) {
      errno = EMFILE;
      return -1;
    }
    return sys.open_append(p);
  };
  ops.rename = [&](const std::string& a, const std::string& b) {
    ++renames;
    return sys.rename(a, b);
  };
  RotatingFile f(path, RotateOptions{60, 0}, ops);
  ASSERT_TRUE(f.open());
  f.write("a\n");
  fail_open = true;
  c.now = utc_ms(2026, 11, 8, 10, 1, 0);
  EXPECT_EQ(f.write("b\n").err, 0);
  EXPECT_EQ(renames, 2);  // path → 회전 이름, 열기 실패 → 되돌림
  EXPECT_TRUE(rotated_files(path).empty());
  auto evs = f.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, Kind::RotateFailed);
  EXPECT_EQ(evs[0].step, "open");
  EXPECT_FALSE(evs[0].paused);
  EXPECT_NE(evs[0].detail.find("Too many open files"), std::string::npos) << evs[0].detail;
  c.now = utc_ms(2026, 11, 8, 10, 1, 30);
  f.write("c\n");
  c.now = utc_ms(2026, 11, 8, 10, 1, 59) + 999;
  f.write("d\n");
  EXPECT_EQ(renames, 2);  // 60초 동안 다시 시도하지 않음
  EXPECT_TRUE(f.take_events().empty());
  EXPECT_EQ(read_all(path), "a\nb\nc\nd\n");
  fail_open = false;
  c.now = utc_ms(2026, 11, 8, 10, 2, 0);
  f.write("e\n");
  f.close();
  const auto rot = rotated_files(path);
  ASSERT_EQ(rot.size(), 1u);
  EXPECT_EQ(rot[0], path + ".20261108-100200");
  EXPECT_EQ(read_all(rot[0]), "a\nb\nc\nd\n");
  EXPECT_EQ(read_all(path), "e\n");
  evs = f.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, Kind::Rotate);
  EXPECT_EQ(evs[0].reason, "time");
}

// RT-T6: 이름 바꾸기 실패(주입) — 옛 파일에 계속 씀, 경고. 60초 뒤 다시 해서 되면 회전 (29_ §2.2)
TEST(RotatingFile, RT06_RenameFailureKeepsWriting) {
  const std::string dir = fresh_dir("t6");
  const std::string path = dir + "/ev.jsonl";
  Clock c;
  c.now = utc_ms(2026, 11, 8, 10, 0, 0);
  FileOps ops = ops_with(c);
  const FileOps sys = FileOps::system();
  bool fail_rename = true;
  int renames = 0;
  ops.rename = [&](const std::string& a, const std::string& b) {
    ++renames;
    if (fail_rename) {
      errno = EACCES;
      return -1;
    }
    return sys.rename(a, b);
  };
  RotatingFile f(path, RotateOptions{0, 10}, ops);
  ASSERT_TRUE(f.open());
  f.write("aaaaaaaa\n");
  EXPECT_EQ(f.write("bbbbbbbb\n").err, 0);  // 크기 상한 → 회전 시도 → 이름 바꾸기 실패 → 지금 파일에
  EXPECT_EQ(renames, 1);
  auto evs = f.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, Kind::RotateFailed);
  EXPECT_EQ(evs[0].step, "rename");
  EXPECT_NE(evs[0].detail.find("Permission denied"), std::string::npos) << evs[0].detail;
  c.now = utc_ms(2026, 11, 8, 10, 0, 59);
  f.write("cccccccc\n");
  EXPECT_EQ(renames, 1);
  EXPECT_EQ(read_all(path), "aaaaaaaa\nbbbbbbbb\ncccccccc\n");
  EXPECT_TRUE(rotated_files(path).empty());
  fail_rename = false;
  c.now = utc_ms(2026, 11, 8, 10, 1, 0);
  f.write("dddddddd\n");
  f.close();
  const auto rot = rotated_files(path);
  ASSERT_EQ(rot.size(), 1u);
  EXPECT_EQ(read_all(rot[0]), "aaaaaaaa\nbbbbbbbb\ncccccccc\n");
  EXPECT_EQ(read_all(path), "dddddddd\n");
  evs = f.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].reason, "size");
}

// 쓰기 오류 주입 — fail이 켜지면 첫 호출은 partial바이트만 쓰고(반쪽 줄), 그 뒤는 ENOSPC
struct WriteFault {
  std::atomic<bool> fail{false};
  std::atomic<std::size_t> partial{0};
  std::atomic<bool> partial_done{false};
};

FileOps with_write_fault(FileOps o, WriteFault& wf) {
  o.write = [&wf](int fd, const void* b, std::size_t n) -> ssize_t {
    if (wf.fail.load()) {
      if (wf.partial.load() > 0 && !wf.partial_done.exchange(true)) return ::write(fd, b, std::min(n, wf.partial.load()));
      errno = ENOSPC;
      return -1;
    }
    return ::write(fd, b, n);
  };
  return o;
}

// RT-T7: 증거 — 쓰기 오류(주입) 뒤 60초가 지난 첫 레코드에서 새 파일로 다시 씀(reason=reopen). 그사이 레코드는 dropped, 옛 파일
// 끝의 반쪽 줄은 새 파일과 섞이지 않음 (29_ §2.5)
TEST(RotatingFile, RT07_EvidenceWriteErrorReopensAfter60s) {
  const std::string dir = fresh_dir("t7");
  const std::string path = dir + "/ev.jsonl";
  Clock c;
  const int64_t t0 = utc_ms(2026, 11, 8, 10, 0, 0);
  c.now = t0;
  WriteFault wf;
  wf.partial = 3;
  EvidenceQueue q(100);
  EvidenceSink sink(q, path, RotateOptions{3600, 0}, with_write_fault(ops_with(c), wf));
  ASSERT_TRUE(sink.start());
  q.push(rec("AAAA"));
  ASSERT_TRUE(wait_for([&] { return sink.written() == 1; }));
  wf.fail = true;
  q.push(rec("BBBB"));  // 3바이트 쓰고 ENOSPC
  ASSERT_TRUE(wait_for([&] { return sink.dropped() == 1; }));
  EXPECT_TRUE(sink.failed());
  auto evs = sink.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, Kind::WriteError);
  EXPECT_TRUE(evs[0].retry);
  EXPECT_NE(evs[0].detail.find("No space"), std::string::npos);
  wf.fail = false;  // 디스크가 비었다 — 그래도 60초 전에는 쓰지 않는다
  c.now = t0 + 30000;
  q.push(rec("CCCC"));
  ASSERT_TRUE(wait_for([&] { return sink.dropped() == 2; }));
  c.now = t0 + 59999;
  q.push(rec("DDDD"));
  ASSERT_TRUE(wait_for([&] { return sink.dropped() == 3; }));
  EXPECT_TRUE(rotated_files(path).empty());
  c.now = t0 + 60000;
  q.push(rec("EEEE"));
  q.push(rec("FFFF"));
  sink.stop();
  const auto rot = rotated_files(path);
  ASSERT_EQ(rot.size(), 1u);
  EXPECT_EQ(rot[0], path + ".20261108-100100");
  EXPECT_EQ(read_all(rot[0]), "AAAA\nBBB");    // 오류가 난 옛 파일 — 반쪽 줄이 끝에 남음
  EXPECT_EQ(read_all(path), "EEEE\nFFFF\n");  // 새 파일은 반쪽 줄과 섞이지 않음
  EXPECT_EQ(sink.written(), 3u);
  EXPECT_EQ(sink.dropped(), 3u);
  EXPECT_EQ(sink.rotated(), 1u);
  EXPECT_FALSE(sink.failed());
  evs = sink.take_events();
  ASSERT_EQ(evs.size(), 2u);
  EXPECT_EQ(evs[0].kind, Kind::Rotate);
  EXPECT_EQ(evs[0].reason, "reopen");
  EXPECT_EQ(evs[0].to, rot[0]);
  EXPECT_EQ(evs[0].bytes, 8u);
  EXPECT_EQ(evs[1].kind, Kind::Reopen);
  EXPECT_EQ(evs[1].to, path);  // 다시 쓰기 시작한 곳 = 기준 경로
  EXPECT_EQ(evs[1].dropped, 3u);
}

// RT-T7: 입력 기록 — 회전을 켜면 쓰기 오류 뒤에도 push는 받고(DroppedStopped 아님) 스레드 C가 꺼내 버린다. 재개 시도가 실패하면
// 60초 뒤 또 해 보고, 경고(paused)는 그 멈춤에 한 번만 (29_ §2.5, 11/08 이슈 #102)
TEST(RotatingFile, RT07_InputRecorderKeepsDrainingWhilePaused) {
  const std::string dir = fresh_dir("t7i");
  const std::string path = dir + "/input.jsonl";
  Clock c;
  const int64_t t0 = utc_ms(2026, 11, 8, 10, 0, 0);
  c.now = t0;
  WriteFault wf;
  FileOps ops = with_write_fault(ops_with(c), wf);
  const FileOps sys = FileOps::system();
  std::atomic<bool> fail_open{false};
  ops.open_append = [&](const std::string& p) {
    if (fail_open.load()) {
      errno = ENOSPC;
      return -1;
    }
    return sys.open_append(p);
  };
  InputRecorder r(path, 1 << 20, RotateOptions{0, 268435456}, ops);
  ASSERT_TRUE(r.start());
  r.push("a");
  ASSERT_TRUE(wait_for([&] { return r.written() == 1; }));
  wf.fail = true;
  EXPECT_EQ(r.push("b"), InputRecorder::Push::Queued);
  ASSERT_TRUE(wait_for([&] { return r.failed(); }));
  EXPECT_EQ(r.push("c"), InputRecorder::Push::Queued);  // 멈춘 동안에도 받는다 — 스레드 C가 버린다
  ASSERT_TRUE(wait_for([&] { return r.dropped() == 2 && r.queued_bytes() == 0; }));
  // 60초 뒤 첫 시도 — 새 파일 열기 실패: 경고(paused), 버림 계속
  wf.fail = false;
  fail_open = true;
  c.now = t0 + 60000;
  EXPECT_EQ(r.push("d"), InputRecorder::Push::Queued);
  ASSERT_TRUE(wait_for([&] { return r.dropped() == 3; }));
  // 그 뒤 60초 안에는 다시 시도하지 않음
  c.now = t0 + 119999;
  EXPECT_EQ(r.push("e"), InputRecorder::Push::Queued);
  ASSERT_TRUE(wait_for([&] { return r.dropped() == 4; }));
  // 둘째 시도도 열기 실패 — 경고는 다시 나지 않는다
  c.now = t0 + 120000;
  EXPECT_EQ(r.push("f"), InputRecorder::Push::Queued);
  ASSERT_TRUE(wait_for([&] { return r.dropped() == 5; }));
  fail_open = false;
  c.now = t0 + 180000;
  EXPECT_EQ(r.push("g"), InputRecorder::Push::Queued);
  ASSERT_TRUE(wait_for([&] { return r.written() == 2; }));
  r.stop();
  const auto rot = rotated_files(path);
  ASSERT_EQ(rot.size(), 1u);
  EXPECT_EQ(rot[0], path + ".20261108-100300");
  EXPECT_EQ(read_all(rot[0]), "a\n");
  EXPECT_EQ(read_all(path), "g\n");
  EXPECT_EQ(r.dropped(), 5u);
  EXPECT_FALSE(r.failed());
  const auto evs = r.take_events();
  ASSERT_EQ(evs.size(), 4u);
  EXPECT_EQ(evs[0].kind, Kind::WriteError);
  EXPECT_TRUE(evs[0].retry);
  EXPECT_EQ(evs[1].kind, Kind::RotateFailed);
  EXPECT_EQ(evs[1].step, "open");
  EXPECT_TRUE(evs[1].paused);
  EXPECT_EQ(evs[2].kind, Kind::Rotate);
  EXPECT_EQ(evs[2].reason, "reopen");
  EXPECT_EQ(evs[3].kind, Kind::Reopen);
  EXPECT_EQ(evs[3].to, path);
  EXPECT_EQ(evs[3].dropped, 5u);
}

// RT-T7 (11/08 이슈 #102, 29_ §2.5): 디스크가 재시도 5번(5분) 동안 계속 차 있어도 회전 파일은 반쪽 줄을 담은 것 하나, 오류 사건 1번.
// 첫 재시도만 회전하고(지금 파일에 반쪽 줄), 그 뒤 새 파일은 비어 있어 회전 없이 같은 핸들로 다시 쓴다. 공간이 돌아오면 재개 사건
// 1번(to = 회전 파일, dropped = 멈춘 동안 버린 수)
TEST(RotatingFile, RT07_DiskFullManyRetriesOneRotatedFile) {
  const std::string dir = fresh_dir("t7d");
  const std::string path = dir + "/ev.jsonl";
  Clock c;
  const int64_t t0 = utc_ms(2026, 11, 8, 10, 0, 0);
  c.now = t0;
  WriteFault wf;
  wf.partial = 3;
  FileOps ops = with_write_fault(ops_with(c), wf);
  const FileOps sys = FileOps::system();
  int renames = 0;
  ops.rename = [&](const std::string& a, const std::string& b) {
    ++renames;
    return sys.rename(a, b);
  };
  RotatingFile f(path, RotateOptions{3600, 268435456}, ops);
  ASSERT_TRUE(f.open());
  std::size_t dropped = 0;
  auto put = [&](const std::string& line) {  // 증거 기록기처럼 — 쓰지 못한 줄은 버린 수로
    const auto r = f.write(line);
    if (r.skipped || r.err != 0) {
      ++dropped;
      f.note_dropped(1);
    }
    return r;
  };
  EXPECT_EQ(put("AAAA\n").err, 0);
  wf.fail = true;
  EXPECT_EQ(put("BBBB\n").err, ENOSPC);  // 3바이트 쓰고 디스크 가득 — 멈춤
  for (int k = 1; k <= 5; ++k) {
    c.now = t0 + k * 60000 - 30000;
    EXPECT_TRUE(put("skip\n").skipped) << k;  // 60초 전
    c.now = t0 + k * 60000;
    const auto r = put("retry\n");  // 재시도 — 여전히 가득
    EXPECT_FALSE(r.skipped) << k;
    EXPECT_EQ(r.err, ENOSPC) << k;
    EXPECT_TRUE(f.failed()) << k;
  }
  EXPECT_EQ(renames, 1);  // 첫 재시도만 회전
  EXPECT_EQ(f.rotated(), 1u);
  auto evs = f.take_events();
  ASSERT_EQ(evs.size(), 2u);
  EXPECT_EQ(evs[0].kind, Kind::WriteError);
  EXPECT_TRUE(evs[0].retry);
  EXPECT_EQ(evs[1].kind, Kind::Rotate);
  EXPECT_EQ(evs[1].reason, "reopen");
  EXPECT_EQ(evs[1].bytes, 8u);
  const std::string rotated_to = evs[1].to;
  // 공간이 돌아옴 — 마지막 시도 뒤 60초 전에는 쓰지 않고, 60초가 지나면 같은 핸들로 다시 써진다
  wf.fail = false;
  c.now = t0 + 5 * 60000 + 30000;
  EXPECT_TRUE(put("skip\n").skipped);
  c.now = t0 + 6 * 60000;
  const auto ok = put("DDDD\n");
  EXPECT_EQ(ok.err, 0);
  EXPECT_FALSE(ok.skipped);
  EXPECT_FALSE(f.failed());
  EXPECT_EQ(put("EEEE\n").err, 0);
  f.close();
  EXPECT_EQ(dropped, 12u);  // BBBB + 60초 전 5번 + 실패한 재시도 5번 + 공간이 돌아온 뒤 60초 전 1번
  evs = f.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, Kind::Reopen);
  EXPECT_NE(rotated_to, path);  // 반쪽 줄이 든 옛 파일 이름은 회전 사건에
  EXPECT_EQ(evs[0].to, path);
  EXPECT_EQ(evs[0].dropped, 12u);
  const auto rot = rotated_files(path);
  ASSERT_EQ(rot.size(), 1u);
  EXPECT_EQ(rot[0], rotated_to);
  EXPECT_EQ(rot[0], path + ".20261108-100100");
  EXPECT_EQ(read_all(rot[0]), "AAAA\nBBB");  // 반쪽 줄은 회전 파일에만
  EXPECT_EQ(read_all(path), "DDDD\nEEEE\n");
  EXPECT_EQ(f.rotated(), 1u);
}

// RT-T7 (11/08 이슈 #102): 오류 때 지금 파일이 비어 있으면 회전하지 않고 같은 핸들로 다시 쓴다 — 회전 파일 없음, 재개 사건의
// to는 기준 경로
TEST(RotatingFile, RT07_EmptyFileRetriesInPlace) {
  const std::string dir = fresh_dir("t7e");
  const std::string path = dir + "/ev.jsonl";
  Clock c;
  const int64_t t0 = utc_ms(2026, 11, 8, 10, 0, 0);
  c.now = t0;
  WriteFault wf;
  wf.fail = true;
  RotatingFile f(path, RotateOptions{0, 268435456}, with_write_fault(ops_with(c), wf));
  ASSERT_TRUE(f.open());
  EXPECT_EQ(f.write("A\n").err, ENOSPC);
  f.note_dropped(1);
  c.now = t0 + 60000;
  EXPECT_EQ(f.write("A\n").err, ENOSPC);
  f.note_dropped(1);
  wf.fail = false;
  c.now = t0 + 120000;
  EXPECT_EQ(f.write("B\n").err, 0);
  f.close();
  EXPECT_TRUE(rotated_files(path).empty());
  EXPECT_EQ(f.rotated(), 0u);
  EXPECT_EQ(read_all(path), "B\n");
  const auto evs = f.take_events();
  ASSERT_EQ(evs.size(), 2u);
  EXPECT_EQ(evs[0].kind, Kind::WriteError);
  EXPECT_EQ(evs[1].kind, Kind::Reopen);
  EXPECT_EQ(evs[1].to, path);
  EXPECT_EQ(evs[1].dropped, 2u);
}

// RT-T8: 쓰기 오류, 회전 끔 — 지금과 같다: 그 실행 동안 멈춤, 60초가 지나도 다시 하지 않음, 이름을 바꾸지 않음
// (기존 /dev/full 시험 EvidenceSink.WriteErrorStopsAndCounts·InputRecorder.WriteErrorStopsRecording도 그대로 통과)
TEST(RotatingFile, RT08_WriteErrorRotationOffStops) {
  const std::string dir = fresh_dir("t8");
  const std::string path = dir + "/ev.jsonl";
  Clock c;
  c.now = utc_ms(2026, 11, 8, 10, 0, 0);
  WriteFault wf;
  FileOps ops = with_write_fault(ops_with(c), wf);
  int renames = 0;
  ops.rename = [&](const std::string&, const std::string&) {
    ++renames;
    return 0;
  };
  RotatingFile f(path, RotateOptions{}, ops);
  ASSERT_TRUE(f.open());
  EXPECT_EQ(f.write("a\n").err, 0);
  wf.fail = true;
  EXPECT_EQ(f.write("b\n").err, ENOSPC);
  EXPECT_TRUE(f.failed());
  EXPECT_TRUE(f.stopped());
  wf.fail = false;
  c.now += 3600 * 1000;
  EXPECT_TRUE(f.write("c\n").skipped);
  f.close();
  EXPECT_EQ(renames, 0);
  EXPECT_EQ(read_all(path), "a\n");
  const auto evs = f.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, Kind::WriteError);
  EXPECT_FALSE(evs[0].retry);

  // 입력 기록 — 회전 끔이면 오류 뒤 push는 DroppedStopped (24_ §3.3 그대로)
  const std::string path2 = dir + "/input.jsonl";
  WriteFault wf2;
  wf2.fail = true;
  InputRecorder r(path2, 1 << 20, RotateOptions{}, with_write_fault(ops_with(c), wf2));
  r.push("x");
  ASSERT_TRUE(r.start());
  ASSERT_TRUE(wait_for([&] { return r.failed(); }));
  EXPECT_EQ(r.push("y"), InputRecorder::Push::DroppedStopped);
  r.stop();
  EXPECT_EQ(r.dropped(), 2u);
  EXPECT_EQ(r.rotated(), 0u);
}

// RT-T9: 기동 — 끝이 반쪽 줄인 파일이면 첫 줄을 쓰기 전에 회전(partial_tail), 새 줄은 새 파일. 회전 키가 0이어도. 쓰지 않으면
// 회전하지 않고, 끝이 \n이면 회전하지 않는다 (29_ §2.4)
TEST(RotatingFile, RT09_PartialTailRotatesBeforeFirstWrite) {
  const std::string dir = fresh_dir("t9");
  const std::string path = dir + "/ev.jsonl";
  Clock c;
  c.now = utc_ms(2026, 11, 8, 10, 15, 0);
  write_file(path, "old1\nfrag");
  RotatingFile f(path, RotateOptions{}, ops_with(c));  // 회전 키 0
  ASSERT_TRUE(f.open());
  EXPECT_TRUE(rotated_files(path).empty());  // 쓰기 전에는 그대로
  f.write("new1\n");
  f.write("new2\n");
  f.close();
  const auto rot = rotated_files(path);
  ASSERT_EQ(rot.size(), 1u);
  EXPECT_EQ(rot[0], path + ".20261108-101500");
  EXPECT_EQ(read_all(rot[0]), "old1\nfrag");  // 조각은 옛 파일 끝에 남는다(잘라내지 않음)
  EXPECT_EQ(read_all(path), "new1\nnew2\n");
  const auto evs = f.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].reason, "partial_tail");
  EXPECT_EQ(evs[0].bytes, 9u);

  // 끝이 \n이면 이어 쓴다
  const std::string path2 = dir + "/ok.jsonl";
  write_file(path2, "old\n");
  RotatingFile g(path2, RotateOptions{}, ops_with(c));
  ASSERT_TRUE(g.open());
  g.write("new\n");
  g.close();
  EXPECT_TRUE(rotated_files(path2).empty());
  EXPECT_EQ(read_all(path2), "old\nnew\n");

  // 증거 기록기 — 레코드가 없으면 반쪽 줄이어도 회전하지 않는다. 있으면 첫 레코드 전에 회전
  const std::string path3 = dir + "/sink.jsonl";
  write_file(path3, "frag");
  {
    EvidenceQueue q(10);
    EvidenceSink sink(q, path3, RotateOptions{}, ops_with(c));
    ASSERT_TRUE(sink.start());
    sink.stop();
    EXPECT_TRUE(rotated_files(path3).empty());
    EXPECT_EQ(read_all(path3), "frag");
  }
  {
    EvidenceQueue q(10);
    EvidenceSink sink(q, path3, RotateOptions{}, ops_with(c));
    ASSERT_TRUE(sink.start());
    q.push(rec("R"));
    sink.stop();
    EXPECT_EQ(sink.rotated(), 1u);
    const auto r3 = rotated_files(path3);
    ASSERT_EQ(r3.size(), 1u);
    EXPECT_EQ(read_all(r3[0]), "frag");
    EXPECT_EQ(read_all(path3), "R\n");
  }
}

// RT-T10: 일반 파일이 아님(FIFO) — 회전·반쪽 줄 처리 없이 쓰고, 경고(NotRegular)는 한 번. 쓰기 오류면 재개 없이 멈춤.
// 회전을 끈 설정이면 경고도 없다(지금과 같음) (29_ §2.1)
TEST(RotatingFile, RT10_FifoIsNotRotated) {
  const std::string dir = fresh_dir("t10");
  const std::string path = dir + "/fifo";
  ASSERT_EQ(::mkfifo(path.c_str(), 0600), 0);
  const int rd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK);  // 읽는 쪽이 있어야 쓰기 열기가 막히지 않는다
  ASSERT_GE(rd, 0);
  Clock c;
  c.now = utc_ms(2026, 11, 8, 10, 0, 30);
  WriteFault wf;
  FileOps ops = with_write_fault(ops_with(c), wf);
  int renames = 0;
  ops.rename = [&](const std::string&, const std::string&) {
    ++renames;
    errno = EPERM;
    return -1;
  };
  RotatingFile f(path, RotateOptions{60, 16}, ops);
  ASSERT_TRUE(f.open());
  auto evs = f.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, Kind::NotRegular);
  EXPECT_EQ(evs[0].path, path);
  f.write("0123456789abcdef\n");
  c.now = utc_ms(2026, 11, 8, 10, 5, 0);  // 경계도 넘기고 크기도 넘김
  f.write("0123456789abcdef\n");
  char buf[64] = {};
  const ssize_t n = ::read(rd, buf, sizeof(buf));
  EXPECT_EQ(std::string(buf, n > 0 ? static_cast<std::size_t>(n) : 0), "0123456789abcdef\n0123456789abcdef\n");
  EXPECT_EQ(renames, 0);
  EXPECT_TRUE(f.take_events().empty());
  wf.fail = true;
  EXPECT_EQ(f.write("x\n").err, ENOSPC);
  EXPECT_TRUE(f.stopped());  // 일반 파일이 아니면 재개도 끔
  wf.fail = false;
  c.now += 120000;
  EXPECT_TRUE(f.write("y\n").skipped);
  evs = f.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, Kind::WriteError);
  EXPECT_FALSE(evs[0].retry);
  f.close();
  EXPECT_EQ(renames, 0);
  struct stat st {};
  ASSERT_EQ(::lstat(path.c_str(), &st), 0);
  EXPECT_TRUE(S_ISFIFO(st.st_mode));

  // 회전 끔 설정이면 경고 없이 지금처럼
  RotatingFile g(path, RotateOptions{}, ops_with(c));
  ASSERT_TRUE(g.open());
  EXPECT_TRUE(g.take_events().empty());
  g.close();
  ::close(rd);
}

// 지금 파일 없어짐 (11/08 이슈 #102, 29_ §2.2) — 회전하려는데 rename이 ENOENT(주입)면 같은 이름으로 새 파일을 열어 바꾼다. 경고 사건
// Missing 1번, 회전 수에 세지 않음, 회전 실패 아님. 새 파일 기준으로 주기 경계를 다시 센다
TEST(RotatingFile, RemovedFile_RenameEnoentOpensNewFile) {
  const std::string dir = fresh_dir("rm1");
  const std::string path = dir + "/ev.jsonl";
  const std::string other = dir + "/new.jsonl";  // 둘째 열기가 돌려줄 파일 — 핸들이 바뀌었는지 보려고
  Clock c;
  c.now = utc_ms(2026, 11, 8, 10, 0, 30);
  FileOps ops = ops_with(c);
  const FileOps sys = FileOps::system();
  bool enoent = false;
  int renames = 0, opens = 0;
  std::vector<std::string> opened;
  ops.rename = [&](const std::string& a, const std::string& b) {
    ++renames;
    if (enoent) {
      errno = ENOENT;
      return -1;
    }
    return sys.rename(a, b);
  };
  ops.open_append = [&](const std::string& p) {
    opened.push_back(p);
    return sys.open_append(++opens == 1 ? p : other);
  };
  RotatingFile f(path, RotateOptions{60, 0}, ops);
  ASSERT_TRUE(f.open());
  f.write("a\n");
  enoent = true;
  c.now = utc_ms(2026, 11, 8, 10, 1, 0);
  EXPECT_EQ(f.write("b\n").err, 0);
  EXPECT_EQ(renames, 1);
  ASSERT_EQ(opened.size(), 2u);
  EXPECT_EQ(opened[1], path);  // 같은 이름으로 새로 연다(O_APPEND|O_CREAT)
  c.now = utc_ms(2026, 11, 8, 10, 1, 59);  // 새 파일의 경계는 10:02:00 — 회전 없음
  f.write("c\n");
  EXPECT_EQ(renames, 1);
  f.close();
  EXPECT_EQ(read_all(path), "a\n");
  EXPECT_EQ(read_all(other), "b\nc\n");  // 바꾼 핸들에 쓴다
  EXPECT_EQ(f.rotated(), 0u);
  EXPECT_FALSE(f.failed());
  const auto evs = f.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, Kind::Missing);
  EXPECT_EQ(evs[0].path, path);
}

// 지금 파일 없어짐 — 실제 파일 시스템: 증거 기록기가 쓰는 파일을 지운 뒤 주기 경계를 넘기면 다음 레코드는 같은 이름의 새 파일에
TEST(RotatingFile, RemovedFile_UnlinkedThenBoundary) {
  const std::string dir = fresh_dir("rm2");
  const std::string path = dir + "/ev.jsonl";
  Clock c;
  c.now = utc_ms(2026, 11, 8, 10, 0, 30);
  EvidenceQueue q(100);
  EvidenceSink sink(q, path, RotateOptions{60, 0}, ops_with(c));
  ASSERT_TRUE(sink.start());
  q.push(rec("A"));
  ASSERT_TRUE(wait_for([&] { return sink.written() == 1; }));
  ASSERT_EQ(::unlink(path.c_str()), 0);
  c.now = utc_ms(2026, 11, 8, 10, 1, 0);
  q.push(rec("B"));
  q.push(rec("C"));
  sink.stop();
  EXPECT_EQ(read_all(path), "B\nC\n");
  EXPECT_TRUE(rotated_files(path).empty());
  EXPECT_EQ(dir_entries(dir), 1u);
  EXPECT_EQ(sink.rotated(), 0u);
  EXPECT_EQ(sink.written(), 3u);
  const auto evs = sink.take_events();
  ASSERT_EQ(evs.size(), 1u);
  EXPECT_EQ(evs[0].kind, Kind::Missing);
  EXPECT_EQ(evs[0].path, path);
}

// 지금 파일 없어짐 — 쓰기 오류로 멈춘 동안 파일을 지움(공간을 비우려고). 재시도 때 새 파일을 열어 다시 쓴다 — 반쪽 줄이 든 파일
// (비어 있지 않음)이든 빈 파일(링크 수 0으로 앎)이든. 재개 사건의 to는 기준 경로(회전하지 않았으므로)
TEST(RotatingFile, RemovedFile_WhilePaused) {
  for (const std::size_t partial : {std::size_t{3}, std::size_t{0}}) {
    const std::string dir = fresh_dir(partial ? "rm3p" : "rm3e");
    const std::string path = dir + "/ev.jsonl";
    Clock c;
    const int64_t t0 = utc_ms(2026, 11, 8, 10, 0, 0);
    c.now = t0;
    WriteFault wf;
    wf.partial = partial;
    RotatingFile f(path, RotateOptions{0, 268435456}, with_write_fault(ops_with(c), wf));
    ASSERT_TRUE(f.open());
    wf.fail = true;
    EXPECT_EQ(f.write("BBBB\n").err, ENOSPC);
    f.note_dropped(1);
    ASSERT_EQ(::unlink(path.c_str()), 0);
    wf.fail = false;
    c.now = t0 + 60000;
    EXPECT_EQ(f.write("CCCC\n").err, 0) << partial;
    f.close();
    EXPECT_EQ(read_all(path), "CCCC\n") << partial;
    EXPECT_TRUE(rotated_files(path).empty()) << partial;
    EXPECT_EQ(f.rotated(), 0u) << partial;
    const auto evs = f.take_events();
    ASSERT_EQ(evs.size(), 3u) << partial;
    EXPECT_EQ(evs[0].kind, Kind::WriteError);
    EXPECT_EQ(evs[1].kind, Kind::Missing);
    EXPECT_EQ(evs[2].kind, Kind::Reopen);
    EXPECT_EQ(evs[2].to, path);
    EXPECT_EQ(evs[2].dropped, 1u);
  }
}
