// libFuzzer 없이 퍼즈 하네스를 돌리는 main (16_ W-19 — 이슈 #52). clang의 -fsanitize=fuzzer가 없는 환경(GCC)에서
// 시드 코퍼스 전체와 시드의 결정적 변형(고정 시드 PRNG)을 LLVMFuzzerTestOneInput에 넣는다 — Sanitizer 빌드의 ctest가 매번 돈다.
//   fuzz_x [--per-line] [--mutations N] [--seed S] [--max-len B] 파일|폴더…
//   --per-line: .jsonl은 줄 하나가 입력 하나(parse_line용). 아니면 파일 하나가 입력 하나(바이트 흐름, uds_lines용)
// 변형(1~4개 겹침): 비트 뒤집기·바이트 치환(JSON 특수 문자 포함)·구간 삭제·구간 복제·자르기·다른 시드와 잇기·사전 토큰 끼우기.
// 커버리지 유도는 없다 — 그것은 libFuzzer 모드(README)로
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, std::size_t size);

namespace {

namespace fs = std::filesystem;
using Input = std::vector<uint8_t>;

void add_file(const fs::path& p, bool per_line, std::vector<Input>& inputs) {
  std::ifstream in(p, std::ios::binary);
  if (!in) {
    std::fprintf(stderr, "cannot read %s\n", p.c_str());
    std::exit(2);
  }
  if (per_line && p.extension() == ".jsonl") {
    std::string line;
    while (std::getline(in, line)) inputs.emplace_back(line.begin(), line.end());
    return;
  }
  inputs.emplace_back(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void collect(const std::string& arg, bool per_line, std::vector<Input>& inputs) {
  const fs::path p(arg);
  if (!fs::is_directory(p)) {
    add_file(p, per_line, inputs);
    return;
  }
  std::vector<fs::path> files;
  for (const auto& e : fs::directory_iterator(p))
    if (e.is_regular_file()) files.push_back(e.path());
  std::sort(files.begin(), files.end());  // 결정성 — 폴더 열거 순서는 OS마다 다르다
  for (const auto& f : files) add_file(f, per_line, inputs);
}

// 입력 형식(2_)의 구조를 건드리는 토큰·바이트 — 무작위 바이트만으로는 JSON 파서 안쪽까지 잘 못 간다
const char* const kDict[] = {"null",  "true", "-1", "0", "1e400", "-0.0", "18446744073709551616", "9223372036854775808",
                             "\"",    "\\",   "\\u0000", "\\ud800", "{", "}", "[", "]", ",", ":", "\n", "\"type\"",
                             "\"hello\"", "\"kpm2\"", "\"ue_evt\"", "\"f1_evt\"", "\"ver\":1", "\"seq\"", "\"cell_id\"",
                             "\"t_end_ms\"", "\"ue_evt_lost\"", "\"s_tmsi\":\"0x\"", "\"cells\":null", "\"f\":{",
                             "\"cc\":null", "\"total\":-1", "\"period_ms\":0", "\"du_ue_id\":null"};
const uint8_t kBytes[] = {0, '\n', '\r', '"', '\\', '{', '}', '[', ']', ',', ':', ' ', '-', '.', 'e', 0x7f, 0x80, 0xff};

void mutate(Input& x, const std::vector<Input>& seeds, std::mt19937_64& rng, std::size_t max_len) {
  auto rnd = [&](std::size_t n) { return n == 0 ? std::size_t{0} : static_cast<std::size_t>(rng() % n); };
  const int rounds = 1 + static_cast<int>(rnd(4));
  for (int r = 0; r < rounds; ++r) {
    switch (rnd(8)) {
      case 0:
        if (!x.empty()) x[rnd(x.size())] ^= static_cast<uint8_t>(1u << rnd(8));
        break;
      case 1:
        if (!x.empty()) x[rnd(x.size())] = rnd(2) ? kBytes[rnd(sizeof(kBytes))] : static_cast<uint8_t>(rng());
        break;
      case 2: {  // 구간 삭제
        if (x.empty()) break;
        const std::size_t a = rnd(x.size());
        const std::size_t n = 1 + rnd(std::min<std::size_t>(64, x.size() - a));
        x.erase(x.begin() + static_cast<std::ptrdiff_t>(a), x.begin() + static_cast<std::ptrdiff_t>(a + n));
        break;
      }
      case 3: {  // 구간 복제 — [a, a+n)을 b에 끼움
        if (x.empty()) break;
        const std::size_t a = rnd(x.size());
        const std::size_t n = 1 + rnd(std::min<std::size_t>(64, x.size() - a));
        const std::size_t b = rnd(x.size() + 1);
        const Input seg(x.begin() + static_cast<std::ptrdiff_t>(a), x.begin() + static_cast<std::ptrdiff_t>(a + n));
        x.insert(x.begin() + static_cast<std::ptrdiff_t>(b), seg.begin(), seg.end());
        break;
      }
      case 4:  // 자르기
        if (!x.empty()) x.resize(rnd(x.size()));
        break;
      case 5: {  // 다른 시드와 잇기
        const Input& o = seeds[rnd(seeds.size())];
        if (o.empty()) break;
        x.resize(rnd(x.size() + 1));
        x.insert(x.end(), o.begin() + static_cast<std::ptrdiff_t>(rnd(o.size())), o.end());
        break;
      }
      default: {  // 사전 토큰 끼우기 또는 덮어쓰기
        const char* tok = kDict[rnd(sizeof(kDict) / sizeof(kDict[0]))];
        const std::size_t n = std::strlen(tok);
        const std::size_t b = rnd(x.size() + 1);
        if (rnd(2) || b + n > x.size())
          x.insert(x.begin() + static_cast<std::ptrdiff_t>(b), tok, tok + n);
        else
          std::memcpy(x.data() + b, tok, n);
        break;
      }
    }
    if (x.size() > max_len) x.resize(max_len);
  }
}

}  // namespace

int main(int argc, char** argv) {
  bool per_line = false;
  std::size_t mutations = 0;
  std::size_t max_len = 70000;
  uint64_t seed = 1;
  std::vector<std::string> paths;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&]() -> const char* {
      if (i + 1 >= argc) {
        std::fprintf(stderr, "%s needs a value\n", a.c_str());
        std::exit(2);
      }
      return argv[++i];
    };
    if (a == "--per-line") {
      per_line = true;
    } else if (a == "--mutations") {
      mutations = std::strtoull(next(), nullptr, 10);
    } else if (a == "--seed") {
      seed = std::strtoull(next(), nullptr, 10);
    } else if (a == "--max-len") {
      max_len = std::strtoull(next(), nullptr, 10);
    } else if (a.rfind("--", 0) == 0) {
      std::fprintf(stderr, "unknown option %s\n", a.c_str());
      return 2;
    } else {
      paths.push_back(a);
    }
  }
  if (paths.empty()) {
    std::fprintf(stderr, "usage: %s [--per-line] [--mutations N] [--seed S] [--max-len B] FILE|DIR...\n", argv[0]);
    return 2;
  }
  std::vector<Input> seeds;
  for (const auto& p : paths) collect(p, per_line, seeds);
  if (seeds.empty()) {
    std::fprintf(stderr, "no inputs\n");
    return 2;
  }
  std::size_t runs = 0;
  for (const Input& s : seeds) {
    LLVMFuzzerTestOneInput(s.data(), s.size());
    ++runs;
  }
  std::mt19937_64 rng(seed);
  for (std::size_t i = 0; i < mutations; ++i) {
    Input x = seeds[static_cast<std::size_t>(rng() % seeds.size())];
    mutate(x, seeds, rng, max_len);
    LLVMFuzzerTestOneInput(x.data(), x.size());
    ++runs;
  }
  std::fprintf(stderr, "%s: seeds=%zu mutations=%zu runs=%zu seed=%llu\n", argv[0], seeds.size(), mutations, runs,
               static_cast<unsigned long long>(seed));
  return 0;
}
