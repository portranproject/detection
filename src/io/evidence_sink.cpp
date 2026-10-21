#include "detect/io/evidence_sink.h"

#include <utility>

namespace detect {

EvidenceSink::EvidenceSink(EvidenceQueue& queue, std::string path) : queue_(queue), path_(std::move(path)) {}

EvidenceSink::~EvidenceSink() { stop(); }

bool EvidenceSink::start() {
  // 이어 쓰기 — 다시 기동해도 이전 증거가 지워지지 않게 (결정 F8)
  out_.open(path_, std::ios::out | std::ios::app);
  if (!out_) return false;
  th_ = std::thread([this] { run(); });
  return true;
}

void EvidenceSink::stop() {
  queue_.close();
  if (th_.joinable()) th_.join();
  if (out_.is_open()) out_.close();
}

// 스레드 B 본체: 꺼낸 레코드를 한 줄씩 쓰고, 큐가 비면 flush한다 (결정 F8).
// 판정 쪽(스레드 A)과는 큐로만 이어진다 — 쓰기가 느려도 A는 기다리지 않는다 (1_ NFR-6)
void EvidenceSink::run() {
  EvidenceRecord rec;
  while (queue_.pop(rec)) {
    out_ << rec.line << '\n';
    ++written_;
    if (queue_.size() == 0) out_.flush();
  }
  out_.flush();
}

}  // namespace detect
