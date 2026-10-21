#include "detect/diag.h"

namespace detect {

const char* to_string(DiagKind kind) {
  switch (kind) {
    case DiagKind::LineTooLong: return "line_too_long";
    case DiagKind::FormatError: return "format_error";
    case DiagKind::UnsupportedVersion: return "unsupported_version";
    case DiagKind::Warning: return "warning";
    case DiagKind::KpmBeforeHello: return "kpm_before_hello";
    case DiagKind::ForeignSession: return "foreign_session";
    case DiagKind::SeqGap: return "seq_gap";
    case DiagKind::SeqRegress: return "seq_regress";
    case DiagKind::SessionStarted: return "session_started";
    case DiagKind::SessionReset: return "session_reset";
    case DiagKind::SessionResumed: return "session_resumed";
    case DiagKind::CellUnknown: return "cell_unknown";
    case DiagKind::CellLimit: return "cell_limit";
    case DiagKind::CellGap: return "cell_gap";
    case DiagKind::CellOverlap: return "cell_overlap";
    case DiagKind::PeriodMismatch: return "period_mismatch";
    case DiagKind::RuleInactive: return "rule_inactive";
    case DiagKind::RuleResumed: return "rule_resumed";
    case DiagKind::ModeChanged: return "mode_changed";
    case DiagKind::BaselineLow: return "baseline_low";
  }
  return "unknown";
}

}  // namespace detect
