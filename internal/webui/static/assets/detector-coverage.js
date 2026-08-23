// detector-coverage.js — pure presentation helpers for the daemon-coverage
// matrix on the Detectors page (GET /api/v1/detectors/coverage). Verdicts are
// host-reality aware: "absent" means the daemon AND its detector are both
// missing, which is informational rather than a problem — it must NOT render
// as an error.

const VERDICT_BY_SUMMARY_KEY = {
  ok: 'ok',
  gaps: 'gap',
  disabled: 'disabled',
  dormant: 'dormant',
  absent: 'absent',
  event_driven: 'na',
};

export function coverageBadge(verdict) {
  switch (String(verdict || '').toLowerCase()) {
    case 'ok':
      return { cls: 'pill ok', label: 'OK', title: 'Daemon running and detector enabled' };
    case 'gap':
      return { cls: 'pill danger', label: 'GAP', title: 'Daemon is running but no section enables this detector' };
    case 'disabled':
      return { cls: 'pill warn', label: 'disabled', title: 'Daemon running, but every section has ENABLED=0' };
    case 'dormant':
      return { cls: 'pill warn', label: 'dormant', title: 'Detector enabled but its daemon is absent or stopped' };
    case 'absent':
      return { cls: 'pill', label: 'absent', title: 'Daemon not on this host and detector not configured — informational' };
    case 'na':
      return { cls: 'pill info', label: 'n/a', title: 'Event-driven detector (no daemon)' };
    default:
      return { cls: 'pill', label: String(verdict || '?'), title: '' };
  }
}

export function coverageSummaryItems(summary) {
  const s = summary || {};
  return Object.entries(VERDICT_BY_SUMMARY_KEY).map(([key, verdict]) => {
    const badge = coverageBadge(verdict);
    const count = Number(s[key] || 0);
    return { key, count, cls: badge.cls, title: badge.title, label: `${badge.label}: ${count}` };
  });
}

export function unitStateText(unit) {
  const u = unit || {};
  if (!u.found) return `${u.unit || '?'}: not installed`;
  if (!u.active) return `${u.unit || '?'}: stopped`;
  return `${u.unit || '?'}: running`;
}
