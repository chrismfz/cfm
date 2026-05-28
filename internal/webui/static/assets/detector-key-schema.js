const BOOL_VALUES = ['0', '1', 'no', 'yes', 'false', 'true', 'off', 'on'];

export const detectorKeySchema = {
  ENABLED: {
    type: 'bool',
    allowed: BOOL_VALUES,
    examples: ['1', '0', 'yes'],
    help: 'Enable or disable this detector section.',
    required: true,
  },
  EVERY: {
    type: 'duration',
    examples: ['20s', '1m'],
    help: 'Polling interval between detector runs.',
  },
  TIMEOUT: {
    type: 'duration',
    examples: ['8s', '30s'],
    help: 'Timeout for detector command/log reads.',
  },
  COOLDOWN: {
    type: 'duration',
    examples: ['10m', '1h'],
    help: 'Minimum delay before a duplicate alert can fire again.',
  },
  WINDOW: {
    type: 'duration',
    examples: ['15m', '30m'],
    help: 'Sliding time window for counting events.',
  },
  TTL: {
    type: 'duration',
    examples: ['10m', '24h'],
    help: 'Time-to-live for temporary mitigation items.',
  },
  BLOCK: {
    type: 'duration_or_enum',
    allowed: ['no', 'off', '0', 'dryrun', 'alert', 'permanent', 'perm'],
    examples: ['30m', 'dryrun', 'permanent'],
    help: 'Blocking mode: disable, dry-run, permanent, or timed duration.',
  },
  BLOCK_COOLDOWN: {
    type: 'duration',
    examples: ['10m', '1h'],
    help: 'Do not block the same source again before this delay.',
  },
  SLOW_FAIL_BLOCK: {
    type: 'int',
    examples: ['6', '10'],
    help: 'Threshold count before triggering slow-fail block handling.',
  },
  SEND_TO_API: {
    type: 'bool',
    allowed: BOOL_VALUES,
    examples: ['0', '1', 'no'],
    help: 'Whether this detector should send events to the API.',
  },
  SEND_TO_BLOCKLIST: {
    type: 'enum',
    allowed: ['lenient', 'blacklist', 'no'],
    examples: ['lenient'],
    help: 'Leniency only: destination list when SEND_TO_API=yes. "lenient" records matched blocks centrally for visibility (never propagated to the farm); blacklist/no use the global blocklist. No effect when SEND_TO_API=no.',
  },
  MODE: {
    type: 'enum',
    allowed: ['journal', 'file', 'docker'],
    examples: ['journal', 'file', 'docker'],
    help: 'Data source mode for detector input.',
  },
  LOG_PATH: {
    type: 'string',
    examples: ['/var/log/mail.log'],
    help: 'Path of the log file used by the detector.',
  },
  JOURNAL_UNIT: {
    type: 'string',
    examples: ['postfix@-.service'],
    help: 'Systemd journal unit name.',
  },
  JOURNAL_MATCHES: {
    type: 'list',
    examples: ['_SYSTEMD_UNIT=postfix@-.service'],
    help: 'Comma-separated or newline-separated journal match filters.',
  },
  MATCH_TARGET: {
    type: 'enum',
    allowed: ['auto', 'ip', 'user', 'both'],
    examples: ['both', 'ip'],
    help: 'How FAIL_REGEX named captures are interpreted for counters and blocking targets.',
  },
  FAIL_REGEX: {
    type: 'regex_multiline',
    examples: ['Failed password for .* from (?P<ip>\\S+)', 'authentication failure.*rhost=(?P<ip>\\S+)'],
    help: 'One regex per line. Use named captures (?P<ip>...) and optionally (?P<user>...).',
  },
  IGNORE_REGEX: {
    type: 'regex_multiline',
    examples: ['^Accepted password', '^session opened for user'],
    help: 'Optional ignore filters, one regex per line.',
  },
  AUTHFAIL_IP: {
    type: 'int',
    examples: ['20', '10'],
    help: 'Threshold of matched failures per source IP within WINDOW.',
  },
  AUTHFAIL_USER: {
    type: 'int',
    examples: ['10', '5'],
    help: 'Threshold of matched failures per user within WINDOW.',
  },
  ENRICH: {
    type: 'bool',
    allowed: BOOL_VALUES,
    examples: ['1', '0'],
    help: 'Enable GeoIP/PTR enrichment.',
  },
  PTR: {
    type: 'bool',
    allowed: BOOL_VALUES,
    examples: ['1', '0'],
    help: 'Enable PTR lookups for source IPs.',
  },
  ENRICH_DIRS: {
    type: 'list',
    examples: ['/var/lib/cfm/maxmind'],
    help: 'Directories searched for enrichment databases.',
  },
  IGNORE_IPS: {
    type: 'list',
    examples: ['127.0.0.1,10.0.0.1'],
    help: 'IP allowlist ignored by detectors.',
  },
  IGNORE_NETS: {
    type: 'list',
    examples: ['10.0.0.0/8,192.168.0.0/16'],
    help: 'CIDR networks ignored by detectors.',
  },
  SAMPLE_LIMIT: {
    type: 'int',
    examples: ['10', '25'],
    help: 'Maximum sample lines included in alert payloads.',
  },
};

const durationFamilyToken = ['EVERY', 'TIMEOUT', 'COOLDOWN', 'WINDOW', 'TTL'];
const thresholdBlockKeys = new Set(['SLOW_FAIL_BLOCK']);

export function lookupDetectorKeySchema(key) {
  if (!key) return null;
  const upper = String(key).toUpperCase();
  if (detectorKeySchema[upper]) return detectorKeySchema[upper];
  if (upper === 'BLOCK') return detectorKeySchema.BLOCK;
  if (upper.endsWith('_BLOCK') && thresholdBlockKeys.has(upper)) {
    return detectorKeySchema[upper];
  }
  if (durationFamilyToken.some((t) => upper.includes(t))) {
    return { type: 'duration', examples: ['30s', '10m'], help: 'Expected Go-style duration (e.g. 30s, 10m, 1h).' };
  }
  return null;
}

export function normalizeSchemaValue(v = '') {
  const s = String(v).trim();
  if (s.startsWith('"') && s.endsWith('"') && s.length >= 2) {
    return s.slice(1, -1);
  }
  return s;
}
