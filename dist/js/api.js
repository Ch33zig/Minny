// The one place in the UI that knows whether we are on fixtures or on the API.
//
// ?mock=1  -> fixtures/mock/*   (no backend, works offline, this is the parachute)
// otherwise -> /api/*           (contract in docs/handoff/00-CONTRACTS.md section 12)

const params = new URLSearchParams(location.search);

export const MOCK = params.get('mock') === '1';
const MOCK_BASE = params.get('mockbase') || '../fixtures/mock';
const API_BASE = params.get('api') || '/api';

export const mode = {
  mock: MOCK,
  label: MOCK ? 'MOCK FIXTURES' : 'LIVE API',
  source: MOCK ? MOCK_BASE : API_BASE,
};

class ApiError extends Error {
  constructor(code, message, status) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

async function getJson(url) {
  const res = await fetch(url, { headers: { Accept: 'application/json' } });
  const text = await res.text();
  let body;
  try { body = text ? JSON.parse(text) : null; } catch (err) {
    throw new ApiError('bad_json', `${url} did not return JSON`, res.status);
  }
  if (!res.ok) {
    const e = body && body.error;
    throw new ApiError(e ? e.code : 'http_' + res.status, e ? e.message : res.statusText, res.status);
  }
  return body;
}

const mockCache = new Map();
function mockFile(name) {
  if (!mockCache.has(name)) mockCache.set(name, getJson(`${MOCK_BASE}/${name}`));
  return mockCache.get(name);
}

export const api = {
  caseFile: () => (MOCK ? mockFile('case_file.json') : getJson(`${API_BASE}/case_file`)),
  incidents: () => (MOCK ? mockFile('incidents.json') : getJson(`${API_BASE}/incidents`)),
  baselines: () => (MOCK ? mockFile('baselines.json') : getJson(`${API_BASE}/baselines`)),
  metrics: () => (MOCK ? mockFile('metrics.json') : getJson(`${API_BASE}/metrics`)),
  blueProposals: () => (MOCK ? mockFile('blue_proposals.json') : getJson(`${API_BASE}/blue/proposals`)),
  alerts: () => (MOCK ? mockFile('alerts.json') : Promise.resolve([])),

  async incident(id) {
    if (MOCK) return (await mockFile('incidents.json')).find((i) => i.incident_id === id) || null;
    return getJson(`${API_BASE}/incidents/${encodeURIComponent(id)}`);
  },

  async emailEvidence(ids) {
    if (!ids || !ids.length) return [];
    if (MOCK) {
      const file = await mockFile('email_evidence.json');
      const all = Array.isArray(file) ? file : file.messages || [];
      const want = new Set(ids);
      const hits = all.filter((m) => want.has(m.evidence_id));
      hits.seeded = Array.isArray(file) ? false : !!file.seeded_demo_mailbox;
      hits.disclosure = Array.isArray(file) ? null : file.disclosure;
      return hits;
    }
    // Fails soft: the mailbox is corroboration, never the critical path.
    try {
      return await getJson(`${API_BASE}/evidence/email?ids=${ids.map(encodeURIComponent).join(',')}`);
    } catch (err) {
      return [];
    }
  },

  async redteamGenerate(body) {
    if (MOCK) return mockVariant(body);
    return postJson(`${API_BASE}/redteam/generate`, body);
  },
};

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify(body),
  });
  const payload = await res.json().catch(() => null);
  if (!res.ok) {
    const e = payload && payload.error;
    throw new ApiError(e ? e.code : 'http_' + res.status, e ? e.message : res.statusText, res.status);
  }
  return payload;
}

// ---------------------------------------------------------------- evidence

// `line` is the universal event ID. Every claim in the product resolves through
// here, so it is cached and batched: the expansion has to feel instant.
const lineCache = new Map();
let pending = new Set();
let pendingTimer = null;
let pendingWaiters = [];

export async function resolveLines(lines) {
  const want = (lines || []).filter((n) => Number.isFinite(n));
  const missing = want.filter((n) => !lineCache.has(n));
  if (missing.length) await fetchLines(missing);
  return want.map((n) => lineCache.get(n) || { line: n, raw: null, missing: true });
}

async function fetchLines(lines) {
  if (MOCK) {
    const all = await mockFile('events.json');
    for (const row of all) lineCache.set(row.line, row);
    return;
  }
  lines.forEach((n) => pending.add(n));
  return new Promise((resolve, reject) => {
    pendingWaiters.push({ resolve, reject });
    clearTimeout(pendingTimer);
    pendingTimer = setTimeout(flushLines, 12);
  });
}

async function flushLines() {
  const batch = Array.from(pending).slice(0, 200); // contract caps /api/events at 200
  pending = new Set(Array.from(pending).slice(200));
  const waiters = pendingWaiters;
  pendingWaiters = [];
  try {
    const rows = await getJson(`${API_BASE}/events?lines=${batch.join(',')}`);
    for (const row of rows) lineCache.set(row.line, row);
    waiters.forEach((w) => w.resolve());
  } catch (err) {
    waiters.forEach((w) => w.reject(err));
  }
  if (pending.size) pendingTimer = setTimeout(flushLines, 12);
}

export function seedLines(rows) {
  for (const row of rows || []) if (row && Number.isFinite(row.line)) lineCache.set(row.line, row);
}

// ------------------------------------------------------------------ stream

/**
 * One interface over both stream sources.
 *
 * Mock: fixtures/mock/stream.ndjson replayed on a timer, speed in log-hours per
 * wall-second so the replay control means the same thing in both modes.
 * Live: EventSource on /api/stream, with `seq` watched for gaps after a drop.
 */
export function openStream({ onFrame, onState, speed = 6 }) {
  return MOCK ? mockStream({ onFrame, onState, speed }) : liveStream({ onFrame, onState, speed });
}

function mockStream({ onFrame, onState, speed }) {
  let frames = [];
  let index = 0;
  let running = false;
  let timer = null;
  let rate = speed;
  let lastSeq = null;

  const ready = (async () => {
    const res = await fetch(`${MOCK_BASE}/stream.ndjson`);
    const text = await res.text();
    frames = text.split('\n').filter(Boolean).map((l) => JSON.parse(l));
    onState({ connected: true, source: 'fixture', total: frames.length, running: false });
  })();

  function schedule() {
    if (!running || index >= frames.length) {
      if (index >= frames.length) {
        running = false;
        onState({ connected: true, source: 'fixture', running: false, done: true, index, total: frames.length });
      }
      return;
    }
    const frame = frames[index];
    const next = frames[index + 1];
    const gapMs = next
      ? Math.min(2500, Math.max(70, ((Date.parse(next.ts) - Date.parse(frame.ts)) / 3600000 / rate) * 1000))
      : 400;
    timer = setTimeout(() => {
      index += 1;
      if (lastSeq !== null && frame.seq !== lastSeq + 1) {
        onState({ gap: { expected: lastSeq + 1, got: frame.seq } });
      }
      lastSeq = frame.seq;
      onFrame(frame);
      onState({ connected: true, source: 'fixture', running, index, total: frames.length, cursor_ts: frame.ts });
      schedule();
    }, gapMs);
  }

  return {
    async start() {
      await ready;
      if (running) return;
      running = true;
      onState({ connected: true, source: 'fixture', running: true, index, total: frames.length });
      schedule();
    },
    pause() {
      running = false;
      clearTimeout(timer);
      onState({ connected: true, source: 'fixture', running: false, index, total: frames.length });
    },
    reset() {
      running = false;
      clearTimeout(timer);
      index = 0;
      lastSeq = null;
      onState({ connected: true, source: 'fixture', running: false, reset: true, index: 0, total: frames.length });
    },
    setSpeed(value) { rate = value; },
    close() { running = false; clearTimeout(timer); },
  };
}

function liveStream({ onFrame, onState, speed }) {
  let source = null;
  let lastSeq = null;
  let retry = null;

  function connect() {
    source = new EventSource(`${API_BASE}/stream`);
    source.onopen = () => onState({ connected: true, source: 'sse', running: true });
    source.onmessage = (ev) => {
      let frame;
      try { frame = JSON.parse(ev.data); } catch (err) { return; }
      if (frame.type === 'heartbeat') return onState({ connected: true, source: 'sse', heartbeat: frame.ts });
      if (lastSeq !== null && frame.seq !== lastSeq + 1) {
        onState({ gap: { expected: lastSeq + 1, got: frame.seq } });
      }
      lastSeq = frame.seq;
      onFrame(frame);
    };
    source.onerror = () => {
      onState({ connected: false, source: 'sse', running: false });
      source.close();
      clearTimeout(retry);
      retry = setTimeout(connect, 2000); // the stream will drop at least once tonight
    };
  }

  const control = (action, extra = {}) =>
    postJson(`${API_BASE}/replay/control`, { action, speed_hours_per_second: speed, ...extra })
      .catch((err) => onState({ error: err.message }));

  return {
    async start() { connect(); await control('start'); },
    pause() { control('pause'); },
    reset() { lastSeq = null; control('reset'); },
    setSpeed(value) { speed = value; control('start', { speed_hours_per_second: value }); },
    close() { clearTimeout(retry); if (source) source.close(); },
  };
}

// A mock variant label, so the judge panel is demonstrable with no backend.
// Shaped exactly like section 8 and flagged so nothing can read as a real finding.
function mockVariant(body) {
  const id = 'v_' + String(Math.floor(Math.random() * 9000) + 1000);
  return Promise.resolve({
    variant_id: id,
    seed: null,
    family: body.family || 'F2',
    family_name: 'content_privilege_escalation',
    persona: body.persona || 'careful_insider',
    operators: body.operators || [],
    attacker: body.attacker,
    victim: body.victim,
    target: body.target,
    injected_lines: [],
    first_malicious_line: null,
    first_malicious_ts: null,
    critic: { accepted: true, checks_passed: [], rejected_reason: null },
    mock: true,
  });
}
