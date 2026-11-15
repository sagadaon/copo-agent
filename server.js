'use strict';
/**
 * Agent Games (zkVerify Season 01) — Proof Gatekeeper endpoint.
 *
 * Plain Node.js, no framework. The platform POSTs a signed task envelope
 * (type "agent-games.proof-gatekeeper.v1") to this endpoint; we verify the
 * HMAC signature against the RAW body BEFORE parsing, decide, and respond
 * within the 60-second deadline with a signed JSON decision.
 *
 * Flat layout (phone-friendly): every file lives at the repo root, no
 * subfolders. The circuit artifacts (gatekeeper.wasm / .zkey) are NOT in
 * the repo — they are downloaded from the official site on first start
 * and verified against pinned SHA-256 hashes (see prove.js).
 *
 * Env vars:
 *   HMAC_SECRET          32-byte secret issued at registration (REQUIRED in production)
 *   PORT                 listen port (default 3000; Railway injects its own)
 *   SEEN_FILE            path for the file-backed seen-set (default ./data/seen.json)
 *   ZKVERIFY_CHECK_MODE  stub (default, fail-closed) | mock (local tests) | disabled
 *   PROOF_TIMEOUT_MS     proof-generation budget (default 50000)
 *   CIRCUITS_DIR         override for the circuit artifacts dir (default ./circuits)
 *
 * See README.md for setup, deployment, and the list of things that remain
 * blocked on registration + practice-mode validation.
 */
const http = require('http');
const crypto = require('crypto');
const { decide } = require('./decide');
const { loadSeenSet } = require('./seen');
const { ensureCircuitsOnce } = require('./prove');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HMAC_SECRET = process.env.HMAC_SECRET || '';
const HMAC_CONFIGURED = HMAC_SECRET.length > 0;
const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB — task envelopes are small

if (!HMAC_CONFIGURED) {
  console.log(JSON.stringify({ level: 'warn', msg: 'HMAC_SECRET is not set — using a dummy secret for LOCAL TESTING ONLY. Never deploy like this.' }));
}
const SECRET = HMAC_CONFIGURED ? HMAC_SECRET : 'local-test-only-dummy-secret-do-not-deploy';

const seen = loadSeenSet(process.env.SEEN_FILE || './data/seen.json');
const startedAt = Date.now();

function log(obj) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), ...obj }));
}

function hmacHex(secret, buf) {
  return crypto.createHmac('sha256', secret).update(buf).digest('hex');
}

/**
 * Verify x-agent-games-signature over the raw request body.
 * Accepts hex (64 chars) or base64 encoding — the public docs do not state
 * the encoding, so both are tried. Comparison is timing-safe. Either way the
 * attacker needs the secret, so accepting both encodings is not a hole.
 */
function verifySignature(rawBody, headerValue) {
  if (!headerValue) return false;
  const expected = crypto.createHmac('sha256', SECRET).update(rawBody).digest();
  const v = String(headerValue).trim();
  let provided;
  try {
    if (/^[0-9a-fA-F]{64}$/.test(v)) provided = Buffer.from(v, 'hex');
    else provided = Buffer.from(v, 'base64');
  } catch {
    return false;
  }
  if (provided.length !== expected.length) return false;
  try {
    return crypto.timingSafeEqual(provided, expected);
  } catch {
    return false;
  }
}

function sendJson(res, status, obj, sign) {
  const body = Buffer.from(JSON.stringify(obj));
  const headers = { 'Content-Type': 'application/json', 'Content-Length': body.length };
  if (sign) headers['x-agent-games-signature'] = hmacHex(SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    let failed = false;
    req.on('data', (c) => {
      if (failed) return;
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        failed = true;
        reject(Object.assign(new Error('body too large'), { code: 'TOO_LARGE' }));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => { if (!failed) resolve(Buffer.concat(chunks)); });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', 'http://localhost');
    if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/')) {
      return sendJson(res, 200, {
        status: 'ok',
        service: 'agent-games-gatekeeper',
        uptime_s: Math.floor((Date.now() - startedAt) / 1000),
        hmac_configured: HMAC_CONFIGURED,
        seen_count: seen.size,
        time: new Date().toISOString(),
      }, false);
    }
    if (req.method !== 'POST' || (url.pathname !== '/' && url.pathname !== '/task' && url.pathname !== '/agent')) {
      return sendJson(res, 404, { error: 'not_found' }, false);
    }
    const raw = await readBody(req);
    // 1) HMAC FIRST, before parsing anything.
    if (!verifySignature(raw, req.headers['x-agent-games-signature'])) {
      log({ level: 'warn', msg: 'hmac_rejected', path: url.pathname });
      return sendJson(res, 401, { error: 'invalid_signature' }, false);
    }
    let envelope;
    try {
      envelope = JSON.parse(raw.toString('utf8'));
    } catch {
      return sendJson(res, 400, { error: 'invalid_json' }, true);
    }
    if (!envelope || typeof envelope !== 'object' || envelope.type !== 'agent-games.proof-gatekeeper.v1') {
      return sendJson(res, 400, { error: 'unsupported_envelope', type: envelope && envelope.type }, true);
    }
    const t0 = Date.now();
    const result = await decide(envelope, seen);
    log({
      msg: 'decision',
      task_id: envelope.task_id,
      decision: result.decision,
      reason_code: result.reason_code,
      proof_included: !!result.proof,
      ms: Date.now() - t0,
    });
    return sendJson(res, 200, result, true);
  } catch (err) {
    log({ level: 'error', msg: 'handler_error', error: String((err && err.message) || err) });
    if (!res.headersSent) return sendJson(res, 500, { error: 'internal_error' }, false);
  }
});

server.listen(PORT, () => {
  log({ msg: 'listening', port: PORT, hmac_configured: HMAC_CONFIGURED });
  // Fetch the circuit artifacts in the background; the health endpoint
  // already answers. Proof calls re-check via the same memoized promise,
  // so a slow download only delays proofs, never the server itself.
  ensureCircuitsOnce()
    .then(() => log({ msg: 'circuits_ready' }))
    .catch((e) => log({ level: 'error', msg: 'circuits_not_ready', error: String(e.message) }));
});
