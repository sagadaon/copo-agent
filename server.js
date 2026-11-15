/**
 * Agent Games (zkVerify Season 01) — COMBINED endpoint: Proof Gatekeeper +
 * Steal the VFY in one process, one URL.
 *
 * The platform dispatches BOTH track envelopes to ONE registered endpoint,
 * so this server routes purely by envelope shape after HMAC verification:
 *   (a) preflight markers  -> protocol-v1 preflight ack (exact body, signed)
 *   (b) looks-like-turn    -> Steal the VFY handler (strategy + policy proof)
 *   (c) looks-like-task    -> Proof Gatekeeper decision engine
 *   (d) anything else      -> preflight ack
 *
 * Plain Node.js, no framework. HMAC signature is verified against the RAW
 * body BEFORE parsing. All responses that carry a decision/turn/preflight
 * are signed with x-agent-games-signature (HMAC-SHA256 hex over the raw
 * response body).
 *
 * LAZY STEAL INIT: the server NEVER fails startup when STRATEGY_SALT is
 * missing. Gatekeeper + preflight keep working; Steal turns return 503
 * {error:'steal_not_configured'} until the handler exists.
 *
 * Flat layout (phone-friendly): every file lives at the repo root, no
 * subfolders. Circuit artifacts are NOT in the repo — they are downloaded
 * from the official site on first start and verified against pinned SHA-256
 * hashes (see prove.js / prover.js).
 *
 * Env vars:
 *   AGENT_GAMES_HMAC_SECRET  32-byte secret (official name; REQUIRED in production)
 *   HMAC_SECRET              fallback secret name (either one works)
 *   PORT                     listen port (default 3000; Railway injects its own)
 *   SEEN_FILE                path for the file-backed seen-set (default ./data/seen.json)
 *   ZKVERIFY_CHECK_MODE      stub (default, fail-closed) | mock (local tests) | disabled
 *   PROOF_TIMEOUT_MS         proof-generation budget (Gatekeeper default 50000; Steal default 240000)
 *   STRATEGY_PARAMS          e.g. "10,30,0,0,0,0,0,0" (default: 10,30,0,0,0,0,0,0)
 *   STRATEGY_SALT            REQUIRED for Steal; missing salt disables Steal only
 *   KURIER_API_KEY           optional; enables Kurier audit submission (Steal)
 *   CIRCUITS_DIR             override for the Gatekeeper circuit artifacts dir (default ./circuits)
 */
import http from 'node:http';
import crypto from 'node:crypto';
import { decide } from './decide.js';
import { loadSeenSet } from './seen.js';
import { ensureCircuitsOnce as ensureGatekeeperCircuits } from './prove.js';
import { loadConfig } from './config.js';
import { createStealHandler } from './steal-handler.js';

const PORT = parseInt(process.env.PORT || '3000', 10);
const ENV_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || process.env.HMAC_SECRET || '';
const HMAC_CONFIGURED = ENV_SECRET.length > 0;
const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB — task/turn envelopes are small

if (!HMAC_CONFIGURED) {
  console.log(JSON.stringify({ level: 'warn', msg: 'No HMAC secret set (AGENT_GAMES_HMAC_SECRET/HMAC_SECRET) — using a dummy secret for LOCAL TESTING ONLY. Never deploy like this.' }));
}
const SECRET = HMAC_CONFIGURED ? ENV_SECRET : 'local-test-only-dummy-secret-do-not-deploy';

// Protocol-v1 preflight handshake (official /build spec): the platform sends
// a signed preflight request and requires EXACTLY this body, signed with
// x-agent-games-signature over the raw response body.
const PREFLIGHT_BODY = { ok: true, protocolVersion: 'v1' };

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
 * Accepts hex (64 chars, optional "sha256=" prefix) or base64 encoding —
 * the public docs do not state the encoding, so all are tried. Comparison
 * is timing-safe. Either way the attacker needs the secret, so accepting
 * multiple encodings is not a hole.
 */
function verifySignature(rawBody, headerValue) {
  if (!headerValue) return false;
  const expected = crypto.createHmac('sha256', SECRET).update(rawBody).digest();
  const v = String(headerValue).trim().replace(/^sha256=/i, '');
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

function sendCached(res, cached) {
  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(cached.body),
    'x-agent-games-signature': cached.signature,
  });
  res.end(cached.body);
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

// ---------------------------------------------------------------------------
// Lazy Steal init — never kills the process. A missing STRATEGY_SALT (or a
// failed circuit download) only disables Steal; Gatekeeper keeps working.
// ---------------------------------------------------------------------------
let stealHandler = null;
let stealInitError = null;
let stealInitPromise = null;

function initSteal() {
  if (!stealInitPromise) {
    stealInitPromise = (async () => {
      try {
        const stealConfig = loadConfig();
        stealHandler = await createStealHandler(stealConfig);
        log({ msg: 'steal_ready', commitment: stealHandler.commitmentHex });
      } catch (e) {
        stealInitError = e;
        log({ level: 'warn', msg: 'steal_not_configured', error: String(e.message) });
      }
    })();
  }
  return stealInitPromise;
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', 'http://localhost');
    if (req.method === 'GET' && (url.pathname === '/health' || url.pathname === '/' || url.pathname === '/preflight')) {
      return sendJson(res, 200, {
        status: 'ok',
        service: 'agent-games-combined',
        protocolVersion: 'v1',
        uptime_s: Math.floor((Date.now() - startedAt) / 1000),
        hmac_configured: HMAC_CONFIGURED,
        seen_count: seen.size,
        steal_configured: stealHandler !== null,
        commitment: stealHandler ? stealHandler.commitmentHex : null,
        turnsServed: stealHandler ? stealHandler.turnsServed : 0,
        time: new Date().toISOString(),
      }, false);
    }
    if (req.method !== 'POST' || (url.pathname !== '/' && url.pathname !== '/task' && url.pathname !== '/agent' && url.pathname !== '/preflight')) {
      return sendJson(res, 404, { error: 'not_found' }, false);
    }
    const raw = await readBody(req);
    // 1) HMAC FIRST, before parsing anything.
    if (!verifySignature(raw, req.headers['x-agent-games-signature'])) {
      log({ level: 'warn', msg: 'hmac_rejected', path: url.pathname });
      return sendJson(res, 401, { error: 'invalid_signature' }, false);
    }
    // Empty body + valid HMAC: a preflight/probe, not an error.
    if (raw.length === 0) {
      log({ msg: 'preflight_empty_body', path: url.pathname });
      return sendJson(res, 200, PREFLIGHT_BODY, true);
    }
    let envelope;
    try {
      envelope = JSON.parse(raw.toString('utf8'));
    } catch {
      return sendJson(res, 400, { error: 'invalid_json' }, true);
    }

    const isObject = envelope && typeof envelope === 'object';
    // (a) Preflight markers — the platform's signed handshake, any shape.
    const isPreflightShape = isObject && (
      (typeof envelope.type === 'string' && envelope.type.toLowerCase().includes('preflight')) ||
      envelope.preflight === true ||
      envelope.action === 'preflight' ||
      envelope.mode === 'preflight');
    if (isPreflightShape) {
      log({ msg: 'preflight_ack', path: url.pathname, type: envelope.type });
      return sendJson(res, 200, PREFLIGHT_BODY, true);
    }
    // (b) Looks like a Steal turn.
    const looksLikeTurn = isObject && (
      envelope.matchId !== undefined ||
      envelope.match_id !== undefined ||
      envelope.turn !== undefined ||
      envelope.turnNumber !== undefined ||
      envelope.eventId === 'steal-the-vfy');
    if (looksLikeTurn) {
      if (!stealHandler) {
        // Init may still be downloading circuits: wait for it to settle
        // (fast failure when the salt is missing). Never hang a turn on a
        // retry loop — one settled attempt decides it.
        await initSteal();
      }
      if (!stealHandler) {
        log({ level: 'warn', msg: 'steal_turn_rejected_not_configured', matchId: envelope.matchId, turn: envelope.turn });
        return sendJson(res, 503, { error: 'steal_not_configured' }, false);
      }
      const turnEnv = stealHandler.normalizeTurnEnvelope(envelope);
      const problems = stealHandler.validateTurnEnvelope(turnEnv);
      // Diagnostic trace: envelope shape (keys + field types only, never
      // values) + validation outcome, so a future rejection is diagnosable
      // from the Railway logs without guessing the platform's envelope.
      log({
        msg: 'steal_turn_received',
        keys: Object.keys(envelope),
        turnField: typeof envelope.turn,
        matchIdField: typeof envelope.matchId,
        hasState: envelope.state !== undefined,
        hasCommitment: envelope.strategyCommitment !== undefined,
        hasNonce: envelope.nonce !== undefined,
        problems,
      });
      if (problems.length > 0) {
        return sendJson(res, 400, { error: 'invalid turn envelope', problems }, false);
      }
      let result;
      try {
        result = await stealHandler.handleTurn(turnEnv);
      } catch (err) {
        log({ level: 'error', msg: 'steal_turn_handler_error', matchId: turnEnv.matchId, turn: turnEnv.turn, error: err.message });
        return sendJson(res, 500, { error: 'turn_handler_error' }, false);
      }
      if (result.cached) return sendCached(res, result.cached);
      const body = JSON.stringify(result.body);
      if (result.cache && result.status === 200) {
        const signature = hmacHex(SECRET, body);
        stealHandler.cacheResponse(turnEnv.matchId, turnEnv.turn, body, signature);
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'x-agent-games-signature': signature,
        });
        return res.end(body);
      }
      return sendJson(res, result.status, result.body, Boolean(result.sign));
    }
    // (c) Looks like a Gatekeeper task.
    const looksLikeTask = isObject && (
      envelope.type === 'agent-games.proof-gatekeeper.v1' ||
      envelope.task_id !== undefined ||
      envelope.input !== undefined);
    if (looksLikeTask) {
      if (envelope.type !== 'agent-games.proof-gatekeeper.v1') {
        return sendJson(res, 400, { error: 'unsupported_envelope', type: envelope.type }, true);
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
    }
    // (d) Anything else: signed probe — preflight ack.
    log({ msg: 'preflight_ack', path: url.pathname, type: isObject ? envelope.type : typeof envelope });
    return sendJson(res, 200, PREFLIGHT_BODY, true);
  } catch (err) {
    log({ level: 'error', msg: 'handler_error', error: String((err && err.message) || err) });
    if (!res.headersSent) return sendJson(res, 500, { error: 'internal_error' }, false);
  }
});

server.listen(PORT, () => {
  log({ msg: 'listening', port: PORT, hmac_configured: HMAC_CONFIGURED });
  // Fetch the Gatekeeper circuit artifacts in the background; the health
  // endpoint already answers. Proof calls re-check via the same memoized
  // promise, so a slow download only delays proofs, never the server.
  ensureGatekeeperCircuits()
    .then(() => log({ msg: 'gatekeeper_circuits_ready' }))
    .catch((e) => log({ level: 'error', msg: 'gatekeeper_circuits_not_ready', error: String(e.message) }));
  // Steal init runs in the background too and must never kill the process.
  initSteal();
});

for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    log({ msg: 'shutdown', signal: sig });
    server.close(() => process.exit(0));
  });
}
