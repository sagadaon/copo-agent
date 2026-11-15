// server.js — Steal the VFY agent endpoint (plain Node, no framework).
//
// POST {AGENT_PATH} (default /agent): signed turn envelopes + preflight.
// GET  /health: liveness (no auth, no sensitive data).
//
// Request flow for a turn envelope:
//   1. Verify x-agent-games-signature HMAC over the RAW body (before parsing).
//   2. Reject stale/expired envelopes (deadlineAt / issuedAt) and nonce replays.
//   3. Return the cached response for a retried (matchId, turn) — same proof,
//      same idempotencyKey (the platform may retry after network failures).
//   4. Verify the envelope's strategyCommitment.hash equals our computed
//      commitment; on mismatch, log loudly and fall back to HOLD (proving
//      against a different commitment can only produce an invalid proof).
//   5. Decide the action with the circuit-enforced tree (strategy.js).
//   6. Generate the Groth16 policy proof (snarkjs, mutex-serialised) within
//      the remaining deadline budget; on timeout/error, fall back to HOLD.
//   7. Optionally submit the proof to Kurier (best-effort, key-gated).
//   8. Respond with the signed, schema-valid turn response.
//
// UNVERIFIED items (see README.md): the exact field names for the Groth16
// proof material inside policyProof (PROOF_FIELDS below), the exact HMAC
// header encoding (plain hex is sent; hex/base64 with or without a "sha256="
// prefix are accepted inbound), and the scoring of a proof-less HOLD fallback.

import { createServer } from "node:http";
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { access } from "node:fs/promises";
import { loadConfig } from "./config.js";
import {
  ACTION,
  computeCommitment,
  commitmentToHex,
  decideAction,
} from "./strategy.js";
import { computePublicInputsHash, matchIdToBigInt } from "./hash.js";
import { defaultPaths, ensureCircuitsOnce, proveWithTimeout } from "./prover.js";
import { submitToKurier } from "./kurier.js";

// --- UNVERIFIED: policyProof field names for the proof material. -------------
// Docs prose says "attach your policy proof (circuitVersion plus the Groth16
// proof and public_signals)", but the sample response JSON shows only
// circuitVersion / proofReference / publicInputsHash. These camelCase names
// follow the envelope's naming convention. If the first practice turn rejects
// them, rename here — everything else is unaffected.
const PROOF_FIELDS = Object.freeze({ proof: "proof", publicSignals: "publicSignals" });

const MAX_BODY_BYTES = 1_000_000;
const NONCE_TTL_MS = 60 * 60 * 1000;
const CACHE_TTL_MS = 60 * 60 * 1000;
const STALE_ENVELOPE_MS = 15 * 60 * 1000;
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const DEADLINE_MARGIN_MS = 15_000;
const MIN_PROVE_BUDGET_MS = 5_000;

// ---------------------------------------------------------------------------
// HMAC helpers
// ---------------------------------------------------------------------------

function hmacHex(secret, bodyBuffer) {
  return createHmac("sha256", secret).update(bodyBuffer).digest("hex");
}

function safeEqualHex(aHex, bHex) {
  try {
    const a = Buffer.from(aHex, "hex");
    const b = Buffer.from(bHex, "hex");
    return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

function safeEqualBase64(candidate, digestHex) {
  try {
    const a = Buffer.from(candidate, "base64");
    const b = Buffer.from(digestHex, "hex");
    return a.length === b.length && a.length > 0 && timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/** Accept hex (with or without "sha256=" prefix) or base64 encodings. */
function verifySignature(header, bodyBuffer, secret) {
  if (!header || typeof header !== "string") return false;
  const digestHex = hmacHex(secret, bodyBuffer);
  const normalized = header.trim().replace(/^sha256=/i, "");
  if (/^[0-9a-fA-F]{64}$/.test(normalized) && safeEqualHex(normalized, digestHex)) {
    return true;
  }
  return safeEqualBase64(normalized, digestHex);
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

/** Deterministic per (matchId, turn): retries reuse the key, turns never share one. */
export function idempotencyKeyFor(matchId, turn) {
  const hash = createHash("sha256")
    .update(`agent-games:steal:${String(matchId)}:${String(turn)}`)
    .digest("hex");
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-${hash.slice(12, 16)}-${hash.slice(16, 20)}-${hash.slice(20, 32)}`;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

export async function createApp(config) {
  const paths = defaultPaths();
  // Circuit artifacts are not in the repo: download + hash-verify them
  // (and export the VK from the .zkey) before the existence check below.
  await ensureCircuitsOnce(paths);
  for (const p of [paths.wasmPath, paths.zkeyPath, paths.vkPath]) {
    await access(p); // throws at startup if a circuit artifact is missing
  }
  const commitment = await computeCommitment(config.params, config.salt);
  const commitmentHex = commitmentToHex(commitment);

  const seenNonces = new Map(); // nonce -> { matchId, turn, expiresAt }
  const responseCache = new Map(); // "matchId:turn" -> { body, signature, expiresAt }
  let turnsServed = 0;

  function prune(map, now) {
    for (const [k, v] of map) if (v.expiresAt <= now) map.delete(k);
    if (map.size > 10000) {
      // Hard bound: drop oldest entries (Map preserves insertion order).
      for (const k of map.keys()) {
        if (map.size <= 10000) break;
        map.delete(k);
      }
    }
  }

  function sendJson(res, status, obj, { sign = false } = {}) {
    const body = JSON.stringify(obj);
    const headers = { "content-type": "application/json" };
    if (sign) headers["x-agent-games-signature"] = hmacHex(config.hmacSecret, body);
    res.writeHead(status, headers);
    res.end(body);
  }

  function sendCached(res, cached) {
    res.writeHead(200, {
      "content-type": "application/json",
      "x-agent-games-signature": cached.signature,
    });
    res.end(cached.body);
  }

  /** HOLD fallback: signed, schema-valid, no proof fields, fresh timestamp. */
  function holdFallback(envelope) {
    const { matchId, turn, state } = envelope;
    const publicInputsHash = computePublicInputsHash({
      commitment: commitmentHex,
      matchId,
      turn,
      selfBalance: state.selfBalance,
      opponentBalance: state.opponentBalance,
      action: "HOLD",
      amount: 0,
      circuitVersion: config.circuitVersion,
    });
    return {
      matchId,
      turn,
      action: { type: "HOLD" }, // NEVER include amount for HOLD/FORTIFY
      policyProof: {
        circuitVersion: config.circuitVersion,
        publicInputsHash,
      },
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: idempotencyKeyFor(matchId, turn),
    };
  }

  function validateTurnEnvelope(env) {
    const problems = [];
    if (env.protocolVersion !== "v1") problems.push("protocolVersion must be 'v1'");
    if (env.eventId !== "steal-the-vfy") problems.push("eventId must be 'steal-the-vfy'");
    if (typeof env.matchId !== "string" || env.matchId === "") {
      problems.push("matchId must be a non-empty string");
    }
    if (env.turn === undefined || env.turn === null || !/^-?\d+$/.test(String(env.turn))) {
      problems.push("turn must be an integer");
    }
    const st = env.state;
    if (!st || typeof st !== "object") {
      problems.push("state is required");
    } else {
      for (const k of ["selfBalance", "opponentBalance"]) {
        if (st[k] === undefined || !/^\d+$/.test(String(st[k]))) {
          problems.push(`state.${k} must be a non-negative integer`);
        }
      }
    }
    const hash = env.strategyCommitment?.hash;
    if (typeof hash !== "string" || !/^0x[0-9a-fA-F]+$/.test(hash)) {
      problems.push("strategyCommitment.hash must be a 0x-hex string");
    }
    if (typeof env.nonce !== "string" || env.nonce === "") {
      problems.push("nonce must be a non-empty string");
    }
    return problems;
  }

  async function handleTurn(env) {
    const { matchId, turn } = env;
    const cacheKey = `${String(matchId)}:${String(turn)}`;
    const now = Date.now();

    // Freshness: reject expired / stale envelopes.
    if (env.deadlineAt) {
      const deadline = Date.parse(env.deadlineAt);
      if (Number.isFinite(deadline) && now > deadline) {
        return { status: 410, body: { error: "turn deadline already passed" } };
      }
    }
    if (env.issuedAt) {
      const issued = Date.parse(env.issuedAt);
      if (Number.isFinite(issued)) {
        if (now - issued > STALE_ENVELOPE_MS) {
          return { status: 400, body: { error: "stale envelope (issuedAt too old)" } };
        }
        if (issued - now > FUTURE_SKEW_MS) {
          return { status: 400, body: { error: "envelope issuedAt too far in the future" } };
        }
      }
    }

    // Nonce replay guard + retry cache.
    prune(seenNonces, now);
    prune(responseCache, now);
    const prior = seenNonces.get(env.nonce);
    if (prior && (prior.matchId !== matchId || String(prior.turn) !== String(turn))) {
      return { status: 409, body: { error: "nonce replay: nonce seen for a different turn" } };
    }
    seenNonces.set(env.nonce, { matchId, turn, expiresAt: now + NONCE_TTL_MS });
    const cached = responseCache.get(cacheKey);
    if (cached) return { status: 200, cached };

    // Commitment check: the envelope's frozen hash must equal ours.
    let envelopeCommitment;
    try {
      envelopeCommitment = BigInt(env.strategyCommitment.hash);
    } catch {
      return { status: 400, body: { error: "strategyCommitment.hash is not parseable" } };
    }
    if (envelopeCommitment !== commitment) {
      console.error(
        `[turn ${matchId} #${turn}] COMMITMENT MISMATCH: envelope=${env.strategyCommitment.hash} computed=${commitmentHex}. ` +
          "Dashboard registration does not match STRATEGY_PARAMS/STRATEGY_SALT; falling back to HOLD. Re-register the commitment before the next round.",
      );
      return { status: 200, body: holdFallback(env), sign: true, cache: true };
    }

    const decision = decideAction(env.state, config.params);
    console.log(
      `[turn ${matchId} #${turn}] state self=${env.state.selfBalance} opp=${env.state.opponentBalance} ` +
        `fortifiedUntil self=${env.state.selfFortifiedUntilTurn} opp=${env.state.opponentFortifiedUntilTurn} -> ${decision.type}` +
        (decision.amount !== null ? ` amount=${decision.amount}` : ""),
    );

    // Deadline budget for proving.
    const deadlineMs = env.deadlineAt ? Date.parse(env.deadlineAt) : now + 300_000;
    const budgetMs = Math.min(
      config.proofTimeoutMs,
      (Number.isFinite(deadlineMs) ? deadlineMs : now + 300_000) - now - DEADLINE_MARGIN_MS,
    );
    if (budgetMs <= MIN_PROVE_BUDGET_MS) {
      console.warn(`[turn ${matchId} #${turn}] insufficient deadline budget (${budgetMs}ms); HOLD fallback`);
      return { status: 200, body: holdFallback(env), sign: true, cache: true };
    }

    const circuitInput = {
      commitment: commitment.toString(),
      matchId: matchIdToBigInt(matchId).toString(),
      turnNumber: String(env.turn),
      selfBalance: String(env.state.selfBalance),
      opponentBalance: String(env.state.opponentBalance),
      action: String(decision.code),
      amount: String(decision.amount ?? 0),
      circuitVersion: String(config.circuitVersionNumber),
      salt: config.salt.toString(),
      strategyParams: config.params.map(String),
    };

    let proofResult;
    try {
      proofResult = await proveWithTimeout(circuitInput, budgetMs, paths);
    } catch (err) {
      console.error(`[turn ${matchId} #${turn}] proof failed (${err.message}); HOLD fallback`);
      return { status: 200, body: holdFallback(env), sign: true, cache: true };
    }
    console.log(`[turn ${matchId} #${turn}] proof generated in ${proofResult.proveMs}ms`);

    const publicInputsHash = computePublicInputsHash({
      commitment: commitmentHex,
      matchId,
      turn: env.turn,
      selfBalance: env.state.selfBalance,
      opponentBalance: env.state.opponentBalance,
      action: decision.type,
      amount: decision.amount ?? 0,
      circuitVersion: config.circuitVersion,
    });

    const policyProof = {
      circuitVersion: config.circuitVersion,
      [PROOF_FIELDS.proof]: proofResult.proof,
      [PROOF_FIELDS.publicSignals]: proofResult.publicSignals,
      publicInputsHash,
    };
    const proofReference = await submitToKurier({
      apiKey: config.kurierApiKey,
      proof: proofResult.proof,
      publicSignals: proofResult.publicSignals,
    });
    if (proofReference) policyProof.proofReference = proofReference;

    const action =
      decision.type === "EXTRACT"
        ? { type: "EXTRACT", amount: decision.amount }
        : { type: decision.type }; // NEVER include amount for HOLD/FORTIFY

    const body = {
      matchId,
      turn: env.turn,
      action,
      policyProof,
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: idempotencyKeyFor(matchId, turn),
    };
    turnsServed += 1;
    return { status: 200, body, sign: true, cache: true };
  }

  function readRawBody(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let total = 0;
      req.on("data", (chunk) => {
        total += chunk.length;
        if (total > MAX_BODY_BYTES) {
          reject(new Error("body too large"));
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => resolve(Buffer.concat(chunks)));
      req.on("error", reject);
    });
  }

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, "http://localhost");
      if (req.method === "GET" && (url.pathname === "/health" || url.pathname === "/")) {
        return sendJson(res, 200, {
          ok: true,
          service: "steal-the-vfy-agent",
          protocolVersion: "v1",
          circuitVersion: config.circuitVersion,
          commitment: commitmentHex,
          turnsServed,
          uptimeSeconds: Math.floor(process.uptime()),
        });
      }
      if (req.method !== "POST" || url.pathname !== config.agentPath) {
        return sendJson(res, 404, { error: "not found" });
      }

      const rawBody = await readRawBody(req);

      // Verify the signature over the RAW body BEFORE parsing.
      if (!verifySignature(req.headers["x-agent-games-signature"], rawBody, config.hmacSecret)) {
        return sendJson(res, 401, { error: "invalid signature" });
      }

      let env;
      try {
        env = JSON.parse(rawBody.toString("utf8"));
      } catch {
        return sendJson(res, 400, { error: "body is not valid JSON" });
      }
      if (!env || typeof env !== "object") {
        return sendJson(res, 400, { error: "body must be a JSON object" });
      }

      // Preflight: platform checks the endpoint before any task.
      if (env.type === "agent-games.preflight.v1") {
        return sendJson(res, 200, { ok: true, protocolVersion: "v1" }, { sign: true });
      }

      const problems = validateTurnEnvelope(env);
      if (problems.length > 0) {
        return sendJson(res, 400, { error: "invalid turn envelope", problems });
      }

      const result = await handleTurn(env);
      if (result.cached) return sendCached(res, result.cached);
      const body = JSON.stringify(result.body);
      if (result.cache && result.status === 200) {
        const signature = hmacHex(config.hmacSecret, body);
        responseCache.set(`${String(env.matchId)}:${String(env.turn)}`, {
          body,
          signature,
          expiresAt: Date.now() + CACHE_TTL_MS,
        });
        res.writeHead(200, {
          "content-type": "application/json",
          "x-agent-games-signature": signature,
        });
        return res.end(body);
      }
      return sendJson(res, result.status, result.body, { sign: Boolean(result.sign) });
    } catch (err) {
      console.error("[server] unexpected error:", err);
      if (!res.headersSent) sendJson(res, 500, { error: "internal error" });
    }
  });

  return {
    server,
    commitment,
    commitmentHex,
    start() {
      return new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(config.port, "0.0.0.0", () => {
          console.log(`[steal] listening on 0.0.0.0:${config.port} (POST ${config.agentPath})`);
          console.log(`[steal] strategyParams: ${JSON.stringify(config.params)}`);
          console.log(`[steal] commitment (hex): ${commitmentHex}`);
          console.log("[steal] The commitment above MUST match the dashboard registration.");
          resolve();
        });
      });
    },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let app;
  try {
    const config = loadConfig();
    app = await createApp(config);
    await app.start();
  } catch (err) {
    console.error("[steal] startup failed:", err.message);
    process.exit(1);
  }
  for (const sig of ["SIGTERM", "SIGINT"]) {
    process.on(sig, () => {
      console.log(`[steal] ${sig} received; shutting down`);
      app.server.close(() => process.exit(0));
    });
  }
}
