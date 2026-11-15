// config.js — environment configuration. Fails fast on missing/invalid config.
//
// Env vars:
//   AGENT_GAMES_HMAC_SECRET (official name) or HMAC_SECRET (fallback) — REQUIRED.
//     From the dashboard ("Rotate Secret"). Used to verify incoming signatures
//     and sign responses. Never log it.
//   STRATEGY_PARAMS — e.g. "10,30,0,0,0,0,0,0". Default: the DEFAULT_PARAMS
//     in strategy.js. See strategy.js for semantics and tuning.
//   STRATEGY_SALT — REQUIRED. Any integer (decimal or 0x-hex). Private input
//     to the commitment hash; keep it secret, never log it, never commit it.
//     Changing it changes the commitment — re-register the new hash first.
//   PORT — default 3000 (Railway sets PORT automatically).
//   AGENT_PATH — POST path for turn envelopes. Default "/agent".
//   PROOF_TIMEOUT_MS — max time to wait for proof generation per turn.
//     Default 240000 (4 min; the turn deadline is 5 min). The effective budget
//     is also capped by the envelope's deadlineAt minus a safety margin.
//   KURIER_API_KEY — optional; enables Kurier audit submission (see kurier.js).
//   CIRCUIT_WASM / CIRCUIT_ZKEY / CIRCUIT_VK — optional overrides; defaults
//     point at ./circuits/.

import { parseParams, parseSalt } from "./strategy.js";

function requiredSecret() {
  const secret = process.env.AGENT_GAMES_HMAC_SECRET || process.env.HMAC_SECRET;
  if (!secret || secret.trim() === "") {
    throw new Error(
      "Missing HMAC secret: set AGENT_GAMES_HMAC_SECRET (or HMAC_SECRET) from the dashboard",
    );
  }
  return secret;
}

export function loadConfig(env = process.env) {
  const params = parseParams(env.STRATEGY_PARAMS);
  const salt = parseSalt(env.STRATEGY_SALT);
  const proofTimeoutMs = env.PROOF_TIMEOUT_MS
    ? Number(env.PROOF_TIMEOUT_MS)
    : 240_000;
  if (!Number.isFinite(proofTimeoutMs) || proofTimeoutMs <= 0) {
    throw new Error("PROOF_TIMEOUT_MS must be a positive number of milliseconds");
  }
  return Object.freeze({
    hmacSecret: requiredSecret(),
    params,
    salt,
    port: Number(env.PORT || 3000),
    agentPath: env.AGENT_PATH || "/agent",
    proofTimeoutMs,
    kurierApiKey: env.KURIER_API_KEY || "",
    circuitVersion: "v1",
    circuitVersionNumber: 1,
  });
}
