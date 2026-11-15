// steal-handler.js — Steal the VFY turn handling, extracted verbatim from the
// standalone Steal server.js createApp() into a factory, so one combined
// process can serve both tracks. Logic preserved EXACTLY: deterministic
// decision tree, snarkjs proving, idempotency cache, Kurier best-effort,
// response schema {matchId, turn, action, policyProof, agentTimestamp,
// idempotencyKey}.
//
// The factory is async: it downloads + hash-verifies the vfy-policy circuit
// artifacts and computes the strategy commitment before resolving. Callers
// MUST wrap createStealHandler in try/catch — a missing STRATEGY_SALT or a
// failed circuit download must never kill the combined process (Gatekeeper
// keeps working; Steal turns get 503 until the handler exists).

import { createHash } from "node:crypto";
import { access } from "node:fs/promises";
import {
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

const NONCE_TTL_MS = 60 * 60 * 1000;
const CACHE_TTL_MS = 60 * 60 * 1000;
const STALE_ENVELOPE_MS = 15 * 60 * 1000;
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const DEADLINE_MARGIN_MS = 15_000;
const MIN_PROVE_BUDGET_MS = 5_000;

/** Deterministic per (matchId, turn): retries reuse the key, turns never share one. */
export function idempotencyKeyFor(matchId, turn) {
  const hash = createHash("sha256")
    .update(`agent-games:steal:${String(matchId)}:${String(turn)}`)
    .digest("hex");
  return `${hash.slice(0, 8)}-${hash.slice(8, 12)}-${hash.slice(12, 16)}-${hash.slice(16, 20)}-${hash.slice(20, 32)}`;
}

export async function createStealHandler(config) {
  const paths = defaultPaths();
  // Circuit artifacts are not in the repo: download + hash-verify them
  // (and export the VK from the .zkey) before the existence check below.
  await ensureCircuitsOnce(paths);
  for (const p of [paths.wasmPath, paths.zkeyPath, paths.vkPath]) {
    await access(p); // throws if a circuit artifact is missing
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

  return {
    commitment,
    commitmentHex,
    get turnsServed() {
      return turnsServed;
    },
    validateTurnEnvelope,
    handleTurn,
    /** Store a signed response body for (matchId, turn) retries. */
    cacheResponse(matchId, turn, body, signature) {
      responseCache.set(`${String(matchId)}:${String(turn)}`, {
        body,
        signature,
        expiresAt: Date.now() + CACHE_TTL_MS,
      });
    },
  };
}
