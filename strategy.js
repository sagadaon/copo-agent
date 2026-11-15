// strategy.js — Steal the VFY strategy: the ONE swappable decision function.
//
// READ THIS BEFORE TUNING
// -----------------------
// The policy circuit (VfyPolicyProof_154) enforces a DETERMINISTIC strategy:
// exactly one valid action exists per game state, and the proof fails for any
// other action. The "strategy" is therefore ONLY the choice of the four numbers
// below, committed (as a Poseidon hash) in the dashboard BEFORE a match. Within
// a match the action is fully determined by (strategyParams, balances) — the
// agent CANNOT adapt to the opponent's history, fortification flags, turn
// number, or anything else inside a match. Any deviation from the tree below
// makes the Groth16 proof fail and the turn scores -2 (invalid proof).
//
// Between rounds, the commitment may be changed (re-register a new hash in the
// dashboard) — that is the only adaptivity the protocol allows.
//
// DECISION TREE (reverse-engineered from the circuit's witness asserts, 2026-11-15):
//   1. If selfBalance < p1            -> FORTIFY
//   2. Else if p3 == 0 AND opponentBalance > p2 -> EXTRACT with amount == p0
//   3. Else                           -> HOLD
//
// PARAMETERS (strategyParams[0..7]; [4..7] MUST be 0):
//   p0 = fixed EXTRACT amount, range [1,10]. EXTRACT amount must EQUAL p0 exactly.
//   p1 = FORTIFY threshold: FORTIFY iff selfBalance < p1 (strict). 0 disables FORTIFY.
//   p2 = EXTRACT threshold: EXTRACT requires opponentBalance > p2 (strict).
//   p3 = 0 allows EXTRACT, 1 disables EXTRACT (does NOT force HOLD; FORTIFY still applies).
//
// COMMITMENT (enforced by the circuit, template line 72):
//   commitment = Poseidon([strategyParams[0..7], salt])  // params FIRST, salt LAST
// The dashboard-registered hash must equal this value or every proof fails.
// Compute it with:  node -e "import('./commitment.js').then(m=>m.printCommitment())"
// (or read the value logged at server startup) and register that hash in the
// dashboard (My Agents -> Edit agent -> Steal the VFY) BEFORE Swiss Round 1.
//
// TUNING GUIDE (re-commit between rounds only; never mid-match):
//   - Aggressive default: [10, 30, 0, 0, ...] — extract 10 whenever the opponent
//     has anything, fortify only when low. EXTRACT is free, so there is no
//     downside to extracting whenever allowed.
//   - If opponents extract heavily and your balance bleeds: raise p1 (fortify
//     earlier). Cost: FORTIFY has a small fixed cost and skips an extract.
//   - If the resolver caps extracts below 10, a lower p0 changes nothing
//     (the resolver clamps); keep p0 = 10 unless the resolver penalises it.
//   - p3 = 1 is a defensive-only posture (never extract). Only useful if
//     extracting somehow backfires — not indicated by the public docs.
//   - Exact resolver numbers (fortify cost, protection amount, extract cap)
//     are NOT in the public docs; tune from observed match outcomes.

import { buildPoseidon } from "circomlibjs";

export const ACTION = Object.freeze({ HOLD: 0, FORTIFY: 1, EXTRACT: 2 });
export const ACTION_NAMES = Object.freeze(["HOLD", "FORTIFY", "EXTRACT"]);

// Default params: extract 10 whenever possible, fortify below 30, never hold
// except when the opponent is at 0. Override via STRATEGY_PARAMS env var.
export const DEFAULT_PARAMS = Object.freeze([10, 30, 0, 0, 0, 0, 0, 0]);

const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

let poseidonInstance = null;
async function getPoseidon() {
  if (!poseidonInstance) poseidonInstance = await buildPoseidon();
  return poseidonInstance;
}

/** Validate the 8 strategy params against the circuit's enforced ranges. */
export function validateParams(params) {
  if (!Array.isArray(params) || params.length !== 8) {
    throw new Error("strategyParams must be an array of exactly 8 numbers");
  }
  const [p0, p1, p2, p3, p4, p5, p6, p7] = params;
  for (const [i, v] of params.entries()) {
    if (!Number.isInteger(v) || v < 0) {
      throw new Error(`strategyParams[${i}] must be a non-negative integer, got ${v}`);
    }
  }
  if (p0 < 1 || p0 > 10) throw new Error(`p0 (extract amount) must be in [1,10], got ${p0}`);
  // Circuit range check fails at 1,000,000 (verified); sane gameplay range is 0..200.
  if (p1 >= 1_000_000) throw new Error(`p1 (fortify threshold) must be < 1000000, got ${p1}`);
  if (p2 >= 1_000_000) throw new Error(`p2 (extract threshold) must be < 1000000, got ${p2}`);
  if (p3 !== 0 && p3 !== 1) throw new Error(`p3 (extract disable) must be 0 or 1, got ${p3}`);
  if (p4 !== 0 || p5 !== 0 || p6 !== 0 || p7 !== 0) {
    throw new Error("strategyParams[4..7] must all be 0 (enforced by the circuit)");
  }
  return params;
}

/** Parse STRATEGY_PARAMS env var: "10,30,0,0,0,0,0,0". */
export function parseParams(str) {
  if (str === undefined || str === null || String(str).trim() === "") {
    return [...DEFAULT_PARAMS];
  }
  const params = String(str)
    .split(",")
    .map((s) => {
      const n = Number(s.trim());
      if (!Number.isFinite(n)) throw new Error(`STRATEGY_PARAMS: not a number: ${s}`);
      return n;
    });
  return validateParams(params);
}

/** Parse STRATEGY_SALT env var: decimal or 0x-hex. Returns a BigInt. */
export function parseSalt(str) {
  if (str === undefined || str === null || String(str).trim() === "") {
    throw new Error("STRATEGY_SALT is required (any integer; keep it private)");
  }
  let salt;
  try {
    salt = BigInt(String(str).trim());
  } catch {
    throw new Error("STRATEGY_SALT must be a decimal or 0x-hex integer");
  }
  if (salt < 0n || salt >= FIELD_PRIME) {
    throw new Error("STRATEGY_SALT must be in [0, field prime)");
  }
  return salt;
}

/**
 * THE decision function — the only place the action is chosen.
 * Implements exactly the circuit-enforced tree. `state` is the envelope
 * state { selfBalance, opponentBalance, ... }; fortification flags and turn
 * number are deliberately ignored (the circuit ignores them too).
 * Returns { type: "HOLD"|"FORTIFY"|"EXTRACT", code, amount|null }.
 */
export function decideAction(state, params) {
  const self = BigInt(state.selfBalance);
  const opp = BigInt(state.opponentBalance);
  const [p0, p1, p2, p3] = params.map((v) => BigInt(v));
  if (self < p1) return { type: "FORTIFY", code: ACTION.FORTIFY, amount: null };
  if (p3 === 0n && opp > p2) {
    return { type: "EXTRACT", code: ACTION.EXTRACT, amount: Number(p0) };
  }
  return { type: "HOLD", code: ACTION.HOLD, amount: null };
}

/**
 * commitment = Poseidon([strategyParams[0..7], salt]) — params first, salt last.
 * Returns a BigInt (the field element). Hex form: "0x" + 64 hex chars.
 */
export async function computeCommitment(params, salt) {
  validateParams(params);
  const poseidon = await getPoseidon();
  const inputs = [...params.map((v) => BigInt(v)), BigInt(salt)];
  const out = poseidon(inputs);
  return poseidon.F.toObject(out);
}

export function commitmentToHex(commitment) {
  return "0x" + BigInt(commitment).toString(16).padStart(64, "0");
}
