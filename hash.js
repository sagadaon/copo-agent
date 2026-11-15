// hash.js — publicInputsHash, VERIFIED formula from the official docs (/build).
//
// The platform independently recomputes this hash and rejects proofs where the
// hashes diverge. Field order (from the official TypeScript snippet, which uses
// viem's keccak256/concat/numberToHex with 32-byte padding):
//   keccak256( concat(
//     numberToHex(commitment, {size:32}),   // strategyCommitment.hash (0x-hex)
//     numberToHex(matchId,    {size:32}),   // UUID dashes removed, parsed as hex
//     numberToHex(turn,       {size:32}),
//     numberToHex(selfBalance,{size:32}),
//     numberToHex(opponentBalance, {size:32}),
//     numberToHex(actionCode, {size:32}),   // HOLD=0, FORTIFY=1, EXTRACT=2
//     numberToHex(amount,     {size:32}),   // 0 for HOLD/FORTIFY
//     numberToHex(circuitVersionNumber, {size:32}) // "v1" -> 1
//   ))
//
// Each field is padded to 32 bytes big-endian. This module re-implements that
// packing with js-sha3 (no viem dependency). The test suite re-derives the
// hash with an independent inline implementation to catch drift.

import pkg from "js-sha3";

const { keccak_256 } = pkg;

export function toBytes32(value) {
  const n = BigInt(value);
  if (n < 0n) throw new Error("toBytes32: negative value");
  const hex = n.toString(16).padStart(64, "0");
  if (hex.length > 64) throw new Error("toBytes32: value exceeds 32 bytes");
  return Buffer.from(hex, "hex");
}

/** UUID string -> BigInt (dashes removed, parsed as hex). Also accepts 0x-hex / BigInt. */
export function matchIdToBigInt(matchId) {
  if (typeof matchId === "bigint") return matchId;
  if (typeof matchId === "number") return BigInt(matchId);
  const s = String(matchId).trim();
  if (s.startsWith("0x") || s.startsWith("0X")) return BigInt(s);
  return BigInt("0x" + s.replace(/-/g, ""));
}

/** "v1" -> 1n, "v2" -> 2n, numbers pass through. */
export function circuitVersionToNumber(version) {
  if (typeof version === "bigint") return version;
  if (typeof version === "number") return BigInt(version);
  const m = /^v(\d+)$/.exec(String(version).trim());
  if (!m) throw new Error(`circuitVersion: unrecognised format: ${version}`);
  return BigInt(m[1]);
}

const ACTION_CODES = { HOLD: 0n, FORTIFY: 1n, EXTRACT: 2n };

export function actionCode(action) {
  if (typeof action === "bigint") return action;
  if (typeof action === "number") return BigInt(action);
  const code = ACTION_CODES[String(action).toUpperCase()];
  if (code === undefined) throw new Error(`actionCode: unknown action: ${action}`);
  return code;
}

/**
 * Compute publicInputsHash. `commitment` may be a 0x-hex string, decimal
 * string, or BigInt. `amount` must be 0 for HOLD/FORTIFY (callers pass the
 * resolved amount; the circuit input amount is 0 for non-EXTRACT actions).
 * Returns "0x..." keccak256 hex.
 */
export function computePublicInputsHash({
  commitment,
  matchId,
  turn,
  selfBalance,
  opponentBalance,
  action,
  amount,
  circuitVersion,
}) {
  const buf = Buffer.concat([
    toBytes32(commitment),
    toBytes32(matchIdToBigInt(matchId)),
    toBytes32(turn),
    toBytes32(selfBalance),
    toBytes32(opponentBalance),
    toBytes32(actionCode(action)),
    toBytes32(amount),
    toBytes32(circuitVersionToNumber(circuitVersion)),
  ]);
  return "0x" + keccak_256(buf);
}
