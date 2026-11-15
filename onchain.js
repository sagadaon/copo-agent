'use strict';
/**
 * STUB — on-chain proof confirmation.
 *
 * The builder field guide's checklist says: "Call zkVerifyJS to confirm the
 * proof is on-chain and its VK matches the registered condition VK." The VK
 * match itself is a local string comparison done in decide.js. Confirming
 * the proof_tx reference on-chain, however, has NO usable read-only path
 * that could be verified without registration:
 *
 * - Kurier (REST) requires a mainnet API key, which requires an account.
 * - zkVerifyJS read-only sessions exist (no account needed), but there is
 *   no documented read API for "was proof reference X verified", and the
 *   proof_tx format in real task envelopes is unknown (the public sample
 *   uses truncated placeholder hashes). Any query code written now would
 *   be untestable speculation.
 *
 * So this module is a clearly-marked stub. Modes (ZKVERIFY_CHECK_MODE):
 * - "stub" (DEFAULT): returns unverified -> the decision engine FAILS CLOSED
 *   (REJECT) for otherwise-valid tasks. Safe, but leaves valid-task points
 *   on the table until a real check exists.
 * - "mock": simulates a confirmed proof. LOCAL TESTING ONLY — lets the full
 *   APPROVE + proof-generation path be exercised without the chain.
 * - "disabled": skips the check; decisions rest on the (HMAC-authenticated)
 *   envelope fields alone. OPERATOR CHOICE, only after practice-mode
 *   validation shows the platform's envelopes are trustworthy for this.
 *
 * TODO (after registration, in practice mode): implement the real check —
 * either a read-only zkVerifyJS session querying the verification state for
 * proof_tx, or Kurier job-status polling with an API key — and flip the
 * default mode only once it is proven against real practice tasks.
 */
const MODE = (process.env.ZKVERIFY_CHECK_MODE || 'stub').toLowerCase();

async function verifyProofOnChain(/* { proof_tx, proof_vk, registered_vk } */) {
  if (MODE === 'mock') {
    return { verified: true, source: 'mock', detail: 'MOCK MODE: local testing only, no chain query performed.' };
  }
  if (MODE === 'disabled') {
    return { verified: true, source: 'disabled', detail: 'On-chain check DISABLED by operator. Field checks only.' };
  }
  return {
    verified: false,
    source: 'stub',
    detail: 'STUB: no read-only on-chain query implemented; failing closed. See lib/onchain.js TODO.',
  };
}

module.exports = { verifyProofOnChain, MODE };
