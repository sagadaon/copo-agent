'use strict';
/**
 * Proof Gatekeeper decision engine — the 7 checks from the event page,
 * evaluated in trap-detection order. Fail closed: any uncertainty,
 * malformed field, or unavailable verification -> REJECT.
 *
 * Check order (a detected trap short-circuits; later checks never override):
 *  1. Parse + validate required fields          -> REJECT/UNVERIFIED if bad
 *  2. PROOF_REUSED      proof_tx seen before    -> REJECT/PROOF_REUSED (no proof; excluded from proof scoring)
 *  3. VK_SUBSTITUTION   proof_vk != registered_vk
 *  4. THRESHOLD_MISMATCH public_balance < minimum
 *  5. RECIPIENT_MISMATCH recipient != condition_recipient
 *  6. EXPIRED_CONDITION  current_block >= expiry_block
 *  7. AMOUNT_OVERFLOW    amount > max_transfer
 *  8. On-chain confirmation (STUB — see lib/onchain.js) -> REJECT/UNVERIFIED if unverified
 *  9. All pass -> APPROVE/VALID_CONDITION
 *
 * Proofs: a Groth16 proof is generated for APPROVE (decision=1) and for
 * trap REJECTs (decision=0), because the circuit constrains decision to the
 * computed result in both directions. PROOF_REUSED tasks carry no proof
 * (the score model excludes them). If proof generation fails for an
 * APPROVE, the circuit disagrees with the field checks -> downgrade to
 * REJECT/UNVERIFIED. If proof generation TIMES OUT after a confident
 * decision, the decision is still returned without a proof (the decision
 * itself is certain; only the reliability bonus is at risk).
 */
const { verifyProofOnChain } = require('./onchain');
const { generateDecisionProof } = require('./prove');

const PROOF_TIMEOUT_MS = parseInt(process.env.PROOF_TIMEOUT_MS || '50000', 10);

function normHex(v) {
  return String(v).trim().toLowerCase().replace(/^0x/, '');
}

function toBig(v, name) {
  try {
    const b = BigInt(String(v).trim());
    if (b < 0n) throw new Error('negative');
    return b;
  } catch {
    throw new Error(`invalid ${name}: ${JSON.stringify(v)}`);
  }
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ __timeout: true }), ms);
  });
  return Promise.race([promise.then((v) => ({ __timeout: false, value: v })), timeout])
    .finally(() => clearTimeout(timer));
}

async function decide(envelope, seen) {
  const input = (envelope && envelope.input) || {};
  const taskId = envelope.task_id;
  const proofTx = typeof input.proof_tx === 'string' ? input.proof_tx : null;

  const respond = (decision, reasonCode, proofBundle) => {
    const out = { decision, reason_code: reasonCode, proof_tx: proofTx };
    if (proofBundle) {
      out.proof = proofBundle.proof;
      out.public_signals = proofBundle.publicSignals;
    }
    return out;
  };

  // Every processed proof reference is recorded as seen (any decision), so a
  // later task reusing the same reference is caught as PROOF_REUSED.
  const recordSeen = () => { if (proofTx) seen.add(proofTx); };

  let f;
  try {
    f = {
      registered_vk: normHex(input.registered_vk),
      proof_vk: normHex(input.proof_vk),
      minimum: toBig(input.minimum, 'minimum'),
      public_balance: toBig(input.public_balance, 'public_balance'),
      expiry_block: toBig(input.expiry_block, 'expiry_block'),
      current_block: toBig(input.current_block, 'current_block'),
      recipient: normHex(input.recipient),
      condition_recipient: normHex(input.condition_recipient),
      amount: toBig(input.amount, 'amount'),
      max_transfer: toBig(input.max_transfer, 'max_transfer'),
    };
    if (!f.registered_vk || !f.proof_vk || !f.recipient || !f.condition_recipient) {
      throw new Error('empty hex field');
    }
    if (!taskId || typeof taskId !== 'string') throw new Error('missing task_id');
  } catch (e) {
    recordSeen();
    console.log(JSON.stringify({ level: 'warn', msg: 'malformed_task', task_id: taskId || null, error: e.message }));
    return respond('REJECT', 'UNVERIFIED', null);
  }

  // 2. Reuse — checked before anything else: a valid proof does not gain
  // re-entry by being re-submitted.
  if (proofTx && seen.has(proofTx)) {
    return respond('REJECT', 'PROOF_REUSED', null);
  }

  let trap = null;
  if (f.proof_vk !== f.registered_vk) trap = 'VK_SUBSTITUTION';
  else if (f.public_balance < f.minimum) trap = 'THRESHOLD_MISMATCH';
  else if (f.recipient !== f.condition_recipient) trap = 'RECIPIENT_MISMATCH';
  else if (f.current_block >= f.expiry_block) trap = 'EXPIRED_CONDITION';
  else if (f.amount > f.max_transfer) trap = 'AMOUNT_OVERFLOW';

  recordSeen();

  if (trap) {
    const proofBundle = await tryProve({ ...input, task_id: taskId }, 0);
    return respond('REJECT', trap, proofBundle);
  }

  // No trap in the fields — last gate is the on-chain confirmation.
  const chain = await verifyProofOnChain({ proof_tx: proofTx, proof_vk: input.proof_vk, registered_vk: input.registered_vk });
  if (!chain.verified) {
    console.log(JSON.stringify({ level: 'warn', msg: 'onchain_unverified_fail_closed', task_id: taskId, source: chain.source }));
    return respond('REJECT', 'UNVERIFIED', null);
  }

  // APPROVE — prove decision=1. If the circuit refuses (witness error), the
  // circuit disagrees with the field checks: fail closed.
  const raced = await withTimeout(
    generateDecisionProof({ ...input, task_id: taskId }, 1).then(
      (b) => ({ ok: true, bundle: b }),
      (e) => ({ ok: false, error: e })
    ),
    PROOF_TIMEOUT_MS
  );
  if (raced.__timeout) {
    console.log(JSON.stringify({ level: 'warn', msg: 'proof_timeout_returning_decision_without_proof', task_id: taskId }));
    return respond('APPROVE', 'VALID_CONDITION', null);
  }
  if (!raced.value.ok) {
    console.log(JSON.stringify({ level: 'error', msg: 'approve_proof_failed_circuit_disagrees', task_id: taskId, error: String(raced.value.error && raced.value.error.message) }));
    return respond('REJECT', 'UNVERIFIED', null);
  }
  return respond('APPROVE', 'VALID_CONDITION', raced.value.bundle);
}

async function tryProve(task, decision) {
  try {
    const raced = await withTimeout(generateDecisionProof(task, decision), PROOF_TIMEOUT_MS);
    if (raced.__timeout) {
      console.log(JSON.stringify({ level: 'warn', msg: 'reject_proof_timeout', task_id: task.task_id }));
      return null;
    }
    return raced.value;
  } catch (e) {
    console.log(JSON.stringify({ level: 'warn', msg: 'reject_proof_failed', task_id: task.task_id, error: String(e.message) }));
    return null;
  }
}

module.exports = { decide };
