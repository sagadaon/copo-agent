'use strict';
/**
 * Groth16 proof generation for the tournament's gatekeeper circuit
 * (BN254 / bn128, Circom 2.x), using the official artifacts.
 *
 * Circuit input signals (13) — names recovered by probing the compiled
 * wasm and confirmed by successful local proving:
 *   registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock,
 *   currentBlock, recipient, conditionRecipient, amount, maxTransfer,
 *   decision, taskId, salt
 *
 * ENCODING ASSUMPTIONS — these match what the circuit accepts locally, but
 * the platform's own recomputation of public inputs could not be verified
 * without a practice task. Validate in practice mode before scored rounds:
 *  - vk hashes (32 bytes, may exceed the field modulus) are reduced mod p.
 *  - addresses are plain field elements (20 bytes fit the field).
 *  - taskId (a string like "gk_24_9d1") is encoded as sha256(task_id) mod p.
 *    If taskId is a PRIVATE signal, any deterministic value works; if it is
 *    PUBLIC, this encoding must match the platform's exactly.
 *  - salt is a fresh random field element per proof (private by design).
 *
 * CIRCUIT ARTIFACTS — not committed to the repo. On first use they are
 * downloaded from the tournament's own site and verified against the
 * pinned SHA-256 hashes below (hashes measured from the official files).
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const https = require('https');
const snarkjs = require('snarkjs');

// BN254 scalar field prime.
const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

const CIRCUITS_DIR = process.env.CIRCUITS_DIR || path.join(__dirname, 'circuits');
const WASM_PATH = path.join(CIRCUITS_DIR, 'gatekeeper.wasm');
const ZKEY_PATH = path.join(CIRCUITS_DIR, 'gatekeeper_final.zkey');

const CIRCUIT_FILES = [
  {
    name: 'gatekeeper.wasm',
    url: 'https://agentgames.zkverify.io/circuits/gatekeeper.wasm',
    sha256: 'be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f',
  },
  {
    name: 'gatekeeper_final.zkey',
    url: 'https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey',
    sha256: 'adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d',
  },
];

function fileMatches(filePath, sha256) {
  try {
    if (!fs.existsSync(filePath)) return false;
    const hash = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
    return hash === sha256;
  } catch {
    return false;
  }
}

function downloadFile(url, dest, redirectsLeft = 3) {
  return new Promise((resolve, reject) => {
    const tmp = `${dest}.download.${process.pid}.${crypto.randomBytes(4).toString('hex')}`;
    const cleanup = () => { try { fs.unlinkSync(tmp); } catch { /* already gone */ } };
    const req = https.get(url, { timeout: 60000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && redirectsLeft > 0) {
        res.resume();
        cleanup();
        resolve(downloadFile(res.headers.location, dest, redirectsLeft - 1));
        return;
      }
      if (res.statusCode !== 200) {
        res.resume();
        cleanup();
        reject(new Error(`HTTP ${res.statusCode} for ${url}`));
        return;
      }
      const file = fs.createWriteStream(tmp);
      file.on('error', (e) => { cleanup(); reject(e); });
      file.on('finish', () => {
        file.close(() => {
          try {
            fs.renameSync(tmp, dest);
            resolve();
          } catch (e) {
            cleanup();
            reject(e);
          }
        });
      });
      res.pipe(file);
    });
    req.on('timeout', () => req.destroy(new Error('download timeout: ' + url)));
    req.on('error', (e) => { cleanup(); reject(e); });
  });
}

async function ensureCircuits() {
  fs.mkdirSync(CIRCUITS_DIR, { recursive: true });
  for (const f of CIRCUIT_FILES) {
    const dest = path.join(CIRCUITS_DIR, f.name);
    if (fileMatches(dest, f.sha256)) continue;
    let ok = false;
    for (let attempt = 1; attempt <= 3 && !ok; attempt++) {
      try {
        console.log(JSON.stringify({ msg: 'circuit_download', file: f.name, attempt }));
        await downloadFile(f.url, dest);
        ok = fileMatches(dest, f.sha256);
        if (!ok) { try { fs.unlinkSync(dest); } catch { /* ignore */ } }
      } catch (e) {
        console.log(JSON.stringify({ level: 'warn', msg: 'circuit_download_failed', file: f.name, attempt, error: String(e.message) }));
      }
    }
    if (!ok) throw new Error('could not fetch verified circuit file: ' + f.name);
  }
  return true;
}

// Memoized: concurrent callers share one download. On failure the memo
// resets so the next call retries.
let ensuring = null;
function ensureCircuitsOnce() {
  if (!ensuring) ensuring = ensureCircuits().catch((e) => { ensuring = null; throw e; });
  return ensuring;
}

function fieldFromHex(hex) {
  return (BigInt(String(hex).trim()) % P).toString();
}

function fieldFromAddress(addr) {
  return BigInt(String(addr).trim()).toString();
}

function fieldFromTaskId(taskId) {
  const h = crypto.createHash('sha256').update(String(taskId), 'utf8').digest('hex');
  return (BigInt('0x' + h) % P).toString();
}

function randomSalt() {
  return (BigInt('0x' + crypto.randomBytes(32).toString('hex')) % P).toString();
}

async function generateDecisionProof(task, decision) {
  await ensureCircuitsOnce();
  const input = {
    registeredVkHash: fieldFromHex(task.registered_vk),
    proofVkHash: fieldFromHex(task.proof_vk),
    minimum: BigInt(String(task.minimum)).toString(),
    publicBalance: BigInt(String(task.public_balance)).toString(),
    expiryBlock: BigInt(String(task.expiry_block)).toString(),
    currentBlock: BigInt(String(task.current_block)).toString(),
    recipient: fieldFromAddress(task.recipient),
    conditionRecipient: fieldFromAddress(task.condition_recipient),
    amount: BigInt(String(task.amount)).toString(),
    maxTransfer: BigInt(String(task.max_transfer)).toString(),
    decision: String(decision),
    taskId: fieldFromTaskId(task.task_id),
    salt: randomSalt(),
  };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals: publicSignals.map(String) };
}

module.exports = { generateDecisionProof, ensureCircuits, ensureCircuitsOnce, fieldFromHex, fieldFromTaskId, randomSalt };
