// prover.js — snarkjs Groth16 proving against the vfy-policy circuit.
//
// Circuit inputs (verified against the .wasm exports, 2026-11-15):
//   commitment, matchId, turnNumber, selfBalance, opponentBalance, action,
//   amount, circuitVersion (public, in this order after the leading output
//   signal), strategyParams[8], salt (private).
// Public signals returned by the prover (9 total, verbatim order):
//   [OUT, commitment, matchId, turnNumber, selfBalance, opponentBalance,
//    action, amount, circuitVersion]
// where OUT is a computed output signal whose identity is unresolved — it is
// passed through verbatim and never interpreted. Do NOT reorder publicSignals.
//
// Proving is serialised with a mutex: concurrent fullProve calls on a small
// Railway instance would thrash memory/CPU and blow the 5-minute turn deadline.
//
// CIRCUIT ARTIFACTS — not committed to the repo. On first use they are
// downloaded from the tournament's own site and verified against the pinned
// SHA-256 hashes below (measured from the official files). The verification
// key is exported locally from the .zkey (it is not published as a download).

import * as snarkjs from "snarkjs";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { createHash, randomBytes } from "node:crypto";
import { createWriteStream, existsSync, readFileSync, renameSync, unlinkSync } from "node:fs";
import https from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

export function defaultPaths() {
  return {
    wasmPath:
      process.env.CIRCUIT_WASM || path.join(HERE, "circuits", "vfy-policy.wasm"),
    zkeyPath:
      process.env.CIRCUIT_ZKEY || path.join(HERE, "circuits", "vfy-policy_final.zkey"),
    vkPath:
      process.env.CIRCUIT_VK || path.join(HERE, "circuits", "vfy-policy_vk.json"),
  };
}

const CIRCUIT_FILES = [
  {
    name: "vfy-policy.wasm",
    url: "https://agentgames.zkverify.io/circuits/vfy-policy.wasm",
    sha256: "bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2",
  },
  {
    name: "vfy-policy_final.zkey",
    url: "https://agentgames.zkverify.io/circuits/vfy-policy_final.zkey",
    sha256: "f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41",
  },
];

function fileMatches(filePath, sha256) {
  try {
    if (!existsSync(filePath)) return false;
    return createHash("sha256").update(readFileSync(filePath)).digest("hex") === sha256;
  } catch {
    return false;
  }
}

function downloadFile(url, dest, redirectsLeft = 3) {
  return new Promise((resolve, reject) => {
    const tmp = `${dest}.download.${process.pid}.${randomBytes(4).toString("hex")}`;
    const cleanup = () => {
      try {
        unlinkSync(tmp);
      } catch {
        /* already gone */
      }
    };
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
      const file = createWriteStream(tmp);
      file.on("error", (e) => {
        cleanup();
        reject(e);
      });
      file.on("finish", () => {
        file.close(() => {
          try {
            renameSync(tmp, dest);
            resolve();
          } catch (e) {
            cleanup();
            reject(e);
          }
        });
      });
      res.pipe(file);
    });
    req.on("timeout", () => req.destroy(new Error("download timeout: " + url)));
    req.on("error", (e) => {
      cleanup();
      reject(e);
    });
  });
}

function vkUsable(vkPath) {
  try {
    if (!existsSync(vkPath)) return false;
    JSON.parse(readFileSync(vkPath, "utf8"));
    return true;
  } catch {
    return false;
  }
}

export async function ensureCircuits(paths = defaultPaths()) {
  await mkdir(path.dirname(paths.wasmPath), { recursive: true });
  for (const f of CIRCUIT_FILES) {
    const dest = path.join(path.dirname(paths.wasmPath), f.name);
    if (fileMatches(dest, f.sha256)) continue;
    let ok = false;
    for (let attempt = 1; attempt <= 3 && !ok; attempt++) {
      try {
        console.log(JSON.stringify({ msg: "circuit_download", file: f.name, attempt }));
        await downloadFile(f.url, dest);
        ok = fileMatches(dest, f.sha256);
        if (!ok) {
          try {
            unlinkSync(dest);
          } catch {
            /* ignore */
          }
        }
      } catch (e) {
        console.log(JSON.stringify({ level: "warn", msg: "circuit_download_failed", file: f.name, attempt, error: String(e.message) }));
      }
    }
    if (!ok) throw new Error("could not fetch verified circuit file: " + f.name);
  }
  if (!vkUsable(paths.vkPath)) {
    console.log(JSON.stringify({ msg: "vk_export", file: path.basename(paths.vkPath) }));
    const vk = await snarkjs.zKey.exportVerificationKey(paths.zkeyPath);
    await writeFile(paths.vkPath, JSON.stringify(vk));
  }
  return true;
}

// Memoized: concurrent callers share one download. On failure the memo
// resets so the next call retries.
let ensuring = null;
export function ensureCircuitsOnce(paths = defaultPaths()) {
  if (!ensuring) {
    ensuring = ensureCircuits(paths).catch((e) => {
      ensuring = null;
      throw e;
    });
  }
  return ensuring;
}

// Simple promise-chain mutex: proves run one at a time, in arrival order.
let mutex = Promise.resolve();
function withMutex(fn) {
  const run = mutex.then(fn, fn);
  mutex = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

/**
 * Generate a Groth16 proof. `input` must contain all 10 circuit inputs
 * (numbers as strings/BigInts are fine; snarkjs stringifies).
 * Returns { proof, publicSignals, proveMs }.
 */
export async function prove(input, paths = defaultPaths()) {
  return withMutex(async () => {
    const started = Date.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      paths.wasmPath,
      paths.zkeyPath,
    );
    return { proof, publicSignals, proveMs: Date.now() - started };
  });
}

/**
 * Prove with a wall-clock timeout. On timeout the underlying prove keeps
 * running behind the mutex (snarkjs has no cancellation); the caller gets a
 * timeout error and should fall back to HOLD. Subsequent proves queue behind
 * the still-running one, so keep PROOF_TIMEOUT_MS generous.
 */
export async function proveWithTimeout(input, timeoutMs, paths = defaultPaths()) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`proof timeout after ${timeoutMs}ms`)), timeoutMs);
  });
  try {
    return await Promise.race([prove(input, paths), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/** Local verification against the exported verification key (used by tests). */
export async function verifyLocally(publicSignals, proof, paths = defaultPaths()) {
  const vk = JSON.parse(await readFile(paths.vkPath, "utf8"));
  return snarkjs.groth16.verify(vk, publicSignals, proof);
}

export async function loadVk(paths = defaultPaths()) {
  return JSON.parse(await readFile(paths.vkPath, "utf8"));
}
