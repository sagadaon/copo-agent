/**
 * Seen-set for proof references (PROOF_REUSED detection).
 *
 * In-memory Set is primary; a JSON file is the backup so a restart does not
 * forget references. NOTE: on Railway the filesystem is ephemeral unless a
 * Volume is attached — mount a volume and set SEEN_FILE to a path on it
 * (e.g. /data/seen.json) for restarts to keep the set. Losing the file only
 * weakens reuse detection after a restart; it never causes a wrong APPROVE
 * on its own, because reuse is only one of the checks.
 *
 * ESM conversion of the standalone Gatekeeper seen.js; logic unchanged.
 */
import fs from 'node:fs';
import path from 'node:path';

export function loadSeenSet(filePath) {
  const set = new Set();
  const abs = path.resolve(filePath);
  try {
    if (fs.existsSync(abs)) {
      const data = JSON.parse(fs.readFileSync(abs, 'utf8'));
      if (Array.isArray(data)) {
        for (const x of data) if (typeof x === 'string') set.add(x);
      }
    }
  } catch (e) {
    console.log(JSON.stringify({ level: 'warn', msg: 'seen_file_load_failed', error: String(e.message) }));
  }
  function persist() {
    try {
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      const tmp = abs + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify([...set]));
      fs.renameSync(tmp, abs);
    } catch (e) {
      console.log(JSON.stringify({ level: 'warn', msg: 'seen_file_persist_failed', error: String(e.message) }));
    }
  }
  return {
    get size() { return set.size; },
    has: (k) => set.has(k),
    add: (k) => { if (!set.has(k)) { set.add(k); persist(); } },
  };
}
