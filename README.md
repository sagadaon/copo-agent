# Proof Gatekeeper — Agent Games (zkVerify Season 01)

Plain Node.js endpoint. The platform POSTs a signed task envelope; this
server verifies the HMAC signature, decides APPROVE / REJECT against the
7 documented trap types, attaches a Groth16 proof for the decision, and
responds with a signed JSON decision — all inside the 60-second deadline.

Flat layout on purpose: every file lives at the repo root, no subfolders,
so the repo can be managed from a phone. There is intentionally no
Dockerfile — Railway's Node builder is the deploy path.

## Files

| File | What it is |
| --- | --- |
| `server.js` | HTTP server, HMAC verify-before-parse, signed responses |
| `decide.js` | The 7 checks in trap-detection order, fail-closed |
| `prove.js` | Groth16 proving + circuit auto-download (hash-verified) |
| `seen.js` | File-backed seen-set for PROOF_REUSED detection |
| `onchain.js` | On-chain confirmation — currently a marked STUB (see below) |
| `package.json` | `npm start` runs the server; only dependency is `snarkjs` |
| `.env.example` | Env vars to set on Railway (never commit a real `.env`) |

## Deploy (Railway)

1. Create a GitHub repo and upload all files in this zip to its root.
2. Railway → New Project → Deploy from GitHub repo → pick the repo.
3. Railway → service → Variables, set:
   - `HMAC_SECRET` — the 32-byte secret shown exactly ONCE when the
     endpoint is registered in the Agent Games dashboard. Paste it here
     directly; never send it through chat.
   - `ZKVERIFY_CHECK_MODE` — leave unset (`stub`, fail-closed) until the
     practice-mode decision below is made.
4. Railway → service → Settings → Networking → Generate Domain. Copy the
   `https://….up.railway.app` URL.
5. Agent Games dashboard → register the endpoint URL → run the signed
   preflight → run at least 1 practice task.
6. Keep the service awake during scored rounds (17:30–03:30 WIB).

Circuit artifacts (`gatekeeper.wasm`, `gatekeeper_final.zkey`) are NOT in
the repo. On first start the server downloads them from
`agentgames.zkverify.io/circuits/` and verifies them against pinned
SHA-256 hashes (see `prove.js`). No manual step needed.

Optional: attach a Railway Volume mounted at `/data` and set
`SEEN_FILE=/data/seen.json` so the seen-set survives restarts. Without it,
a restart only weakens reuse detection; it never causes a wrong APPROVE.

## Practice-mode validation checklist

These five things can only be confirmed against a real practice task.
Check them before the first scored round:

1. **taskId encoding** — the code encodes it as `sha256(task_id) mod p`.
   `taskId` is a public signal, so the platform recomputes it. If the
   encoding differs, proofs still verify cryptographically but the public
   inputs mismatch (decisions still score; only the proof bonus is lost).
2. **Proof field names** — the code sends `proof` + `public_signals`.
   Confirm the platform accepts them.
3. **HMAC encoding** — hex is assumed, base64 also accepted. Confirm
   against a real signed request.
4. **On-chain check mode** — `onchain.js` is a stub: no read-only query
   path could be verified from the public docs. `stub` mode fails closed
   (valid tasks get REJECT/UNVERIFIED, so valid-task points are lost).
   `disabled` mode decides on the HMAC-authenticated envelope fields
   alone. Choose only after practice tasks show the envelopes behave as
   documented.
5. **Preflight format** — `GET /` and `GET /health` return 200 JSON.
   Adjust if the platform expects otherwise.

## Local test

```sh
npm install
HMAC_SECRET=test-secret ZKVERIFY_CHECK_MODE=mock node server.js
curl localhost:3000/health
```

`mock` mode simulates a confirmed proof — local testing only, never
deploy with it.
