# Steal the VFY — Agent Games (zkVerify Season 01)

Plain Node.js endpoint (ESM, no framework). The platform POSTs a signed
turn envelope; this server verifies the HMAC signature, decides the action
with the circuit-enforced decision tree, attaches a Groth16 policy proof,
and responds with a signed, schema-valid turn response — inside the
5-minute turn deadline.

Flat layout on purpose: every file lives at the repo root, no subfolders,
so the repo can be managed from a phone. There is intentionally no
Dockerfile — Railway's Node builder is the deploy path.

## The strategy is four numbers, committed in advance

The policy circuit enforces a DETERMINISTIC strategy: exactly one valid
action exists per game state. Within a match the agent CANNOT adapt to the
opponent's history, fortification flags, or turn number. The "strategy"
is only the choice of four numbers, committed (as a Poseidon hash) in the
dashboard BEFORE a match. Between rounds the commitment may be changed —
that is the only adaptivity the protocol allows.

Decision tree (enforced by the circuit):

1. `selfBalance < p1` → FORTIFY
2. Else `p3 == 0` AND `opponentBalance > p2` → EXTRACT, amount MUST equal `p0`
3. Else → HOLD

Parameters (`STRATEGY_PARAMS`, 8 numbers, last four MUST be 0):

- `p0` — fixed EXTRACT amount, range [1,10].
- `p1` — FORTIFY threshold (strict). 0 disables FORTIFY.
- `p2` — EXTRACT threshold: EXTRACT requires `opponentBalance > p2` (strict).
- `p3` — 0 allows EXTRACT, 1 disables EXTRACT (FORTIFY still applies).

Default: `10,30,0,0,0,0,0,0` — extract 10 whenever the opponent has
anything, fortify only below 30. See `strategy.js` for the tuning guide.

## Files

| File | What it is |
| --- | --- |
| `server.js` | HTTP server, HMAC verify-before-parse, turn handling, HOLD fallback |
| `strategy.js` | THE decision function + Poseidon commitment computation |
| `hash.js` | `publicInputsHash` (verified formula from the official docs) |
| `prover.js` | Groth16 proving + circuit auto-download (hash-verified) + VK export |
| `config.js` | Env parsing, fail-fast on missing secret/salt |
| `commitment.js` | CLI that prints the commitment hash for dashboard registration |
| `kurier.js` | Optional Kurier audit submission (off unless `KURIER_API_KEY` set) |
| `package.json` | `npm start` runs the server; `npm run commitment` prints the hash |
| `.env.example` | Env vars to set on Railway (never commit a real `.env`) |

## Deploy (Railway)

1. Create a GitHub repo and upload all files in this zip to its root.
2. Railway → New Project → Deploy from GitHub repo → pick the repo.
3. Railway → service → Variables, set:
   - `AGENT_GAMES_HMAC_SECRET` — the secret shown in the Agent Games
     dashboard. Paste it here directly; never send it through chat.
   - `STRATEGY_PARAMS` — e.g. `10,30,0,0,0,0,0,0`.
   - `STRATEGY_SALT` — a private random integer (decimal or `0x`-hex).
     REQUIRED. Keep it secret. Changing it changes the commitment.
   - `KURIER_API_KEY` — optional; omit to disable Kurier.
4. Railway → service → Settings → Networking → Generate Domain. Copy the
   `https://….up.railway.app` URL.
5. Register the endpoint `https://<host>/agent` in the Agent Games
   dashboard (My Agents → Edit agent → Steal the VFY).
6. Compute the commitment hash (see below) and register it in the
   dashboard BEFORE the next Swiss round. The hash MUST match
   `STRATEGY_PARAMS` + `STRATEGY_SALT` exactly, or every proof fails.
7. Run at least 1 practice turn and confirm the checklist below.

Circuit artifacts (`vfy-policy.wasm`, `vfy-policy_final.zkey`) are NOT in
the repo. On first start the server downloads them from
`agentgames.zkverify.io/circuits/`, verifies them against pinned SHA-256
hashes (see `prover.js`), and exports the verification key from the
`.zkey`. No manual step needed.

## Commitment hash

From a machine with the repo checked out and dependencies installed:

```sh
STRATEGY_PARAMS="10,30,0,0,0,0,0,0" STRATEGY_SALT="<same secret as Railway>" npm run commitment
```

The server also logs the commitment hash at startup. Register the hex
hash in the dashboard. Re-run and re-register after ANY change to
`STRATEGY_PARAMS` or `STRATEGY_SALT` — before the next round, never
mid-match (the commitment freezes once paired).

## Practice-turn validation checklist

These can only be confirmed against a real practice turn:

1. **Proof field names** — the code sends `proof` + `publicSignals`
   inside `policyProof`. Confirm the platform accepts them (one-line
   fix via `PROOF_FIELDS` in `server.js` if not).
2. **HMAC encoding** — responses are sent as plain hex; inbound hex
   (with/without `sha256=` prefix) and base64 are accepted. Confirm
   against a real signed request.
3. **Kurier payload** — implemented from the docs, never tried against
   the live API. Failures are swallowed (the turn still succeeds).
4. **Proof-less HOLD scoring** — the HOLD fallback (proof timeout/error)
   is signed and schema-valid, but whether it scores as HOLD or −2 is
   undocumented.
5. **Resolver numbers** (fortify cost, protection amount, extract cap)
   are not in the public docs; tune `p0`/`p1` from observed matches.

## Local test

```sh
npm install
AGENT_GAMES_HMAC_SECRET=test-secret STRATEGY_SALT=12345 node server.js
curl localhost:3000/health
```
