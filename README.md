# Agent Games — Combined Endpoint (Proof Gatekeeper + Steal the VFY)

One process, one URL, both tracks. The platform dispatches Gatekeeper task
envelopes AND Steal turn envelopes to the single registered endpoint, so
this server routes purely by envelope shape after HMAC verification:

1. Preflight markers → protocol-v1 preflight ack (`{"ok":true,"protocolVersion":"v1"}`, signed)
2. Looks like a Steal turn (`matchId` / `turn` / `eventId: steal-the-vfy`) → Steal handler
3. Looks like a Gatekeeper task (`agent-games.proof-gatekeeper.v1` / `task_id` / `input`) → decision engine
4. Anything else signed → preflight ack

POST is accepted on `/`, `/task`, `/agent`, `/preflight`. GET `/`, `/health`,
`/preflight` returns service status (including `steal_configured` and the
public strategy `commitment` hex).

## Files (flat — no subfolders)

| File | What it is |
|---|---|
| `server.js` | Combined HTTP server, HMAC verify, shape routing, lazy Steal init |
| `decide.js` | Gatekeeper decision engine (7 checks, fail-closed) |
| `prove.js` | Gatekeeper Groth16 proving + circuit auto-download (pinned SHA-256) |
| `seen.js` | Proof-reference seen-set (PROOF_REUSED detection) |
| `onchain.js` | STUB on-chain check (`ZKVERIFY_CHECK_MODE`: stub/mock/disabled) |
| `steal-handler.js` | Steal turn handling: validation, decision tree, proving, cache |
| `strategy.js` | Deterministic Steal decision tree + Poseidon commitment |
| `hash.js` | `publicInputsHash` (verified formula from the official docs) |
| `prover.js` | Steal Groth16 proving + circuit auto-download (pinned SHA-256) |
| `kurier.js` | Optional Kurier audit submission (best-effort, key-gated) |
| `config.js` | Steal environment config (fail-fast; wrapped by the server) |
| `commitment.js` | CLI: print the strategy commitment hash for dashboard registration |

## Setup

```sh
npm ci
```

Set Variables on Railway (see `.env.example`):

- `AGENT_GAMES_HMAC_SECRET` (or `HMAC_SECRET`) — from the dashboard, shown once.
- `ZKVERIFY_CHECK_MODE` — `disabled` for scored rounds (default `stub`
  fail-closes and rejects every valid task).
- `STRATEGY_PARAMS` — default `10,30,0,0,0,0,0,0`.
- `STRATEGY_SALT` — required for Steal. If missing, Steal turns return 503
  and Gatekeeper keeps working. The commitment hash in `/health` must match
  the hash registered in the dashboard (recompute with `npm run commitment`
  after any params/salt change, and re-register before the next round).

Deploy: upload all files to the repo root (no folders), connect the repo to
a Railway service, Generate Domain, register the URL in the dashboard, run
preflight, then at least one practice task per track.

## Notes

- Circuit artifacts (`gatekeeper.*`, `vfy-policy.*`) are NOT in the repo.
  They download from the official site on first start and are verified
  against pinned SHA-256 hashes.
- The Steal strategy is deterministic per the circuit: exactly one valid
  action per state. The only adaptivity is re-committing between rounds.
- `ZKVERIFY_CHECK_MODE=stub` is the default and rejects all valid Gatekeeper
  tasks (fail-closed). The on-chain check is a stub; `disabled` is the
  operator's choice after practice-mode validation.
