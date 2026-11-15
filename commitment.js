// commitment.js — print the strategy commitment hash for dashboard registration.
//
// Usage (from this directory):
//   STRATEGY_PARAMS="10,30,0,0,0,0,0,0" STRATEGY_SALT="<secret>" node commitment.js
//
// The printed hash is what must be registered in the dashboard
// (My Agents -> Edit agent -> Steal the VFY) BEFORE Swiss Round 1. The server
// also logs this value at startup. Re-run after ANY change to STRATEGY_PARAMS
// or STRATEGY_SALT and re-register the new hash before the next round.

import { computeCommitment, commitmentToHex, parseParams, parseSalt } from "./strategy.js";

export async function printCommitment() {
  const params = parseParams(process.env.STRATEGY_PARAMS);
  const salt = parseSalt(process.env.STRATEGY_SALT);
  const commitment = await computeCommitment(params, salt);
  console.log("strategyParams:", JSON.stringify(params));
  console.log("commitment (decimal):", commitment.toString());
  console.log("commitment (hex):    ", commitmentToHex(commitment));
  console.log("");
  console.log("Register the hex hash in the dashboard (Steal the VFY commitment).");
  return commitment;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  printCommitment().catch((err) => {
    console.error("error:", err.message);
    process.exit(1);
  });
}
