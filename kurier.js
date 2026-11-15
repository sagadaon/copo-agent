// kurier.js — OPTIONAL on-chain audit pointer via Kurier (zkVerify).
//
// Disabled by default. Enabled only when KURIER_API_KEY is set. Best-effort:
// any failure (network, timeout, API error) is swallowed and the turn response
// simply omits proofReference. Never blocks or fails a turn.
//
// Payload shape per the official docs:
//   POST https://api.kurier.xyz/api/v1/submit-proof/<KURIER_API_KEY>
//   { proofType: "groth16", vkRegistered: true,
//     proofOptions: { library: "snarkjs", curve: "bn128" },
//     proofData: { proof, publicSignals, vk: registeredVkHash } }
//
// UNVERIFIED: this payload/response shape has not been exercised against the
// live Kurier API (needs the user's mainnet API key). The first live turn with
// a key set will confirm or correct it from Kurier's response.

export const KURIER_VK_HASH =
  "0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047";

const KURIER_TIMEOUT_MS = 15000;

/**
 * Submit a proof to Kurier. Returns the proof reference string, or null when
 * Kurier is disabled/unreachable/unsuccessful. Never throws.
 */
export async function submitToKurier({ apiKey, proof, publicSignals, vkHash = KURIER_VK_HASH }) {
  if (!apiKey) return null;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), KURIER_TIMEOUT_MS);
    try {
      const res = await fetch(`https://api.kurier.xyz/api/v1/submit-proof/${apiKey}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          proofType: "groth16",
          vkRegistered: true,
          proofOptions: { library: "snarkjs", curve: "bn128" },
          proofData: { proof, publicSignals, vk: vkHash },
        }),
        signal: controller.signal,
      });
      if (!res.ok) {
        console.warn(`[kurier] HTTP ${res.status}; omitting proofReference`);
        return null;
      }
      const data = await res.json().catch(() => null);
      // Response field name is unverified; accept the plausible ones.
      const ref =
        data?.proofReference ?? data?.reference ?? data?.jobId ?? data?.id ?? null;
      if (typeof ref !== "string") {
        console.warn("[kurier] response had no recognisable reference field; omitting");
        return null;
      }
      return ref;
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    console.warn(`[kurier] submission failed (${err.message}); omitting proofReference`);
    return null;
  }
}
