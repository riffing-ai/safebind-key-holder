/**
 * What the browser will do in Phase 4 and what the tests do now: wrap the §4 payload to a holder's
 * public key with RSA-OAEP-256. Test helper only.
 */

import { base64Decode, encodeWrappedPayload } from "./contract";

export async function importPublicKey(spkiBase64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    base64Decode(spkiBase64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

export async function wrapTo(
  spkiBase64: string,
  k1: Uint8Array,
  certId: string,
  kver: number
): Promise<Uint8Array> {
  const key = await importPublicKey(spkiBase64);
  return new Uint8Array(
    await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, encodeWrappedPayload(k1, certId, kver))
  );
}

export const randomK1 = (): Uint8Array => crypto.getRandomValues(new Uint8Array(32));
export const CERT_A = "11111111-1111-4111-8111-111111111111";
export const CERT_B = "22222222-2222-4222-8222-222222222222";
