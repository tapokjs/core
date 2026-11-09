import type { AuthorizationSecrets } from "./types.ts";

const textEncoder = /* @__PURE__ */ new TextEncoder();

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

export async function createAuthorizationSecrets(): Promise<AuthorizationSecrets> {
  const random = globalThis.crypto.getRandomValues(new Uint8Array(96));
  const state = base64UrlEncode(random.subarray(0, 32));
  const nonce = base64UrlEncode(random.subarray(32, 64));
  const verifier = base64UrlEncode(random.subarray(64));
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    textEncoder.encode(verifier),
  );

  return {
    state,
    nonce,
    pkce: {
      verifier,
      challenge: base64UrlEncode(new Uint8Array(digest)),
      method: "S256",
    },
  };
}
