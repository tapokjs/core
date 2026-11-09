import assert from "node:assert/strict";
import {
  buildBaseAuthorizeUrl,
  createAuthorizationSecrets,
  parseBaseExchangeResponse,
} from "@tapokjs/core";

const secrets = await createAuthorizationSecrets();
assert.equal(secrets.pkce.challenge.length, 43);
const url = new URL(
  buildBaseAuthorizeUrl({
    redirectUri: "https://client.example/callback",
    state: secrets.state,
    nonce: secrets.nonce,
    codeChallenge: secrets.pkce.challenge,
  }),
);
assert.equal(url.searchParams.get("code_challenge_method"), "S256");
assert.equal(url.searchParams.get("state"), secrets.state);
assert.equal(
  parseBaseExchangeResponse({
    identity_token: "synthetic-identity-token",
    expires_in: 600,
    scope: "session",
  }).expires_in,
  600,
);
console.log("Installed Core archive passed its Web API contract");
