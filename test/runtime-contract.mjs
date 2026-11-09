import {
  TAPOK_ISSUER,
  TapokCallbackValidationError,
  buildBaseAuthorizeUrl,
  buildConnectAuthorizeUrl,
  createAuthorizationSecrets,
  createBaseExchangeBody,
  parseAndValidateAuthorizationCallback,
  parseBaseExchangeResponse,
  parseConnectRefreshResponse,
  parseConnectTokenResponse,
  parseConnectUserInfo,
  parseProtocolError,
} from "../dist/index.js";

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertThrows(run, check, message) {
  try {
    run();
  } catch (error) {
    assert(check(error), message);
    return;
  }
  throw new Error(message);
}

const secrets = await createAuthorizationSecrets();
assert(
  new Set([secrets.state, secrets.nonce, secrets.pkce.verifier]).size === 3,
  "Authorization secrets must use independent random bytes",
);
assert(secrets.pkce.method === "S256", "PKCE method must be S256");
assert(secrets.pkce.verifier.length === 43, "PKCE verifier must have 256 bits");
assert(
  secrets.pkce.challenge.length === 43,
  "PKCE challenge must be base64url SHA-256",
);

const baseUrl = buildBaseAuthorizeUrl({
  redirectUri: "https://app.example/callback",
  scopes: ["age:18", "age:18"],
  state: secrets.state,
  nonce: secrets.nonce,
  codeChallenge: secrets.pkce.challenge,
});
assert(
  baseUrl.searchParams.get("scope") === "session age:18",
  "Base scopes must be canonical",
);
assert(
  baseUrl.searchParams.get("code_challenge_method") === "S256",
  "Base must use PKCE S256",
);

const connectUrl = buildConnectAuthorizeUrl({
  clientId: "tpk_client_example",
  redirectUri: "https://app.example/callback",
  scopes: ["openid", "phone", "openid"],
  state: secrets.state,
  nonce: secrets.nonce,
  codeChallenge: secrets.pkce.challenge,
});
assert(
  connectUrl.searchParams.get("scope") === "openid phone",
  "Connect scopes must be deduplicated",
);
assertThrows(
  () =>
    buildConnectAuthorizeUrl({
      clientId: "tpk_client_example",
      redirectUri: "https://app.example/callback",
      scopes: ["phone"],
      state: secrets.state,
      nonce: secrets.nonce,
      codeChallenge: secrets.pkce.challenge,
    }),
  (error) => error instanceof TypeError,
  "Connect must require openid",
);

const issuer = encodeURIComponent(TAPOK_ISSUER);
const callback = parseAndValidateAuthorizationCallback({
  callbackUrl: `https://app.example/callback?code=code&state=${secrets.state}&iss=${issuer}`,
  expectedState: secrets.state,
  expectedIssuer: TAPOK_ISSUER,
});
assert(callback.ok && callback.code === "code", "Success callback must parse");
assertThrows(
  () =>
    parseAndValidateAuthorizationCallback({
      callbackUrl: `https://app.example/callback?code=code&state=wrong&iss=${issuer}`,
      expectedState: secrets.state,
      expectedIssuer: TAPOK_ISSUER,
    }),
  (error) =>
    error instanceof TapokCallbackValidationError &&
    error.code === "state_mismatch",
  "Callback must reject a state mismatch",
);

const exchangeBody = createBaseExchangeBody({
  grant_type: "authorization_code",
  code: "code",
  client_id: "origin:https://app.example",
  redirect_uri: "https://app.example/callback",
  code_verifier: secrets.pkce.verifier,
});
assert(
  exchangeBody.get("grant_type") === "authorization_code",
  "Exchange body must set the grant type",
);

assert(
  parseBaseExchangeResponse({
    identity_token: "jwt",
    expires_in: 600,
    scope: "session",
  }).expires_in === 600,
  "Base exchange response must parse",
);
assert(
  parseConnectTokenResponse({
    access_token: "opaque",
    token_type: "Bearer",
    expires_in: 900,
    scope: "openid phone",
    id_token: "jwt",
  }).token_type === "Bearer",
  "Connect token response must parse",
);
assertThrows(
  () =>
    parseConnectUserInfo({ sub: "subject", phone_number: "+70000000000" }, [
      "openid",
    ]),
  (error) => error instanceof TypeError,
  "UserInfo must reject an out-of-scope claim",
);
assert(
  parseConnectUserInfo({ sub: "subject", birthdate: "2000-02-29" }, [
    "openid",
    "profile:birthdate",
  ]).birthdate === "2000-02-29",
  "UserInfo must accept a real ISO date",
);
assertThrows(
  () =>
    parseConnectUserInfo({ sub: "subject", birthdate: "1900-02-29" }, [
      "openid",
      "profile:birthdate",
    ]),
  (error) => error instanceof TypeError,
  "UserInfo must reject an impossible date",
);
assert(
  parseProtocolError({ error: "invalid_grant" }).error === "invalid_grant",
  "Protocol error must parse",
);

const refreshResponse = {
  access_token: "access",
  token_type: "Bearer",
  expires_in: 300,
  scope: "openid",
};
assert(
  !Object.hasOwn(parseConnectRefreshResponse(refreshResponse), "id_token"),
  "Refresh may omit the ID token",
);
assertThrows(
  () => parseConnectRefreshResponse({ ...refreshResponse, id_token: null }),
  (error) => error instanceof TypeError,
  "Refresh must reject a null ID token",
);
assertThrows(
  () =>
    parseConnectTokenResponse(
      Object.create({ ...refreshResponse, id_token: "jwt" }),
    ),
  (error) => error instanceof TypeError,
  "Token fields must not come from the prototype",
);
assertThrows(
  () =>
    buildBaseAuthorizeUrl({
      issuer: "https://id.example?",
      redirectUri: "https://app.example/callback",
      state: secrets.state,
      nonce: secrets.nonce,
      codeChallenge: secrets.pkce.challenge,
    }),
  (error) => error instanceof TypeError,
  "Issuer must reject even an empty query",
);
