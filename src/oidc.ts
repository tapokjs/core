import { TAPOK_ISSUER } from "./constants.ts";
import {
  parseAbsoluteHttpUrl,
  parseRedirectUri,
  assertRecord,
  requireIssuer,
  requireNonEmptyString,
  connectScopeList,
  ownField,
} from "./internal.ts";
import type {
  BaseOidcScope,
  OidcAuthorizationOptions,
  OidcEndpoints,
} from "./types.ts";

export const TAPOK_BASE_OIDC_ISSUER =
  "https://tapok.orria.space/oidc/base" as const;
export const CONNECT_SCOPES = connectScopeList;
export const BASE_OIDC_SCOPES = /* @__PURE__ */ Object.freeze([
  "openid",
  "profile",
  "email",
  "age:18",
] as const);

const prompts = ["none", "login", "consent", "select_account"];
// Tokens of ui_locales and login_hint travel in a URL the user can see and
// share; bound them and keep control characters out.
// eslint-disable-next-line no-control-regex -- Reject control characters at the input boundary.
const controlCharacters = /[\u0000-\u001f\u007f]/u;

function requireHint(value: unknown, field: string, maxLength: number): string {
  const text = requireNonEmptyString(value, field);
  if (text.length > maxLength || controlCharacters.test(text)) {
    throw new TypeError(
      `${field} must be at most ${maxLength} characters without control characters`,
    );
  }
  return text;
}

/**
 * The issuer is trusted configuration, never a value from an incoming request.
 * `mode: "base"` selects the Base OIDC issuer (`…/oidc/base`); the native Base
 * endpoints are `<issuer>/api/v1/base/authorize` and `/exchange`.
 */
export function resolveTapokEndpoints(
  input: { issuer?: string; mode?: "connect" | "base" } = {},
): OidcEndpoints {
  const mode = input.mode ?? "connect";
  if (mode !== "connect" && mode !== "base") {
    throw new TypeError("mode must be connect or base");
  }
  const issuer = requireIssuer(
    input.issuer ?? (mode === "base" ? TAPOK_BASE_OIDC_ISSUER : TAPOK_ISSUER),
    "issuer",
  );
  const prefix = mode === "base" ? issuer : issuer + "/api/v1/connect";
  return {
    issuer,
    authorization_endpoint: prefix + "/authorize",
    token_endpoint: prefix + "/token",
    userinfo_endpoint: prefix + "/userinfo",
    revocation_endpoint: prefix + "/revoke",
    end_session_endpoint: prefix + "/logout",
    jwks_uri: issuer + "/.well-known/jwks.json",
  };
}

/** Validate metadata before fetching any advertised endpoint. Cross-origin hosts require explicit trust. */
export function validateOidcDiscovery(
  value: unknown,
  expectedIssuer: string,
  allowedEndpointOrigins: readonly string[] = [],
): OidcEndpoints {
  assertRecord(value, "discovery");
  const issuerUrl = new URL(requireIssuer(expectedIssuer, "expectedIssuer"));
  if (!Array.isArray(allowedEndpointOrigins)) {
    throw new TypeError("allowedEndpointOrigins must be an array");
  }
  for (const origin of allowedEndpointOrigins) {
    // A value such as "https://cdn.example/" would silently never match.
    if (
      typeof origin !== "string" ||
      parseAbsoluteHttpUrl(origin, "allowedEndpointOrigins").origin !== origin
    ) {
      throw new TypeError("allowedEndpointOrigins must contain exact origins");
    }
  }
  if (ownField(value, "issuer") !== expectedIssuer)
    throw new TypeError("discovery issuer mismatch");
  const result = { issuer: expectedIssuer } as OidcEndpoints;
  for (const key of [
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "revocation_endpoint",
    "end_session_endpoint",
    "jwks_uri",
  ] as const) {
    const endpoint = requireNonEmptyString(ownField(value, key), key);
    const url = parseAbsoluteHttpUrl(endpoint, key);
    if (
      url.origin !== issuerUrl.origin &&
      !allowedEndpointOrigins.includes(url.origin)
    )
      throw new TypeError("Untrusted discovery endpoint origin");
    result[key] = endpoint;
  }
  return result;
}

/** Internal: validates optional OIDC request parameters and adds them to the URL. */
export function applyOidcAuthorizationOptions(
  url: URL,
  options: OidcAuthorizationOptions,
): URL {
  if (options.prompt !== undefined) {
    if (!prompts.includes(options.prompt))
      throw new TypeError("Invalid prompt");
    url.searchParams.set("prompt", options.prompt);
  }
  if (options.maxAge !== undefined) {
    if (!Number.isSafeInteger(options.maxAge) || options.maxAge < 0)
      throw new TypeError("maxAge must be a nonnegative integer");
    url.searchParams.set("max_age", String(options.maxAge));
  }
  if (options.uiLocales !== undefined)
    url.searchParams.set(
      "ui_locales",
      requireHint(options.uiLocales, "uiLocales", 255),
    );
  if (options.loginHint !== undefined)
    url.searchParams.set(
      "login_hint",
      requireHint(options.loginHint, "loginHint", 320),
    );
  return url;
}

export function buildOidcBaseAuthorizeUrl(
  input: OidcAuthorizationOptions & {
    issuer?: string;
    clientId: string;
    redirectUri: string;
    scopes: readonly BaseOidcScope[];
    state: string;
    nonce: string;
    codeChallenge: string;
  },
): URL {
  parseRedirectUri(input.redirectUri, "redirectUri");
  if (
    !Array.isArray(input.scopes) ||
    !input.scopes.includes("openid") ||
    input.scopes.some((scope) => !BASE_OIDC_SCOPES.includes(scope))
  )
    throw new TypeError("Unsupported Base OIDC scopes");
  const url = new URL(
    resolveTapokEndpoints({ issuer: input.issuer, mode: "base" })
      .authorization_endpoint,
  );
  for (const [key, value] of Object.entries({
    response_type: "code",
    client_id: input.clientId,
    redirect_uri: input.redirectUri,
    scope: [...new Set(input.scopes)].join(" "),
    state: input.state,
    nonce: input.nonce,
    code_challenge: input.codeChallenge,
    code_challenge_method: "S256",
  }))
    url.searchParams.set(key, requireNonEmptyString(value, key));
  return applyOidcAuthorizationOptions(url, input);
}

export function buildLogoutUrl(input: {
  issuer?: string;
  mode?: "base" | "connect";
  idTokenHint?: string;
  clientId?: string;
  postLogoutRedirectUri?: string;
  state?: string;
}): URL {
  const url = new URL(resolveTapokEndpoints(input).end_session_endpoint);
  if (input.postLogoutRedirectUri !== undefined)
    parseAbsoluteHttpUrl(input.postLogoutRedirectUri, "postLogoutRedirectUri");
  for (const [key, value] of Object.entries({
    id_token_hint: input.idTokenHint,
    client_id: input.clientId,
    post_logout_redirect_uri: input.postLogoutRedirectUri,
    state: input.state,
  }))
    if (value !== undefined)
      url.searchParams.set(key, requireNonEmptyString(value, key));
  return url;
}
