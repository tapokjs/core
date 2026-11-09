import { applyOidcAuthorizationOptions } from "./oidc.ts";
import { TAPOK_ISSUER } from "./constants.ts";
import {
  parseRedirectUri,
  requireIssuer,
  requireNonEmptyString,
  toConnectScopes,
} from "./internal.ts";
import type {
  BaseScope,
  ConnectScope,
  OidcAuthorizationOptions,
} from "./types.ts";

const authorizationParameterOrder = [
  "response_type",
  "client_id",
  "redirect_uri",
  "scope",
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
] as const;

function createAuthorizeUrl(
  endpoint: "base" | "connect",
  issuer: string | undefined,
  values: Record<(typeof authorizationParameterOrder)[number], string>,
): URL {
  const url = new URL(
    requireIssuer(issuer ?? TAPOK_ISSUER, "issuer") +
      `/api/v1/${endpoint}/authorize`,
  );
  for (const parameter of authorizationParameterOrder) {
    url.searchParams.set(parameter, values[parameter]);
  }
  return url;
}

export function deriveBaseClientId(redirectUri: string): `origin:${string}` {
  const redirectUrl = parseRedirectUri(redirectUri, "redirectUri");
  return `origin:${redirectUrl.origin}`;
}

export function buildBaseAuthorizeUrl(input: {
  issuer?: string;
  redirectUri: string;
  scopes?: readonly BaseScope[];
  state: string;
  nonce: string;
  codeChallenge: string;
}): URL {
  const redirectUrl = parseRedirectUri(input.redirectUri, "redirectUri");
  const scopes = new Set<BaseScope>(["session"]);

  if (input.scopes !== undefined && !Array.isArray(input.scopes)) {
    throw new TypeError("scopes must be an array");
  }
  for (const scope of input.scopes ?? []) {
    if (scope !== "session" && scope !== "age:18") {
      throw new TypeError("scopes contains an unsupported Base scope");
    }
    scopes.add(scope);
  }

  return createAuthorizeUrl("base", input.issuer, {
    response_type: "code",
    client_id: `origin:${redirectUrl.origin}`,
    redirect_uri: input.redirectUri,
    scope: scopes.has("age:18") ? "session age:18" : "session",
    state: requireNonEmptyString(input.state, "state"),
    nonce: requireNonEmptyString(input.nonce, "nonce"),
    code_challenge: requireNonEmptyString(input.codeChallenge, "codeChallenge"),
    code_challenge_method: "S256",
  });
}

export function buildConnectAuthorizeUrl(
  input: OidcAuthorizationOptions & {
    issuer?: string;
    clientId: string;
    redirectUri: string;
    scopes: readonly ConnectScope[];
    state: string;
    nonce: string;
    codeChallenge: string;
  },
): URL {
  parseRedirectUri(input.redirectUri, "redirectUri");
  if (!Array.isArray(input.scopes)) {
    throw new TypeError("scopes must be an array");
  }
  const scopes = toConnectScopes(input.scopes, "scopes", "skip");

  return applyOidcAuthorizationOptions(
    createAuthorizeUrl("connect", input.issuer, {
      response_type: "code",
      client_id: requireNonEmptyString(input.clientId, "clientId"),
      redirect_uri: input.redirectUri,
      scope: scopes.join(" "),
      state: requireNonEmptyString(input.state, "state"),
      nonce: requireNonEmptyString(input.nonce, "nonce"),
      code_challenge: requireNonEmptyString(
        input.codeChallenge,
        "codeChallenge",
      ),
      code_challenge_method: "S256",
    }),
    input,
  );
}
