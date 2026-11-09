import type {
  AuthorizationResponseErrorCode,
  ConnectScope,
  TapokProtocolErrorCode,
} from "./types.ts";

export const authorizationErrorCodes = new Set<AuthorizationResponseErrorCode>([
  "invalid_request",
  "unauthorized_client",
  "invalid_scope",
  "login_required",
  "interaction_required",
  "consent_required",
  "account_selection_required",
  "request_not_supported",
  "request_uri_not_supported",
  "registration_not_supported",
  "access_denied",
  "unsupported_response_type",
  "server_error",
  "temporarily_unavailable",
]);

// Kept separate from authorizationErrorCodes: spreading one Set into another is
// not side-effect free for bundlers and would pin both tables in every bundle.
const tokenEndpointErrorCodes = new Set<TapokProtocolErrorCode>([
  "invalid_client",
  "invalid_grant",
  "unsupported_grant_type",
  "unsupported_token_type",
  "invalid_token",
  "insufficient_scope",
]);

export function isProtocolErrorCode(
  value: unknown,
): value is TapokProtocolErrorCode {
  return (
    authorizationErrorCodes.has(value as AuthorizationResponseErrorCode) ||
    tokenEndpointErrorCodes.has(value as TapokProtocolErrorCode)
  );
}

export const connectScopeList = /* @__PURE__ */ Object.freeze<ConnectScope[]>([
  "openid",
  "email",
  "profile",
  "age:18",
  "profile:display_name",
  "profile:name",
  "profile:birthdate",
  "phone",
  "address",
  "offline_access",
]);

export const connectScopes = /* @__PURE__ */ new Set<ConnectScope>(
  connectScopeList,
);

/** Parameters the authorization server adds to a redirect URI. */
export const callbackParameters = new Set([
  "code",
  "state",
  "iss",
  "error",
  "error_description",
]);

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function assertRecord(
  value: unknown,
  context: string,
): asserts value is Record<string, unknown> {
  if (!isRecord(value)) {
    throw new TypeError(`${context} must be an object`);
  }
}

/** JSON response fields must come from the response itself, never its prototype. */
export function ownField(value: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(value, key) ? value[key] : undefined;
}

export function requireNonEmptyString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${field} must be a non-empty string`);
  }
  return value;
}

export function optionalString(
  value: unknown,
  field: string,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  return value;
}

function hasExplicitPort(value: string): boolean {
  const authorityStart = value.indexOf("//");
  if (authorityStart === -1) {
    return false;
  }
  const authority = value.slice(authorityStart + 2).split(/[/?#]/u, 1)[0] ?? "";
  const host = authority.slice(authority.lastIndexOf("@") + 1);

  if (host.startsWith("[")) {
    const closingBracket = host.indexOf("]");
    return (
      closingBracket !== -1 && /^:\d+$/u.test(host.slice(closingBracket + 1))
    );
  }

  return /:\d+$/u.test(host);
}

export function parseAbsoluteHttpUrl(value: string, field: string): URL {
  // eslint-disable-next-line no-control-regex -- Reject control characters at the input boundary.
  if (typeof value !== "string" || /[\u0000-\u0020\u007f\\]/u.test(value)) {
    throw new TypeError(
      `${field} must be a URL without whitespace, control characters or backslashes`,
    );
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${field} must be an absolute URL`);
  }

  if (
    (url.protocol !== "https:" && url.protocol !== "http:") ||
    url.origin === "null" ||
    url.username !== "" ||
    url.password !== "" ||
    value.includes("#")
  ) {
    throw new TypeError(
      `${field} must be an HTTP(S) URL without credentials or a fragment`,
    );
  }

  if (url.protocol === "http:") {
    const loopback =
      url.hostname === "localhost" ||
      url.hostname === "127.0.0.1" ||
      url.hostname === "[::1]";
    if (!loopback || !hasExplicitPort(value)) {
      throw new TypeError(
        `${field} must use HTTPS, except loopback development URLs with an explicit port`,
      );
    }
  }

  return url;
}

/**
 * A redirect URI may carry its own query, but never a parameter the
 * authorization response uses: the server would overwrite it and the callback
 * could no longer be told apart from a forged one.
 */
export function parseRedirectUri(value: string, field: string): URL {
  const url = parseAbsoluteHttpUrl(value, field);
  for (const key of url.searchParams.keys()) {
    if (callbackParameters.has(key)) {
      throw new TypeError(
        `${field} must not contain the ${key} query parameter`,
      );
    }
  }
  return url;
}

/** Trusted issuer: HTTPS URL without query, fragment or trailing slash. */
export function requireIssuer(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
  }
  parseIssuerUrl(value, field);
  if (value.endsWith("/")) {
    throw new TypeError(`${field} must have no query or trailing slash`);
  }
  return value;
}

export function parseIssuerUrl(value: string, field: string): URL {
  const url = parseAbsoluteHttpUrl(value, field);
  // URL.search is empty for both an absent query and an explicit trailing '?'.
  if (value.includes("?")) {
    throw new TypeError(`${field} must have no query`);
  }
  return url;
}

/** Validate Connect scopes: known values only, openid required, duplicates rejected or skipped. */
export function toConnectScopes(
  scopes: Iterable<string>,
  field: string,
  onDuplicate: "reject" | "skip",
): ConnectScope[] {
  const seen = new Set<ConnectScope>();
  const result: ConnectScope[] = [];

  for (const scope of scopes) {
    if (!connectScopes.has(scope as ConnectScope)) {
      throw new TypeError(`${field} contains an unsupported scope`);
    }
    if (seen.has(scope as ConnectScope)) {
      if (onDuplicate === "reject") {
        throw new TypeError(`${field} contains a duplicate scope`);
      }
      continue;
    }
    seen.add(scope as ConnectScope);
    result.push(scope as ConnectScope);
  }

  if (!seen.has("openid")) {
    throw new TypeError(`${field} must contain openid`);
  }

  return result;
}

export function parseConnectScopeString(
  value: unknown,
  field: string,
): ConnectScope[] {
  return toConnectScopes(
    requireNonEmptyString(value, field).split(" "),
    field,
    "reject",
  );
}
