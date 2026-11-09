import {
  assertRecord,
  ownField,
  parseConnectScopeString,
  isProtocolErrorCode,
  requireNonEmptyString,
  toConnectScopes,
} from "./internal.ts";
import type {
  BaseExchangeResponse,
  ConnectScope,
  ConnectRefreshResponse,
  ConnectTokenResponse,
  ConnectUserInfo,
  IsoDate,
  TapokProtocolErrorBody,
} from "./types.ts";

/** Longest lifetime a Base identity token may have, in seconds. */
const BASE_IDENTITY_TOKEN_MAX_TTL = 600;
/** Deep-freezes the policy table inside one call so bundlers can drop it when unused. */
function freezeClaimScopes<
  const T extends Record<string, readonly ConnectScope[]>,
>(table: T): Readonly<T> {
  for (const scopes of Object.values(table)) Object.freeze(scopes);
  return Object.freeze(table);
}

export const USERINFO_CLAIM_SCOPES = /* @__PURE__ */ freezeClaimScopes({
  email: ["email"],
  email_verified: ["email"],
  is_adult: ["age:18"],
  display_name: ["profile", "profile:display_name"],
  name: ["profile"],
  family_name: ["profile", "profile:name"],
  given_name: ["profile", "profile:name"],
  middle_name: ["profile", "profile:name"],
  birthdate: ["profile", "profile:birthdate"],
  phone_number: ["phone"],
  phone_number_verified: ["phone"],
  nickname: ["profile"],
  preferred_username: ["profile"],
  picture: ["profile"],
  profile: ["profile"],
  website: ["profile"],
  gender: ["profile"],
  zoneinfo: ["profile"],
  locale: ["profile"],
  updated_at: ["profile"],
  address: ["address"],
  custom_fields: ["profile"],
} satisfies Record<
  Exclude<keyof ConnectUserInfo, "sub">,
  readonly ConnectScope[]
>);

const userInfoClaimEntries = /* @__PURE__ */ Object.entries(
  USERINFO_CLAIM_SCOPES,
) as Array<[keyof typeof USERINFO_CLAIM_SCOPES, readonly ConnectScope[]]>;

const addressFields = new Set([
  "formatted",
  "street_address",
  "locality",
  "region",
  "postal_code",
  "country",
]);
const daysInMonth = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] as const;

function isIsoDate(value: string): value is IsoDate {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/u.exec(value);
  if (match === null) {
    return false;
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const leapYear = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const maxDay = month === 2 && leapYear ? 29 : (daysInMonth[month - 1] ?? 0);
  return month >= 1 && month <= 12 && day >= 1 && day <= maxDay;
}

/**
 * Known fields are validated strictly; fields this version does not know are
 * ignored and never copied, so the platform can extend the response. The
 * lifetime may shrink but never exceed the Base limit, and the scope stays an
 * exact allowlist because it decides which claims the token may carry.
 */
export function parseBaseExchangeResponse(
  value: unknown,
): BaseExchangeResponse {
  assertRecord(value, "Base exchange response");

  const identityToken = requireNonEmptyString(
    ownField(value, "identity_token"),
    "identity_token",
  );
  const expiresIn = ownField(value, "expires_in");
  if (
    !Number.isSafeInteger(expiresIn) ||
    (expiresIn as number) <= 0 ||
    (expiresIn as number) > BASE_IDENTITY_TOKEN_MAX_TTL
  ) {
    throw new TypeError(
      `expires_in must be a positive integer no greater than ${BASE_IDENTITY_TOKEN_MAX_TTL}`,
    );
  }
  const scope = ownField(value, "scope");
  if (scope !== "session" && scope !== "session age:18") {
    throw new TypeError("scope must be session or session age:18");
  }

  return {
    identity_token: identityToken,
    expires_in: expiresIn as number,
    scope,
  };
}

function parseTokenResponse(
  value: unknown,
  requireIdToken: true,
): ConnectTokenResponse;
function parseTokenResponse(
  value: unknown,
  requireIdToken: false,
): ConnectRefreshResponse;
function parseTokenResponse(
  value: unknown,
  requireIdToken: boolean,
): ConnectRefreshResponse {
  assertRecord(
    value,
    requireIdToken ? "Connect token response" : "Refresh response",
  );

  const accessToken = requireNonEmptyString(
    ownField(value, "access_token"),
    "access_token",
  );
  const idTokenValue = ownField(value, "id_token");
  const idToken =
    requireIdToken || idTokenValue !== undefined
      ? requireNonEmptyString(idTokenValue, "id_token")
      : undefined;
  // RFC 6749 section 5.1: the token type is case-insensitive. The result is
  // normalised so callers can keep comparing with "Bearer".
  const tokenType = ownField(value, "token_type");
  if (typeof tokenType !== "string" || tokenType.toLowerCase() !== "bearer") {
    throw new TypeError("token_type must be Bearer");
  }
  const expiresIn = ownField(value, "expires_in");
  if (
    !Number.isSafeInteger(expiresIn) ||
    (expiresIn as number) <= 0 ||
    (expiresIn as number) > 86400
  ) {
    throw new TypeError(
      "expires_in must be a positive integer no greater than 86400",
    );
  }
  const scope = requireNonEmptyString(ownField(value, "scope"), "scope");
  parseConnectScopeString(scope, "scope");

  const result: ConnectRefreshResponse = {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: expiresIn as number,
    scope,
  };
  if (idToken !== undefined) result.id_token = idToken;
  const refreshToken = ownField(value, "refresh_token");
  if (refreshToken !== undefined)
    result.refresh_token = requireNonEmptyString(refreshToken, "refresh_token");
  return result;
}

export function parseConnectTokenResponse(
  value: unknown,
): ConnectTokenResponse {
  return parseTokenResponse(value, true);
}

export function parseConnectRefreshResponse(
  value: unknown,
): ConnectRefreshResponse {
  return parseTokenResponse(value, false);
}

export function parseConnectUserInfo(
  value: unknown,
  grantedScopes: readonly ConnectScope[],
): ConnectUserInfo {
  assertRecord(value, "UserInfo response");

  const scopes = new Set(
    toConnectScopes(grantedScopes, "grantedScopes", "reject"),
  );
  const result: ConnectUserInfo = {
    sub: requireNonEmptyString(ownField(value, "sub"), "sub"),
  };

  for (const [claim, requiredScopes] of userInfoClaimEntries) {
    if (!Object.hasOwn(value, claim)) {
      continue;
    }
    if (!requiredScopes.some((scope) => scopes.has(scope))) {
      throw new TypeError(`${claim} is not allowed by the granted scopes`);
    }

    const claimValue = value[claim];
    if (claim === "email_verified" || claim === "phone_number_verified") {
      if (typeof claimValue !== "boolean")
        throw new TypeError(`${claim} must be a boolean`);
      result[claim] = claimValue;
    } else if (claim === "is_adult") {
      if (typeof claimValue !== "boolean" && claimValue !== null) {
        throw new TypeError("is_adult must be a boolean or null");
      }
      result.is_adult = claimValue;
    } else if (claim === "updated_at") {
      if (!Number.isSafeInteger(claimValue) || (claimValue as number) < 0)
        throw new TypeError("updated_at must be a nonnegative integer");
      result.updated_at = claimValue as number;
    } else if (claim === "address" || claim === "custom_fields") {
      assertRecord(claimValue, claim);
      const fields: Record<string, string> = {};
      for (const key of Object.keys(claimValue)) {
        if (claim === "address" && !addressFields.has(key)) continue;
        const field = claimValue[key];
        if (typeof field !== "string")
          throw new TypeError(claim + " fields must be strings");
        // defineProperty keeps a field named "__proto__" as plain data.
        Object.defineProperty(fields, key, {
          value: field,
          enumerable: true,
          writable: true,
          configurable: true,
        });
      }
      result[claim] = fields;
    } else if (claim === "birthdate") {
      if (typeof claimValue !== "string" || !isIsoDate(claimValue)) {
        throw new TypeError("birthdate must be an existing YYYY-MM-DD date");
      }
      result.birthdate = claimValue;
    } else {
      const text = requireNonEmptyString(claimValue, claim);
      if (claim === "email") {
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(text)) {
          throw new TypeError("email must be a valid email address");
        }
      }
      result[claim] = text;
    }
  }

  return result;
}

export function parseProtocolError(value: unknown): TapokProtocolErrorBody {
  assertRecord(value, "Protocol error");

  const error = ownField(value, "error");
  if (!isProtocolErrorCode(error)) {
    throw new TypeError("error must be a supported Tapok protocol error code");
  }

  const result: TapokProtocolErrorBody = {
    error,
  };
  if (Object.hasOwn(value, "error_description")) {
    const description = value["error_description"];
    if (typeof description !== "string") {
      throw new TypeError("error_description must be a string");
    }
    result.error_description = description;
  }
  return result;
}
