import { describe, expect, test } from "bun:test";
import {
  TAPOK_ISSUER,
  TapokCallbackValidationError,
  USERINFO_CLAIM_SCOPES,
  buildBaseAuthorizeUrl,
  buildConnectAuthorizeUrl,
  buildOidcBaseAuthorizeUrl,
  deriveBaseClientId,
  parseAndValidateAuthorizationCallback,
  parseBaseExchangeResponse,
  parseConnectRefreshResponse,
  parseConnectTokenResponse,
  parseConnectUserInfo,
  parseProtocolError,
  resolveTapokEndpoints,
  validateOidcDiscovery,
} from "../src/index.ts";

const authorization = {
  redirectUri: "https://app.example/callback",
  clientId: "client",
  state: "state",
  nonce: "nonce",
  codeChallenge: "A".repeat(43),
};
const tokenResponse = {
  access_token: "access",
  token_type: "Bearer",
  expires_in: 300,
  scope: "openid profile",
  id_token: "jwt",
  refresh_token: "refresh",
} as const;

describe("URL validation boundaries", () => {
  test.each(["?", "?query=value", "#", "#fragment"])(
    "rejects issuer components %s before appending endpoints",
    (suffix) => {
      const issuer = `https://id.example${suffix}`;
      expect(() => buildBaseAuthorizeUrl({ ...authorization, issuer })).toThrow(
        TypeError,
      );
      expect(() =>
        buildConnectAuthorizeUrl({
          ...authorization,
          issuer,
          scopes: ["openid"],
        }),
      ).toThrow(TypeError);
      expect(() =>
        buildOidcBaseAuthorizeUrl({
          ...authorization,
          issuer,
          scopes: ["openid"],
        }),
      ).toThrow(TypeError);
      expect(() => resolveTapokEndpoints({ issuer })).toThrow(TypeError);
      expect(() =>
        validateOidcDiscovery({ ...resolveTapokEndpoints(), issuer }, issuer),
      ).toThrow(TypeError);
    },
  );

  test.each([
    " https://app.example/callback",
    "https://app.example/callback ",
    "https://app.exam\nple/callback",
    "https://app.example/call\tback",
    "https://app.example/callback\u0000",
    "https://app.example\\callback",
    "https://app.example/callback#",
  ])("rejects ambiguous redirect URI %j", (redirectUri) => {
    expect(() => deriveBaseClientId(redirectUri)).toThrow(TypeError);
    expect(() =>
      buildBaseAuthorizeUrl({ ...authorization, redirectUri }),
    ).toThrow(TypeError);
  });

  test("preserves encoded delimiters and explicit default loopback ports", () => {
    const redirectUri =
      "https://app.example/callback?next=%23section&path=with%20space";
    expect(
      buildBaseAuthorizeUrl({ ...authorization, redirectUri }).searchParams.get(
        "redirect_uri",
      ),
    ).toBe(redirectUri);
    expect(deriveBaseClientId("http://localhost:80/callback")).toBe(
      "origin:http://localhost",
    );
    expect(deriveBaseClientId("http://[::1]:80/callback")).toBe(
      "origin:http://[::1]",
    );
    const issuer = "https://id.example/tenant%3Fone%23two";
    expect(resolveTapokEndpoints({ issuer }).token_endpoint).toBe(
      `${issuer}/api/v1/connect/token`,
    );
  });

  test("rejects even an empty callback fragment for strings and URL objects", () => {
    const callback = `https://app.example/callback?code=code&state=state&iss=${encodeURIComponent(TAPOK_ISSUER)}#`;
    for (const callbackUrl of [callback, new URL(callback)]) {
      try {
        parseAndValidateAuthorizationCallback({
          callbackUrl,
          expectedState: "state",
          expectedIssuer: TAPOK_ISSUER,
        });
        throw new Error("Expected an invalid callback");
      } catch (error) {
        expect(error).toBeInstanceOf(TapokCallbackValidationError);
        expect((error as TapokCallbackValidationError).code).toBe(
          "malformed_callback",
        );
      }
    }
  });
});

describe("response parsing boundaries", () => {
  test.each([null, "", 42, false, [], {}].map((id_token) => ({ id_token })))(
    "rejects invalid optional refresh ID token %j",
    ({ id_token }) => {
      expect(() =>
        parseConnectRefreshResponse({ ...tokenResponse, id_token }),
      ).toThrow("id_token");
    },
  );

  test("refresh ID tokens can be omitted, but never synthesized", () => {
    const { id_token, ...refreshResponse } = tokenResponse;
    expect(parseConnectRefreshResponse(refreshResponse)).toEqual(
      refreshResponse,
    );
    expect(
      parseConnectRefreshResponse({ ...refreshResponse, id_token: undefined }),
    ).not.toHaveProperty("id_token");
    expect(
      parseConnectRefreshResponse({ ...refreshResponse, id_token }),
    ).toEqual(tokenResponse);
    expect(() => parseConnectTokenResponse(refreshResponse)).toThrow(
      "id_token",
    );
  });

  test("ignores extensions without reading their values", () => {
    const response = {
      ...tokenResponse,
      get vendor_extension(): never {
        throw new Error("Extension must be ignored");
      },
    };
    expect(parseConnectTokenResponse(response)).toEqual(tokenResponse);
    expect(parseConnectRefreshResponse(response)).toEqual(tokenResponse);
    expect(
      parseConnectUserInfo(
        {
          sub: "subject",
          address: {
            country: "RU",
            get vendor_extension(): never {
              throw new Error("Extension must be ignored");
            },
          },
        },
        ["openid", "address"],
      ),
    ).toEqual({ sub: "subject", address: { country: "RU" } });
  });

  test("required protocol fields cannot come from an object's prototype", () => {
    expect(() =>
      parseBaseExchangeResponse(
        Object.create({
          identity_token: "jwt",
          expires_in: 600,
          scope: "session",
        }),
      ),
    ).toThrow("identity_token");
    for (const field of [
      "access_token",
      "id_token",
      "token_type",
      "expires_in",
      "scope",
    ] as const) {
      const response: Record<string, unknown> = { ...tokenResponse };
      delete response[field];
      Object.setPrototypeOf(response, { [field]: tokenResponse[field] });
      expect(() => parseConnectTokenResponse(response)).toThrow(field);
    }
    expect(() =>
      parseConnectUserInfo(Object.create({ sub: "subject" }), ["openid"]),
    ).toThrow("sub");
    expect(() =>
      parseProtocolError(Object.create({ error: "invalid_grant" })),
    ).toThrow("error");
    const endpoints = resolveTapokEndpoints();
    expect(() =>
      validateOidcDiscovery(Object.create(endpoints), endpoints.issuer),
    ).toThrow("issuer");
    const { jwks_uri, ...discovery } = endpoints;
    Object.setPrototypeOf(discovery, { jwks_uri });
    expect(() => validateOidcDiscovery(discovery, endpoints.issuer)).toThrow(
      "jwks_uri",
    );
  });

  test("accepts records without prototypes and ignores inherited optional fields", () => {
    expect(
      parseConnectTokenResponse(
        Object.assign(Object.create(null), tokenResponse),
      ),
    ).toEqual(tokenResponse);
    const { id_token, refresh_token, ...refreshResponse } = tokenResponse;
    Object.setPrototypeOf(refreshResponse, { id_token, refresh_token });
    expect(parseConnectRefreshResponse(refreshResponse)).toEqual({
      access_token: "access",
      token_type: "Bearer",
      expires_in: 300,
      scope: "openid profile",
    });
  });

  test("validates and returns the same single read of known fields", () => {
    let tokenReads = 0;
    expect(
      parseConnectRefreshResponse({
        ...tokenResponse,
        get id_token() {
          return tokenReads++ === 0 ? "jwt" : null;
        },
      }).id_token,
    ).toBe("jwt");
    expect(tokenReads).toBe(1);
    let descriptionReads = 0;
    expect(
      parseProtocolError({
        error: "invalid_grant",
        get error_description() {
          return descriptionReads++ === 0 ? "Denied" : 42;
        },
      }).error_description,
    ).toBe("Denied");
    expect(descriptionReads).toBe(1);
  });

  test("claim scope rules cannot be changed through the public policy object", () => {
    expect(Reflect.set(USERINFO_CLAIM_SCOPES, "phone_number", ["openid"])).toBe(
      false,
    );
    expect(Reflect.set(USERINFO_CLAIM_SCOPES.phone_number, "0", "openid")).toBe(
      false,
    );
    expect(() =>
      parseConnectUserInfo({ sub: "subject", phone_number: "+70000000000" }, [
        "openid",
      ]),
    ).toThrow("granted scopes");
  });

  test("custom field names remain data without changing result prototypes", () => {
    const custom_fields = JSON.parse(
      '{"__proto__":"data","constructor":"data","toString":"data"}',
    ) as Record<string, string>;
    const result = parseConnectUserInfo({ sub: "subject", custom_fields }, [
      "openid",
      "profile",
    ]);
    expect(Object.getPrototypeOf(result.custom_fields)).toBe(Object.prototype);
    expect(Object.hasOwn(result.custom_fields!, "__proto__")).toBe(true);
    expect(result.custom_fields).toEqual(custom_fields);
    expect(() =>
      parseConnectUserInfo({ sub: "subject", phone_number_verified: "true" }, [
        "openid",
        "phone",
      ]),
    ).toThrow("phone_number_verified");
  });
});
