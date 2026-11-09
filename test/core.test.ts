import { describe, expect, test } from "bun:test";
import {
  TAPOK_API_BASE_URL,
  TAPOK_ISSUER,
  TapokCallbackValidationError,
  buildBaseAuthorizeUrl,
  buildConnectAuthorizeUrl,
  createAuthorizationSecrets,
  createBaseExchangeBody,
  createConnectRevokeBody,
  createConnectTokenBody,
  deriveBaseClientId,
  parseAndValidateAuthorizationCallback,
  parseBaseExchangeResponse,
  parseConnectTokenResponse,
  parseConnectUserInfo,
  parseProtocolError,
  tapokEndpoints,
} from "../src/index.js";
import type { CallbackValidationErrorCode, IsoDate } from "../src/index.js";

const redirectUri = "https://app.example:8443/auth/tapok/callback?return=home";
const verifier = "A".repeat(43);

function expectCallbackError(
  callbackUrl: string,
  code: CallbackValidationErrorCode,
): void {
  try {
    parseAndValidateAuthorizationCallback({
      callbackUrl,
      expectedState: "expected",
      expectedIssuer: TAPOK_ISSUER,
    });
    throw new Error("Expected callback validation to fail");
  } catch (error) {
    expect(error).toBeInstanceOf(TapokCallbackValidationError);
    expect((error as TapokCallbackValidationError).code).toBe(code);
  }
}

describe("constants", () => {
  test("uses the versioned API namespace and well-known namespace", () => {
    expect(TAPOK_API_BASE_URL).toBe("https://tapok.orria.space/api/v1");
    expect(tapokEndpoints.baseAuthorize).toBe(
      `${TAPOK_API_BASE_URL}/base/authorize`,
    );
    expect(tapokEndpoints.oidcDiscovery).toBe(
      `${TAPOK_ISSUER}/.well-known/openid-configuration`,
    );
  });
});

describe("authorization secrets", () => {
  test("creates fresh RFC 7636 S256 material", async () => {
    const first = await createAuthorizationSecrets();
    const second = await createAuthorizationSecrets();

    expect(first.state).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(first.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(first.pkce.verifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(first.pkce.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(first.pkce.method).toBe("S256");
    expect(first.state).not.toBe(second.state);
    expect(first.nonce).not.toBe(second.nonce);
    expect(first.pkce.verifier).not.toBe(second.pkce.verifier);

    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(first.pkce.verifier),
    );
    const expected = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replace(/=+$/u, "");
    expect(first.pkce.challenge).toBe(expected);
  });
});

describe("authorize URL builders", () => {
  test("derives a Base client ID from the exact origin", () => {
    expect(deriveBaseClientId(redirectUri)).toBe(
      "origin:https://app.example:8443",
    );
    expect(() => deriveBaseClientId("data:text/plain,nope")).toThrow(TypeError);
    expect(() =>
      deriveBaseClientId("https://user@app.example/callback"),
    ).toThrow(TypeError);
    expect(() =>
      deriveBaseClientId("http://app.example:3000/callback"),
    ).toThrow("HTTPS");
    expect(() => deriveBaseClientId("http://localhost/callback")).toThrow(
      "explicit port",
    );
    expect(deriveBaseClientId("http://localhost:3000/callback")).toBe(
      "origin:http://localhost:3000",
    );
    expect(deriveBaseClientId("http://127.0.0.1:3000/callback")).toBe(
      "origin:http://127.0.0.1:3000",
    );
    expect(deriveBaseClientId("http://[::1]:3000/callback")).toBe(
      "origin:http://[::1]:3000",
    );
  });

  test("builds a canonical Base authorize URL", () => {
    const url = buildBaseAuthorizeUrl({
      redirectUri,
      scopes: ["age:18", "session", "age:18"],
      state: "state value",
      nonce: "nonce",
      codeChallenge: "challenge",
    });

    expect(url.origin + url.pathname).toBe(tapokEndpoints.baseAuthorize);
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe(
      "origin:https://app.example:8443",
    );
    expect(url.searchParams.get("redirect_uri")).toBe(redirectUri);
    expect(url.searchParams.get("scope")).toBe("session age:18");
    expect(url.searchParams.get("state")).toBe("state value");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  });

  test("requires openid and removes duplicate Connect scopes", () => {
    const url = buildConnectAuthorizeUrl({
      clientId: "tpk_client_example",
      redirectUri,
      scopes: ["openid", "profile", "openid"],
      state: "state",
      nonce: "nonce",
      codeChallenge: "challenge",
    });
    expect(url.origin + url.pathname).toBe(tapokEndpoints.connectAuthorize);
    expect(url.searchParams.get("scope")).toBe("openid profile");

    expect(() =>
      buildConnectAuthorizeUrl({
        clientId: "client",
        redirectUri,
        scopes: ["phone"],
        state: "state",
        nonce: "nonce",
        codeChallenge: "challenge",
      }),
    ).toThrow("openid");
  });

  test("rejects foreign issuers, unsupported scopes, and empty protocol values", () => {
    const input = {
      redirectUri,
      state: "state",
      nonce: "nonce",
      codeChallenge: "challenge",
    };
    expect(() =>
      buildBaseAuthorizeUrl({
        ...input,
        issuer: "http://evil.example",
      }),
    ).toThrow("HTTPS");
    expect(() =>
      buildBaseAuthorizeUrl({
        ...input,
        scopes: ["openid" as never],
      }),
    ).toThrow("unsupported");
    expect(() => buildBaseAuthorizeUrl({ ...input, state: "" })).toThrow(
      "state",
    );
    expect(() =>
      buildConnectAuthorizeUrl({
        ...input,
        clientId: "tpk_client_example",
        scopes: ["openid", "unsupported" as never],
      }),
    ).toThrow("unsupported");
    expect(() =>
      buildConnectAuthorizeUrl({
        ...input,
        clientId: "",
        scopes: ["openid"],
      }),
    ).toThrow("clientId");
  });
});

describe("callback validation", () => {
  test("parses success and protocol error callbacks", () => {
    expect(
      parseAndValidateAuthorizationCallback({
        callbackUrl: `https://app.example/callback?code=code&state=expected&iss=${encodeURIComponent(TAPOK_ISSUER)}`,
        expectedState: "expected",
        expectedIssuer: TAPOK_ISSUER,
      }),
    ).toEqual({
      ok: true,
      code: "code",
      state: "expected",
      issuer: TAPOK_ISSUER,
    });

    expect(
      parseAndValidateAuthorizationCallback({
        callbackUrl: `https://app.example/callback?error=access_denied&error_description=Denied&state=expected&iss=${encodeURIComponent(TAPOK_ISSUER)}`,
        expectedState: "expected",
        expectedIssuer: TAPOK_ISSUER,
      }),
    ).toEqual({
      ok: false,
      error: "access_denied",
      errorDescription: "Denied",
      state: "expected",
      issuer: TAPOK_ISSUER,
    });
  });

  test("reports each security validation class", () => {
    expectCallbackError("not a URL", "malformed_callback");
    expectCallbackError(
      `https://app.example/cb?iss=${TAPOK_ISSUER}&code=x`,
      "missing_state",
    );
    expectCallbackError(
      `https://app.example/cb?state=wrong&iss=${TAPOK_ISSUER}&code=x`,
      "state_mismatch",
    );
    expectCallbackError(
      "https://app.example/cb?state=expected&code=x",
      "missing_issuer",
    );
    expectCallbackError(
      "https://app.example/cb?state=expected&iss=https://evil.example&code=x",
      "issuer_mismatch",
    );
  });

  test("rejects duplicate, mixed, unknown and fragment parameters", () => {
    const issuer = encodeURIComponent(TAPOK_ISSUER);
    expectCallbackError(
      `https://app.example/cb?state=expected&state=expected&iss=${issuer}&code=x`,
      "malformed_callback",
    );
    expectCallbackError(
      `https://app.example/cb?state=expected&iss=${issuer}&code=x&error=access_denied`,
      "malformed_callback",
    );
    expectCallbackError(
      `https://app.example/cb?state=expected&iss=${issuer}&code=x&extra=y`,
      "malformed_callback",
    );
    expectCallbackError(
      `https://app.example/cb?state=expected&iss=${issuer}&code=x#fragment`,
      "malformed_callback",
    );
  });

  test("accepts URL instances and rejects unknown error codes, empty code, and stray descriptions", () => {
    const issuer = encodeURIComponent(TAPOK_ISSUER);
    const result = parseAndValidateAuthorizationCallback({
      callbackUrl: new URL(
        `https://app.example/cb?code=x&state=expected&iss=${issuer}`,
      ),
      expectedState: "expected",
      expectedIssuer: TAPOK_ISSUER,
    });
    expect(result.ok).toBe(true);

    expectCallbackError(
      `https://app.example/cb?state=expected&iss=${issuer}&error=not_a_code`,
      "malformed_callback",
    );
    expectCallbackError(
      `https://app.example/cb?state=expected&iss=${issuer}&code=`,
      "malformed_callback",
    );
    expectCallbackError(
      `https://app.example/cb?state=expected&iss=${issuer}&code=x&error_description=d`,
      "malformed_callback",
    );
  });
});

describe("form bodies", () => {
  test("serializes exact protocol fields", () => {
    expect(
      createBaseExchangeBody({
        grant_type: "authorization_code",
        code: "code",
        client_id: "origin:https://app.example",
        redirect_uri: "https://app.example/callback",
        code_verifier: verifier,
      }).toString(),
    ).toBe(
      `grant_type=authorization_code&code=code&client_id=origin%3Ahttps%3A%2F%2Fapp.example&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&code_verifier=${verifier}`,
    );

    expect(
      createConnectTokenBody({
        grant_type: "authorization_code",
        code: "code",
        redirect_uri: "https://app.example/callback",
        code_verifier: verifier,
      }).get("code_verifier"),
    ).toBe(verifier);

    expect(
      createConnectRevokeBody({ token: "token" }).has("token_type_hint"),
    ).toBe(false);
    expect(
      createConnectRevokeBody({
        token: "token",
        token_type_hint: "access_token",
      }).get("token_type_hint"),
    ).toBe("access_token");
  });

  test("rejects malformed body inputs", () => {
    const exchange = {
      grant_type: "authorization_code",
      code: "code",
      client_id: "origin:https://app.example",
      redirect_uri: "https://app.example/callback",
      code_verifier: verifier,
    } as const;
    expect(() =>
      createBaseExchangeBody({
        ...exchange,
        grant_type: "client_credentials" as never,
      }),
    ).toThrow("authorization_code");
    expect(() =>
      createBaseExchangeBody({
        ...exchange,
        redirect_uri: "http://app.example/callback",
      }),
    ).toThrow("HTTPS");
    expect(() =>
      createConnectTokenBody({
        grant_type: "authorization_code",
        code: "",
        redirect_uri: "https://app.example/callback",
        code_verifier: verifier,
      }),
    ).toThrow("code");
    expect(() => createConnectRevokeBody({ token: "" })).toThrow("token");
    expect(() =>
      createConnectRevokeBody({
        token: "token",
        token_type_hint: "invalid" as never,
      }),
    ).toThrow("access_token");
  });
});

describe("runtime parsers", () => {
  test("parses exact Base and Connect responses", () => {
    expect(
      parseBaseExchangeResponse({
        identity_token: "jwt",
        expires_in: 600,
        scope: "session age:18",
      }).identity_token,
    ).toBe("jwt");

    expect(
      parseConnectTokenResponse({
        access_token: "opaque",
        token_type: "Bearer",
        expires_in: 900,
        scope: "openid phone",
        id_token: "jwt",
      }).scope,
    ).toBe("openid phone");
  });

  test("rejects wrong TTLs and invalid scopes", () => {
    for (const expires_in of [0, -1, 601, 1.5, "600", null, undefined]) {
      expect(() =>
        parseBaseExchangeResponse({
          identity_token: "jwt",
          expires_in,
          scope: "session",
        }),
      ).toThrow("expires_in");
    }
    expect(() =>
      parseBaseExchangeResponse({
        identity_token: "jwt",
        expires_in: 600,
        scope: "session profile",
      }),
    ).toThrow("scope");

    expect(() =>
      parseConnectTokenResponse({
        access_token: "opaque",
        token_type: "Bearer",
        expires_in: -1,
        scope: "openid",
        id_token: "jwt",
      }),
    ).toThrow("positive integer");

    expect(() =>
      parseConnectTokenResponse({
        access_token: "opaque",
        token_type: "Bearer",
        expires_in: 900,
        scope: "phone",
        id_token: "jwt",
      }),
    ).toThrow("openid");
  });

  test("enforces UserInfo claim scopes and calendar dates", () => {
    expect(
      parseConnectUserInfo(
        {
          sub: "subject",
          is_adult: null,
          family_name: "Doe",
          given_name: "Jane",
          birthdate: "2000-02-29",
        },
        ["openid", "age:18", "profile:name", "profile:birthdate"],
      ),
    ).toEqual({
      sub: "subject",
      is_adult: null,
      family_name: "Doe",
      given_name: "Jane",
      birthdate: "2000-02-29" as IsoDate,
    });

    expect(
      parseConnectUserInfo(
        {
          sub: "subject",
          email: "user-abcdefghijklmnopqrst@tapok.orria.space",
          email_verified: true,
        },
        ["openid", "email"],
      ),
    ).toEqual({
      sub: "subject",
      email: "user-abcdefghijklmnopqrst@tapok.orria.space",
      email_verified: true,
    });
    expect(() =>
      parseConnectUserInfo({ sub: "subject", email: "not-an-email" }, [
        "openid",
        "email",
      ]),
    ).toThrow("valid email address");
    expect(
      parseConnectUserInfo(
        {
          sub: "subject",
          name: "Jane Doe",
          family_name: "Doe",
          birthdate: "2000-02-29",
        },
        ["openid", "profile"],
      ),
    ).toEqual({
      sub: "subject",
      name: "Jane Doe",
      family_name: "Doe",
      birthdate: "2000-02-29" as IsoDate,
    });
    expect(() =>
      parseConnectUserInfo({ sub: "subject", email: "invalid@@example.com" }, [
        "openid",
        "email",
      ]),
    ).toThrow("valid email address");
    expect(() =>
      parseConnectUserInfo({ sub: "subject", name: "Jane Doe" }, [
        "openid",
        "profile:name",
      ]),
    ).toThrow("granted scopes");
    expect(() =>
      parseConnectUserInfo({ sub: "subject", phone_number: "+70000000000" }, [
        "openid",
      ]),
    ).toThrow("granted scopes");
    expect(() =>
      parseConnectUserInfo({ sub: "subject", birthdate: "1900-02-29" }, [
        "openid",
        "profile:birthdate",
      ]),
    ).toThrow("YYYY-MM-DD");
    expect(() =>
      parseConnectUserInfo({ sub: "subject", birthdate: "2024-04-31" }, [
        "openid",
        "profile:birthdate",
      ]),
    ).toThrow("YYYY-MM-DD");
  });

  test("parses only allowlisted protocol errors", () => {
    expect(
      parseProtocolError({
        error: "invalid_grant",
        error_description: "The grant is no longer valid",
      }),
    ).toEqual({
      error: "invalid_grant",
      error_description: "The grant is no longer valid",
    });
    expect(() => parseProtocolError({ error: "other" })).toThrow(TypeError);
    expect(
      parseProtocolError({ error: "invalid_request", code: "secret" }),
    ).toEqual({ error: "invalid_request" });
    expect(() =>
      parseProtocolError({ error: "invalid_grant", error_description: 5 }),
    ).toThrow("string");
  });

  test("validates granted scope lists before reading UserInfo", () => {
    expect(() =>
      parseConnectUserInfo({ sub: "s" }, ["openid", "openid"]),
    ).toThrow("duplicate");
    expect(() => parseConnectUserInfo({ sub: "s" }, ["phone"])).toThrow(
      "openid",
    );
    expect(parseConnectUserInfo({ sub: "s" }, ["openid", "email"])).toEqual({
      sub: "s",
    });
  });

  test("rejects invalid response shapes and claim value types", () => {
    expect(() => parseBaseExchangeResponse("nope")).toThrow("object");
    expect(() =>
      parseBaseExchangeResponse({
        identity_token: "jwt",
        expires_in: 601,
        scope: "session",
      }),
    ).toThrow("600");
    expect(() =>
      parseBaseExchangeResponse({
        identity_token: "jwt",
        expires_in: 600,
        scope: "age:18",
      }),
    ).toThrow("session");
    expect(() => parseConnectUserInfo({ sub: 42 }, ["openid"])).toThrow("sub");
    expect(() =>
      parseConnectUserInfo({ sub: "s", is_adult: "yes" }, ["openid", "age:18"]),
    ).toThrow("boolean");
    expect(() =>
      parseConnectUserInfo({ sub: "s", display_name: "" }, [
        "openid",
        "profile:display_name",
      ]),
    ).toThrow("display_name");
    expect(() =>
      parseConnectUserInfo({ sub: "s", birthdate: 20000229 }, [
        "openid",
        "profile:birthdate",
      ]),
    ).toThrow("YYYY-MM-DD");
  });
});
