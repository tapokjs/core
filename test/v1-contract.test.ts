import { describe, expect, test } from "bun:test";
import * as core from "../src/index.ts";
import {
  TAPOK_ISSUER,
  TapokCallbackValidationError,
  TapokError,
  buildBaseAuthorizeUrl,
  buildConnectAuthorizeUrl,
  buildLogoutUrl,
  buildOidcBaseAuthorizeUrl,
  createBaseExchangeBody,
  createConnectRevokeBody,
  createConnectTokenBody,
  deriveBaseClientId,
  parseAndValidateAuthorizationCallback,
  parseBaseExchangeResponse,
  parseConnectRefreshResponse,
  parseConnectTokenResponse,
  parseConnectUserInfo,
  parseProtocolError,
  resolveTapokEndpoints,
  tapokEndpoints,
  validateOidcDiscovery,
} from "../src/index.ts";

const secrets = {
  state: "state",
  nonce: "nonce",
  codeChallenge: "c".repeat(43),
};

describe("public surface", () => {
  test("exports exactly the documented runtime names", () => {
    // A new export must be a decision, not a side effect of `export *`.
    expect(Object.keys(core).sort()).toEqual([
      "BASE_OIDC_SCOPES",
      "CONNECT_SCOPES",
      "TAPOK_API_BASE_URL",
      "TAPOK_BASE_OIDC_ISSUER",
      "TAPOK_ISSUER",
      "TapokCallbackValidationError",
      "TapokError",
      "USERINFO_CLAIM_SCOPES",
      "buildBaseAuthorizeUrl",
      "buildConnectAuthorizeUrl",
      "buildLogoutUrl",
      "buildOidcBaseAuthorizeUrl",
      "createAuthorizationSecrets",
      "createBaseExchangeBody",
      "createConnectRefreshBody",
      "createConnectRevokeBody",
      "createConnectTokenBody",
      "deriveBaseClientId",
      "parseAndValidateAuthorizationCallback",
      "parseBaseExchangeResponse",
      "parseConnectRefreshResponse",
      "parseConnectTokenResponse",
      "parseConnectUserInfo",
      "parseProtocolError",
      "resolveTapokEndpoints",
      "tapokEndpoints",
      "validateOidcDiscovery",
    ]);
  });

  test("constants keep their values and cannot be repointed", () => {
    expect(core.TAPOK_API_BASE_URL).toBe(`${TAPOK_ISSUER}/api/v1`);
    expect(core.TAPOK_BASE_OIDC_ISSUER).toBe(`${TAPOK_ISSUER}/oidc/base`);
    expect(tapokEndpoints.baseExchange).toBe(
      `${TAPOK_ISSUER}/api/v1/base/exchange`,
    );
    expect(tapokEndpoints.jwks).toBe(`${TAPOK_ISSUER}/.well-known/jwks.json`);
    expect(Object.isFrozen(tapokEndpoints)).toBe(true);
    expect([...core.CONNECT_SCOPES]).toEqual([
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
    expect(Object.isFrozen(core.CONNECT_SCOPES)).toBe(true);
    expect(Object.isFrozen(core.USERINFO_CLAIM_SCOPES.email)).toBe(true);
  });

  test("callback errors share the TapokError base and a stable code", () => {
    const error = new TapokCallbackValidationError("state_mismatch");
    expect(error).toBeInstanceOf(TapokError);
    expect(error).toBeInstanceOf(Error);
    expect(error.name).toBe("TapokCallbackValidationError");
    expect(error.code).toBe("state_mismatch");
    expect(error.message).toBe("state_mismatch");
  });
});

describe("redirect URI with its own query", () => {
  const redirectUri = "https://app.example/callback?tenant=a%20b&flow=1";
  const issuer = TAPOK_ISSUER;
  const callback = (query: string) => `https://app.example/callback?${query}`;
  // `null` means "do not pass the option at all".
  const validate = (query: string, registered: string | null = redirectUri) =>
    parseAndValidateAuthorizationCallback({
      callbackUrl: callback(query),
      expectedState: "state",
      expectedIssuer: issuer,
      ...(registered === null ? {} : { redirectUri: registered }),
    });
  const oauth = `code=c&state=state&iss=${encodeURIComponent(issuer)}`;

  test("builders keep the registered URI byte for byte", () => {
    const url = buildBaseAuthorizeUrl({ redirectUri, ...secrets });
    expect(url.searchParams.get("redirect_uri")).toBe(redirectUri);
    expect(deriveBaseClientId(redirectUri)).toBe("origin:https://app.example");
  });

  test("accepts the callback the platform builds from the registered URI", () => {
    // The platform copies the registered URI and appends its own parameters.
    const built = new URL(redirectUri);
    built.searchParams.set("code", "c");
    built.searchParams.set("state", "state");
    built.searchParams.set("iss", issuer);
    expect(
      parseAndValidateAuthorizationCallback({
        callbackUrl: built,
        expectedState: "state",
        expectedIssuer: issuer,
        redirectUri,
      }),
    ).toEqual({ ok: true, code: "c", state: "state", issuer });
    expect(validate(`tenant=a+b&flow=1&${oauth}`).ok).toBe(true);
  });

  test.each([
    ["a registered parameter is missing", `tenant=a+b&${oauth}`],
    ["a registered value was changed", `tenant=evil&flow=1&${oauth}`],
    [
      "a registered parameter is duplicated",
      `tenant=a+b&tenant=a+b&flow=1&${oauth}`,
    ],
    ["the registered order was changed", `flow=1&tenant=a+b&${oauth}`],
    ["a foreign parameter was added", `tenant=a+b&flow=1&debug=1&${oauth}`],
    ["a protocol parameter is duplicated", `tenant=a+b&flow=1&${oauth}&code=d`],
  ])("rejects a callback where %s", (_name, query) => {
    expect(() => validate(query)).toThrow(
      new TapokCallbackValidationError("malformed_callback"),
    );
  });

  test("without redirectUri every non-protocol parameter is still rejected", () => {
    expect(() => validate(`tenant=a+b&flow=1&${oauth}`, null)).toThrow(
      "malformed_callback",
    );
    expect(validate(oauth, null).ok).toBe(true);
    // A URI without a query behaves exactly like the omitted option.
    expect(validate(oauth, "https://app.example/callback").ok).toBe(true);
    expect(() =>
      validate(`tenant=1&${oauth}`, "https://app.example/callback"),
    ).toThrow("malformed_callback");
  });

  test("state and issuer are still checked before the registered query", () => {
    expect(() =>
      parseAndValidateAuthorizationCallback({
        callbackUrl: callback(`code=c&state=other&iss=${issuer}`),
        expectedState: "state",
        expectedIssuer: issuer,
        redirectUri,
      }),
    ).toThrow("state_mismatch");
  });

  test.each(["code", "state", "iss", "error", "error_description"])(
    "fails fast when the redirect URI itself carries %s",
    (name) => {
      const reserved = `https://app.example/callback?${name}=x`;
      const message = `must not contain the ${name} query parameter`;
      expect(() =>
        buildBaseAuthorizeUrl({ redirectUri: reserved, ...secrets }),
      ).toThrow(message);
      expect(() =>
        buildConnectAuthorizeUrl({
          redirectUri: reserved,
          clientId: "client",
          scopes: ["openid"],
          ...secrets,
        }),
      ).toThrow(message);
      expect(() =>
        buildOidcBaseAuthorizeUrl({
          redirectUri: reserved,
          clientId: "client",
          scopes: ["openid"],
          ...secrets,
        }),
      ).toThrow(message);
      expect(() => deriveBaseClientId(reserved)).toThrow(message);
      expect(() =>
        createConnectTokenBody({
          grant_type: "authorization_code",
          code: "c",
          redirect_uri: reserved,
          code_verifier: "v",
        }),
      ).toThrow(message);
      expect(() =>
        createBaseExchangeBody({
          grant_type: "authorization_code",
          code: "c",
          client_id: "origin:https://app.example",
          redirect_uri: reserved,
          code_verifier: "v",
        }),
      ).toThrow(message);
      expect(() =>
        parseAndValidateAuthorizationCallback({
          callbackUrl: callback(oauth),
          expectedState: "state",
          expectedIssuer: issuer,
          redirectUri: reserved,
        }),
      ).toThrow(message);
    },
  );
});

describe("forward-compatible response parsing", () => {
  test("Base exchange ignores fields it does not know and never copies them", () => {
    const parsed = parseBaseExchangeResponse({
      identity_token: "jwt",
      expires_in: 600,
      scope: "session age:18",
      token_type: "Bearer",
      future: { nested: true },
    });
    expect(parsed).toEqual({
      identity_token: "jwt",
      expires_in: 600,
      scope: "session age:18",
    });
  });

  test("Base exchange accepts a shorter lifetime and reports it", () => {
    expect(
      parseBaseExchangeResponse({
        identity_token: "jwt",
        expires_in: 300,
        scope: "session",
      }).expires_in,
    ).toBe(300);
  });

  test("Base exchange still requires its own fields", () => {
    const inherited = Object.create({ identity_token: "jwt" }) as Record<
      string,
      unknown
    >;
    inherited["expires_in"] = 600;
    inherited["scope"] = "session";
    expect(() => parseBaseExchangeResponse(inherited)).toThrow(
      "identity_token",
    );
    expect(() =>
      parseBaseExchangeResponse({ identity_token: "", expires_in: 600 }),
    ).toThrow("identity_token");
  });

  test.each(["Bearer", "bearer", "BEARER"])(
    "token_type %s is accepted and normalised",
    (token_type) => {
      const response = {
        access_token: "a",
        token_type,
        expires_in: 300,
        scope: "openid",
        id_token: "jwt",
      };
      expect(parseConnectTokenResponse(response).token_type).toBe("Bearer");
      expect(parseConnectRefreshResponse(response).token_type).toBe("Bearer");
    },
  );

  test.each(["MAC", "", "Bearer ", 1, null, undefined])(
    "token_type %p is rejected",
    (token_type) => {
      expect(() =>
        parseConnectTokenResponse({
          access_token: "a",
          token_type,
          expires_in: 300,
          scope: "openid",
          id_token: "jwt",
        }),
      ).toThrow("token_type");
    },
  );

  test("UserInfo objects are ordinary mutable data", () => {
    const info = parseConnectUserInfo(
      {
        sub: "u",
        custom_fields: { plan: "pro", ["__proto__"]: "data" },
        address: { country: "RU", unknown: "dropped" },
      },
      ["openid", "profile", "address"],
    );
    info.custom_fields!["plan"] = "free";
    delete info.address!.country;
    expect(info.custom_fields!["plan"]).toBe("free");
    expect(info.address).toEqual({});
    expect(Object.getPrototypeOf(info.custom_fields)).toBe(Object.prototype);
    expect(Object.hasOwn(info.custom_fields!, "__proto__")).toBe(true);
  });
});

describe("runtime validation of options", () => {
  const connect = {
    clientId: "tpk_client_x",
    redirectUri: "https://app.example/callback",
    scopes: ["openid"] as const,
    ...secrets,
  };

  test("accepts well-formed optional OIDC parameters", () => {
    const url = buildConnectAuthorizeUrl({
      ...connect,
      prompt: "login",
      maxAge: 0,
      uiLocales: "ru en-US",
      loginHint: "user@example.com",
    });
    expect(url.searchParams.get("prompt")).toBe("login");
    expect(url.searchParams.get("max_age")).toBe("0");
    expect(url.searchParams.get("ui_locales")).toBe("ru en-US");
    expect(url.searchParams.get("login_hint")).toBe("user@example.com");
  });

  test.each([
    [{ uiLocales: "" }, "uiLocales"],
    [{ uiLocales: 5 }, "uiLocales"],
    [{ uiLocales: "ru\nen" }, "uiLocales"],
    [{ uiLocales: "x".repeat(256) }, "uiLocales"],
    [{ loginHint: "" }, "loginHint"],
    [{ loginHint: {} }, "loginHint"],
    [{ loginHint: "a\u0000b" }, "loginHint"],
    [{ loginHint: "x".repeat(321) }, "loginHint"],
    [{ prompt: "silent" }, "prompt"],
    [{ prompt: ["none"] }, "prompt"],
    [{ maxAge: -1 }, "maxAge"],
    [{ maxAge: "60" }, "maxAge"],
    [{ maxAge: 1.5 }, "maxAge"],
  ])("rejects %p", (options, field) => {
    expect(() =>
      buildConnectAuthorizeUrl({ ...connect, ...(options as object) }),
    ).toThrow(field);
    expect(() =>
      buildOidcBaseAuthorizeUrl({ ...connect, ...(options as object) }),
    ).toThrow(field);
  });

  test("scopes must be arrays", () => {
    const scopes = "openid" as unknown as readonly ["openid"];
    expect(() => buildConnectAuthorizeUrl({ ...connect, scopes })).toThrow(
      "scopes must be an array",
    );
    expect(() => buildOidcBaseAuthorizeUrl({ ...connect, scopes })).toThrow(
      "Unsupported Base OIDC scopes",
    );
    expect(() =>
      buildBaseAuthorizeUrl({
        redirectUri: connect.redirectUri,
        scopes: "age:18" as unknown as readonly ["age:18"],
        ...secrets,
      }),
    ).toThrow("scopes must be an array");
  });

  test("endpoint mode and issuer are validated", () => {
    expect(() =>
      resolveTapokEndpoints({ mode: "native" as unknown as "base" }),
    ).toThrow("mode must be connect or base");
    expect(() =>
      resolveTapokEndpoints({ issuer: 5 as unknown as string }),
    ).toThrow("issuer must be a string");
    for (const issuer of [
      "https://id.example/",
      "https://id.example?x=1",
      "http://id.example",
    ]) {
      expect(() => resolveTapokEndpoints({ issuer })).toThrow("issuer");
      expect(() => buildConnectAuthorizeUrl({ ...connect, issuer })).toThrow(
        "issuer",
      );
      expect(() => buildLogoutUrl({ issuer })).toThrow("issuer");
    }
  });

  test("discovery trust list must contain exact origins", () => {
    const issuer = "https://id.example";
    const discovery = {
      issuer,
      authorization_endpoint: "https://login.example/authorize",
      token_endpoint: `${issuer}/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      revocation_endpoint: `${issuer}/revoke`,
      end_session_endpoint: `${issuer}/logout`,
      jwks_uri: `${issuer}/jwks`,
    };
    expect(
      validateOidcDiscovery(discovery, issuer, ["https://login.example"])
        .authorization_endpoint,
    ).toBe("https://login.example/authorize");
    for (const origins of [
      ["https://login.example/"],
      ["https://login.example/path"],
      ["login.example"],
      [5],
      "https://login.example",
    ]) {
      expect(() =>
        validateOidcDiscovery(
          discovery,
          issuer,
          origins as unknown as readonly string[],
        ),
      ).toThrow("allowedEndpointOrigins");
    }
    expect(() => validateOidcDiscovery(discovery, issuer + "/")).toThrow(
      "expectedIssuer",
    );
  });

  test("revoke hint error names both accepted values", () => {
    expect(() =>
      createConnectRevokeBody({
        token: "t",
        token_type_hint: "id_token" as unknown as "access_token",
      }),
    ).toThrow("access_token or refresh_token");
  });
});

describe("parser errors name the field and never quote a value", () => {
  // The SDK forwards these messages into errors that applications log whole.
  const MARKER = "SECRET-MARKER-7f3a";
  const token = {
    access_token: `access-${MARKER}`,
    token_type: "Bearer",
    expires_in: 300,
    scope: "openid",
    id_token: `id-${MARKER}`,
  };
  const message = (run: () => unknown): string => {
    try {
      run();
    } catch (error) {
      expect(error).toBeInstanceOf(TypeError);
      expect((error as Error).cause).toBeUndefined();
      return String(error) + JSON.stringify(error);
    }
    throw new Error("Expected the parser to reject");
  };

  test.each([
    { token_type: `type-${MARKER}` },
    { expires_in: `ttl-${MARKER}` },
    { scope: `openid ${MARKER}` },
    { scope: `openid openid ${MARKER}` },
    { scope: [MARKER] },
    { access_token: { value: MARKER } },
    { access_token: "" },
    { id_token: 5 },
    { refresh_token: { value: MARKER } },
  ])("token response patched with %p", (patch) => {
    for (const parse of [
      parseConnectTokenResponse,
      parseConnectRefreshResponse,
    ]) {
      expect(message(() => parse({ ...token, ...patch }))).not.toContain(
        MARKER,
      );
    }
  });

  test.each([
    { identity_token: { value: MARKER } },
    { expires_in: `ttl-${MARKER}` },
    { scope: `session ${MARKER}` },
  ])("Base exchange patched with %p", (patch) => {
    const valid = {
      identity_token: `jwt-${MARKER}`,
      expires_in: 600,
      scope: "session",
    };
    expect(
      message(() => parseBaseExchangeResponse({ ...valid, ...patch })),
    ).not.toContain(MARKER);
  });

  test.each([
    [{ sub: { value: MARKER } }, ["openid"]],
    [{ sub: "u", email: `not-an-email-${MARKER}` }, ["openid", "email"]],
    [{ sub: "u", email: `${MARKER}@mail.example` }, ["openid"]],
    [{ sub: "u", email_verified: MARKER }, ["openid", "email"]],
    [{ sub: "u", birthdate: `2000-13-${MARKER}` }, ["openid", "profile"]],
    [{ sub: "u", is_adult: MARKER }, ["openid", "age:18"]],
    [{ sub: "u", updated_at: MARKER }, ["openid", "profile"]],
    [{ sub: "u", address: { country: { v: MARKER } } }, ["openid", "address"]],
    [{ sub: "u", custom_fields: { [MARKER]: 5 } }, ["openid", "profile"]],
    [{ sub: "u", name: { v: MARKER } }, ["openid", "profile"]],
    [{ sub: "u" }, ["openid", MARKER]],
  ] as const)("UserInfo %p", (value, scopes) => {
    expect(
      message(() =>
        parseConnectUserInfo(value, scopes as unknown as readonly ["openid"]),
      ),
    ).not.toContain(MARKER);
  });

  test("protocol error body and callback", () => {
    expect(
      message(() => parseProtocolError({ error: `code-${MARKER}` })),
    ).not.toContain(MARKER);
    expect(
      message(() =>
        parseProtocolError({
          error: "invalid_grant",
          error_description: { v: MARKER },
        }),
      ),
    ).not.toContain(MARKER);
    try {
      parseAndValidateAuthorizationCallback({
        callbackUrl: `https://app.example/cb?code=${MARKER}&state=${MARKER}&iss=${MARKER}&x=${MARKER}`,
        expectedState: "state",
        expectedIssuer: TAPOK_ISSUER,
      });
      throw new Error("Expected the callback to be rejected");
    } catch (error) {
      expect(error).toBeInstanceOf(TapokCallbackValidationError);
      expect(
        String(error) + JSON.stringify(error) + String((error as Error).cause),
      ).not.toContain(MARKER);
    }
  });
});
