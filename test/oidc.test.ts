import { expect, test } from "bun:test";
import {
  buildOidcBaseAuthorizeUrl,
  resolveTapokEndpoints,
  validateOidcDiscovery,
  parseConnectTokenResponse,
  parseConnectRefreshResponse,
  parseConnectUserInfo,
  createConnectRefreshBody,
  buildLogoutUrl,
  parseAndValidateAuthorizationCallback,
} from "../src/index.ts";

test("discovery pins issuer and rejects untrusted egress targets before use", () => {
  const endpoints = resolveTapokEndpoints({
    issuer: "https://id.example",
    mode: "connect",
  });
  expect(
    validateOidcDiscovery(
      { ...endpoints, extension: "ignored" },
      endpoints.issuer,
    ),
  ).toEqual(endpoints);
  expect(() =>
    validateOidcDiscovery(
      { ...endpoints, issuer: "https://evil.example" },
      endpoints.issuer,
    ),
  ).toThrow("issuer");
  expect(() =>
    validateOidcDiscovery(
      { ...endpoints, jwks_uri: "http://169.254.169.254/latest" },
      endpoints.issuer,
    ),
  ).toThrow();
  expect(() =>
    validateOidcDiscovery(
      { ...endpoints, token_endpoint: "https://evil.example/token" },
      endpoints.issuer,
    ),
  ).toThrow("Untrusted");
});

test("Base OIDC uses isolated issuer and refuses personal scopes", () => {
  const input = {
    clientId: "base-client",
    redirectUri: "https://app.example/callback",
    state: "state",
    nonce: "nonce",
    codeChallenge: "challenge",
    scopes: ["openid", "profile", "email"] as const,
  };
  const url = buildOidcBaseAuthorizeUrl({
    ...input,
    prompt: "none",
    maxAge: 0,
  });
  expect(url.pathname).toBe("/oidc/base/authorize");
  expect(url.searchParams.get("max_age")).toBe("0");
  expect(() =>
    buildOidcBaseAuthorizeUrl({
      ...input,
      scopes: ["openid", "phone" as never],
    }),
  ).toThrow("scopes");
  expect(() =>
    buildOidcBaseAuthorizeUrl({ ...input, maxAge: Infinity }),
  ).toThrow("maxAge");
  const issuer = resolveTapokEndpoints({ mode: "base" }).issuer;
  expect(
    parseAndValidateAuthorizationCallback({
      callbackUrl:
        "https://app.example/callback?state=state&error=login_required&iss=" +
        encodeURIComponent(issuer),
      expectedIssuer: issuer,
      expectedState: "state",
    }).ok,
  ).toBe(false);
});

test("OIDC responses allow extensions while retaining known-field validation", () => {
  const response = {
    access_token: "access",
    token_type: "Bearer",
    expires_in: 300,
    scope: "openid email offline_access",
    id_token: "jwt",
    refresh_token: "refresh",
    vendor_extension: true,
  };
  expect(parseConnectTokenResponse(response)).not.toHaveProperty(
    "vendor_extension",
  );
  expect(parseConnectTokenResponse(response).refresh_token).toBe("refresh");
  for (const expires_in of [NaN, Infinity, 0, -1, 1.5, 86401])
    expect(() =>
      parseConnectTokenResponse({ ...response, expires_in }),
    ).toThrow();
  expect(() =>
    parseConnectTokenResponse({ ...response, refresh_token: 42 }),
  ).toThrow();
  const { id_token, ...refresh } = response;
  expect(parseConnectRefreshResponse(refresh)).not.toHaveProperty("id_token");
  expect(
    createConnectRefreshBody({
      grant_type: "refresh_token",
      refresh_token: "opaque",
      scope: "openid email",
    }).get("grant_type"),
  ).toBe("refresh_token");
});

test("standard profile and contact email retain scope boundaries", () => {
  expect(
    parseConnectUserInfo(
      {
        sub: "s",
        email: "contact@example.org",
        email_verified: false,
        nickname: "reader",
        locale: "ru",
        updated_at: 123,
        vendor_extension: "secret",
      },
      ["openid", "email", "profile"],
    ),
  ).toEqual({
    sub: "s",
    email: "contact@example.org",
    email_verified: false,
    nickname: "reader",
    locale: "ru",
    updated_at: 123,
  });
  expect(() =>
    parseConnectUserInfo({ sub: "s", phone_number_verified: true }, ["openid"]),
  ).toThrow("scopes");
  expect(() =>
    parseConnectUserInfo({ sub: "s", updated_at: "now" }, [
      "openid",
      "profile",
    ]),
  ).toThrow();
  expect(() =>
    parseConnectUserInfo({ sub: "s", address: { country: 7 } }, [
      "openid",
      "address",
    ]),
  ).toThrow();
  expect(
    buildLogoutUrl({
      clientId: "client",
      postLogoutRedirectUri: "https://app.example/signed-out",
      state: "bound",
    }).searchParams.get("state"),
  ).toBe("bound");
});
