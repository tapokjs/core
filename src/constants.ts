// Plain string literals (no template substitutions) keep every constant
// removable by bundlers that do not evaluate templates at build time.
export const TAPOK_ISSUER = "https://tapok.orria.space" as const;
export const TAPOK_API_BASE_URL = "https://tapok.orria.space/api/v1" as const;

export const tapokEndpoints = /* @__PURE__ */ Object.freeze({
  baseAuthorize: "https://tapok.orria.space/api/v1/base/authorize",
  baseExchange: "https://tapok.orria.space/api/v1/base/exchange",
  connectAuthorize: "https://tapok.orria.space/api/v1/connect/authorize",
  connectToken: "https://tapok.orria.space/api/v1/connect/token",
  connectUserInfo: "https://tapok.orria.space/api/v1/connect/userinfo",
  connectRevoke: "https://tapok.orria.space/api/v1/connect/revoke",
  oidcDiscovery: "https://tapok.orria.space/.well-known/openid-configuration",
  baseMetadata:
    "https://tapok.orria.space/.well-known/tapok-base-configuration",
  jwks: "https://tapok.orria.space/.well-known/jwks.json",
} as const);
