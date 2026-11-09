export type TapokMode = "base" | "connect";

export type BaseScope = "session" | "age:18";

export type ConnectScope =
  | "openid"
  | "email"
  | "profile"
  | "age:18"
  | "profile:display_name"
  | "profile:name"
  | "profile:birthdate"
  | "phone"
  | "address"
  | "offline_access";

export type AuthorizationResponseErrorCode =
  | "invalid_request"
  | "unauthorized_client"
  | "invalid_scope"
  | "login_required"
  | "interaction_required"
  | "consent_required"
  | "account_selection_required"
  | "request_not_supported"
  | "request_uri_not_supported"
  | "registration_not_supported"
  | "access_denied"
  | "unsupported_response_type"
  | "server_error"
  | "temporarily_unavailable";

export type TokenEndpointErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "invalid_scope"
  | "unsupported_grant_type"
  | "unsupported_token_type"
  | "invalid_token"
  | "insufficient_scope"
  | "server_error"
  | "temporarily_unavailable";

export type TapokProtocolErrorCode =
  AuthorizationResponseErrorCode | TokenEndpointErrorCode;

export type TapokProtocolErrorBody = {
  error: TapokProtocolErrorCode;
  error_description?: string;
};

export type AuthorizationRequest = {
  response_type: "code";
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  nonce: string;
  code_challenge: string;
  code_challenge_method: "S256";
};

export type AuthorizationSuccessCallback = {
  code: string;
  state: string;
  iss: string;
};

export type AuthorizationErrorCallback = {
  error: AuthorizationResponseErrorCode;
  error_description?: string;
  state: string;
  iss: string;
};

export type BaseClientManifest = {
  issuer: string;
  redirect_uris: string[];
};

export type BaseAuthorizeRequest = AuthorizationRequest & {
  client_id: `origin:${string}`;
  scope: "session" | "session age:18";
};

export type BaseExchangeRequest = {
  grant_type: "authorization_code";
  code: string;
  client_id: `origin:${string}`;
  redirect_uri: string;
  code_verifier: string;
};

export type BaseExchangeResponse = {
  identity_token: string;
  /** Seconds, at most 600. */
  expires_in: number;
  scope: "session" | "session age:18";
};

export type BaseIdentityTokenClaims = {
  iss: string;
  sub: string;
  aud: `origin:${string}`;
  exp: number;
  iat: number;
  jti: string;
  nonce: string;
  mode: "base";
  pairwise_sub: string;
  is_adult?: boolean | null;
};

export type TapokJwtHeader = {
  alg: "ES256" | "RS256";
  typ: "JWT";
  kid: string;
};

export type BaseMetadata = {
  issuer: string;
  authorization_endpoint: string;
  exchange_endpoint: string;
  jwks_uri: string;
  response_type: "code";
  code_challenge_methods_supported: "S256"[];
  identity_token_signing_alg_values_supported: ("ES256" | "RS256")[];
  scopes_supported: BaseScope[];
  authorization_response_iss_parameter_supported: true;
};

export type ConnectAuthorizeRequest = Omit<
  AuthorizationRequest,
  "state" | "nonce"
> & {
  state?: string;
  nonce?: string;
  client_id: `tpk_client_${string}`;
  scope: string;
  prompt?: string;
  max_age?: string;
  response_mode?: "query";
  display?: string;
  ui_locales?: string;
  claims_locales?: string;
  login_hint?: string;
  id_token_hint?: string;
};

export type ConnectTokenRequest = {
  grant_type: "authorization_code";
  code: string;
  redirect_uri: string;
  code_verifier: string;
};

export type ConnectTokenResponse = {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
  id_token: string;
  refresh_token?: string;
};

export type ConnectIdTokenClaims = {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat: number;
  jti: string;
  nonce?: string;
  auth_time?: number;
  mode: "connect";
  /** Pairwise technical address, included only when the email scope is granted. */
  email?: string;
  email_verified?: boolean;
  name?: string;
  is_adult?: boolean | null;
};

declare const isoDateBrand: unique symbol;

export type IsoDate = string & {
  readonly [isoDateBrand]: "YYYY-MM-DD";
};

export type ConnectUserInfo = {
  sub: string;
  email?: string;
  email_verified?: boolean;
  is_adult?: boolean | null;
  display_name?: string;
  name?: string;
  family_name?: string;
  given_name?: string;
  middle_name?: string;
  birthdate?: IsoDate;
  phone_number?: string;
  phone_number_verified?: boolean;
  nickname?: string;
  preferred_username?: string;
  picture?: string;
  profile?: string;
  website?: string;
  gender?: string;
  zoneinfo?: string;
  locale?: string;
  updated_at?: number;
  address?: OidcAddress;
  custom_fields?: Record<string, string>;
};

export type ConnectRevokeRequest = {
  token: string;
  token_type_hint?: "access_token" | "refresh_token";
};

export type TapokOidcDiscovery = {
  issuer: string;
  end_session_endpoint?: string;
  response_modes_supported?: ("query" | "form_post")[];
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  revocation_endpoint: string;
  jwks_uri: string;
  response_types_supported: "code"[];
  grant_types_supported: ("authorization_code" | "refresh_token")[];
  subject_types_supported: "pairwise"[];
  token_endpoint_auth_methods_supported: (
    "client_secret_basic" | "client_secret_post" | "none"
  )[];
  revocation_endpoint_auth_methods_supported: (
    "client_secret_basic" | "client_secret_post"
  )[];
  id_token_signing_alg_values_supported: ("ES256" | "RS256")[];
  code_challenge_methods_supported: "S256"[];
  authorization_response_iss_parameter_supported: true;
  scopes_supported: ConnectScope[];
  claims_supported: string[];
};

export type PkcePair = {
  verifier: string;
  challenge: string;
  method: "S256";
};

export type AuthorizationSecrets = {
  state: string;
  nonce: string;
  pkce: PkcePair;
};

export type CallbackValidationErrorCode =
  | "malformed_callback"
  | "missing_state"
  | "state_mismatch"
  | "missing_issuer"
  | "issuer_mismatch";

export type ParsedAuthorizationCallback =
  | {
      ok: true;
      code: string;
      state: string;
      issuer: string;
    }
  | {
      ok: false;
      error: AuthorizationResponseErrorCode;
      errorDescription?: string;
      state: string;
      issuer: string;
    };

export type BaseOidcScope = "openid" | "profile" | "email" | "age:18";
export type OidcAddress = {
  formatted?: string;
  street_address?: string;
  locality?: string;
  region?: string;
  postal_code?: string;
  country?: string;
};
export type ConnectRefreshRequest = {
  grant_type: "refresh_token";
  refresh_token: string;
  scope?: string;
};
export type ConnectRefreshResponse = Omit<ConnectTokenResponse, "id_token"> & {
  id_token?: string;
};
export type OidcAuthorizationOptions = {
  prompt?: "none" | "login" | "consent" | "select_account";
  maxAge?: number;
  uiLocales?: string;
  loginHint?: string;
};
export type OidcEndpoints = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  revocation_endpoint: string;
  jwks_uri: string;
  end_session_endpoint: string;
};
