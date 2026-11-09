import { parseRedirectUri, requireNonEmptyString } from "./internal.ts";
import type {
  BaseExchangeRequest,
  ConnectRefreshRequest,
  ConnectRevokeRequest,
  ConnectTokenRequest,
} from "./types.ts";

export function createBaseExchangeBody(
  input: BaseExchangeRequest,
): URLSearchParams {
  if (input.grant_type !== "authorization_code") {
    throw new TypeError("grant_type must be authorization_code");
  }
  parseRedirectUri(input.redirect_uri, "redirect_uri");

  return new URLSearchParams({
    grant_type: "authorization_code",
    code: requireNonEmptyString(input.code, "code"),
    client_id: requireNonEmptyString(input.client_id, "client_id"),
    redirect_uri: input.redirect_uri,
    code_verifier: requireNonEmptyString(input.code_verifier, "code_verifier"),
  });
}

export function createConnectTokenBody(
  input: ConnectTokenRequest,
): URLSearchParams {
  if (input.grant_type !== "authorization_code") {
    throw new TypeError("grant_type must be authorization_code");
  }
  parseRedirectUri(input.redirect_uri, "redirect_uri");

  return new URLSearchParams({
    grant_type: "authorization_code",
    code: requireNonEmptyString(input.code, "code"),
    redirect_uri: input.redirect_uri,
    code_verifier: requireNonEmptyString(input.code_verifier, "code_verifier"),
  });
}

export function createConnectRevokeBody(
  input: ConnectRevokeRequest,
): URLSearchParams {
  if (
    input.token_type_hint !== undefined &&
    input.token_type_hint !== "access_token" &&
    input.token_type_hint !== "refresh_token"
  ) {
    throw new TypeError(
      "token_type_hint must be access_token or refresh_token when provided",
    );
  }

  const body = new URLSearchParams({
    token: requireNonEmptyString(input.token, "token"),
  });
  if (input.token_type_hint !== undefined) {
    body.set("token_type_hint", input.token_type_hint);
  }
  return body;
}

export function createConnectRefreshBody(
  input: ConnectRefreshRequest,
): URLSearchParams {
  if (input.grant_type !== "refresh_token")
    throw new TypeError("grant_type must be refresh_token");
  const body = new URLSearchParams({
    grant_type: input.grant_type,
    refresh_token: requireNonEmptyString(input.refresh_token, "refresh_token"),
  });
  if (input.scope !== undefined) {
    if (
      !/^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$/u.test(
        input.scope,
      )
    )
      throw new TypeError("Invalid scope");
    body.set("scope", input.scope);
  }
  return body;
}
