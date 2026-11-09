import { TapokError } from "./errors.ts";
import {
  authorizationErrorCodes,
  callbackParameters,
  parseRedirectUri,
} from "./internal.ts";
import type {
  AuthorizationResponseErrorCode,
  CallbackValidationErrorCode,
  ParsedAuthorizationCallback,
} from "./types.ts";

/** The authorization response failed validation; never use its `code`. */
export class TapokCallbackValidationError extends TapokError {
  override readonly name = "TapokCallbackValidationError";
  declare readonly code: CallbackValidationErrorCode;

  constructor(code: CallbackValidationErrorCode, message?: string) {
    super(code, message);
  }
}

function getSingleParameter(
  parameters: URLSearchParams,
  name: string,
  missingCode: CallbackValidationErrorCode,
): string {
  const values = parameters.getAll(name);
  if (values.length === 0 || values[0] === "") {
    throw new TapokCallbackValidationError(missingCode);
  }
  if (values.length !== 1) {
    throw new TapokCallbackValidationError("malformed_callback");
  }
  return values[0] as string;
}

/**
 * Validates an authorization response before its `code` may be used: exactly
 * one `state` equal to the stored one, exactly one `iss` equal to the trusted
 * issuer, no fragment, no duplicated or foreign parameters.
 *
 * Pass `redirectUri` when the registered redirect URI has its own query: those
 * parameters must then come back unchanged and in the same order. Without it
 * every non-protocol parameter is rejected. Origin and path are not compared,
 * because a server behind a reverse proxy often sees an internal request URL.
 */
export function parseAndValidateAuthorizationCallback(input: {
  callbackUrl: string | URL;
  expectedState: string;
  expectedIssuer: string;
  redirectUri?: string;
}): ParsedAuthorizationCallback {
  let callbackUrl: URL;
  try {
    callbackUrl =
      input.callbackUrl instanceof URL
        ? new URL(input.callbackUrl.href)
        : new URL(input.callbackUrl);
  } catch {
    throw new TapokCallbackValidationError("malformed_callback");
  }

  if (callbackUrl.href.includes("#")) {
    throw new TapokCallbackValidationError("malformed_callback");
  }

  const state = getSingleParameter(
    callbackUrl.searchParams,
    "state",
    "missing_state",
  );
  if (state !== input.expectedState) {
    throw new TapokCallbackValidationError("state_mismatch");
  }

  const issuer = getSingleParameter(
    callbackUrl.searchParams,
    "iss",
    "missing_issuer",
  );
  if (issuer !== input.expectedIssuer) {
    throw new TapokCallbackValidationError("issuer_mismatch");
  }

  const registered =
    input.redirectUri === undefined
      ? []
      : [...parseRedirectUri(input.redirectUri, "redirectUri").searchParams];
  let matched = 0;
  for (const [key, value] of callbackUrl.searchParams) {
    if (callbackParameters.has(key)) continue;
    const expected = registered[matched++];
    if (
      expected === undefined ||
      expected[0] !== key ||
      expected[1] !== value
    ) {
      throw new TapokCallbackValidationError("malformed_callback");
    }
  }
  if (matched !== registered.length) {
    throw new TapokCallbackValidationError("malformed_callback");
  }

  const codes = callbackUrl.searchParams.getAll("code");
  const errors = callbackUrl.searchParams.getAll("error");
  const descriptions = callbackUrl.searchParams.getAll("error_description");

  if (codes.length === 1 && codes[0] !== "" && errors.length === 0) {
    if (descriptions.length !== 0) {
      throw new TapokCallbackValidationError("malformed_callback");
    }
    return {
      ok: true,
      code: codes[0] as string,
      state,
      issuer,
    };
  }

  if (
    errors.length === 1 &&
    authorizationErrorCodes.has(errors[0] as AuthorizationResponseErrorCode) &&
    codes.length === 0 &&
    descriptions.length <= 1
  ) {
    const result: ParsedAuthorizationCallback = {
      ok: false,
      error: errors[0] as AuthorizationResponseErrorCode,
      state,
      issuer,
    };
    if (descriptions.length === 1) {
      result.errorDescription = descriptions[0];
    }
    return result;
  }

  throw new TapokCallbackValidationError("malformed_callback");
}
