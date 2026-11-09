/**
 * Base class of every error Tapok packages raise for a failed authorization.
 * `code` is stable and safe to branch on; `message` is diagnostic text only.
 * Invalid arguments and configuration still throw a plain `TypeError`.
 *
 * There is deliberately no `cause`: errors of JWT libraries, JSON parsers and
 * transports can carry token payloads, response fragments or URLs, and an
 * error object is routinely logged whole. A Tapok error holds only fixed text
 * and codes.
 */
export class TapokError extends Error {
  override readonly name: string = "TapokError";
  readonly code: string;

  constructor(code: string, message?: string) {
    super(message ?? code);
    this.code = code;
  }
}
