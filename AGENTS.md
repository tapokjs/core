# @tapokjs/core

Isomorphic TypeScript foundation for Tapok Base and Connect SDKs. It is published as `@tapokjs/core` and must work in Bun 1.4, Node.js >=22, Deno >=2 and browsers.

## Scope

- Protocol types, endpoints, scopes, claims and neutral protocol errors.
- Web Crypto generation of `state`, `nonce` and PKCE S256.
- Authorize URL builders, form bodies, callback validation (`state` and exact `iss`) and runtime response parsers.

## Constraints

- Use only standard Web APIs: Web Crypto, `URL`, `URLSearchParams`, `TextEncoder` and `fetch` types. Never import Node or Bun APIs.
- Do not handle browser storage/popups, client secrets, Basic authentication, JWT signature verification, sessions or logging of OAuth artifacts.
- Never log codes, tokens, state, nonce or PKCE verifier.
- Source is in `src/`; generated `.js`, `.mjs`, `.cjs` and `.d.ts` files belong in `dist/`.
