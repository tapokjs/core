# @tapokjs/core

Изоморфный TypeScript-пакет для протокола Tapok Base и Connect. Работает в браузере, Bun 1.4+, Node.js 22+ и Deno 2+. Только ESM, без runtime-зависимостей.

Полное руководство по интеграции: [tapok.orria.space/docs/core](https://tapok.orria.space/docs/core). Сначала выберите режим в [обзоре](https://tapok.orria.space/docs/overview).

## Установка

```sh
bun add @tapokjs/core
```

## Когда нужен Core

Берите Core, если пишете свой browser или server adapter. Он предоставляет:

- константы `TAPOK_ISSUER`, `TAPOK_API_BASE_URL`, `tapokEndpoints`;
- генерацию `state`, `nonce` и PKCE S256;
- builders для Base и Connect authorize URL;
- bodies для Base exchange, Connect token и revoke;
- строгую проверку callback по `state` и exact `iss`;
- runtime-парсеры protocol responses.

Core не хранит transaction, не открывает popup, не создаёт `client_secret_basic`, не проверяет JWT signature и не создаёт сессию. Для готовой интеграции используйте `@tapokjs/sdk/browser` или `@tapokjs/sdk/server`.

## Base пример

```ts
import {
  TAPOK_ISSUER,
  buildBaseAuthorizeUrl,
  createAuthorizationSecrets,
  parseAndValidateAuthorizationCallback,
} from "@tapokjs/core";

const secrets = await createAuthorizationSecrets();
const authorizationUrl = buildBaseAuthorizeUrl({
  redirectUri: "https://app.example/auth/tapok/callback",
  scopes: ["age:18"],
  state: secrets.state,
  nonce: secrets.nonce,
  codeChallenge: secrets.pkce.challenge,
});

// Сохраните state, nonce и secrets.pkce.verifier в transaction приложения.
location.assign(authorizationUrl);

const callback = parseAndValidateAuthorizationCallback({
  callbackUrl: location.href,
  expectedState: transaction.state,
  expectedIssuer: TAPOK_ISSUER,
});
```

`buildBaseAuthorizeUrl()` сам вычисляет `client_id` как `origin:<redirect origin>`, всегда добавляет `session` и принимает только optional `age:18`. `parseAndValidateAuthorizationCallback()` до возврата `code` проверяет единственность и совпадение `state` и `iss`, отсутствие fragment, повторов и посторонних параметров. При ошибке он бросает `TapokCallbackValidationError` с кодом `missing_state`, `state_mismatch`, `missing_issuer`, `issuer_mismatch` или `malformed_callback`.

Если зарегистрированный redirect URI содержит собственный query (`…/callback?tenant=acme`), передайте его в `redirectUri`: эти параметры должны вернуться без изменений и в том же порядке. Origin и путь callback не сравниваются — сервер за reverse proxy часто видит внутренний адрес; точное совпадение redirect URI проверяет Tapok. Параметры `code`, `state`, `iss`, `error` и `error_description` в самом redirect URI запрещены.

## Connect helpers

Для Connect используйте `buildConnectAuthorizeUrl()`, `createConnectTokenBody()`, `createConnectRevokeBody()`, `parseConnectTokenResponse()` и `parseConnectUserInfo()`. В список scopes обязательно входит `openid`.

```ts
const authorizationUrl = buildConnectAuthorizeUrl({
  clientId: "tpk_client_example",
  redirectUri: "https://app.example/auth/tapok/callback",
  scopes: ["openid", "email"],
  state: secrets.state,
  nonce: secrets.nonce,
  codeChallenge: secrets.pkce.challenge,
});
```

В Connect храните `state`, `nonce` и `pkce.verifier` только на backend. Scope `email` возвращает выбранный для приложения адрес. По умолчанию используется почта провайдера с его признаком подтверждения. При отсутствии почты или выборе сервисного адреса Tapok выдаёт стабильный технический адрес с `email_verified: true`: подтверждена привязка к аккаунту, а не доставка писем. Свой адрес пользователя имеет `false` до подтверждения через OTP и `true` после; сброс возвращает сервисный адрес. Проверку ES256/RS256 signature, `kid`, `iss`, `aud`, nonce, срока жизни и mode выполняйте через `@tapokjs/sdk/server` или свой server verifier.

## API

- Base: [быстрый старт](https://tapok.orria.space/docs/base-quickstart), [manifest](https://tapok.orria.space/docs/base-manifest), [API](https://tapok.orria.space/docs/api)
- Connect: [быстрый старт](https://tapok.orria.space/docs/connect-quickstart), [scopes](https://tapok.orria.space/docs/scopes)
- Общие требования: [безопасность](https://tapok.orria.space/docs/security)

## Ошибки

`TapokError` — базовый класс ошибок неудавшейся авторизации со стабильным полем `code`; его наследуют `TapokCallbackValidationError` и ошибки `@tapokjs/sdk`. У него нет `cause`: ошибки Tapok содержат только фиксированный текст и коды. Неверные аргументы builders и ответы, нарушающие контракт парсеров, бросают `TypeError`; его текст называет поле, но не цитирует значение из ответа.

## Публичная поверхность

Публичным является только то, что перечислено в `src/index.ts`; набор runtime-экспортов закреплён тестом. Константы (`tapokEndpoints`, `CONNECT_SCOPES`, `BASE_OIDC_SCOPES`, `USERINFO_CLAIM_SCOPES`) заморожены. Пакет не имеет побочных эффектов при импорте: неиспользуемые таблицы и функции удаляются бандлером.

## Команды разработки

```sh
bun install
bun run typecheck
bun test
bun run build
bun run check
```

`bun run check` запускает typecheck, contract tests, сборку tsdown и проверку собранного ESM в Bun, Node.js и Deno. Исходники проверяются без глобальных типов Bun и Node.js.

Изменения и инструкция перехода с 0.1 — в [CHANGELOG](./CHANGELOG.md), выпуск — в [RELEASING](./RELEASING.md).

## OIDC контракты

`CONNECT_SCOPES`, `BASE_OIDC_SCOPES` и `USERINFO_CLAIM_SCOPES` задают
разрешённые scopes и claims. Connect поддерживает стандартные profile, email,
phone, address и offline_access. Последний требует серверного refresh flow.

Для Base OIDC используйте `buildOidcBaseAuthorizeUrl()` с отдельным issuer.
`resolveTapokEndpoints()` строит стандартные адреса из доверенного issuer;
`mode: "base"` в нём означает issuer Base OIDC (`…/oidc/base`), а не нативный
Base, адреса которого — `<issuer>/api/v1/base/authorize` и `/exchange`.
`validateOidcDiscovery()` проверяет точное совпадение issuer и origins endpoints;
список доверенных origins должен содержать точные origins без пути и слеша.
Helpers не загружают discovery самостоятельно.

`createConnectRefreshBody()` и `parseConnectRefreshResponse()` поддерживают
refresh response с необязательным ID token. `buildLogoutUrl()` строит
RP-Initiated Logout URL. Авторизация поддерживает prompt, maxAge, uiLocales
и loginHint; значения проверяются до построения URL.

Все парсеры игнорируют неизвестные extension fields и не копируют их в
результат, проверяя типы известных полей и доступ к ним по scopes. В Connect
`expires_in` — целое число от 1 до 86400, `token_type` сравнивается без учёта
регистра и возвращается как `"Bearer"`; SDK отдельно ограничивает срок
подписанного ID token. В Base exchange `expires_in` — целое число от 1 до 600,
а scope остаётся точным списком `session` или `session age:18`.
