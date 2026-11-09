# Разработка и выпуск Core

Исходники: [tapokjs/core](https://github.com/tapokjs/core). Пакет публикуется как `@tapokjs/core`; SDK использует обычный semver range и версионируется независимо.

## Проверки

Нужны Node.js 22+, Deno 2+ и версия Bun из `.bun-version`:

```sh
npm install --global "bun@$(cat .bun-version)"
bun install --frozen-lockfile
bun run check
bun lint --no-script --max-warnings 0
bun fmt --no-script --check
bun audit
```

`check` проверяет типы, тесты и собранный ESM в Bun, Node и Deno. CI `package` дополнительно устанавливает npm-архив во внешний проект и проверяет его на Node 22/26, Bun и Deno. `prepack` пересобирает `dist`; в npm не попадают исходники, тесты и зависимости разработки.

## Версия

До выпуска обновите `package.json`, `CHANGELOG.md` и lockfile. После 1.0 несовместимые изменения требуют нового major и инструкции миграции. Проверьте уже выпущенные номера через `npm view @tapokjs/core versions --json`: повторная публикация номера невозможна.

Для самостоятельной публикации workflow `publish.yml` использует GitHub environment `npm` и provenance. Настройте npm trusted publisher: owner `tapokjs`, repository `core`, workflow `publish.yml`, environment `npm`. Если trusted publisher ещё не настроен, требуется разрешённый npm publish token в environment secret `NPM_PUBLISH_TOKEN`; секреты никогда не добавляются в Git.

После успешных проверок опубликуйте архив, проверьте npm dist-tag, затем создайте тег `v<version>` и GitHub Release на том же коммите. Публикация Core не обновляет зависимые приложения автоматически.
