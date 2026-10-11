# План: HTTPS-апстримы и недостающие директивы Caddyfile (Фаза 3)

## 1. Контекст и цель

Фаза 2 (`plan/06`) дала гибрид L4/L7: на тестовом `:4443` уже едут 10 простых
сайтов (`reverse_proxy` + `redir`), L4-сплайс Xray побайтово совпадает с
`penik-proxy`, живая страница `stats.other.penik.ru` отдаётся побайтово
идентично Caddy. За кадром найден и починен баг `Host`/origin-form
(`src/l7/proxy.rs`, коммит `b012688`).

Цель Фазы 3: научить Vane всему, что используют оставшиеся 14 сайтов на
`2.26.100.168`, включая два HTTPS-апстрима, после чего Caddy можно
выключать. Старый `penik-proxy :443` и Caddy `:8444` не трогаются до
финального cutover; вся проверка идёт на `:4443`.

## 2. Инвентаризация: что реально используется на сервере

Снято с `/etc/caddy/sites-available/*.caddy` (23 файла) и
`/opt/penik/penik.caddy` (200 строк). Подсчёт по `grep`:

| Директива / конструкция | Кол-во | Статус в Vane | Решение |
|---|---|---|---|
| `reverse_proxy host:port` + `header_up/down` | 14 | ✅ работает | — |
| `reverse_proxy https://…` | 2 | ❌ нет TLS к апстриму | Этап C |
| `transport http { tls_insecure_skip_verify }` | 1 | ❌ | Этап C |
| `handle /prefix/*`, `handle` (пустой) | ~29 | ⚠️ парсится, игнорируется | Этап D |
| `handle_path /…` | 3 | ❌ | Этап D |
| `handle_errors` + `expression` | 1 | ❌ | Этап D (урезанный) |
| `handle_response @name` внутри `reverse_proxy` | 2 | ❌ | Этап D (только X-Accel) |
| `@name` + `path` / `path_regexp` / `method` / `header` / `file` / `expression` | ~10 | ❌ | Этап A (матчеры) |
| `header` (ответов, в т.ч. `header @name`) | 14 | ❌ | Этап A+D |
| `uri strip_prefix` | 8 | ❌ | Этап A+D |
| `rewrite` (в т.ч. `rewrite * {rp.header.…}`) | 4 | ⚠️ только верхний уровень | Этап B+D |
| `redir` | 1 | ✅ (см. расхождение R1) | — |
| `respond "body" code` / `respond @m code` | 7 | ❌ | Этап A+D |
| `try_files` | 3 | ⚠️ парсится, игнорируется | Этап D |
| `root`, `file_server` (простые) | 8 | ✅ | — |
| `file_server { hide … }`, `browse <template>` | 3 | ❌ (`hide` нужен, `browse`-шаблон — нет) | Этап E |
| `encode gzip/zstd` | 8 | ❌ | Этап E (только gzip) |
| `request_body { max_size 250MB }` | 1 | ❌ (риск OOM!) | Этап E |
| `log` | 2 | ❌ (свой access_log уже есть) | Игнор с варнингом |
| `import` (сниппеты `tls_wildcard`, `h3_fix`) | 17 | ❌ осознанно | Этап F (миграционный скрипт, не поддержка) |
| `tls <cert> <key>` (файловая форма) | 0 напрямую, только через импорт | ❌ не нужна | Серты уже лежат в store как named (этап 0 готов) |
| Плейсхолдеры `{host} {remote} {client_ip} {scheme} {http.request.header.*} {rp.header.*} {http.error.status_code}` | везде | ❌ подставляются как есть (буквально!) | Этап B, критично |

Известные расхождения (фиксируем, не чиним молча):
- **R1**: `redir / /status/slav 302` у Vane — `starts_with`, у Caddy — точное
  совпадение пути. Для `status.slavchat.ru` приемлемо, задокументировать.
- **R2**: `flush_interval -1` (SSE): hyper и так стримит без буферизации —
  директива принимается и игнорируется с варнингом.
- **R3**: `encode zstd`: не поддерживаем, только `gzip`. Сайты, где был
  `zstd`, получат `gzip` — клиенты договариваются через `Accept-Encoding`.

## 3. Архитектурные решения

### 3.1 Модель данных (`src/caddyfile/model.rs`)

```rust
pub enum Upstream {
    Tcp(String),          // как было
    Unix(PathBuf),        // как было
    Tls(TlsUpstream),     // NEW: https://host:port
}
pub struct TlsUpstream {
    pub addr: String,     // host:port для TCP-коннекта
    pub sni: String,      // SNI для TLS-хендшейка (host без порта)
    pub insecure: bool,   // tls_insecure_skip_verify (только loopback!)
}
pub enum Matcher {         // NEW: именованные @матчеры и инлайн-префиксы
    PathPrefix(String),    // /api/*, /ws*, точный /join
    PathRegexp(String),    // \.(mp3|…)$ — через regex-крейт
    Method(String),        // OPTIONS
    Header(String, String),// X-Accel-Redirect *
    FileCheck,             // file (для @static в vpn.penik.ru)
    StatusExpr(StatusCond),// только status_code ==/>=/… NNN (для handle_errors)
}
pub enum Directive {
    // существующие + новые:
    Respond(RespondConfig),       // respond [matcher] [body] [code]
    ResponseHeader(NamedHeaders), // header [@matcher] Name Value…
    UriStripPrefix(String),       // uri strip_prefix <p>
    HandlePath(HandlePathBlock),  // handle_path <prefix> { … } (стрип + handle)
    HandleErrors(Vec<Directive>), // handle_errors { … }
    RequestBodyLimit(u64),        // request_body max_size (байты)
}
pub struct ReverseProxyConfig {
    pub upstreams: Vec<Upstream>,
    pub header_up: Vec<HeaderOp>,
    pub header_down: Vec<HeaderOp>,
    pub insecure_tls: bool,              // NEW (transport-блок)
    pub intercept_accel: bool,           // NEW: handle_response X-Accel
    pub accel_prefix: String,            // NEW: default /static-internal
    pub accel_root: PathBuf,             // NEW: root для accel-файлов
}
```

Fail-fast сохраняется: неизвестная директива/матчер/плейсхолдер — ошибка
с файлом, строкой, колонкой; невалидный сайт не роняет остальные.

### 3.2 Плейсхолдер-движок (новый `src/caddyfile/placeholders.rs`)

Контекст подстановки: `{method} {path} {host} {remote} {client_ip} {scheme}`,
`{http.request.header.Name}`, `{rp.header.Name}` (ответ апстрима, для
`handle_response`), `{http.error.status_code}` (внутри `handle_errors`).
Применяется к: `header_up/down` значениям, `rewrite`-целям, `header`-ответам,
`redir`-целям, `respond`-телам. Неизвестный плейсхолдер — ошибка парсинга,
а не молчаливая строка (иначе апстрим получит мусор вместо IP).

### 3.3 HTTPS-апстрим (`src/l7/proxy.rs`)

- Транспорт: `TcpStream` → `tokio_rustls::TlsConnector` (rustls 0.23, ring —
  уже в дереве) → `hyper::client::conn::http1::handshake`. Без новых
  тяжёлых зависимостей (`hyper-rustls` не тащим).
- `insecure=true`: кастомный `ServerCertVerifier`, возвращающий `Ok` без
  проверки. **Гард**: `insecure` разрешается только для loopback
  (`127.0.0.0/8`, `::1`, `localhost`); иначе — ошибка конфигурации.
  `sub.penik.ru → sub.pnc.penik.ru:8082` едет с полной проверкой цепочки.
- SNI берётся из `TlsUpstream.sni`; `Host` апстриму по умолчанию = SNI-хост,
  `header_up Host …` переопределяет (как требует snikket).
- Версия upstream HTTP: только 1.1 на старте (ALPN-h2 — follow-up, не нужен
  ни одному сайту сейчас). H2-downstream → H1-upstream уже нормализуем
  (коммит `b012688`).
- Таймаут коннекта = `backend_connect_timeout_ms`; чтения — без изменений.
  Пул соединений осознанно НЕ делаем (паритет с текущим поведением).

### 3.4 Диспетчер (`src/l7/service.rs`)

Новая семантика `handle_site_request` (документировать в README):

1. `request_body max_size`: отклонить `413` до чтения тела. Дефолт при
   отсутствии директивы — **10 МБ** (сейчас лимита нет вовсе — дыра).
2. `redir`/`rewrite` верхнего уровня — как сейчас.
3. `handle`-блоки **по порядку файла**, первый совпавший побеждает; пустой
   `handle` — catch-all (должен быть последним, иначе варнинг в лог).
   `handle_path P` = strip `P` + семантика `handle`.
4. Внутри `handle`: `uri strip_prefix` → `root`/`file_server`/`rewrite` →
   `reverse_proxy` → `respond`. `header`-директивы блока применяются к
   любому исходу блока. `@options method OPTIONS` + `respond @options 204`
   покрывают все CORS-префлайты на сервере.
5. `try_files`: последовательная проверка файлов от `root`, фолбэк —
   последний аргумент (`/index.html` → внутренний рерайт) или 404.
   Магия Caddy с неявным `file_server`-фолбэком не копируется.
6. `handle_errors`: выполняется при итоговом статусе 4xx/5xx; внутри —
   только `root`/`rewrite`/`file_server`/`respond`; условие — урезанный
   `expression` вида `{http.error.status_code} == 404` / `>= 500 && < 600`.
   Сложные expression — fail-fast.
7. `handle_response` внутри `reverse_proxy`: поддерживается **только**
   кейс `@accel header X-Accel-Redirect *` (проверка по имени заголовка):
   взять `{rp.header.X-Accel-Redirect}` как новый путь, проверить префикс
   `accel_prefix` (защита от `..`), отдать файл из `accel_root`.
   Прямые запросы клиентов на `/static-internal/*` блокируются сайтовым
   `handle … { respond 404 }` (уже есть в конфигах).
8. `encode`: только `gzip` через `tower-http` (`Compression` слой вокруг
   ответа; сейчас это транзитивная зависимость — поднять в прямые).
   Условие: клиент прислал `Accept-Encoding: gzip`, тип — текст/JSON/JS/CSS/SVG.

### 3.5 Миграционный скрипт вместо `import` (Этап F)

`import` и сниппеты (`tls_wildcard`, `h3_fix`) в Vane **не поддерживаем**:
вместо этого `scripts/migrate-caddy.py` разворачивает сниппеты, выкидывает
`tls …`-строки (серты уже в store), `log`, `encode zstd→gzip`,
`flush_interval`, переписывает `header_up X-Real-IP {remote}` →
`{client_ip}`. Выход — готовые файлы для `/etc/vane/sites-enabled/`,
дифф ревьюится глазами. Скрипт идемпотентный, живёт в репо.

## 4. Этапы, тесты, DoD

### Этап A: модель + парсер (матчеры, `respond`, `header`, `uri`, `handle_path`, `transport`, `request_body`, `https://`-апстримы)
- Тесты: unit на каждую директиву (позитив + точная строка/колонка в негативе);
  `respond @options 204`, `rewrite * {rp.header.X-Accel-Redirect}`,
  `reverse_proxy https://… { transport http { tls_insecure_skip_verify } }`.
- DoD: `cargo test` зелёный; все 24 серверных файла парсятся после прогона
  через миграционный скрипт (Этап F делается раньше парсера? нет: F после A).

### Этап B: плейсхолдеры
- Тесты: подстановка всех 6 семейств; неизвестный плейсхолдер — ошибка.
- DoD: дамп апстрима (приём из Фазы 2: python-слушатель на `:18989`)
  показывает `Host`, `X-Real-IP` с реальным IP, а не `{client_ip}` буквально.

### Этап C: TLS-апстрим
- Тесты: e2e против локального TLS-эха (rcgen-сертификат): обычный + insecure;
  гард «insecure только loopback» (unit).
- DoD: через `:4443` резолвятся `snikket.penik.ru` (self-signed) и
  `sub.penik.ru` (внешний `:8082`), коды совпадают с путём через Caddy.

### Этап D: диспетчер handle/try_files/handle_errors/handle_response
- Тесты: порядок handle (первый матч), `handle_path`-стрип,
  `try_files → /index.html` для SPA, `handle_errors` 404/5xx со статикой,
  X-Accel-перехват (фейковый Go: заголовок → файл с диска; прямой запрос
  → 404), `@options`→204.
- DoD: паритетная таблица (как в Фазе 2) для `keys`, `kvncdn`, `met.home`,
  `slavcall`, `slavchat.ru`, `web.slavchat.ru`, `vpn.penik.ru`,
  `call.slavchat.ru`, `music`, `api/web.penik.ru`, `penik.ru` — коды и тела
  совпадают с `:443`.

### Этап E: encode gzip, `hide`, `request_body`-лимит, `header`-ответы
- Тесты: `Content-Encoding: gzip` при `Accept-Encoding`; `hide` прячет
  `bundle.zip`; тело > лимита → 413; CORS-заголовки из `header`-блоков.
- DoD: `api.penik.ru` (стикеры, бандлы, accel-вложения, аплоад 250 МБ)
  полностью паритетичен.

### Этап F: миграционный скрипт + батчи на `:4443`
- Батч 1 (простые + HTTPS): `snikket.*`, `sub.penik.ru` (после C).
- Батч 2 (handle-простые): `keys`, `met.home`, `ws-relay`, `tg.other`(проверить живой ли 6781), `mp.slav` уже едет.
- Батч 3 (статика/SPA): `slavchat.ru`, `web.slavchat.ru`, `vpn.penik.ru`, `music`, `call.slavchat.ru`.
- Батч 4 (penik-экосистема): `penik.ru`, `web.penik.ru`, `api.penik.ru` (после E).
- Каждый батч: файлы → `SIGHUP` → паритетная таблица код/тело/заголовки
  `:4443` vs `:443` → откат удалением файла при расхождении.
- DoD: все живые сайты резолвятся в L7 на `:4443`, мёртвые дают 502
  с обеих сторон.

### Этап G: финальный cutover (отдельное окно, по согласованию)
1. Стоп `caddy`, включить у Vane `http_listen :80`, переключить `:443`
   (`penik-proxy` → `vane`), `default_backend` убрать.
2. Откат: `stop vane && start penik-proxy && start caddy` (старые юниты
   и `/usr/local/bin/penik-proxy` хранятся до +7 дней).

## 5. Не-цели

H3/QUIC, OCSP-stapling, пул upstream-соединений, upstream-H2 по ALPN,
Caddy-совместимый `encode zstd`, сложные `expression`, `on-demand TLS`,
лог-формат Caddy, `map`/`invoke`, `basicauth`.

## 6. Риски

- **X-Accel-Redirect** — единственный путь отдачи вложений `api.penik.ru`;
  ошибка в проверке префикса = path traversal. Митигация: строгий префикс +
  тест на `..`.
- **`insecure` только loopback** — гард в коде + warn в лог при каждом старте.
- **Мёртвые бэкенды** (9 из 12 портов DOWN): их сайты мигрируют «для галочки»
  (502≈502); перед cutover — отдельный разбор с владельцами, иначе тащим мусор.
- **LE rate-limits**: prod-сертификаты уже лежат в store как named — новых
  заказов не нужно до истечения; ACME не трогаем в этой фазе.
- **R1 (redir `starts_with`)**: задокументировано выше; при жалобах — отдельная
  задача на точный матчинг.
