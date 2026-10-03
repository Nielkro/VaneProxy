# 02 — Конфиг

Формат: TOML, путь по умолчанию `/etc/penik-proxy/config.toml`, override через `--config` / env `PENIK_CONFIG`.

## Пример `config.toml`
```toml
# Dual-stack: два сокета явно. На хосте без IPv6 второй bind упадёт —
# см. strict_listen ниже. Альтернатива — один "[::]:443" с v6only=false.
listen = ["0.0.0.0:443", "[::]:443"]
# strict_listen = true  # true → падение любого bind = fatal; false → warn+продолжить (по умолчанию true)

client_hello_timeout_ms = 5000
backend_connect_timeout_ms = 3000
max_client_hello_bytes = 16389

# Логи: error по умолчанию. access_log включается только явно.
log_level = "error"   # error | warn | info | debug (если access_log=true, level минимум info)
access_log = false    # true → строка на каждое соединение
# access_log_format = "text" # text | json (по умолчанию text)

# Единая сущность бэкенда: адрес + флаг PPv2 (не две рассинхронизированные секции).
[backends.xray]
addr = "127.0.0.1:8443"
send_proxy_protocol = false

[backends.caddy]
addr = "127.0.0.1:8444"
send_proxy_protocol = true

# default — куда идёт всё неизвестное / без SNI / не-TLS
default_backend = "caddy"

[[routes]]
# точное совпадение, case-insensitive
sni = "studio.iuharin.ru"
backend = "xray"

[[routes]]
sni = "dmitryme.home.kg"
backend = "xray"

[[routes]]
sni = "penik.ru"
backend = "caddy"

[[routes]]
sni = "slavchat.ru"
backend = "caddy"

# Опционально позже:
# [[routes]]
# sni = "*.penik.ru"   # wildcard, матчится после exact
# backend = "caddy"
```

## Правила матчинга
1. SNI: ASCII case-fold (A-Z→a-z побайтово), срезать один trailing dot (`example.com.` → `example.com`).
   Пустой / >253 символов / с NUL / вне printable ASCII → None → default без ошибки.
2. Сначала exact-match по `routes`.
3. Потом wildcard `*.domain` (только один уровень, если решим добавить — в MVP можно без него).
4. Иначе `default_backend` (у тебя — `caddy`).
5. Невалидный IDN/пустой SNI → default, без ошибки.

## Валидация при старте
- `listen` — непустой список `IP:port`, каждый парсится; дубли портов — ошибка;
- все `routes[*].backend` есть в `[backends.*]`;
- `default_backend` есть в `[backends.*]`;
- дубли `sni` (после ASCII-fold + trim-dot) — ошибка старта с указанием строки;
- файл читается процессом, права `640 root:penik-proxy`.

Горячий reload (SIGHUP) — **не в MVP**, только рестарт systemd. Заложить структуру чтобы добавить `notify`-watch позже.
