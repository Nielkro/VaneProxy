# PenikProxy — SNI-роутер :443 → Xray / Caddy (Rust)

## Цель
Один бинарник на Rust слушает `0.0.0.0:443`, читает TLS ClientHello, достаёт SNI (extension `0x0000`), и сплайсит TCP-стрим:
- SNI из списка Xray (`studio.iuharin.ru`, `dmitryme.home.kg`, ...) → напрямую в локальный порт Xray, **без** изменения стрима;
- SNI сайтов (`penik.ru`, `slavchat.ru`) или неизвестен / нет SNI / не-TLS → в локальный порт Caddy (`127.0.0.1:8444`), **с** препендом PROXY protocol v2, чтобы Caddy видел реальный IP.

TLS **не терминируется** в Rust — только peek + `copy_bidirectional`.

## Подтверждено опросом
1. Маппинг: **через конфиг** (гибкий `SNI → backend`, а не жёсткие 2 порта).
2. Fallback: **всё неизвестное → Caddy** (включая без SNI и не-TLS — для маскировки).
3. PROXY v2: **только ветка Caddy**, ветка Xray — чистый TCP.
4. Деплой: **systemd на Linux**, биндинг `:443` через capabilities.
5. Логи: по умолчанию **только error**, access-лог **только если явно включён в конфиге** (`access_log = true`).

## Состав плана
- `01-architecture.md` — как парсим, как сплайсим, формат PROXYv2
- `02-config.md` — формат конфига (TOML) с примером
- `03-implementation.md` — структура Rust-проекта, шаги, зависимости
- `04-deploy.md` — systemd, Caddy, Xray, права на :443
- `05-testing-risks.md` — тесты, риски, крайние случаи

Статус: план, кода пока нет.
