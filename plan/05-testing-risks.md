# 05 — Тестирование и риски

## Тесты (cargo test)
1. **SNI-парсер**: ClientHello с SNI `xray.example.com` / `example.com`, без SNI, с GREASE-extensions, с fragmented extensions, мусор (не-TLS) → `None` без паники. Отдельно: `EXAMPLE.COM.` → `example.com`, `ex\0ample.com` → `None`, >253 → `None`, punycode `xn--...` проходит как есть.
2. **PPv2**: IPv4 `1.2.3.4:1234 → 5.6.7.8:443` и IPv6 — побайтовое сравнение с эталоном из спеки HAProxy. Отдельно: `::ffff:1.2.3.4` после `to_canonical()` → AF_INET-кодировка.
3. **Конфиг**: дубли SNI (`Example.com` vs `example.com.` → дубль) → ошибка; неизвестный backend в route → ошибка; `default_backend` missing → ошибка; пустой `listen` → ошибка.
4. **Интеграция**: поднять 2 TCP-echo на `127.0.0.1:9xxx/9yyy`, прокси на `127.0.0.1:4433`, слать ClientHello с разными SNI → проверять что дошло до правильного бэкенда и что Caddy-ветка начинается с PPv2-сигнатуры.

Ручные проверки на сервере:
```bash
# SNI Xray
openssl s_client -connect 127.0.0.1:443 -servername xray.example.com -ign_eof
# SNI Caddy
curl -vk https://example.com --resolve example.com:443:127.0.0.1
# неизвестный SNI → должен попасть в Caddy
openssl s_client -connect 127.0.0.1:443 -servername unknown.example.com -ign_eof
# не-TLS → тоже в Caddy (проверить что Caddy ответил, а не дроп)
printf 'GET / HTTP/1.0\r\n\r\n' | nc 127.0.0.1 443 -w 3
ss -s ; journalctl -u penik-proxy -p err
```

Логика логов:
- `access_log=false` → только `ERROR` (backend connect fail, parse OOM невозможен, accept fail).
- `access_log=true` → + одна строка на коннект: `peer sni backend ms up down` (text) или JSON.

## Риски / крайние случаи
- **Фрагментированный ClientHello / два уровня длин**: Record Length (header [3..4]) vs Handshake Length (u24 [6..8]) не путать. Обязательно read-loop: 5 байт → проверка 0x16 → 6-й байт → проверка 0x01 → дочитка Record Length. `byte[0] != 0x16` → immediate default в Caddy без ожидания 5s таймаута.
- **TLS 1.3 + ECH (Encrypted ClientHello)** — SNI скрыт, парсер вернёт outer SNI или None → уйдёт в Caddy. Это ожидаемо, не чинить.
- **Клиент шлёт сразу много records / early data** — мы форвардим весь `buf` целиком, потерь нет.
- **Сканеры шлют мусор** — лимит `max_client_hello_bytes`, быстрый путь не-TLS сразу в Caddy (Caddy их отфутболит), 5s таймаут только для молчащих/полуоткрытых.
- **IPv6**: `listen = ["0.0.0.0:443", "[::]:443"]` — два сокета. Для IPv6 сокета обязательно `set_only_v6(true)` через `socket2`, чтобы Linux `sysctl net.ipv6.bindv6only=0` не вызывал `AddrInUse` при бинде `0.0.0.0:443`. На хосте без v6 второй bind упадёт: `strict_listen=true` → fatal с понятным логом. `to_canonical()` для mapped-адресов в PPv2 обязателен.
- **Два процесса на :443** (старый Caddy не выключен или забыт `https_port 8444`) → `AddrInUse` при старте, громкий error + exit non-zero чтобы systemd ретраил.
- **Caddy xcaddy + PROXY protocol**: директива `proxy_protocol` требует сборки Caddy с плагином `github.com/caddyserver/proxy-protocol`. При настройке только `servers :8444 { listener_wrappers { proxy_protocol ... tls } }`, `:80` — чистый.
- **Производительность**: один `accept` + `spawn`, весь хот-пат — `copy_bidirectional`. `splice` осознанно вне Фазы 1. Ботлнек — `LimitNOFILE` и `net.core.somaxconn`.

## Что НЕ в Фазе 1 (L4 SNI-роутер)
- SIGHUP hot-reload конфига (только restart; запланирован на Фазу 2).
- Prometheus `/metrics` (выбран «лог по флагу», метрики не делаем).
- UDP/QUIC (HTTP/3 на 443/udp — отдельный вопрос, Caddy/Xray сами; TCP-прокси его не трогает).
- Терминация TLS / сертификаты в Rust — вынесены в Фазу 2 (`06-reverse-proxy-auto-ssl.md`). В Фазе 1 сохраняется чистый L4 peek + splice.
