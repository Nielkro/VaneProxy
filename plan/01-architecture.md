# 01 — Архитектура

## Поток одного соединения
```
client :xxx ──TCP──> :443 [Rust]
  1. accept, socket: nodelay=true, timeout ClientHello (default 5s)
  2. read-loop в Vec<u8> (НЕ один read, НЕ MSG_PEEK):
     - сначала дочитать минимум 5 байт (TLS record header):
       [0]=ContentType, [1..2]=Version, [3..4]=Record Length (u16 BE)
     - если byte[0] != 0x16 → сразу "не-TLS", НЕ ждать таймаут до конца:
       route=default (Caddy), дальше только connect+forward того что есть
     - если 0x16 → дочитать минимум до 6-го байта, затем смотреть byte[5] (Handshake Type):
       != 0x01 → не ClientHello → route=default
     - иначе дочитать ровно Record Length байт (cap max_client_hello_bytes = 16384+5):
       ВНИМАНИЕ: Record Length [3..4] != Handshake Length [6..8] (u24 BE внутри).
       Для SNI достаточно первой record; если ClientHello фрагментирован на
       несколько records (практика: 99.9% — одна), парсим то что есть,
       при truncated → route=default, не ошибка.
       Цикл: read() может вернуть 2 байта сейчас и остаток через 10мс — ждать
       в пределах client_hello_timeout, а не решать по первому recv.
  3. parse ClientHello → SNI:
     ClientHello body: ver(2) + random(32) + session_id(len+data)
       + cipher_suites(len+data) + compression(len+data) + extensions(len+data)
     extensions: loop { type(u16), len(u16), data }
       type == 0x0000 → ServerNameList: list_len(u16) { name_type(u8=0), name_len(u16), name(bytes) } → взять первый host
     - Нормализация SNI: ASCII case-fold ONLY (A-Z → a-z, побайтово), срезать
       один trailing dot, отбросить пустой/слишком длинный (>253) / с нулевым
       байтом / не-ASCII-printable → считать None → default. Полный Unicode
       lowercase и IDNA НЕ делаем — SNI на проводе всегда A-label (punycode),
       этого достаточно и убирает класс багов с case-folding.
     - SNI найден → lookup в конфиге (exact match по уже lowercased; опционально wildcard `*.example.com`)
     - SNI не найден / парсинг упал / truncated → default (Caddy)
  4. connect к backend (timeout ~3s):
     - ветка Xray: `TcpStream.connect(xray_addr)` → сначала записать в backend **все уже прочитанные байты как есть**, затем `copy_bidirectional`
     - ветка Caddy: `connect(caddy_addr)` → сначала записать **PROXYv2 header (src/dst)**, затем прочитанные байты, затем `copy_bidirectional`
  5. учёт: bytes c→s / s→c, duration; access-лог если включён; всегда лог ошибок
```

## Почему peek, а не terminate
- Xray (VLESS/Reality) сам терминирует TLS — Rust не должен трогать ключи/сертификаты.
- Caddy тоже терминирует TLS сам — ему нужен оригинальный ClientHello + реальный IP через PPv2.

## PROXY protocol v2 (только ветка Caddy)
Сигнатура 12 байт: `\r\n\r\n\0\r\nQUIT\n` = `0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A`
Далее:
- `ver_cmd`: `0x21` = v2 + PROXY (не LOCAL)
- `fam_proto`: `0x11` = AF_INET+STREAM (IPv4/TCP), `0x21` = AF_INET6+STREAM (IPv6/TCP)
- `len`: u16 BE длина остатка (12 для IPv4, 36 для IPv6)
- addrs: IPv4: src(4)+dst(4)+sport(2)+dport(2); IPv6: src(16)+dst(16)+sport(2)+dport(2)

src = `peer_addr()` клиента, dst = `local_addr()` слушателя (или `socket.local_addr()` входящего).
IPv4-mapped IPv6 (`::ffff:a.b.c.d`) нормализовать через `IpAddr::to_canonical()`
(stable с 1.75) в чистый IPv4 → шлём AF_INET, иначе Caddy увидит v6.
Если peer/local не IP (unix — не наш случай) → слать `LOCAL` (`0x20 0x00 0x00 0x00`, только 16 байт) чтобы не ронять Caddy.

Caddy на `:8444` принимает PPv2 СТРОГО на этом порту через `servers :8444 { listener_wrappers { proxy_protocol ... } }`,
порядок `proxy_protocol` ДО `tls`. Глобально на все servers НЕ включать — иначе
сломается :80 и HTTP-01. Детали в `04-deploy.md`.

## Конкурентность и сокеты
- `tokio`: список `listen = ["0.0.0.0:443", "[::]:443"]` и по листенеру на адрес.
  **ВАЖНО про Linux:** по умолчанию `sysctl net.ipv6.bindv6only = 0`. Если IPv6-сокет биндится первым,
  он перехватывает IPv4 и следующий бинд `0.0.0.0:443` падает с `EADDRINUSE`.
  Поэтому для IPv6 сокета ОБЯЗАТЕЛЬНО явно выставляем `set_only_v6(true)` через `socket2`
  перед конвертацией в Tokio `TcpListener`.
- `tokio::spawn` на коннект.
- Никакого пула к бэкендам — короткое `connect` на каждый коннект (локалхост, дёшево).
- Backpressure — через `copy_bidirectional` без своих буферов.
- Решение по `splice(2)`: осознанно НЕ используем в MVP. `copy_bidirectional`
  (user-space буфер ~8KB) даёт достаточную пропускную способность для локального
  сплайса в Xray/Caddy, а `splice` добавляет unsafe/Linux-only код, проблемы
  с TLS-record границами и ноль выигрыша пока ботлнек — не CPU копирования.
  Пересмотреть только по flamegraph при >1 Gbit/s sustained.

## Таймауты и лимиты (в конфиг)
- `client_hello_timeout_ms`: 5000
- `backend_connect_timeout_ms`: 3000
- `max_client_hello_bytes`: 16384 + 5 (защита от мусорных клиентов)
- `nofile` поднять в systemd (`LimitNOFILE=65535`).
