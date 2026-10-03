# 03 — Реализация (Rust)

## Стек
- `tokio = { version = "1", features = ["full"] }` — listeners, spawn, timeouts, copy_bidirectional
- `socket2` — для явной установки `set_only_v6(true)` на IPv6 сокетах перед передачей в Tokio, чтобы избежать коллизий с `bindv6only=0` на Linux
- `serde`, `toml`, `clap` — конфиг + CLI
- `tracing`, `tracing-subscriber` — error по умолчанию, access-лог по флагу
- `thiserror` — ошибки
- Парсер ClientHello/SNI — **свой, без openssl/rustls** (нам нужен только SNI, не валидация). ~120 строк, ноль зависимостей, без паник на мусоре.
  Нормализация SNI — ASCII-fold побайтово + trim одного trailing dot + строгий reject мусора (NUL, пусто, >253).
- PROXYv2 энкодер — свой, ~40 строк. `to_canonical()` для IPv4-mapped.
- Копирование — `copy_bidirectional`. `splice(2)` в MVP НЕ делаем (over-engineering:
  Linux-only unsafe, выигрыш только при sustained >1 Gbit/s, ботлнек раньше упрётся в NOFILE/conntrack).

MSRV: stable последний. Edition 2021. Один бинарник `penik-proxy`.

## Структура
```
Cargo.toml
src/
  main.rs        # CLI (--config), load config, init tracing, bind (socket2 set_only_v6), accept-loop
  config.rs      # structs Config/Backends/Route + load+validate (unit-тесты)
  sni.rs         # parse_client_hello(buf) -> Option<String> (ASCII-folded), без паник
                 # различать Record Length (5-байт header) vs Handshake Length (u24 внутри)
  proxy_proto.rs # encode_ppv2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> (>=16 байт)
                 # src/dst перед encode прогнать через to_canonical()
  relay.rs       # handle_conn(inbound, cfg): read hello w/ timeout → route → connect → preface → copy_bidir → stats
  logging.rs     # init(level, access_log) + access!(...) макрос/фн
tests/
  sni_vectors.rs       # реальные ClientHello (сгенерить openssl) → ожидаемый SNI
  ppv2_vectors.rs      # эталонные байты PPv2 для v4/v6
  integration.rs       # 2 echo-бэкенда + прокси + клиент с SNI → проверка маршрутов и PPv2 префикса
```

## Псевдокод `relay::handle_conn`
```rust
async fn handle_conn(inbound: TcpStream, cfg: Arc<Config>) {
  let peer = inbound.peer_addr();
  let local = inbound.local_addr();
  // 1. read-loop с таймаутом: накапливать байты в буфер.
  //    - если накопили >= 1 байт и buf[0] != 0x16 → НЕ ждать таймаута, сразу default (Caddy).
  //    - если buf[0] == 0x16:
  //        * дочитать до >= 6 байт (5 байт record header + 1 байт handshake type);
  //        * если buf[5] != 0x01 → не ClientHello → сразу default;
  //        * извлечь record_len из buf[3..4], дочитать до 5 + record_len (с ограничением max_client_hello_bytes).
  let mut buf = Vec::with_capacity(2048);
  read_hello_into(&mut inbound, &mut buf, hello_timeout, max_bytes).await;
  // 2. parse_sni(&buf) (Record Len vs Handshake Len не путать; truncated → default)
  // 3. backend = match_sni(sni) or default
  // 4. TcpStream::connect(backend.addr) w/ timeout
  // 5. если backend.send_proxy_protocol: write_all(encode_ppv2(peer.canonical, local.canonical))
  // 6. write_all(buf) в backend, затем copy_bidirectional().await
  // 7. access-лог если включён: peer, sni|"-", backend, ms, up/down bytes
}
```

Важные детали:
- Читать через `inbound.read()` в цикле, а не `peek`, чтобы потом не дублировать — всё прочитанное храним в `buf` и первыми шлём в backend.
- `TCP_NODELAY` на inbound и outbound.
- `copy_bidirectional` возвращает `(u64,u64)` — использовать для access-лога.
- Любая ошибка backend-connect → просто закрыть inbound (клиент заретраит); залогировать warn/error с backend именем.
- Не делать `unwrap()` на сетевых данных — только на программных инвариантах.

## Шаги разработки
1. `cargo init --bin`, добавить зависимости, `config.rs` + валидация + тесты.
2. `sni.rs` — парсер + векторы (сгенерить `openssl s_client` / python-скриптом ClientHello с разными SNI, GREASE, без SNI).
3. `proxy_proto.rs` — энкодер + векторы (сверить с `haproxy` спекой).
4. `relay.rs` + `main.rs` — accept-loop, graceful shutdown (Ctrl-C/SIGTERM).
5. `logging.rs` — `error` default; `access_log=true` → info-строка/JSON.
6. `clippy -D warnings`, `cargo fmt --check`, `cargo test`.
7. Ручной прогон: `socat`/`openssl s_server` как фейковые бэкенды, `curl --resolve` с разными SNI.
