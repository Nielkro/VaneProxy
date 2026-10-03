# 04 — Деплой (systemd + Caddy + Xray)

## Бинарник и права на :443
- Юнит `penik-proxy.service`, пользователь `penik-proxy` (без shell), бинарь `/usr/local/bin/penik-proxy`.
- Порт 443 < 1024 → дать capability без root:
  ```ini
  AmbientCapabilities=CAP_NET_BIND_SERVICE
  CapabilityBoundingSet=CAP_NET_BIND_SERVICE
  ```
  Альтернатива — `authbind`/setcap на файл, но через systemd чище.

## Пример юнита `/etc/systemd/system/penik-proxy.service`
```ini
[Unit]
Description=Penik SNI proxy :443 -> Xray/Caddy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=penik-proxy
Group=penik-proxy
ExecStart=/usr/local/bin/penik-proxy --config /etc/penik-proxy/config.toml
Restart=on-failure
RestartSec=2
LimitNOFILE=65535
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

Установка:
```bash
sudo useradd -r -s /usr/sbin/nologin penik-proxy
sudo install -m 0755 target/release/penik-proxy /usr/local/bin/penik-proxy
sudo mkdir -p /etc/penik-proxy && sudo install -m 0640 config.toml /etc/penik-proxy/config.toml
sudo chown root:penik-proxy /etc/penik-proxy/config.toml
sudo systemctl daemon-reload && sudo systemctl enable --now penik-proxy
sudo journalctl -u penik-proxy -f
```

## Caddy (`:8444` + PROXY v2) — КРИТИЧНО: сборка xcaddy и https_port 8444
Caddy должен слушать `127.0.0.1:8444` и принимать PROXYv2, иначе все IP будут `127.0.0.1`.

1. **Плагин PROXY Protocol**:
   В стандартном бинарнике Caddy директивы `proxy_protocol` нет — Caddy должен быть собран через `xcaddy`:
   ```bash
   xcaddy build --with github.com/caddyserver/proxy-protocol
   ```
2. **Порт HTTPS (`https_port 8444`)**:
   Обязательно указать `https_port 8444` в глобальных опциях, иначе Caddy по умолчанию попытается занять `:443` и упадёт с ошибкой `EADDRINUSE`.
3. `listener_wrappers` с `proxy_protocol` включается СТРОГО в блоке `servers :8444`, `proxy_protocol` ДО `tls`. Глобальное включение сломало бы `:80` (HTTP-01, редиректы).

```caddyfile
{
	https_port 8444

	servers :8444 {
		listener_wrappers {
			proxy_protocol {
				timeout 5s
				allow 127.0.0.1/32 ::1/128
			}
			tls
		}
	}
}

# :80 остаётся напрямую за Caddy (0.0.0.0:80) — без proxy_protocol,
# чтобы проходил ACME HTTP-01 и http->https редиректы.
# TLS-ALPN-01 через :443 работает сквозь penik-proxy: ClientHello
# форвардится как есть, ALPN-расширение сохраняется и доходит до Caddy.
penik.ru, www.penik.ru {
	reverse_proxy 127.0.0.1:8080
}
```
- Проверка после включения: `curl -k https://penik.ru` (через 443) → в access-лог Caddy должен попасть реальный src IP, а не `127.0.0.1`.
- Если Caddy пока без PP — в план входит отдельным коммитом: поднять `:8444` с PPv2, оставить `:443` Caddy выключенным чтобы не было конфликта биндинга.

## Xray
- Inbound(ы) остаются как есть на `127.0.0.1:8443` (или твои текущие), **без** `acceptProxyProtocol` — Rust шлёт туда чистый TCP.
- Если у тебя несколько inbounds под разные домены — добавить `[backends.*]` + `[[routes]]` (конфиг уже это умеет: один бэкенд = addr + флаг PPv2).
- Reality/VLESS: ничего не менять — SNI-роутер прозрачен, хендшейк доезжает целиком.

## Порядок переключения (чтобы не лечь)
1. Caddy перевести на `:8444` + PPv2 (блок выше) + оставить `:80` напрямую, проверить напрямую `curl --resolve penik.ru:8444:127.0.0.1 https://penik.ru:8444 -k`.
2. Xray проверить что слушает локально.
3. Запустить Rust на обоих `:443` (v4+v6 по `listen`-списку), проверить все 4 домена + неизвестный.
4. Только потом гасить старый Caddy на `:443` (если он там был).
5. `ss -tlnp | grep 443` — на tcp/443 должен остаться только `penik-proxy` (плюс отдельно tcp/80 за Caddy).
