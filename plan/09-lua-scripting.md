# План внедрения Lua-скриптинга в Vane (OpenResty/Nginx style)

Документ описывает архитектуру и этапы реализации поддержки скриптинга Lua в L7-пайплайне Vane по аналогии с `ngx_http_lua_module` (OpenResty).

---

## 1. Архитектура и фазы жизненного цикла (Phases)

В Nginx (OpenResty) Lua встроен в дискретные фазы обработки HTTP-запроса. В Vane пайплайн выстраивается по аналогичной схеме:

```
                  Входящий запрос (L7 / HTTP)
                              │
                              ▼
           ┌──────────────────────────────────────┐
           │   1. REWRITE PHASE                   │  rewrite_by_lua
           │   (изменение URI, роутинг, редиректы)│  
           └──────────────────┬───────────────────┘
                              ▼
           ┌──────────────────────────────────────┐
           │   2. ACCESS PHASE                    │  access_by_lua
           │   (auth, токены, IP rate-limit, 403) │
           └──────────────────┬───────────────────┘
                              ▼
           ┌──────────────────────────────────────┐
           │   3. CONTENT PHASE                   │  content_by_lua
           │   (генерация ответа без бэкенда)     │
           └──────────────────┬───────────────────┘
                              │ (если контент не сгенерирован — proxy / static)
                              ▼
           ┌──────────────────────────────────────┐
           │   4. HEADER FILTER PHASE             │  header_filter_by_lua
           │   (модификация заголовков ответа)    │
           └──────────────────┬───────────────────┘
                              ▼
           ┌──────────────────────────────────────┐
           │   5. BODY FILTER PHASE (опционально) │  body_filter_by_lua
           │   (потоковая трансформация тела)     │
           └──────────────────┬───────────────────┘
                              ▼
           ┌──────────────────────────────────────┐
           │   6. LOG PHASE                       │  log_by_lua
           │   (асинхронная отправка метрик/логов)│
           └──────────────────────────────────────┘
```

Фундамент реализации — крейт **`mlua`** (с фичами `luajit` / `lua54`, `async`, `send`), обеспечивающий интеграцию с асинхронным рантаймом Tokio, нулевые копирования буферов и строгую типобезопасность.

---

## 2. Синтаксис директив Caddyfile

Поддерживаются как inline-блоки кода, так и внешние `.lua` файлы:

```caddy
example.com {
    # Глобальная инициализация состояния / модулей
    lua_load /etc/vane/lua/init.lua

    # 1. Проверка авторизации на входе (Access Phase)
    @api path /api/*
    handle @api {
        access_by_lua '
            local token = vane.req.get_header("Authorization")
            if not token or not token:find("^Bearer ") then
                vane.exit(401, "{\"error\": \"Unauthorized\"}")
            end
            
            -- Проброс метаданных в апстрим
            vane.req.set_header("X-User-Id", "12345")
        '
        reverse_proxy 127.0.0.1:8000
    }

    # 2. Чистая генерация ответа на лету (Content Phase)
    handle /healthz {
        content_by_lua '
            vane.header["Content-Type"] = "application/json"
            vane.say("{\"status\": \"ok\", \"time\": " .. os.time() .. "}")
        '
    }

    # 3. Внешний скрипт для сложных сценариев
    handle /custom/* {
        rewrite_by_lua_file /etc/vane/lua/dynamic_rewrite.lua
        reverse_proxy 127.0.0.1:9000
    }
}
```

---

## 3. Lua API (`vane.*` — аналог `ngx.*`)

Модуль предоставляет глобальный объект `vane` (с алиасом `ngx` для совместимости со сниппетами):

### `vane.req` (Работа с запросом)
- `vane.req.get_method()`: возвращает метод (`"GET"`, `"POST"`, etc.).
- `vane.req.get_uri()`: текущий URI path.
- `vane.req.set_uri(new_path)`: rewrite пути.
- `vane.req.get_headers()`: таблица входящих заголовков.
- `vane.req.get_header(name)`: значение заголовка.
- `vane.req.set_header(name, val)`: перезаписать заголовок для апстрима.
- `vane.req.get_query()`: таблица URL query параметров.
- `vane.req.get_body()`: чтение тела запроса (буферизированное).
- `vane.req.get_client_ip()`: IP-клиента (SocketAddr).

### `vane.resp` / `vane.*` (Формирование ответа)
- `vane.status = 200`: установка HTTP-статуса ответа.
- `vane.header[name] = val`: установка/модификация заголовка ответа.
- `vane.say(body)` / `vane.print(body)`: отправка тела ответа.
- `vane.exit(code, [body])`: немедленное прерывание цепочки и отправка HTTP-ответа (`401`, `403`, `302`, `500`).
- `vane.redirect(url, [status])`: редирект (301/302).

### Утилиты и Shared State
- `vane.shared.DICT`: потокобезопасный key-value кэш в памяти (`vane.shared.cache:set(key, val, ttl)`, `get()`, `incr()`) через `dashmap` или `parking_lot::RwLock<HashMap>`.
- `vane.log(level, msg)`: вывод в лог Vane (`tracing::info!`, `warn!`, `error!`).
- `vane.sleep(seconds)`: неблокирующий асинхронный `tokio::time::sleep`.

---

## 4. Этапы реализации

### Этап 1. Зависимости и Lua Runtime (`src/lua/mod.rs`)
1. Добавить `mlua = { version = "0.10", features = ["luajit", "async", "send"] }` (с фолбэком на `lua54`, если luajit недоступен на платформе сборки).
2. Создать пул виртуальных машин Lua (`LuaEngine`) или thread-local инстансы во избежание глобального lock contention между worker threads Tokio.
3. Компиляция и кэширование байткода скриптов при парсинге/старте (поддержка hot-reload).

### Этап 2. Модели и парсер Caddyfile (`src/caddyfile/`)
1. Расширить `Directive` в `model.rs`:
   ```rust
   pub enum LuaSource {
       Inline(String),
       File(PathBuf),
   }

   pub enum Directive {
       // ...
       RewriteByLua(LuaSource),
       AccessByLua(LuaSource),
       ContentByLua(LuaSource),
       HeaderFilterByLua(LuaSource),
       LogByLua(LuaSource),
   }
   ```
2. Поддержать парсинг директив в `parser.rs`:
   - `rewrite_by_lua`, `rewrite_by_lua_file`
   - `access_by_lua`, `access_by_lua_file`
   - `content_by_lua`, `content_by_lua_file`
   - `header_filter_by_lua`
   - `log_by_lua`

### Этап 3. Биндинги Rust <-> Lua (`src/lua/bindings.rs`)
1. Реализовать типы `UserData` для `mlua`:
   - `LuaRequest`: безопасная обёртка над ссылкой на `Request<B>`.
   - `LuaResponse`: билдер формируемого ответа.
   - Механизм `ActionControl` (`Continue`, `RespondImmediately(Response)`, `Rewrite(String)`).
2. Поддержка `vane.shared`: реализация in-memory LRU/TTL хранилища (аналог `lua_shared_dict`), разделяемого между всеми контекстами исполнения.

### Этап 4. Интеграция в пайплайн L7 (`src/l7/service.rs`)
1. **Rewrite-фаза:** перед выбором поддиректив/эндпоинта выполнить `rewrite_by_lua`. Если скрипт изменил URI (`vane.req.set_uri`) — обновить URI запроса. Если вызван `vane.exit()` — вернуть ответ.
2. **Access-фаза:** перед `reverse_proxy` и `file_server` вызвать `access_by_lua`. При возврате `vane.exit(401/403)` — прервать обработку.
3. **Content-фаза:** если объявлен `content_by_lua` — исполнить скрипт вместо проксирования или статики, вернуть сформированный ответ.
4. **Header-фильтр:** перед отдачей клиенту прогнать заголовки ответа через `header_filter_by_lua`.

### Этап 5. Тестирование и бенчмаркинг
1. **Юнит-тесты (`cargo test`):**
   - Блокировка неавторизованных запросов через `access_by_lua`.
   - Модификация заголовков через `header_filter_by_lua`.
   - Генерация JSON-ответов через `content_by_lua`.
   - Разделяемая память `vane.shared.DICT`.
2. **Бенчмарки:**
   - Замер оверхеда исполнения LuaJIT против нативного reverse-proxy на Rust (цель: < 5-10 микросекунд на запрос).
