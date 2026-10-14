# Архитектурный план: Lua-скриптинг в Vane (OpenResty/Nginx style)

Документ фиксирует архитектуру, модель параллелизма, биндинги и защиту рантайма для Lua-скриптинга в L7-пайплайне Vane с учётом специфики асинхронного Tokio-рантайма и `mlua`.

---

## 1. Модель параллелизма и жизненный цикл VM (Архитектура без lock-contention)

### 1.1. Проблема наивного подхода
- Если использовать одну глобальную `Lua` VM с фичей `send` в `mlua`, все worker-потоки Tokio блокируются на одном мьютексе внутреннего C-состояния Lua.
- Если использовать `thread_local!` инстансы без пула, асинхронные вызовы (`.await`, сетевые походы, таймеры) в work-stealing шедулере Tokio могут проснуться на другом ОС-потоке, что делает `Future` не-`Send` либо приводит к панике при миграции между потоками.

### 1.2. Выбранное решение: Пул независимых VM (Object Pool)
Используется пул изолированных виртуальных машин Lua через lock-free канал (`crossbeam_channel` или `tokio::sync::mpsc`):
- Для пула включается фича `send` в `mlua`. Каждая отдельная VM полностью изолирована (свой независимый `lua_State`), поэтому внутри запроса лочится **только взятая из пула VM**, никакого межпоточного lock contention нет.
- При начале выполнения Lua-фазы запрос берет свободную VM из пула (`pool.acquire().await`).
- Запрос удерживает VM на время выполнения фазы. Если скрипт делает асинхронную операцию (`vane.sleep`, `vane.http_get`), корутина Tokio свободно мигрирует между потоками пула Tokio, так как `Lua` реализует `Send`.
- По завершении фазы VM сбрасывает локальный контекст (`vane.ctx`, временные таблицы) и возвращается в пул.
- Количество VM в пуле конфигурируется (по умолчанию `num_cpus * 4`).

---

## 2. Передача контекста запроса без войны с лайфтаймами

### 2.1. Проблема ссылок `&mut Request<B>`
- В `mlua` любой `UserData` по умолчанию требует `'static`.
- Попытка прокинуть ссылку `&mut Request` через сырые указатели небезопасна (скрипт может сохранить объект запроса в глобальную таблицу Lua, что приведет к Use-After-Free).
- Механизм `Lua::scope` не поддерживает полноценную асинхронность (`async userdata methods`).

### 2.2. Выбранное решение: Деструктуризация `http::request::Parts`
На время выполнения цепочки Lua-фаз запрос деструктуризируется:
```rust
let (parts, body) = req.into_parts();
let req_ctx = Arc::new(RwLock::new(LuaRequestContext {
    method: parts.method,
    uri: parts.uri,
    headers: parts.headers,
    client_ip: peer_addr,
}));
```
1. `LuaRequestContext` оборачивается в потокобезопасный `Arc<RwLock<...>>` и регистрируется в VM как `'static UserData`.
2. Lua-скрипт читает и модифицирует заголовки, метод и URI через методы `vane.req.*`.
3. После завершения фаз `Parts` собираются обратно в `Request::from_parts(parts, body)` и передаются дальше в пайплайн (Reverse Proxy или Static Server).
4. Никакого `unsafe`, никаких висячих указателей и строгая типобезопасность Rust.

---

## 3. Фазы жизненного цикла запроса

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
           │   5. LOG PHASE                       │  log_by_lua
           │   (асинхронная отправка метрик/логов)│
           └──────────────────────────────────────┘
```

---

## 4. Механизм мгновенного прерывания `vane.exit()`

### 4.1. Поведение
`vane.exit(code, [body])` должен **немедленно прерывать** выполнение Lua-скрипта (код, следующий за `vane.exit()`, никогда не исполняется).

### 4.2. Реализация через ExternalError
В Rust объявляется специальный тип ошибки прерывания:
```rust
#[derive(Debug)]
pub struct LuaExitSignal {
    pub status: StatusCode,
    pub body: Option<Bytes>,
}

impl std::error::Error for LuaExitSignal {}
impl std::fmt::Display for LuaExitSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vane.exit({})", self.status)
    }
}
```
1. Функция `vane.exit(status, body)` формирует `LuaExitSignal` и возвращает `Err(mlua::Error::external(signal))`.
2. Lua runtime немедленно разворачивает стек исполнения и выходит в Rust.
3. Диспетчер фаз Vane перехватывает `mlua::Error`:
   - Если это `LuaExitSignal` — он преобразуется в `ActionControl::RespondImmediately(Response)` со статусом и телом, прерывая дальнейший пайплайн.
   - Если это реальная ошибка скрипта (синтаксис, nil index) — логируется `error!` и возвращается `500 Internal Server Error`.

---

## 5. Межфазный контекст `vane.ctx` (Аналог `ngx.ctx`)

Для передачи произвольных данных между фазами одного запроса (например, распарсенный токен в `access_by_lua` -> чтение роли пользователя в `header_filter_by_lua` или `log_by_lua`) реализуется таблица `vane.ctx`:
- При начале обработки HTTP-запроса создается чистая Lua-таблица `ctx = lua.create_table()?`.
- Таблица регистрируется в глобальном скоупе запроса под именем `vane.ctx`.
- Любая фаза этого запроса может свободно писать и читать поля:
  ```lua
  -- В access_by_lua:
  vane.ctx.user_id = 42
  vane.ctx.roles = {"admin", "editor"}

  -- В header_filter_by_lua:
  if vane.ctx.user_id then
      vane.header["X-Auth-User"] = tostring(vane.ctx.user_id)
  end
  ```
- По завершении HTTP-запроса таблица автоматически уничтожается сборщиком мусора Lua без загрязнения других запросов.

---

## 6. Песочница и безопасность рантайма (Sandbox & Guardrails)

### 6.1. Удаление блокирующих стандартных библиотек
Чтобы скрипты не могли заблокировать пул воркеров Tokio синхронным вводом-выводом или системными вызовами, при инициализации каждой Lua VM отключаются опасные библиотеки:
- Полностью удаляются библиотеки `io`, `os`, `package`, `debug`.
- Время отдается не через блокирующий `os.time()`, а через оптимизированный метод `vane.now()`, возвращающий закэшированное атомарное время из Rust-рантайма (`coarse time` без лишних системных вызовов).

### 6.2. Защита от бесконечных циклов и зависаний (Instruction Hooks)
Для предотвращения зависания воркера из-за `while true do end` или тяжелых регулярных выражений:
- Настраивается `lua.set_hook(HookTriggers::every_nth_instruction(100_000), ...)` с лимитом инструкций на запрос (например, не более 5 000 000 инструкций).
- При превышении лимита скрипт аварийно завершается с ошибкой `InstructionLimitExceeded`, запрос получает статус `504 Gateway Timeout` или `500`, а воркер Tokio продолжает работу.

---

## 7. Lua API (`vane.*` / `ngx.*`)

### `vane.req`
- `vane.req.get_method() -> string`
- `vane.req.get_uri() -> string`
- `vane.req.set_uri(path: string)`
- `vane.req.get_headers() -> table`
- `vane.req.get_header(name: string) -> string|nil`
- `vane.req.set_header(name: string, value: string)`
- `vane.req.clear_header(name: string)`
- `vane.req.get_query() -> table`
- `vane.req.get_client_ip() -> string`

### `vane.resp` / `vane.*`
- `vane.status = <number>`
- `vane.header[name] = <string>`
- `vane.say(body: string)` / `vane.print(body: string)`
- `vane.exit(status: number, [body: string])`
- `vane.redirect(url: string, [status: number])`

### Служебные функции
- `vane.ctx` — per-request таблица.
- `vane.now() -> number` — текущее UNIX-время (секунды/миллисекунды).
- `vane.sleep(seconds: number)` — неблокирующий асинхронный сон (`tokio::time::sleep`).
- `vane.log(level: string, message: string)` — вывод в tracing лог (`"info"`, `"warn"`, `"error"`, `"debug"`).
- `vane.shared.DICT` — разделяемый между всеми VM потокобезопасный key-value кэш в памяти (`get`, `set`, `incr`, `delete`).

---

## 8. Этапы внедрения

1. **Этап 1: Добавление зависимостей и каркас пула VM (`src/lua/mod.rs`, `src/lua/pool.rs`)**
   - Добавление `mlua` (с `luajit` / `lua54`, `async`, `send`).
   - Реализация `LuaPool` с ограничением емкости и санитаризацией окружения (песочница без `io`/`os`, хук лимита инструкций).
2. **Этап 2: Парсер Caddyfile (`src/caddyfile/model.rs`, `parser.rs`)**
   - Добавление директив `rewrite_by_lua`, `access_by_lua`, `content_by_lua`, `header_filter_by_lua`, `log_by_lua` (inline и `*_file`).
3. **Этап 3: Биндинги и контекст (`src/lua/bindings.rs`)**
   - Реализация `LuaRequestContext`, таблиц `vane.req`, `vane.header`, `vane.ctx`.
   - Реализация `vane.exit()` через `ExternalError`.
   - Реализация `vane.shared` кэша.
4. **Этап 4: Встраивание в L7 пайплайн (`src/l7/service.rs`)**
   - Интеграция фаз в `handle_site_request` и `execute_directive_pipeline`.
5. **Этап 5: Тесты и верификация (`tests/`)**
   - Unit-тесты для прерывания по `vane.exit()`.
   - Тесты передачи данных через `vane.ctx`.
   - Тесты защиты от бесконечного цикла.
   - Тесты асинхронного `vane.sleep` без блокировки Tokio.
