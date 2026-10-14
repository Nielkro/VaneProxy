# Архитектурный план: Lua-скриптинг в Vane (OpenResty/Nginx style)

Документ фиксирует архитектуру, модель параллелизма, биндинги и защиту рантайма для Lua-скриптинга в L7-пайплайне Vane с учётом специфики асинхронного Tokio-рантайма и `mlua`.

---

## 1. Модель параллелизма и жизненный цикл VM (Архитектура без lock-contention)

### 1.1. Проблема наивного подхода
- Если использовать одну глобальную `Lua` VM с фичей `send` в `mlua`, все worker-потоки Tokio блокируются на одном мьютексе внутреннего C-состояния Lua.
- Если использовать `thread_local!` инстансы без пула, асинхронные вызовы (`.await`, сетевые походы, таймеры) в work-stealing шедулере Tokio могут проснуться на другом ОС-потоке, что делает `Future` не-`Send` либо приводит к панике при миграции между потоками.

### 1.2. Выбранное решение: Асинхронный пул независимых VM (Object Pool)
Используется пул изолированных виртуальных машин Lua с неблокирующим Tokio-совместимым пулом:
- **Архитектура пула:** Связка `tokio::sync::Semaphore` (для асинхронного ожидания слотов без блокировки потоков Tokio) + `crossbeam::queue::ArrayQueue<mlua::Lua>` (lock-free хранилище свободных машин).
- **Схема работы:**
  ```rust
  pub struct LuaVmPool {
      semaphore: Arc<tokio::sync::Semaphore>,
      vms: Arc<crossbeam::queue::ArrayQueue<mlua::Lua>>,
  }
  
  impl LuaVmPool {
      pub async fn acquire(&self) -> PooledLuaVm {
          let permit = self.semaphore.clone().acquire_owned().await.expect("pool closed");
          let vm = self.vms.pop().expect("semaphore guarantees available VM");
          PooledLuaVm { vm: Some(vm), permit, pool: self.vms.clone() }
      }
  }
  ```
- **RAII Guard (`PooledLuaVm`) и порядок операций в `drop` (Критично!):**
  Чтобы исключить race condition, когда проснувшийся по семафору поток делает `pop()` из ещё не пополненной очереди, возврат VM в `ArrayQueue` обязан происходить **строго до** освобождения permit семафора:
  ```rust
  pub struct PooledLuaVm {
      pub vm: Option<mlua::Lua>,
      pub permit: tokio::sync::OwnedSemaphorePermit,
      pub pool: Arc<crossbeam::queue::ArrayQueue<mlua::Lua>>,
  }

  impl Drop for PooledLuaVm {
      fn drop(&mut self) {
          // 1. Сначала возвращаем VM обратно в lock-free очередь
          if let Some(vm) = self.vm.take() {
              let _ = self.pool.push(vm);
          }
          // 2. После выхода из drop() дропается permit, гарантируя,
          // что проснувшийся поток сразу найдет VM в очереди.
      }
  }
  ```
- Для пула включается фича `send` в `mlua`. Каждая отдельная VM полностью изолирована (свой независимый `lua_State`), поэтому лочится **только взятая из пула VM** во время фазы.
- **Освобождение перед апстримом (Критично!):** Запрос держит VM **только** на время исполнения конкретной фазы (`rewrite_by_lua`, `access_by_lua` или `header_filter_by_lua`). Перед походом в апстрим (Reverse Proxy сетевой I/O, который может длиться секунды) VM **немедленно возвращается в пул**. Это гарантирует, что даже при пуле из `num_cpus * 4` инстансов тысячи медленных бэкенд-запросов не исчерпают пул и не заблокируют сервер.

---

## 2. Безопасность контекста запроса и защита от утечек данных

### 2.1. Проблема ссылок `&mut Request<B>`
- В `mlua` любой `UserData` по умолчанию требует `'static`.
- Попытка прокинуть ссылку `&mut Request` через сырые указатели небезопасна (скрипт может сохранить объект запроса в глобальную таблицу Lua, что приведет к Use-After-Free).
- Механизм `Lua::scope` не поддерживает полноценную асинхронность (`async userdata methods`).

### 2.2. Защита от Use-After-Free и утечек: `Arc<RwLock<Option<LuaRequestContext>>>`
Если скрипт выполнит вредоносный или ошибочный код вида `_G.stolen_req = vane.req`, то при повторном использовании VM из пула следующий запрос другого клиента рискует утечкой данных, а Rust не сможет вернуть владение `Parts` через `Arc::try_unwrap`.

Решение строится на временном владении через `Option::take()`:
```rust
pub struct LuaRequestContext {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub client_ip: IpAddr,
}

pub struct LuaRequestHandle(pub Arc<RwLock<Option<LuaRequestContext>>>);
```

1. **Деструктуризация запроса:** На время выполнения фазы запрос разбирается:
   ```rust
   let (parts, body) = req.into_parts();
   let ctx_inner = LuaRequestContext {
       method: parts.method,
       uri: parts.uri,
       headers: parts.headers,
       client_ip: peer_addr,
   };
   let handle = LuaRequestHandle(Arc::new(RwLock::new(Some(ctx_inner))));
   ```
2. **Экспорт в VM:** `LuaRequestHandle` регистрируется как `'static UserData`. Любой метод (`vane.req.get_header(...)`) проверяет:
   ```rust
   let guard = self.0.read().map_err(|_| mlua::Error::runtime("poisoned lock"))?;
   let ctx = guard.as_ref().ok_or_else(|| {
       mlua::Error::runtime("attempt to use expired request context")
   })?;
   ```
3. **Завершение фазы и отчуждение:** По завершении фазы Rust выполняет:
   ```rust
   let ctx = handle.0.write().unwrap().take().expect("context must be present");
   parts.method = ctx.method;
   parts.uri = ctx.uri;
   parts.headers = ctx.headers;
   ```
4. **Гарантии:**
   - Если скрипт попытался сохранить `vane.req` в глобал или замкнутую корутину, последующий доступ мгновенно вернет ошибку `"attempt to use expired request context"`.
   - Владение `Parts` возвращается в Rust без клонирования структуры, позволяя пересобрать `Request::from_parts(parts, body)`.
   - Данные предыдущих запросов физически не могут утечь в следующие сессии.

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
                              │ ──► [Возврат VM в пул!]
                              ▼
           ┌──────────────────────────────────────┐
           │   3. CONTENT PHASE / UPSTREAM        │  content_by_lua / Proxy / Static
           │   (поход в апстрим без удержания VM) │
           └──────────────────┬───────────────────┘
                              │ ──► [Взятие новой VM из пула!]
                              ▼
           ┌──────────────────────────────────────┐
           │   4. HEADER FILTER PHASE             │  header_filter_by_lua
           │   (модификация заголовков ответа)    │
           └──────────────────┬───────────────────┘
                              │ ──► [Возврат VM в пул!]
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

## 5. Межфазный контекст `vane.ctx` (Rust-backed контекст)

### 5.1. Архитектурное противоречие пула VM и чистого Lua
- Обычная Lua-таблица (`lua.create_table()`) жестко привязана к конкретному инстансу `lua_State`.
- Поскольку запрос освобождает VM перед походом в апстрим и берет **другую** свободную VM для фазы `header_filter_by_lua` или `log_by_lua`, хранить данные контекста запроса в таблице Lua невозможно.

### 5.2. Реализация: Rust-хранилище с Lua UserData-фасадом
Данные `vane.ctx` живут на стороне Rust на протяжении всего времени жизни HTTP-запроса:
```rust
#[derive(Clone, Debug)]
pub enum LuaCtxValue {
    Nil,
    Boolean(bool),
    Integer(i64),
    Number(f64),
    String(String),
    Map(HashMap<String, LuaCtxValue>),
    List(Vec<LuaCtxValue>),
}

#[derive(Clone, Default)]
pub struct RequestSharedContext(pub Arc<RwLock<HashMap<String, LuaCtxValue>>>);
```

В Lua каждой фазы прокидывается UserData `vane.ctx` с метаметодами `__index` и `__newindex`:
- При записи `vane.ctx.user_id = 42` метод `__newindex` конвертирует Lua-примитив в `LuaCtxValue` и сохраняет его в общий `Arc<RwLock<HashMap<...>>>`.
- При чтении `vane.ctx.user_id` в следующей фазе на **совершенно другой VM** метод `__index` достает значение из Rust-хранилища и возвращает его в стек Lua.
- Поддерживаются примитивы (строки, числа, булевы флаги) и вложенные простые таблицы/массивы.
- При завершении HTTP-запроса Rust-контекст просто деаллоцируется, освобождая память.

```lua
-- В access_by_lua (VM #1):
vane.ctx.user_id = 42
vane.ctx.user_role = "admin"

-- [Поход в апстрим: VM #1 отдана в пул, запрос ждет ответа бэкенда]

-- В header_filter_by_lua (VM #2):
if vane.ctx.user_role == "admin" then
    vane.header["X-Is-Admin"] = "1"
end
```

---

## 6. Песочница и безопасность рантайма (Sandbox & Guardrails)

### 6.1. Удаление блокирующих стандартных библиотек
Чтобы скрипты не могли заблокировать пул воркеров Tokio синхронным вводом-выводом или системными вызовами, при инициализации каждой Lua VM отключаются опасные библиотеки:
- Полностью удаляются библиотеки `io`, `os`, `package`, `debug`.
- Время отдается не через блокирующий `os.time()`, а через оптимизированный метод `vane.now()`, возвращающий закэшированное атомарное время из Rust-рантайма (`coarse time` без лишних системных вызовов).

### 6.2. Изоляция глобального окружения (_ENV / setfenv)
Чтобы скрипты не могли загрязнять глобальную таблицу `_G` инстанса VM (например, случайными глобальными переменными `x = 10` или попыткой переопределить стандартные функции), каждый скрипт выполняется в изолированном окружении:
- Создается индивидуальная таблица окружения с метатаблицей `__index = _G`.
- Запись любых глобальных переменных происходит в локальную таблицу запроса, не затрагивая глобальный стейт `_G` самой VM.

### 6.3. Защита от бесконечных циклов и зависаний (Instruction Hooks)
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
   - Реализация асинхронного `LuaVmPool` на базе `tokio::sync::Semaphore` + `crossbeam::queue::ArrayQueue<mlua::Lua>`.
   - Реализация RAII Guard (`PooledLuaVm`), возвращающего VM в очередь на `drop`.
   - Санитаризация окружения (песочница без `io`/`os`, хук лимита инструкций `HookTriggers::every_nth_instruction`).
2. **Этап 2: Парсер Caddyfile (`src/caddyfile/model.rs`, `parser.rs`)**
   - Добавление директив `rewrite_by_lua`, `access_by_lua`, `content_by_lua`, `header_filter_by_lua`, `log_by_lua` (inline и `*_file`).
3. **Этап 3: Биндинги и контекст (`src/lua/bindings.rs`)**
   - Реализация `LuaRequestHandle` с `Arc<RwLock<Option<LuaRequestContext>>>` и безопасным `Option::take()` по окончании фазы (с защитой от `_G`-утечек и Use-After-Free).
   - Реализация `RequestSharedContext` на стороне Rust (`HashMap<String, LuaCtxValue>`) с `UserData`-фасадом (`__index` / `__newindex`), сохраняющим состояние между фазами при смене VM.
   - Изоляция окружения скриптов через песочницу `_ENV` (`setfenv`).
   - Реализация `vane.exit()` через `ExternalError` (`LuaExitSignal`).
   - Реализация `vane.shared` кэша.
4. **Этап 4: Встраивание в L7 пайплайн (`src/l7/service.rs`)**
   - Интеграция фаз в `handle_site_request` и `execute_directive_pipeline`.
   - Освобождение VM обратно в пул перед апстрим-запросами (`proxy.forward(...)`).
5. **Этап 5: Тесты и верификация (`tests/`)**
   - Unit-тесты для прерывания по `vane.exit()`.
   - Тесты передачи данных через `vane.ctx` между разными VM из пула.
   - Тесты защиты от висячих ссылок (`attempt to use expired request context`).
   - Тесты защиты от бесконечного цикла.
   - Тесты асинхронного `vane.sleep` без блокировки Tokio-воркеров.
