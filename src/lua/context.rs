use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hyper::header::{HeaderMap, HeaderName, HeaderValue};
use hyper::{Method, StatusCode, Uri};
use mlua::{IntoLua, Lua, MetaMethod, UserData, UserDataMethods, Value};
use tracing::{debug, error, info, warn};

/// Exit signal returned when `vane.exit(status, [body])` is called inside a script.
#[derive(Debug, Clone)]
pub struct LuaExitSignal {
    pub status: StatusCode,
    pub body: Option<Bytes>,
}

impl fmt::Display for LuaExitSignal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vane.exit({})", self.status)
    }
}

impl std::error::Error for LuaExitSignal {}

/// Context of the current HTTP request, disassembled from hyper::Request parts.
#[derive(Debug, Clone)]
pub struct LuaRequestContext {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub client_ip: IpAddr,
}

/// Thread-safe handle containing the request context inside an Option.
/// Upon phase completion, `Option::take()` is called to extract ownership back to Rust.
#[derive(Clone)]
pub struct LuaRequestHandle(pub Arc<RwLock<Option<LuaRequestContext>>>);

impl LuaRequestHandle {
    pub fn new(ctx: LuaRequestContext) -> Self {
        Self(Arc::new(RwLock::new(Some(ctx))))
    }

    /// Takes the inner context back into exclusive Rust ownership.
    /// Any subsequent calls from Lua will encounter None and fail safely.
    pub fn take(&self) -> Option<LuaRequestContext> {
        self.0.write().ok()?.take()
    }

    pub fn get_method(&self) -> Result<String, mlua::Error> {
        let guard = self
            .0
            .read()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let ctx = guard
            .as_ref()
            .ok_or_else(|| mlua::Error::runtime("attempt to use expired request context"))?;
        Ok(ctx.method.as_str().to_string())
    }

    pub fn set_method(&self, method_str: String) -> Result<(), mlua::Error> {
        let mut guard = self
            .0
            .write()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let ctx = guard
            .as_mut()
            .ok_or_else(|| mlua::Error::runtime("attempt to use expired request context"))?;
        let method = Method::from_bytes(method_str.as_bytes())
            .map_err(|e| mlua::Error::runtime(format!("invalid HTTP method: {e}")))?;
        ctx.method = method;
        Ok(())
    }

    pub fn get_uri(&self) -> Result<String, mlua::Error> {
        let guard = self
            .0
            .read()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let ctx = guard
            .as_ref()
            .ok_or_else(|| mlua::Error::runtime("attempt to use expired request context"))?;
        Ok(ctx.uri.to_string())
    }

    pub fn set_uri(&self, uri_str: String) -> Result<(), mlua::Error> {
        let mut guard = self
            .0
            .write()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let ctx = guard
            .as_mut()
            .ok_or_else(|| mlua::Error::runtime("attempt to use expired request context"))?;
        let uri: Uri = uri_str
            .parse()
            .map_err(|e| mlua::Error::runtime(format!("invalid URI: {e}")))?;
        ctx.uri = uri;
        Ok(())
    }

    pub fn get_header(&self, name: &str) -> Result<Option<String>, mlua::Error> {
        let guard = self
            .0
            .read()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let ctx = guard
            .as_ref()
            .ok_or_else(|| mlua::Error::runtime("attempt to use expired request context"))?;
        let val = ctx
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        Ok(val)
    }

    pub fn set_header(&self, name: String, val: String) -> Result<(), mlua::Error> {
        let mut guard = self
            .0
            .write()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let ctx = guard
            .as_mut()
            .ok_or_else(|| mlua::Error::runtime("attempt to use expired request context"))?;
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| mlua::Error::runtime(format!("invalid header name: {e}")))?;
        let header_val = HeaderValue::from_str(&val)
            .map_err(|e| mlua::Error::runtime(format!("invalid header value: {e}")))?;
        ctx.headers.insert(header_name, header_val);
        Ok(())
    }

    pub fn clear_header(&self, name: &str) -> Result<(), mlua::Error> {
        let mut guard = self
            .0
            .write()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let ctx = guard
            .as_mut()
            .ok_or_else(|| mlua::Error::runtime("attempt to use expired request context"))?;
        ctx.headers.remove(name);
        Ok(())
    }

    pub fn get_headers(&self) -> Result<HashMap<String, String>, mlua::Error> {
        let guard = self
            .0
            .read()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let ctx = guard
            .as_ref()
            .ok_or_else(|| mlua::Error::runtime("attempt to use expired request context"))?;
        let mut map = HashMap::new();
        for (key, val) in ctx.headers.iter() {
            if let Ok(v) = val.to_str() {
                map.insert(key.as_str().to_string(), v.to_string());
            }
        }
        Ok(map)
    }

    pub fn get_client_ip(&self) -> Result<String, mlua::Error> {
        let guard = self
            .0
            .read()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let ctx = guard
            .as_ref()
            .ok_or_else(|| mlua::Error::runtime("attempt to use expired request context"))?;
        Ok(ctx.client_ip.to_string())
    }
}

impl UserData for LuaRequestHandle {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("get_method", |_, this, ()| this.get_method());
        methods.add_method("set_method", |_, this, m: String| this.set_method(m));
        methods.add_method("get_uri", |_, this, ()| this.get_uri());
        methods.add_method("set_uri", |_, this, u: String| this.set_uri(u));
        methods.add_method("get_header", |_, this, name: String| this.get_header(&name));
        methods.add_method("set_header", |_, this, (name, val): (String, String)| {
            this.set_header(name, val)
        });
        methods.add_method("clear_header", |_, this, name: String| this.clear_header(&name));
        methods.add_method("get_headers", |_, this, ()| this.get_headers());
        methods.add_method("get_client_ip", |_, this, ()| this.get_client_ip());
    }
}

/// Primitive values supported inside `vane.ctx` across phase boundaries and VM instances.
#[derive(Clone, Debug, PartialEq)]
pub enum LuaCtxValue {
    Nil,
    Boolean(bool),
    Integer(i64),
    Number(f64),
    String(String),
    Map(HashMap<String, LuaCtxValue>),
    List(Vec<LuaCtxValue>),
}

impl LuaCtxValue {
    pub fn from_lua_value(val: Value) -> Result<Self, mlua::Error> {
        match val {
            Value::Nil => Ok(Self::Nil),
            Value::Boolean(b) => Ok(Self::Boolean(b)),
            Value::Integer(i) => Ok(Self::Integer(i)),
            Value::Number(n) => Ok(Self::Number(n)),
            Value::String(s) => Ok(Self::String(s.to_str()?.to_string())),
            Value::Table(tbl) => {
                let is_sequence = tbl.raw_len() > 0;
                if is_sequence {
                    let mut list = Vec::new();
                    for val in tbl.sequence_values::<Value>() {
                        list.push(Self::from_lua_value(val?)?);
                    }
                    Ok(Self::List(list))
                } else {
                    let mut map = HashMap::new();
                    for pair in tbl.pairs::<String, Value>() {
                        let (k, v) = pair?;
                        map.insert(k, Self::from_lua_value(v)?);
                    }
                    Ok(Self::Map(map))
                }
            }
            _ => Err(mlua::Error::runtime(
                "unsupported value type stored in vane.ctx (must be primitive or table)",
            )),
        }
    }

    pub fn to_lua_value(&self, lua: &Lua) -> Result<Value, mlua::Error> {
        match self {
            Self::Nil => Ok(Value::Nil),
            Self::Boolean(b) => Ok(Value::Boolean(*b)),
            Self::Integer(i) => Ok(Value::Integer(*i)),
            Self::Number(n) => Ok(Value::Number(*n)),
            Self::String(s) => s.as_str().into_lua(lua),
            Self::List(list) => {
                let tbl = lua.create_table()?;
                for (idx, item) in list.iter().enumerate() {
                    tbl.raw_set(idx + 1, item.to_lua_value(lua)?)?;
                }
                Ok(Value::Table(tbl))
            }
            Self::Map(map) => {
                let tbl = lua.create_table()?;
                for (k, v) in map.iter() {
                    tbl.raw_set(k.as_str(), v.to_lua_value(lua)?)?;
                }
                Ok(Value::Table(tbl))
            }
        }
    }
}

/// Request-scoped context that persists across phases and across different VM instances from the pool.
#[derive(Clone, Default)]
pub struct RequestSharedContext(pub Arc<RwLock<HashMap<String, LuaCtxValue>>>);

impl UserData for RequestSharedContext {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::Index, |lua, this, key: String| {
            let guard = this
                .0
                .read()
                .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
            if let Some(val) = guard.get(&key) {
                val.to_lua_value(lua)
            } else {
                Ok(Value::Nil)
            }
        });

        methods.add_meta_method(
            MetaMethod::NewIndex,
            |_lua, this, (key, val): (String, Value)| {
                let mut guard = this
                    .0
                    .write()
                    .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
                let ctx_val = LuaCtxValue::from_lua_value(val)?;
                if ctx_val == LuaCtxValue::Nil {
                    guard.remove(&key);
                } else {
                    guard.insert(key, ctx_val);
                }
                Ok(())
            },
        );
    }
}

/// Response mutations made by Lua scripts during content or header filter phases.
#[derive(Clone, Debug, Default)]
pub struct LuaResponseMutations {
    pub status: Option<StatusCode>,
    pub set_headers: Vec<(HeaderName, HeaderValue)>,
    pub remove_headers: Vec<HeaderName>,
    pub body: Option<Bytes>,
}

#[derive(Clone, Default)]
pub struct LuaResponseHandle(pub Arc<RwLock<LuaResponseMutations>>);

impl LuaResponseHandle {
    pub fn set_status(&self, status: u16) -> Result<(), mlua::Error> {
        let mut guard = self
            .0
            .write()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let code = StatusCode::from_u16(status)
            .map_err(|e| mlua::Error::runtime(format!("invalid status code: {e}")))?;
        guard.status = Some(code);
        Ok(())
    }

    pub fn set_header(&self, k: String, v: String) -> Result<(), mlua::Error> {
        let mut guard = self
            .0
            .write()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|e| mlua::Error::runtime(format!("invalid header name: {e}")))?;
        let val = HeaderValue::from_str(&v)
            .map_err(|e| mlua::Error::runtime(format!("invalid header value: {e}")))?;
        guard.set_headers.push((name, val));
        Ok(())
    }

    pub fn remove_header(&self, k: String) -> Result<(), mlua::Error> {
        let mut guard = self
            .0
            .write()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let name = HeaderName::from_bytes(k.as_bytes())
            .map_err(|e| mlua::Error::runtime(format!("invalid header name: {e}")))?;
        guard.remove_headers.push(name);
        Ok(())
    }

    pub fn say(&self, content: String) -> Result<(), mlua::Error> {
        let mut guard = self
            .0
            .write()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let bytes = Bytes::from(content);
        guard.body = Some(bytes);
        Ok(())
    }
}

impl UserData for LuaResponseHandle {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("set_status", |_, this, status: u16| this.set_status(status));
        methods.add_method("set_header", |_, this, (k, v): (String, String)| {
            this.set_header(k, v)
        });
        methods.add_method("remove_header", |_, this, k: String| this.remove_header(k));
        methods.add_method("say", |_, this, content: String| this.say(content));
    }
}

/// Helper to extract LuaExitSignal if an error represents an intentional vane.exit() call.
pub fn extract_exit_signal(err: &mlua::Error) -> Option<&LuaExitSignal> {
    match err {
        mlua::Error::ExternalError(ext) => ext.downcast_ref::<LuaExitSignal>(),
        mlua::Error::CallbackError { cause, .. } => match cause.as_ref() {
            mlua::Error::ExternalError(ext) => ext.downcast_ref::<LuaExitSignal>(),
            _ => None,
        },
        _ => None,
    }
}

use super::shared_dict::SharedDictRegistry;

/// Builds an isolated per-request execution environment table (`_ENV`) containing `vane.*` APIs.
pub fn create_request_env(
    lua: &Lua,
    req_handle: LuaRequestHandle,
    ctx: RequestSharedContext,
    resp_handle: LuaResponseHandle,
    shared_dict: Option<SharedDictRegistry>,
) -> Result<mlua::Table, mlua::Error> {
    let env = lua.create_table()?;

    // Setup metatable so read lookups fallback to global safe functions (string, math, table etc.)
    let mt = lua.create_table()?;
    mt.set("__index", lua.globals())?;
    env.set_metatable(Some(mt));

    // Create vane namespace
    let vane = lua.create_table()?;

    // vane.req
    let vane_req = lua.create_table()?;
    let h1 = req_handle.clone();
    vane_req.set(
        "get_method",
        lua.create_function(move |_, ()| h1.get_method())?,
    )?;
    let h2 = req_handle.clone();
    vane_req.set(
        "set_method",
        lua.create_function(move |_, m: String| h2.set_method(m))?,
    )?;
    let h3 = req_handle.clone();
    vane_req.set(
        "get_uri",
        lua.create_function(move |_, ()| h3.get_uri())?,
    )?;
    let h4 = req_handle.clone();
    vane_req.set(
        "set_uri",
        lua.create_function(move |_, u: String| h4.set_uri(u))?,
    )?;
    let h5 = req_handle.clone();
    vane_req.set(
        "get_header",
        lua.create_function(move |_, name: String| h5.get_header(&name))?,
    )?;
    let h6 = req_handle.clone();
    vane_req.set(
        "set_header",
        lua.create_function(move |_, (name, val): (String, String)| h6.set_header(name, val))?,
    )?;
    let h7 = req_handle.clone();
    vane_req.set(
        "clear_header",
        lua.create_function(move |_, name: String| h7.clear_header(&name))?,
    )?;
    let h8 = req_handle.clone();
    vane_req.set(
        "get_headers",
        lua.create_function(move |_, ()| h8.get_headers())?,
    )?;
    let h9 = req_handle.clone();
    vane_req.set(
        "get_client_ip",
        lua.create_function(move |_, ()| h9.get_client_ip())?,
    )?;

    vane.set("req", vane_req)?;

    // vane.ctx (UserData facade to Rust-backed RequestSharedContext)
    vane.set("ctx", ctx)?;

    // vane.resp / vane response methods
    let r1 = resp_handle.clone();
    vane.set(
        "status",
        lua.create_function(move |_, code: u16| r1.set_status(code))?,
    )?;
    let r2 = resp_handle.clone();
    let header_tbl = lua.create_table()?;
    let h_mt = lua.create_table()?;
    let r2_clone = r2.clone();
    h_mt.set(
        "__newindex",
        lua.create_function(move |_, (_tbl, k, v): (Value, String, String)| {
            r2_clone.set_header(k, v)
        })?,
    )?;
    header_tbl.set_metatable(Some(h_mt));
    vane.set("header", header_tbl)?;

    let r3 = resp_handle.clone();
    vane.set(
        "say",
        lua.create_function(move |_, content: String| r3.say(content))?,
    )?;

    // vane.exit(status, [body])
    vane.set(
        "exit",
        lua.create_function(|_, (status, body): (u16, Option<String>)| {
            let code = StatusCode::from_u16(status)
                .map_err(|e| mlua::Error::runtime(format!("invalid status code: {e}")))?;
            let bytes = body.map(Bytes::from);
            Err::<(), _>(mlua::Error::external(LuaExitSignal {
                status: code,
                body: bytes,
            }))
        })?,
    )?;

    // vane.now()
    vane.set(
        "now",
        lua.create_function(|_, ()| {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            Ok(now)
        })?,
    )?;

    // vane.sleep(seconds)
    vane.set(
        "sleep",
        lua.create_async_function(|_, seconds: f64| async move {
            tokio::time::sleep(std::time::Duration::from_secs_f64(seconds.max(0.0))).await;
            Ok(())
        })?,
    )?;

    // vane.log(level, msg)
    vane.set(
        "log",
        lua.create_function(|_, (level, msg): (String, String)| {
            match level.to_lowercase().as_str() {
                "error" => error!(target: "vane::lua", "{msg}"),
                "warn" => warn!(target: "vane::lua", "{msg}"),
                "debug" => debug!(target: "vane::lua", "{msg}"),
                _ => info!(target: "vane::lua", "{msg}"),
            }
            Ok(())
        })?,
    )?;

    if let Some(shared) = shared_dict {
        vane.set("shared", shared)?;
    }

    env.set("vane", vane)?;
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lua::pool::LuaVmPool;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_request_handle_and_expiry() {
        let pool = LuaVmPool::new(1, 100_000).unwrap();
        let vm = pool.acquire().await;

        let ctx = LuaRequestContext {
            method: Method::GET,
            uri: "/test?foo=bar".parse().unwrap(),
            headers: HeaderMap::new(),
            client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        };

        let handle = LuaRequestHandle::new(ctx);
        let shared_ctx = RequestSharedContext::default();
        let resp_handle = LuaResponseHandle::default();

        let env = create_request_env(&vm, handle.clone(), shared_ctx, resp_handle, None).unwrap();

        // Check read
        let method: String = vm
            .load("return vane.req.get_method()")
            .set_environment(env.clone())
            .eval()
            .unwrap();
        assert_eq!(method, "GET");

        // Mutate header in Lua
        let _: () = vm
            .load("vane.req.set_header('X-Custom-Auth', 'secret123')")
            .set_environment(env.clone())
            .exec()
            .unwrap();

        // Take ownership back to Rust
        let taken = handle.take().expect("must be able to take");
        assert_eq!(
            taken.headers.get("X-Custom-Auth").unwrap().to_str().unwrap(),
            "secret123"
        );

        // Attempting to access now-expired context must fail safely with our exact error message
        let res: Result<String, mlua::Error> = vm
            .load("return vane.req.get_method()")
            .set_environment(env)
            .eval();
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("attempt to use expired request context"));
    }

    #[tokio::test]
    async fn test_cross_phase_ctx_across_different_vms() {
        let pool = LuaVmPool::new(2, 100_000).unwrap();

        let shared_ctx = RequestSharedContext::default();
        let dummy_ctx = LuaRequestContext {
            method: Method::GET,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };

        // Phase 1: access_by_lua runs on VM #1
        {
            let vm1 = pool.acquire().await;
            let handle1 = LuaRequestHandle::new(dummy_ctx.clone());
            let env1 = create_request_env(
                &vm1,
                handle1,
                shared_ctx.clone(),
                LuaResponseHandle::default(),
                None,
            )
            .unwrap();

            let script = r#"
                vane.ctx.user_id = 999
                vane.ctx.role = "superadmin"
                vane.ctx.tags = {"proxy", "fast"}
            "#;
            vm1.load(script).set_environment(env1).exec().unwrap();
        } // VM1 dropped and returned to pool!

        // Phase 2: header_filter_by_lua runs on VM #2
        {
            let vm2 = pool.acquire().await;
            let handle2 = LuaRequestHandle::new(dummy_ctx.clone());
            let resp_handle2 = LuaResponseHandle::default();
            let env2 = create_request_env(
                &vm2,
                handle2,
                shared_ctx.clone(),
                resp_handle2.clone(),
                None,
            )
            .unwrap();

            let script = r#"
                if vane.ctx.role == "superadmin" and vane.ctx.user_id == 999 then
                    vane.header["X-Admin-Allowed"] = "true"
                    vane.header["X-Tag"] = vane.ctx.tags[1]
                end
            "#;
            vm2.load(script).set_environment(env2).exec().unwrap();

            let mutations = resp_handle2.0.read().unwrap();
            assert_eq!(mutations.set_headers.len(), 2);
            assert_eq!(
                mutations.set_headers[0].1.to_str().unwrap(),
                "true"
            );
            assert_eq!(
                mutations.set_headers[1].1.to_str().unwrap(),
                "proxy"
            );
        }
    }

    #[tokio::test]
    async fn test_vane_exit_signal() {
        let pool = LuaVmPool::new(1, 100_000).unwrap();
        let vm = pool.acquire().await;

        let handle = LuaRequestHandle::new(LuaRequestContext {
            method: Method::GET,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        });
        let env = create_request_env(
            &vm,
            handle,
            RequestSharedContext::default(),
            LuaResponseHandle::default(),
            None,
        )
        .unwrap();

        let script = r#"
            vane.exit(403, "Access Denied by Lua")
            error("This should never run!")
        "#;

        let res: Result<(), mlua::Error> = vm.load(script).set_environment(env).exec();
        assert!(res.is_err());
        let err = res.unwrap_err();
        let signal = extract_exit_signal(&err).expect("must be LuaExitSignal");
        assert_eq!(signal.status, StatusCode::FORBIDDEN);
        assert_eq!(
            signal.body.as_ref().unwrap(),
            &Bytes::from("Access Denied by Lua")
        );
    }

    #[tokio::test]
    async fn test_async_vane_sleep() {
        let pool = LuaVmPool::new(1, 100_000).unwrap();
        let vm = pool.acquire().await;

        let handle = LuaRequestHandle::new(LuaRequestContext {
            method: Method::GET,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        });
        let env = create_request_env(
            &vm,
            handle,
            RequestSharedContext::default(),
            LuaResponseHandle::default(),
            None,
        )
        .unwrap();

        let script = r#"
            vane.sleep(0.01)
            return "slept"
        "#;

        let res: String = vm.load(script).set_environment(env).eval_async().await.unwrap();
        assert_eq!(res, "slept");
    }

    #[tokio::test]
    async fn test_lua_backend_script_execution() {
        let script = include_str!("../../examples/lua/backend.lua");
        let pool = LuaVmPool::new(2, 500_000).unwrap();
        let registry = SharedDictRegistry::new();

        // Helper closure to run a request against the Lua backend
        let execute_request = |uri: &'static str, headers: HeaderMap| {
            let pool = pool.clone();
            let registry = registry.clone();
            async move {
                let vm = pool.acquire().await;
                let req_ctx = LuaRequestContext {
                    method: Method::GET,
                    uri: uri.parse().unwrap(),
                    headers,
                    client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                };
                let handle = LuaRequestHandle::new(req_ctx);
                let resp_handle = LuaResponseHandle::default();
                let env = create_request_env(
                    &vm,
                    handle,
                    RequestSharedContext::default(),
                    resp_handle.clone(),
                    Some(registry),
                )
                .unwrap();

                let res: Result<(), mlua::Error> =
                    vm.load(script).set_environment(env).exec_async().await;
                let mutations = resp_handle.0.read().unwrap().clone();
                (res, mutations)
            }
        };

        // 1. Test GET / -> 200 HTML
        {
            let (res, mutations) = execute_request("/", HeaderMap::new()).await;
            assert!(res.is_ok());
            assert_eq!(mutations.status, Some(StatusCode::OK));
            let body_str = String::from_utf8(mutations.body.unwrap().to_vec()).unwrap();
            assert!(body_str.contains("Welcome to Vane Lua Backend!"));
            assert!(mutations
                .set_headers
                .iter()
                .any(|(k, v)| k.as_str() == "content-type" && v == "text/html; charset=utf-8"));
            assert!(mutations
                .set_headers
                .iter()
                .any(|(k, v)| k.as_str() == "x-powered-by" && v == "Vane-Lua-Core"));
        }

        // 2. Test GET /api/stats -> First call hits = 1
        {
            let (res, mutations) = execute_request("/api/stats", HeaderMap::new()).await;
            assert!(res.is_ok());
            assert_eq!(mutations.status, Some(StatusCode::OK));
            let body_str = String::from_utf8(mutations.body.unwrap().to_vec()).unwrap();
            assert!(body_str.contains("\"total_requests\":1"));
            assert!(body_str.contains("\"client_ip\":\"192.168.1.100\""));
            assert!(mutations
                .set_headers
                .iter()
                .any(|(k, v)| k.as_str() == "x-total-hits" && v == "1"));
        }

        // 3. Test GET /api/stats -> Second call hits = 2 (verifies cross-request shared memory counter)
        {
            let (res, mutations) = execute_request("/api/stats", HeaderMap::new()).await;
            assert!(res.is_ok());
            assert_eq!(mutations.status, Some(StatusCode::OK));
            let body_str = String::from_utf8(mutations.body.unwrap().to_vec()).unwrap();
            assert!(body_str.contains("\"total_requests\":2"));
            assert!(mutations
                .set_headers
                .iter()
                .any(|(k, v)| k.as_str() == "x-total-hits" && v == "2"));
        }

        // 4. Test GET /api/protected without auth -> 401 via vane.exit
        {
            let (res, _) = execute_request("/api/protected", HeaderMap::new()).await;
            assert!(res.is_err());
            let err = res.unwrap_err();
            let signal = extract_exit_signal(&err).expect("must be exit signal");
            assert_eq!(signal.status, StatusCode::UNAUTHORIZED);
            let body = String::from_utf8(signal.body.as_ref().unwrap().to_vec()).unwrap();
            assert!(body.contains("\"error\":\"Unauthorized\""));
        }

        // 5. Test GET /api/protected with valid bearer token -> 200 JSON
        {
            let mut headers = HeaderMap::new();
            headers.insert("Authorization", "Bearer secret-token-42".parse().unwrap());
            let (res, mutations) = execute_request("/api/protected", headers).await;
            assert!(res.is_ok());
            assert_eq!(mutations.status, Some(StatusCode::OK));
            let body_str = String::from_utf8(mutations.body.unwrap().to_vec()).unwrap();
            assert!(body_str.contains("\"status\":\"authenticated\""));
            assert!(mutations
                .set_headers
                .iter()
                .any(|(k, v)| k.as_str() == "x-user-role" && v == "administrator"));
        }

        // 6. Test GET /api/delay -> 200 with async sleep
        {
            let (res, mutations) = execute_request("/api/delay", HeaderMap::new()).await;
            assert!(res.is_ok());
            assert_eq!(mutations.status, Some(StatusCode::OK));
            let body_str = String::from_utf8(mutations.body.unwrap().to_vec()).unwrap();
            assert!(body_str.contains("\"status\":\"delayed\""));
        }

        // 7. Test GET /nonexistent -> 404 via vane.exit
        {
            let (res, _) = execute_request("/nonexistent/endpoint", HeaderMap::new()).await;
            assert!(res.is_err());
            let err = res.unwrap_err();
            let signal = extract_exit_signal(&err).expect("must be exit signal");
            assert_eq!(signal.status, StatusCode::NOT_FOUND);
            let body = String::from_utf8(signal.body.as_ref().unwrap().to_vec()).unwrap();
            assert!(body.contains("\"error\":\"NotFound\""));
        }
    }
}
