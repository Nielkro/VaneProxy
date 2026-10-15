use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use mlua::{MetaMethod, UserData, UserDataMethods, Value};

use super::context::LuaCtxValue;

/// Thread-safe in-memory key-value dictionary shared across all requests and VM instances.
#[derive(Clone, Default)]
pub struct SharedDict(pub Arc<RwLock<HashMap<String, LuaCtxValue>>>);

impl SharedDict {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }

    pub fn get(&self, key: &str) -> Option<LuaCtxValue> {
        self.0.read().ok()?.get(key).cloned()
    }

    pub fn set(&self, key: String, val: LuaCtxValue) {
        if let Ok(mut guard) = self.0.write() {
            guard.insert(key, val);
        }
    }

    pub fn delete(&self, key: &str) {
        if let Ok(mut guard) = self.0.write() {
            guard.remove(key);
        }
    }

    pub fn incr(&self, key: String, delta: i64) -> Result<i64, mlua::Error> {
        let mut guard = self
            .0
            .write()
            .map_err(|_| mlua::Error::runtime("poisoned lock"))?;
        let entry = guard.entry(key).or_insert(LuaCtxValue::Integer(0));
        match entry {
            LuaCtxValue::Integer(ref mut val) => {
                *val += delta;
                Ok(*val)
            }
            _ => Err(mlua::Error::runtime(
                "shared dict key holds non-integer value for incr",
            )),
        }
    }
}

impl UserData for SharedDict {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("get", |lua, this, key: String| {
            if let Some(val) = this.get(&key) {
                val.to_lua_value(lua)
            } else {
                Ok(Value::Nil)
            }
        });

        methods.add_method("set", |_lua, this, (key, val): (String, Value)| {
            let ctx_val = LuaCtxValue::from_lua_value(val)?;
            this.set(key, ctx_val);
            Ok(())
        });

        methods.add_method("delete", |_lua, this, key: String| {
            this.delete(&key);
            Ok(())
        });

        methods.add_method("incr", |_lua, this, (key, delta): (String, Option<i64>)| {
            this.incr(key, delta.unwrap_or(1))
        });
    }
}

/// Registry of named shared dictionaries (`vane.shared.<NAME>`).
#[derive(Clone, Default)]
pub struct SharedDictRegistry(pub Arc<RwLock<HashMap<String, SharedDict>>>);

impl SharedDictRegistry {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }

    pub fn get_or_create(&self, name: &str) -> SharedDict {
        let mut guard = self.0.write().expect("shared dict lock poisoned");
        guard
            .entry(name.to_string())
            .or_insert_with(SharedDict::new)
            .clone()
    }
}

impl UserData for SharedDictRegistry {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_meta_method(MetaMethod::Index, |_lua, this, key: String| {
            Ok(this.get_or_create(&key))
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lua::context::{create_request_env, LuaRequestContext, LuaRequestHandle, LuaResponseHandle, RequestSharedContext};
    use crate::lua::pool::LuaVmPool;
    use hyper::header::HeaderMap;
    use hyper::Method;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_shared_dict_cross_vm() {
        let pool = LuaVmPool::new(2, 100_000).unwrap();
        let registry = SharedDictRegistry::new();

        let req_ctx = LuaRequestContext {
            method: Method::GET,
            uri: "/".parse().unwrap(),
            headers: HeaderMap::new(),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        };

        // VM #1 sets and incrs in shared dict
        {
            let vm1 = pool.acquire().await;
            let env1 = create_request_env(
                &vm1,
                LuaRequestHandle::new(req_ctx.clone()),
                RequestSharedContext::default(),
                LuaResponseHandle::default(),
                Some(registry.clone()),
            )
            .unwrap();

            let script = r#"
                local cache = vane.shared.RATE_LIMIT
                cache:set("hits", 10)
                cache:incr("hits", 5)
            "#;
            vm1.load(script).set_environment(env1).exec().unwrap();
        }

        // VM #2 reads and increments further
        {
            let vm2 = pool.acquire().await;
            let env2 = create_request_env(
                &vm2,
                LuaRequestHandle::new(req_ctx.clone()),
                RequestSharedContext::default(),
                LuaResponseHandle::default(),
                Some(registry.clone()),
            )
            .unwrap();

            let script = r#"
                local cache = vane.shared.RATE_LIMIT
                local hits = cache:get("hits")
                local next_val = cache:incr("hits", 1)
                return hits, next_val
            "#;
            let (hits, next_val): (i64, i64) = vm2.load(script).set_environment(env2).eval().unwrap();
            assert_eq!(hits, 15);
            assert_eq!(next_val, 16);
        }
    }
}
