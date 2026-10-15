use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use crossbeam_queue::ArrayQueue;
use mlua::{HookTriggers, Lua, StdLib};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

struct VmEntry {
    lua: Lua,
    instruction_count: Arc<std::sync::atomic::AtomicU64>,
}

/// Wrapper around a pooled `Lua` instance with RAII return to queue.
pub struct PooledLuaVm {
    entry: Option<VmEntry>,
    _permit: Option<OwnedSemaphorePermit>,
    pool: Arc<ArrayQueue<VmEntry>>,
}

impl Deref for PooledLuaVm {
    type Target = Lua;

    fn deref(&self) -> &Self::Target {
        &self.entry.as_ref().expect("VM not dropped").lua
    }
}

impl DerefMut for PooledLuaVm {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entry.as_mut().expect("VM not dropped").lua
    }
}

impl Drop for PooledLuaVm {
    fn drop(&mut self) {
        // 1. Return the VM entry back to the lock-free queue first.
        if let Some(entry) = self.entry.take() {
            let _ = self.pool.push(entry);
        }
        // 2. Drop the permit afterwards so any waiting task immediately finds the VM in the queue.
        drop(self._permit.take());
    }
}

/// Asynchronous pool of isolated, sanitized Lua VMs.
#[derive(Clone)]
pub struct LuaVmPool {
    semaphore: Arc<Semaphore>,
    vms: Arc<ArrayQueue<VmEntry>>,
    capacity: usize,
    max_instructions: u64,
}

impl LuaVmPool {
    /// Creates a new Lua VM pool with the specified capacity and instruction limit.
    pub fn new(capacity: usize, max_instructions: u64) -> Result<Self, mlua::Error> {
        let capacity = capacity.max(1);
        let queue = Arc::new(ArrayQueue::new(capacity));

        for _ in 0..capacity {
            let (vm, counter) = Self::create_sanitized_vm(max_instructions)?;
            let _ = queue.push(VmEntry {
                lua: vm,
                instruction_count: counter,
            });
        }

        Ok(Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
            vms: queue,
            capacity,
            max_instructions,
        })
    }

    /// Acquires a free Lua VM asynchronously without blocking Tokio runtime worker threads.
    pub async fn acquire(&self) -> PooledLuaVm {
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("Lua pool semaphore closed unexpectedly");

        let entry = self
            .vms
            .pop()
            .expect("Semaphore guarantees available VM in pool");

        // Reset instruction counter for the new phase / request
        entry
            .instruction_count
            .store(0, std::sync::atomic::Ordering::Relaxed);

        PooledLuaVm {
            entry: Some(entry),
            _permit: Some(permit),
            pool: self.vms.clone(),
        }
    }

    /// Returns pool capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of currently idle VMs available in queue.
    pub fn available(&self) -> usize {
        self.vms.len()
    }

    /// Returns configured instruction limit per VM execution.
    pub fn max_instructions(&self) -> u64 {
        self.max_instructions
    }

    /// Creates and sandboxes a new Lua VM instance.
    fn create_sanitized_vm(
        max_instructions: u64,
    ) -> Result<(Lua, Arc<std::sync::atomic::AtomicU64>), mlua::Error> {
        // Allow safe standard libraries only (table, string, math, bit, jit).
        // Exclude io, os, package, debug, and ffi.
        let safe_libs = StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::BIT | StdLib::JIT;

        let lua = Lua::new_with(safe_libs, mlua::LuaOptions::default())?;

        // Disable JIT compiler traces so count and line hooks are reliably checked on loops.
        // The LuaJIT interpreter itself is written in hand-optimized x86_64 assembly and remains extremely fast.
        let _: () = lua.load("if jit then jit.off() end").exec()?;

        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));

        // Setup instruction hook to guard against infinite loops and heavy compute.
        if max_instructions > 0 {
            let count = counter.clone();
            lua.set_hook(
                HookTriggers::default().every_nth_instruction(10_000),
                move |_lua, _debug| {
                    if count.fetch_add(10_000, std::sync::atomic::Ordering::Relaxed)
                        >= max_instructions
                    {
                        Err(mlua::Error::runtime("instruction limit exceeded (timeout)"))
                    } else {
                        Ok(mlua::VmState::Continue)
                    }
                },
            );
        }

        Ok((lua, counter))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pool_acquire_and_release() {
        let pool = LuaVmPool::new(2, 100_000).expect("failed to create pool");
        assert_eq!(pool.available(), 2);

        {
            let vm1 = pool.acquire().await;
            assert_eq!(pool.available(), 1);

            let res: i32 = vm1.load("return 20 + 22").eval().unwrap();
            assert_eq!(res, 42);

            {
                let vm2 = pool.acquire().await;
                assert_eq!(pool.available(), 0);
                let s: String = vm2.load("return string.upper('vane')").eval().unwrap();
                assert_eq!(s, "VANE");
            }

            assert_eq!(pool.available(), 1);
        }

        assert_eq!(pool.available(), 2);
    }

    #[tokio::test]
    async fn test_sandbox_excludes_io_and_os() {
        let pool = LuaVmPool::new(1, 100_000).expect("failed to create pool");
        let vm = pool.acquire().await;

        let io_val: mlua::Value = vm.load("return io").eval().unwrap();
        assert!(matches!(io_val, mlua::Value::Nil));

        let os_val: mlua::Value = vm.load("return os").eval().unwrap();
        assert!(matches!(os_val, mlua::Value::Nil));
    }

    #[tokio::test]
    async fn test_instruction_limit_infinite_loop() {
        let pool = LuaVmPool::new(1, 50_000).expect("failed to create pool");
        let vm = pool.acquire().await;

        let res: Result<(), mlua::Error> = vm.load("while true do end").exec();
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("instruction limit exceeded"), "Unexpected error: {err_msg}");
    }

    #[tokio::test]
    async fn test_instruction_counter_resets_on_acquire() {
        let pool = LuaVmPool::new(1, 50_000).expect("failed to create pool");
        
        // Run first execution that takes ~20_000 instructions
        {
            let vm = pool.acquire().await;
            let _: () = vm.load("local x = 0; for i = 1, 10000 do x = x + 1 end").exec().unwrap();
        }

        // Run second execution on the same pooled VM: if counter didn't reset, 20_000 + 20_000 + 20_000 would breach 50_000
        {
            let vm = pool.acquire().await;
            let _: () = vm.load("local x = 0; for i = 1, 10000 do x = x + 1 end").exec().unwrap();
        }

        {
            let vm = pool.acquire().await;
            let _: () = vm.load("local x = 0; for i = 1, 10000 do x = x + 1 end").exec().unwrap();
        }
    }
}
