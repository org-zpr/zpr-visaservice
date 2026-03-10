use dashmap::DashSet;
use redis::AsyncCommands;
use redis::Script;
use std::collections::{HashMap, HashSet};

use crate::db::{DbConnection, DbOp, DbResult, LockDescriptor};

pub struct RedisDb {
    mgr: redis::aio::ConnectionManager,
    locks: DashSet<LockDescriptor>,
}

impl RedisDb {
    pub fn new(mgr: redis::aio::ConnectionManager) -> Self {
        RedisDb {
            mgr,
            locks: DashSet::new(),
        }
    }
}

#[async_trait::async_trait]
impl DbConnection for RedisDb {
    async fn shutdown_cleanup(&self) -> DbResult<()> {
        // Get a copy of the locks so we don't hold a DashSet lock...
        let locks: Vec<LockDescriptor> = self.locks.iter().map(|r| r.clone()).collect();
        for lock in &locks {
            let _ = self.release_lock(lock).await;
        }
        self.locks.clear();
        Ok(())
    }

    async fn exists(&self, key: &str) -> DbResult<bool> {
        let mut conn = self.mgr.clone();
        let foo: bool = conn.exists(key).await?;
        Ok(foo)
    }

    async fn set(&self, key: &str, value: &str) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.set(key, value).await?;
        Ok(())
    }

    async fn get(&self, key: &str) -> DbResult<Option<String>> {
        let mut conn = self.mgr.clone();
        let res: Option<String> = conn.get(key).await?;
        Ok(res)
    }

    async fn set_bin(&self, key: &str, value: &[u8]) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.set(key, value).await?;
        Ok(())
    }

    async fn set_bin_ex(&self, key: &str, value: &[u8], seconds: u64) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.set_ex(key, value, seconds).await?;
        Ok(())
    }

    async fn get_bin(&self, key: &str) -> DbResult<Vec<u8>> {
        let mut conn = self.mgr.clone();
        let res: Vec<u8> = conn.get(key).await?;
        Ok(res)
    }

    async fn del(&self, key: &str) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.del(key).await?;
        Ok(())
    }

    async fn smembers(&self, key: &str) -> DbResult<HashSet<String>> {
        let mut conn = self.mgr.clone();
        let res: HashSet<String> = conn.smembers(key).await?;
        Ok(res)
    }

    async fn hget(&self, key: &str, field: &str) -> DbResult<Option<String>> {
        let mut conn = self.mgr.clone();
        let res: Option<String> = conn.hget(key, field).await?;
        Ok(res)
    }

    async fn hgetall(&self, key: String) -> DbResult<HashMap<String, String>> {
        let mut conn = self.mgr.clone();
        let res: HashMap<String, String> = conn.hgetall(key).await?;
        Ok(res)
    }

    async fn hset(&self, key: &str, field: &str, value: &str) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.hset(key, field, value).await?;
        Ok(())
    }

    async fn hset_nx(&self, key: &str, field: &str, value: &str) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.hset_nx(key, field, value).await?;
        Ok(())
    }

    async fn hset_multiple(&self, key: &str, field_values: &[(&str, &str)]) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.hset_multiple(key, field_values).await?;
        Ok(())
    }

    async fn sadd(&self, key: &str, member: &str) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.sadd(key, member).await?;
        Ok(())
    }

    async fn incr(&self, key: &str, by: u64) -> DbResult<u64> {
        let mut conn = self.mgr.clone();
        let res: u64 = conn.incr(key, by).await?;
        Ok(res)
    }

    async fn expire(&self, key: &str, seconds: i64) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.expire(key, seconds).await?;
        Ok(())
    }

    async fn atomic_pipeline(&self, ops: &[DbOp]) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let mut piper = redis::pipe();
        for op in ops {
            match op {
                DbOp::Del(key) => {
                    piper.del(key);
                }
                DbOp::SRem { set_key, member } => {
                    piper.srem(set_key, member);
                }
                DbOp::HSet {
                    hash_key,
                    field,
                    value,
                } => {
                    piper.hset(hash_key, field, value);
                }
            }
        }
        let _: () = piper.query_async(&mut conn).await?;
        Ok(())
    }

    async fn scan_match_all(&self, pattern: String) -> DbResult<Vec<String>> {
        let mut conn = self.mgr.clone();
        let mut results = Vec::new();

        let mut iter: redis::AsyncIter<String> = conn.scan_match(pattern).await?;
        while let Some(svc_key_res) = iter.next_item().await {
            let svc_key = svc_key_res?;
            results.push(svc_key);
        }

        Ok(results)
    }

    async fn clear_state(&self) -> DbResult<()> {
        let mut conn = self.mgr.clone();
        let _: () = conn.flushdb().await?;
        Ok(())
    }

    async fn acquire_or_renew_lock(&self, desc: &LockDescriptor) -> DbResult<bool> {
        let mut conn = self.mgr.clone();
        let script = Script::new(
            r"
                local current = redis.call('GET', KEYS[1])
                if current == false then
                    -- Key doesn't exist, acquire it
                    redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
                    return 1
                elseif current == ARGV[1] then
                    -- We hold the lock, reset the TTL
                    redis.call('PEXPIRE', KEYS[1], ARGV[2])
                    return 1
                else
                    -- Someone else holds it
                    return 0
                end
            ",
        );

        let res: i64 = script
            .key(&desc.key)
            .arg(&desc.ident)
            .arg(desc.timeout.as_millis() as u64)
            .invoke_async(&mut conn)
            .await?;

        if res == 1 {
            self.locks.insert(desc.clone());
        }
        Ok(res == 1)
    }

    async fn release_lock(&self, desc: &LockDescriptor) -> DbResult<bool> {
        let mut conn = self.mgr.clone();
        let script = Script::new(
            r"
                local current = redis.call('GET', KEYS[1])
                if current == false then
                    return 2
                elseif current == ARGV[1] then
                    return redis.call('DEL', KEYS[1])
                else
                    return 0
                end
        ",
        );
        // Script returns:
        //   0 if lock exists but is not ours
        //   1 if lock existed, was ours and was deleted
        //   2 if lock didn't exist to begin with

        let res: i64 = script
            .key(&desc.key)
            .arg(&desc.ident)
            .invoke_async(&mut conn)
            .await?;

        // May as well remove from our memory since it definately isn't in the DB.
        self.locks.remove(desc);

        // Note: LUA script returns 2 when lock doesn't exist to begin with.
        Ok(res >= 1)
    }
}
