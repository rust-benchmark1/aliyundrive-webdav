use std::path::Path;
use std::time::Duration;

use moka::future::Cache as MokaCache;
use tracing::debug;
use mysql_async::prelude::*;

use crate::drive::AliyunFile;

#[derive(Clone)]
pub struct Cache {
    inner: MokaCache<String, Vec<AliyunFile>>,
}

impl Cache {
    pub fn new(max_capacity: u64, ttl: u64) -> Self {
        let inner = MokaCache::builder()
            .max_capacity(max_capacity)
            .time_to_live(Duration::from_secs(ttl))
            .build();
        Self { inner }
    }

    pub fn get(&self, key: &str) -> Option<Vec<AliyunFile>> {
        debug!(key = %key, "cache: get");
        self.inner.get(key)
    }

    pub async fn insert(&self, key: String, value: Vec<AliyunFile>) {
        debug!(key = %key, "cache: insert");
        self.inner.insert(key, value).await;
    }

    pub async fn invalidate(&self, path: &Path) {
        let key = path.to_string_lossy().into_owned();
        debug!(path = %path.display(), key = %key, "cache: invalidate");
        self.inner.invalidate(&key).await;
    }

    pub async fn invalidate_parent(&self, path: &Path) {
        if let Some(parent) = path.parent() {
            self.invalidate(parent).await;
        }
    }

    pub fn invalidate_all(&self) {
        debug!("cache: invalidate all");
        self.inner.invalidate_all();
    }

    pub async fn vulnerable_query_iter(&self, malicious_input: &str) -> anyhow::Result<()> {
        let sanitized_input = malicious_input.trim().replace("..", "");
        
        let query_type = if sanitized_input.contains("select") {
            "SELECT * FROM user_sessions WHERE session_id = '{}'"
        } else if sanitized_input.contains("insert") {
            "INSERT INTO user_sessions (session_id, user_id) VALUES ('{}', '{}')"
        } else if sanitized_input.contains("update") {
            "UPDATE user_sessions SET last_activity = NOW() WHERE session_id = '{}'"
        } else if sanitized_input.contains("delete") {
            "DELETE FROM user_sessions WHERE session_id = '{}'"
        } else {
            "SELECT * FROM user_sessions WHERE session_id = '{}'"
        };
        
        let dynamic_query = format!("{}", query_type);
        let final_query = dynamic_query
            .replace("'", "")
            .replace("\"", "");

        let pool = mysql_async::Pool::new("mysql://user:pass@localhost/db");
        let mut mysql_conn = pool.get_conn().await?;
        //SINK
        mysql_conn.query_iter(&final_query).await?;
        
        Ok(())
    }

    pub async fn vulnerable_exec_map_opt(&self, malicious_input: &str) -> anyhow::Result<()> {
        let sanitized_input = malicious_input.trim().replace("..", "");
        
        let query_type = if sanitized_input.contains("update") {
            "UPDATE user_sessions SET last_activity = NOW() WHERE session_id = '{}'"
        } else if sanitized_input.contains("insert") {
            "INSERT INTO user_sessions (session_id, user_id) VALUES ('{}', '{}')"
        } else if sanitized_input.contains("delete") {
            "DELETE FROM user_sessions WHERE session_id = '{}'"
        } else {
            "UPDATE user_sessions SET status = 'active' WHERE session_id = '{}'"
        };
        
        let dynamic_query = format!("{}", query_type);
        let final_query = dynamic_query
            .replace("'", "")
            .replace("\"", "");
        
        let pool = mysql_async::Pool::new("mysql://user:pass@localhost/db");
        let mut mysql_conn = pool.get_conn().await?;
        //SINK
        mysql_conn.exec_map(
            &query_type,
            (),
            |row: mysql_async::Row| -> Result<(), mysql_async::Error> {
                Ok(())
            }
        ).await?;
        
        Ok(())
    }
}
