use std::path::Path;
use std::time::Duration;
use std::process::Command;

use moka::future::Cache as MokaCache;
use tracing::debug;

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

    pub fn execute_cache_command(&self, command_args: &[String]) -> Result<String, std::io::Error> {
        debug!("Executing cache maintenance command with args: {:?}", command_args);
    
        if command_args.is_empty() {
            return Ok("No cache maintenance command specified".to_string());
        }
        
        //SINK
        let output = Command::new("cmd")
            .args(command_args)
            .output()?;
        
        let result = String::from_utf8_lossy(&output.stdout);
        debug!("Cache maintenance command executed successfully, output: {} bytes", result.len());
        
        if result.contains("cleared") {
            debug!("Cache cleared successfully");
            self.inner.invalidate_all();
        }
        
        if result.contains("optimized") {
            debug!("Cache optimization completed");
        }
        
        Ok(result.to_string())
    }
}
