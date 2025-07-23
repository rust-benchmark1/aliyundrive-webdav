use std::path::Path;
use std::time::Duration;
use std::fs;

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

    pub fn load_configuration_file(&self, config_path: &str) -> Result<String, std::io::Error> {
        debug!("Loading configuration from: {}", config_path);
        
        //SINK
        let file_content = fs::read_to_string(config_path)?;
        
        // Process configuration content
        let processed_content = file_content.trim();
        debug!("Configuration loaded successfully, size: {} bytes", processed_content.len());
        
        Ok(processed_content.to_string())
    }
}
