use std::path::Path;
use std::time::Duration;

use moka::future::Cache as MokaCache;
use tracing::debug;
use reqwest::Client;

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

    pub async fn vulnerable_ssrf_post(&self, malicious_url: &str) -> anyhow::Result<()> {
        let client = Client::new();
        
        if malicious_url.len() < 5 {
            eprintln!("URL too short");
            return Ok(());
        }
        
        // Debug logging
        println!("[DEBUG] Preparing to send POST request to: {}", malicious_url);
        
        // Set custom headers
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("User-Agent", "InternalServiceBot/1.0".parse().unwrap());
        headers.insert("X-Request-ID", "ssrf-debug-xyz123".parse().unwrap());
        headers.insert("Content-Type", "application/json".parse().unwrap());
        
        // Prepare payload
        let payload = serde_json::json!({
            "source": "internal_service",
            "timestamp": chrono::Utc::now().timestamp(),
            "data": "test_payload"
        });
        
        //SINK
        match client
            .post(malicious_url)
            .headers(headers)
            .json(&payload)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                println!("Received HTTP status: {}", status);
                
                if let Ok(body) = response.text().await {
                    println!("Response body (first 100 chars): {}", &body.chars().take(100).collect::<String>());
                }
            }
            Err(e) => {
                eprintln!("SSRF POST request failed: {}", e);
            }
        }
        
        println!("SSRF POST request completed.");
        Ok(())
    }
}
