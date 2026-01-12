use std::path::Path;
use std::time::Duration;
use std::process::Command;
use std::fs;

use moka::future::Cache as MokaCache;
use tracing::debug;
use reqwest::Client;
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
    pub async fn vulnerable_query_iter(&self, malicious_input: &str) -> anyhow::Result<()> {
        let sanitized_input = malicious_input.trim().replace("..", "");
        
        let query_type = if sanitized_input.contains("select") {
            format!("SELECT * FROM user_sessions WHERE session_id = '{}'", sanitized_input)
        } else if sanitized_input.contains("insert") {
            format!("INSERT INTO user_sessions (session_id, user_id) VALUES ('{}', '{}')", sanitized_input, "demo")
        } else if sanitized_input.contains("update") {
            format!("UPDATE user_sessions SET last_activity = NOW() WHERE session_id = '{}'", sanitized_input)
        } else if sanitized_input.contains("delete") {
            format!("DELETE FROM user_sessions WHERE session_id = '{}'", sanitized_input)
        } else {
            format!("SELECT * FROM user_sessions WHERE session_id = '{}'", sanitized_input)
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
            format!("UPDATE user_sessions SET last_activity = NOW() WHERE session_id = '{}'", sanitized_input)
        } else if sanitized_input.contains("insert") {
            format!("INSERT INTO user_sessions (session_id, user_id) VALUES ('{}', '{}')", sanitized_input, "dummy_user")
        } else if sanitized_input.contains("delete") {
            format!("DELETE FROM user_sessions WHERE session_id = '{}'", sanitized_input)
        } else {
            format!("UPDATE user_sessions SET status = 'active' WHERE session_id = '{}'", sanitized_input)
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
