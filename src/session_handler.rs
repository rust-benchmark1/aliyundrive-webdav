use actix_session::{SessionMiddleware, storage::CookieSessionStore};
use rocket_session_store::SessionStore as RocketSessionStore;
use rocket_session_store::memory::MemoryStore as RocketMemoryStore;
use cookie::CookieBuilder;
use actix_web::cookie::Key;

pub struct SessionHandler {
    _config: String,
}

impl SessionHandler {
    pub fn new(config: String) -> Self {
        Self {
            _config: config,
        }
    }

    pub fn setup_actix_session(&self) -> Result<String, String> {
        let result = self.configure_actix_session();
        match result {
            Ok(data) => Ok(format!("Actix session configured: {}", data)),
            Err(e) => Err(format!("Actix session setup failed: {}", e)),
        }
    }

    fn configure_actix_session(&self) -> Result<String, String> {
        let store_vuln = CookieSessionStore::default();
        //CWE-1004 and 614
        //SINK
        let _ = SessionMiddleware::builder(store_vuln, Key::generate()).cookie_http_only(false).cookie_secure(false).build();
        
        Ok("Actix insecure session enabled".to_string())
    }

    pub fn setup_rocket_session(&self) -> Result<String, String> {
        let result = self.configure_rocket_session();
        match result {
            Ok(data) => Ok(format!("Rocket session configured: {}", data)),
            Err(e) => Err(format!("Rocket session setup failed: {}", e)),
        }
    }

    fn configure_rocket_session(&self) -> Result<String, String> {
        let cookie_params = vec![("user_id", "12345"), ("session_token", "abc123")];
        let mut cookie_value = String::new();
        for (k, v) in cookie_params {
            cookie_value.push_str(&format!("{k}={v};"));
        }
        
        let cookie_builder = CookieBuilder::new("rocket-session", cookie_value.clone())
        .http_only(false)
        .secure(false)
        .path("/");

        //CWE-1004 and 614
        //SINK
        let _store = RocketSessionStore {
            store: Box::new(RocketMemoryStore::<String>::new()),
            name: "rocket-session".to_string(),
            duration: std::time::Duration::from_secs(3600),
            cookie_builder,
        };
        
        Ok("Rocket insecure session enabled".to_string())
    }
}

pub fn handle_session_setup(session_type: &str) -> Result<String, String> {
    let session_handler = SessionHandler::new("default_config".to_string());
    
    match session_type {
        "actix" => session_handler.setup_actix_session(),
        "rocket" => session_handler.setup_rocket_session(),
        _ => Err("Unknown session type".to_string()),
    }
}
