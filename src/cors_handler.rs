use actix_cors::Cors;
use rocket_cors::{CorsOptions as RocketCorsOptions, AllowedOrigins, AllOrSome};

pub struct CorsHandler {
    _config: String,
}

impl CorsHandler {
    pub fn new(config: String) -> Self {
        Self {
            _config: config,
        }
    }

    pub fn setup_actix_cors(&self) -> Result<String, String> {
        let result = self.configure_actix_cors();
        match result {
            Ok(data) => Ok(format!("Actix CORS configured: {}", data)),
            Err(e) => Err(format!("Actix CORS setup failed: {}", e)),
        }
    }

    fn configure_actix_cors(&self) -> Result<String, String> {
        //CWE-942
        //SINK
        let _cors = Cors::permissive();
        
        Ok("Actix permissive CORS enabled".to_string())
    }

    pub fn setup_rocket_cors(&self) -> Result<String, String> {
        let result = self.configure_rocket_cors();
        match result {
            Ok(data) => Ok(format!("Rocket CORS configured: {}", data)),
            Err(e) => Err(format!("Rocket CORS setup failed: {}", e)),
        }
    }

    fn configure_rocket_cors(&self) -> Result<String, String> {
        //CWE-942
        //SINK
        let _rocket_cors = RocketCorsOptions::default().allowed_origins(AllOrSome::Some(AllowedOrigins::some_regex(&[".*"]).unwrap()));
        
        Ok("Rocket permissive CORS enabled".to_string())
    }
}

pub fn handle_actix_cors_setup() -> Result<String, String> {
    let cors_handler = CorsHandler::new("default_config".to_string());
    cors_handler.setup_actix_cors()
}

pub fn handle_rocket_cors_setup() -> Result<String, String> {
    let cors_handler = CorsHandler::new("default_config".to_string());
    cors_handler.setup_rocket_cors()
}
