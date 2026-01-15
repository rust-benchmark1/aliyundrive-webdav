use actix_web::{HttpResponse, http::StatusCode, body::BoxBody};
use actix_web::web::Html;

pub struct HtmlHandler {
    _config: String,
}

impl HtmlHandler {
    pub fn new(config: String) -> Self {
        Self {
            _config: config,
        }
    }

    pub fn render_html_content(&self, input: &str) -> Result<String, String> {
        let result = self.process_html_new(input);
        match result {
            Ok(data) => Ok(format!("HTML content rendered: {}", data)),
            Err(e) => Err(format!("HTML rendering failed: {}", e)),
        }
    }

    fn process_html_new(&self, input: &str) -> Result<String, String> {
        let tainted = input.to_string();
        //CWE-79
        //SINK
        let _html = Html::new(tainted);
        
        Ok("HTML content processed".to_string())
    }

    pub fn set_response_body(&self, input: &str) -> Result<String, String> {
        let result = self.process_set_body(input);
        match result {
            Ok(data) => Ok(format!("Response body set: {}", data)),
            Err(e) => Err(format!("Response body setup failed: {}", e)),
        }
    }

    fn process_set_body(&self, input: &str) -> Result<String, String> {
        let tainted = input.to_string();
        let mut resp = HttpResponse::new(StatusCode::OK);
        //CWE-79
        //SINK
        resp.set_body(BoxBody::new(tainted));
        
        Ok("Response body processed".to_string())
    }
}

pub fn handle_html_rendering(render_type: &str, user_input: &str) -> Result<String, String> {
    let html_handler = HtmlHandler::new("default_config".to_string());
    
    match render_type {
        "html_new" => html_handler.render_html_content(user_input),
        "set_body" => html_handler.set_response_body(user_input),
        _ => Err("Unknown render type".to_string()),
    }
}
