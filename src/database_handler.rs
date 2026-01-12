use surrealdb::{Surreal, engine::remote::ws::Ws};
use mongodb::{Client, Collection, bson::{Document, Bson, doc}};
use serde_json;

pub struct DatabaseHandler {
    _connection_pool: String,
}

impl DatabaseHandler {
    pub fn new(connection_pool: String) -> Self {
        Self {
            _connection_pool: connection_pool,
        }
    }

    pub async fn query_user_data(&self, query: &str) -> Result<String, String> {
        let result = self.execute_surreal_user_query(query).await;
        match result {
            Ok(data) => Ok(format!("User data retrieved: {}", data)),
            Err(e) => Err(format!("Query failed: {}", e)),
        }
    }

    async fn execute_surreal_user_query(&self, query: &str) -> Result<String, String> {
        let q_c_raw = query.replace("'", "");
        
        let db = Surreal::new::<Ws>("127.0.0.1:8002").await.unwrap();
        
        //CWE-943
        //SINK
        let _ = db.query(&q_c_raw).await.unwrap();
        
        Ok(format!("Executed query: {}", q_c_raw))
    }

    pub async fn search_documents(&self, search_term: &str) -> Result<String, String> {
        let result = self.execute_mongo_search(search_term).await;
        match result {
            Ok(data) => Ok(format!("Documents found: {}", data)),
            Err(e) => Err(format!("Search failed: {}", e)),
        }
    }

    async fn execute_mongo_search(&self, search_term: &str) -> Result<String, String> {
        // Construct filter with user input
        let unsafe_json_filter = search_term.replace("'", "");
        
        let client = Client::with_uri_str("mongodb://127.0.0.1:27017").await.unwrap();
        let db = client.database("example_db");
        let coll: Collection<Document> = db.collection("users");
        
        let filter_doc: Document = match serde_json::from_str::<serde_json::Value>(&unsafe_json_filter) {
            Ok(val) => match bson::to_bson(&val).unwrap() {
                Bson::Document(d) => d,
                other => doc! { "$expr": other },
            },
            Err(_) => {
                doc! { "$where": unsafe_json_filter.clone() }
            }
        };
        
        //CWE-943
        //SINK
        let _ = coll.count_documents(filter_doc, None).await.unwrap();
        
        Ok(format!("Executed filter: {}", unsafe_json_filter))
    }
}

pub async fn handle_database_query(query_type: &str, user_input: &str) -> Result<String, String> {
    let db_handler = DatabaseHandler::new("main_pool".to_string());
    
    match query_type {
        "user_query" => db_handler.query_user_data(user_input).await,
        "document_search" => db_handler.search_documents(user_input).await,
        _ => Err("Unknown query type".to_string()),
    }
}
