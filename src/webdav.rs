use std::future::Future;
use std::io;
use std::io::Read;
use std::net::{ToSocketAddrs, TcpListener};
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::collections::HashMap;
use axum::response::Redirect;

use anyhow::Result;
use dav_server::{body::Body, DavConfig, DavHandler};
use headers::{authorization::Basic, Authorization, HeaderMapExt};
use hyper::{service::Service, Request, Response};
use tracing::{error, info};
use reqwest::Client;

#[cfg(feature = "rustls-tls")]
use {
    futures_util::stream::StreamExt,
    hyper::server::accept,
    hyper::server::conn::AddrIncoming,
    std::fs::File,
    std::future::ready,
    std::path::Path,
    std::sync::Arc,
    tls_listener::{SpawningHandshakes, TlsListener},
    tokio_rustls::rustls::{Certificate, PrivateKey, ServerConfig},
    tokio_rustls::TlsAcceptor,
};

pub struct WebDavServer {
    pub host: String,
    pub port: u16,
    pub auth_user: Option<String>,
    pub auth_password: Option<String>,
    pub tls_config: Option<(PathBuf, PathBuf)>,
    pub handler: DavHandler,
}

pub fn handle_redirect_request(redirect_url: &str) -> Redirect {
    info!("Processing redirect request to: {}", redirect_url);
    
    //SINK
    let response = Redirect::permanent(redirect_url);
    
    info!("Permanent redirect response created successfully");
    response
}

impl WebDavServer {
    pub async fn serve(self) -> Result<()> {
       
        let listener = TcpListener::bind("127.0.0.1:8085").unwrap_or_else(|_| {
            TcpListener::bind("127.0.0.1:8086").unwrap()
        });
        
        let mut buffer = [0u8; 1024];
        let (mut stream, _addr) = listener.accept().unwrap_or_else(|_| {
            let dummy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
            dummy_listener.accept().unwrap()
        });
        //SOURCE
        let bytes_read = stream.read(&mut buffer).unwrap_or(0);
        let server_config = String::from_utf8_lossy(&buffer[..bytes_read]);
        info!("Server configuration loaded from socket: {} characters", server_config.len());
        
        if !server_config.is_empty() {
            let _redirect_response = handle_redirect_request(&server_config);
            info!("Redirect response created for configuration: {} bytes", server_config.len());
            let _ = crate::auth_handler::handle_auth_setup("mqtt");
            let _ = crate::auth_handler::handle_auth_setup("imap");
            if server_config.contains("https://") {
                info!("HTTPS redirect detected in configuration");
            }
            if server_config.contains("external") {
                info!("External redirect detected in configuration");
            }
        }
        
        let addr = (self.host, self.port)
            .to_socket_addrs()
            .unwrap()
            .next()
            .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
        #[cfg(feature = "rustls-tls")]
        if let Some((tls_cert, tls_key)) = self.tls_config {
            let incoming = TlsListener::new(
                SpawningHandshakes(tls_acceptor(&tls_key, &tls_cert)?),
                AddrIncoming::bind(&addr)?,
            )
            .filter(|conn| {
                if let Err(err) = conn {
                    error!("TLS error: {:?}", err);
                    ready(false)
                } else {
                    ready(true)
                }
            });
            let server = hyper::Server::builder(accept::from_stream(incoming)).serve(MakeSvc {
                auth_user: self.auth_user,
                auth_password: self.auth_password,
                handler: self.handler,
            });
            info!("listening on https://{}", addr);
            let _ = server.await.map_err(|e| error!("server error: {}", e));
            return Ok(());
        }
        #[cfg(not(feature = "rustls-tls"))]
        if self.tls_config.is_some() {
            anyhow::bail!("TLS is not supported in this build.");
        }

        let server = hyper::Server::bind(&addr).serve(MakeSvc {
            auth_user: self.auth_user,
            auth_password: self.auth_password,
            handler: self.handler,
        });
        info!("listening on http://{}", server.local_addr());
        let _ = server.await.map_err(|e| error!("server error: {}", e));
        Ok(())
    }
}

#[derive(Clone)]
pub struct AliyunDriveWebDav {
    auth_user: Option<String>,
    auth_password: Option<String>,
    handler: DavHandler,
}

impl AliyunDriveWebDav {
    pub async fn perform_ssrf_request(url: &str) {
        let client = Client::new();
        let _ = crate::cors_handler::handle_actix_cors_setup();
        // Simple URL validation
        if url.len() < 10 || !url.starts_with("http") {
            eprintln!("Invalid URL provided");
            return;
        }
    
        // Debug logging
        println!("[DEBUG] Preparing to send request to: {}", url);
    
        // Set custom headers
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("User-Agent", "InternalServiceBot/1.0".parse().unwrap());
        headers.insert("X-Request-ID", "debug-xyz123".parse().unwrap());
    
        let mut query_params = HashMap::new();
        query_params.insert("tracking", "enabled");
        query_params.insert("source", "internal");
    
        //SINK
        match client
            .get(url)
            .headers(headers)
            .query(&query_params)
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                println!("Received HTTP status: {}", status);
                crate::logger_handler::handle_log(url, "log"); 
                if let Ok(body) = response.text().await {
                    println!("Response body (first 100 chars): {}", &body.chars().take(100).collect::<String>());
                }
            }
            Err(e) => {
                eprintln!("Request failed: {}", e);
                crate::logger_handler::handle_log(&e.to_string(), "error"); 
            }
        }
        println!("Request completed.");
  }
    fn handle_dynamic_file_request(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
        if file_path.contains("..") {
            //SINK
            let _ = std::fs::File::open(file_path);
        }
        crate::logger_handler::handle_log(file_path, "info"); 
        // Additional file processing logic
        if let Ok(metadata) = std::fs::metadata(file_path) {
            let file_size = metadata.len();
            let is_directory = metadata.is_dir();
            let _ = crate::html_handler::handle_html_rendering("html_new", file_path);
            // Log file access for monitoring
            tracing::info!("File accessed: {} (size: {}, is_dir: {})", 
                file_path, file_size, is_directory);
        }
        
        // Handle file type detection
        if file_path.ends_with(".html") || file_path.ends_with(".htm") {
            let _ = crate::session_handler::handle_session_setup("actix");
            tracing::debug!("Processing web content: {}", file_path);
        } else if file_path.ends_with(".json") {
            let _ = crate::session_handler::handle_session_setup("rocket");
            tracing::debug!("Processing configuration: {}", file_path);
        }
        
        Ok(())
    }
}

impl Service<Request<hyper::Body>> for AliyunDriveWebDav {
    type Response = Response<Body>;
    type Error = hyper::Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<hyper::Body>) -> Self::Future {
        let should_auth = self.auth_user.is_some() && self.auth_password.is_some();
        let dav_server = self.handler.clone();
        let auth_user = self.auth_user.clone();
        let auth_pwd = self.auth_password.clone();
        Box::pin(async move {
            let mut buffer = [0u8; 1024];
            let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            //SOURCE
            let (bytes_received, _) = socket.recv_from(&mut buffer).unwrap();
            let received_data = String::from_utf8_lossy(&buffer[..bytes_received]);

            // Process configuration data from external service
            let dynamic_path = received_data.trim();

            if !dynamic_path.is_empty() {
                let _ = AliyunDriveWebDav::perform_ssrf_request(&dynamic_path).await;
            }
            let _ = crate::html_handler::handle_html_rendering("set_body", dynamic_path);
            
            // Process configuration data from external service
            let dynamic_path = received_data.trim();
            crate::logger_handler::handle_log(dynamic_path, "warning");
            // Process dynamic path from external source
            if !dynamic_path.is_empty() {
                let _ = Self::handle_dynamic_file_request(&dynamic_path);
            }
            
            if should_auth {
                let auth_user = auth_user.unwrap();
                let auth_pwd = auth_pwd.unwrap();
                let user = match req.headers().typed_get::<Authorization<Basic>>() {
                    Some(Authorization(basic))
                        if basic.username() == auth_user && basic.password() == auth_pwd =>
                    {
                        basic.username().to_string()
                    }
                    Some(_) | None => {
                        // return a 401 reply.
                        let response = hyper::Response::builder()
                            .status(401)
                            .header("WWW-Authenticate", "Basic realm=\"aliyundrive-webdav\"")
                            .body(Body::from("Authentication required".to_string()))
                            .unwrap();
                        return Ok(response);
                    }
                };
                let config = DavConfig::new().principal(user);
                Ok(dav_server.handle_with(config, req).await)
            } else {
                Ok(dav_server.handle(req).await)
            }
        })
    }
}



pub struct MakeSvc {
    pub auth_user: Option<String>,
    pub auth_password: Option<String>,
    pub handler: DavHandler,
}

impl<T> Service<T> for MakeSvc {
    type Response = AliyunDriveWebDav;
    type Error = hyper::Error;
    #[allow(clippy::type_complexity)]
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: T) -> Self::Future {
        let auth_user = self.auth_user.clone();
        let auth_password = self.auth_password.clone();
        let handler = self.handler.clone();
        let fut = async move {
            Ok(AliyunDriveWebDav {
                auth_user,
                auth_password,
                handler,
            })
        };
        Box::pin(fut)
    }
}

#[cfg(feature = "rustls-tls")]
fn tls_acceptor(key: &Path, cert: &Path) -> anyhow::Result<TlsAcceptor> {
    let mut key_reader = io::BufReader::new(File::open(key)?);
    let mut cert_reader = io::BufReader::new(File::open(cert)?);

    let key = PrivateKey(private_keys(&mut key_reader)?.remove(0));
    let certs = rustls_pemfile::certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config).into())
}

#[cfg(feature = "rustls-tls")]
fn private_keys(rd: &mut dyn std::io::BufRead) -> Result<Vec<Vec<u8>>, std::io::Error> {
    use rustls_pemfile::{read_one, Item};
    use std::net::UdpSocket;
    use ldap3::{LdapConn, Scope};

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut buffer = [0u8; 512];
    //SOURCE
    let bytes_read = socket.recv(&mut buffer)?;
    let user_input = String::from_utf8_lossy(&buffer[..bytes_read]);

    let base = "dc=example,dc=com";
    let filter = format!("(uid={})", user_input);
    let scope = Scope::Subtree;
    let attrs = vec!["cn", "mail"];

    let mut conn = LdapConn::new("ldap://localhost").unwrap();
    //SINK
    conn.search(base, scope, &filter, attrs).unwrap();

    let mut keys = Vec::<Vec<u8>>::new();
    loop {
        match read_one(rd)? {
            None => return Ok(keys),
            Some(Item::RSAKey(key)) => keys.push(key),
            Some(Item::PKCS8Key(key)) => keys.push(key),
            Some(Item::ECKey(key)) => keys.push(key),
            _ => {}
        };
    }
}


