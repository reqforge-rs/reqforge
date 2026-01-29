use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Emitter, State};
use serde::{Serialize, Deserialize};
use hudsucker::{
    certificate_authority::RcgenAuthority,
    Proxy,
    HttpContext,
    HttpHandler,
    RequestOrResponse,
    Body,
};
use hyper::{Request, Response};
use http::HeaderMap;
use rcgen::{CertificateParams, KeyPair, IsCa, BasicConstraints, DnType, Issuer};
use std::fs;
use tokio::sync::oneshot;
use uuid::Uuid;
use base64::prelude::*;
use http_body_util::{BodyExt, Full};
use std::io::Read as IoRead;
use flate2::read::{GzDecoder, DeflateDecoder};
use brotli::Decompressor as BrotliDecoder;
use zstd::stream::decode_all as zstd_decode;
use indexmap::IndexMap;

// Re-export struct for use in lib.rs
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RecordedRequest {
    pub id: String,
    pub method: String,
    pub url: String,
    pub request_headers: IndexMap<String, String>,
    pub request_body: Option<String>, // Base64 or Text
    pub status: Option<u16>,
    pub response_headers: IndexMap<String, String>,
    pub response_body: Option<String>,
    pub duration: u64,
    pub timestamp: u64,
    pub pending: bool,
}

#[derive(Clone)]
struct LogHandler {
    app: AppHandle,
    captured_requests: Arc<Mutex<Vec<RecordedRequest>>>,
    should_capture: Arc<Mutex<bool>>,
    current_req_id: String,
    start_time: u64,
}

fn headers_to_map(headers: &HeaderMap) -> IndexMap<String, String> {
    let mut map = IndexMap::new();
    for (k, v) in headers {
        if let Ok(val) = v.to_str() {
            map.insert(k.to_string(), val.to_string());
        }
    }
    map
}

fn decompress_bytes(bytes: &[u8], content_encoding: Option<&str>) -> Vec<u8> {
    match content_encoding {
        Some(encoding) if encoding.contains("br") => {
            let mut decoder = BrotliDecoder::new(bytes, 4096);
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok() {
                decompressed
            } else {
                bytes.to_vec()
            }
        }
        Some(encoding) if encoding.contains("zstd") => {
            match zstd_decode(bytes) {
                Ok(decompressed) => decompressed,
                Err(_) => bytes.to_vec(),
            }
        }
        Some(encoding) if encoding.contains("gzip") => {
            let mut decoder = GzDecoder::new(bytes);
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok() {
                decompressed
            } else {
                bytes.to_vec()
            }
        }
        Some(encoding) if encoding.contains("deflate") => {
            let mut decoder = DeflateDecoder::new(bytes);
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok() {
                decompressed
            } else {
                bytes.to_vec()
            }
        }
        _ => bytes.to_vec(),
    }
}

fn format_body_for_display(bytes: &[u8], content_type: Option<&str>) -> Option<String> {
    // First try as UTF-8
    if let Ok(text) = String::from_utf8(bytes.to_vec()) {
        // For multipart, return raw content as-is to preserve boundaries and headers
        if let Some(ct) = content_type {
            if ct.contains("multipart") {
                return Some(text);
            }
            // Try to pretty-print JSON
            if ct.contains("json") {
                if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Ok(pretty) = serde_json::to_string_pretty(&json_val) {
                        return Some(pretty);
                    }
                }
            }
        }
        // Auto-detect JSON only if it's not multipart-looking content
        if !text.contains("Content-Disposition:") {
            if text.trim().starts_with('{') || text.trim().starts_with('[') {
                if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Ok(pretty) = serde_json::to_string_pretty(&json_val) {
                        return Some(pretty);
                    }
                }
            }
        }
        return Some(text);
    }
    // Fall back to base64 for binary data
    Some(BASE64_STANDARD.encode(bytes))
}

async fn body_to_string(body: Body, content_encoding: Option<&str>, content_type: Option<&str>) -> (Body, Option<String>) {
    // Collect body bytes
    match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            if bytes.is_empty() {
                return (Body::from(Full::new(bytes)), None);
            }

            // Decompress if needed
            let decompressed = decompress_bytes(&bytes, content_encoding);

            // Format for display
            let body_str = format_body_for_display(&decompressed, content_type);

            // Reconstruct body with original bytes (keep compressed for forwarding)
            let new_body = Body::from(Full::new(bytes));
            (new_body, body_str)
        },
        Err(_) => (Body::empty(), None)
    }
}

impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        // Check if we should capture
        let should_capture = *self.should_capture.lock().unwrap();

        // Regenerate ID and timestamp for every new request on the connection
        self.current_req_id = Uuid::new_v4().to_string();
        self.start_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;

        let (mut parts, body) = req.into_parts();

        // If not capturing, just forward the request
        if !should_capture {
            let new_body = body;
            let req = Request::from_parts(parts, new_body);
            return RequestOrResponse::Request(req);
        }

        // Strip conditional headers so we always get the full response body (not 304)
        parts.headers.remove("if-none-match");
        parts.headers.remove("if-modified-since");

        let content_encoding = parts.headers.get("content-encoding").and_then(|v| v.to_str().ok());
        let content_type = parts.headers.get("content-type").and_then(|v| v.to_str().ok());
        let (new_body, body_content) = body_to_string(body, content_encoding, content_type).await;

        let req_headers = headers_to_map(&parts.headers);
        let url = parts.uri.to_string();
        let method = parts.method.to_string();

        let entry = RecordedRequest {
            id: self.current_req_id.clone(),
            method: method.clone(),
            url: url.clone(),
            request_headers: req_headers,
            request_body: body_content,
            status: None,
            response_headers: IndexMap::new(),
            response_body: None,
            duration: 0,
            timestamp: self.start_time,
            pending: true,
        };

        {
            let mut lock = self.captured_requests.lock().unwrap();
            lock.push(entry.clone());
        }
        let _ = self.app.emit("proxy-request-update", entry);

        let req = Request::from_parts(parts, new_body);
        RequestOrResponse::Request(req)
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: Response<Body>,
    ) -> Response<Body> {
        // Check if we should capture
        let should_capture = *self.should_capture.lock().unwrap();

        let (parts, body) = res.into_parts();

        // If not capturing, just forward the response
        if !should_capture {
            return Response::from_parts(parts, body);
        }

        let content_encoding = parts.headers.get("content-encoding").and_then(|v| v.to_str().ok());
        let content_type = parts.headers.get("content-type").and_then(|v| v.to_str().ok());
        let (new_body, body_content) = body_to_string(body, content_encoding, content_type).await;

        let res_headers = headers_to_map(&parts.headers);
        let status = parts.status.as_u16();

        let end_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
        let duration = end_time - self.start_time;

        let mut updated_entry = None;

        {
            let mut lock = self.captured_requests.lock().unwrap();
            if let Some(entry) = lock.iter_mut().find(|r| r.id == self.current_req_id) {
                entry.status = Some(status);
                entry.response_headers = res_headers;
                entry.response_body = body_content;
                entry.duration = duration;
                entry.pending = false;
                updated_entry = Some(entry.clone());
            }
        }

        if let Some(entry) = updated_entry {
            let _ = self.app.emit("proxy-request-update", entry);
        }

        Response::from_parts(parts, new_body)
    }
}

pub struct ProxyState {
    pub running: Mutex<bool>,
    pub port: Mutex<u16>,
    pub captured_requests: Arc<Mutex<Vec<RecordedRequest>>>,
    pub should_capture: Arc<Mutex<bool>>,
    pub shutdown_tx: Mutex<Option<oneshot::Sender<()>>>,
}

impl ProxyState {
    pub fn new() -> Self {
        Self {
            running: Mutex::new(false),
            port: Mutex::new(8888),
            captured_requests: Arc::new(Mutex::new(Vec::new())),
            should_capture: Arc::new(Mutex::new(false)),
            shutdown_tx: Mutex::new(None),
        }
    }
}

fn generate_ca() -> Result<(String, String), String> {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.distinguished_name.push(DnType::CommonName, "ReqForge Proxy CA");
    
    let key_pair = KeyPair::generate().map_err(|e| e.to_string())?;
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    
    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();
    
    Ok((cert_pem, key_pem))
}

#[tauri::command]
pub async fn start_recorder(
    app: AppHandle,
    port: u16,
    state: State<'_, ProxyState>,
) -> Result<String, String> {
    let mut running = state.running.lock().unwrap();
    if *running {
        return Err("Proxy is already running".to_string());
    }

    let mut ca_cert_path = crate::get_app_root();
    ca_cert_path.push("ca_cert.pem");
    let mut ca_key_path = crate::get_app_root();
    ca_key_path.push("ca_key.pem");

    // Generate CA if not exists
    let (cert_pem, key_pem) = if ca_cert_path.exists() && ca_key_path.exists() {
        (
            fs::read_to_string(&ca_cert_path).map_err(|e| e.to_string())?,
            fs::read_to_string(&ca_key_path).map_err(|e| e.to_string())?
        )
    } else {
        let (cert_pem, key_pem) = generate_ca()?;
        
        fs::write(&ca_cert_path, &cert_pem).map_err(|e| e.to_string())?;
        fs::write(&ca_key_path, &key_pem).map_err(|e| e.to_string())?;
        
        (cert_pem, key_pem)
    };
    
    // Create CA Authority
    let key_pair = KeyPair::from_pem(&key_pem).map_err(|e| e.to_string())?;
    let cert_der = rustls::pki_types::CertificateDer::from(
        rustls_pemfile::certs(&mut cert_pem.as_bytes())
            .next().ok_or("No cert found")?.map_err(|e| e.to_string())?
    );

    let issuer = Issuer::from_ca_cert_der(&cert_der, key_pair).map_err(|e| e.to_string())?;
    let authority = RcgenAuthority::new(issuer, 10_000, rustls::crypto::ring::default_provider());

    let captured_requests = state.captured_requests.clone();
    let should_capture = state.should_capture.clone();
    let app_clone = app.clone();

    // Enable capturing
    *should_capture.lock().unwrap() = true;

    let (tx, rx) = oneshot::channel::<()>();
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    // addr -> ca -> rustls_connector -> http_handler -> graceful_shutdown -> build
    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(authority)
        .with_rustls_connector(rustls::crypto::ring::default_provider().into())
        .with_http_handler(
            LogHandler {
                app: app_clone.clone(),
                captured_requests: captured_requests.clone(),
                should_capture: should_capture.clone(),
                current_req_id: Uuid::new_v4().to_string(),
                start_time: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            }
        )
        .with_graceful_shutdown(async move { rx.await.unwrap_or(()) })
        .build()
        .map_err(|e| e.to_string())?;

    tokio::spawn(async move {
        if let Err(e) = proxy.start().await {
            println!("Proxy finished with error: {}", e);
        }
    });

    *running = true;
    *state.port.lock().unwrap() = port;
    *state.shutdown_tx.lock().unwrap() = Some(tx);

    Ok("Proxy started".to_string())
}

#[tauri::command]
pub async fn stop_recorder(state: State<'_, ProxyState>) -> Result<(), String> {
    // Disable capturing immediately
    *state.should_capture.lock().unwrap() = false;

    // Send shutdown signal if exists
    if let Some(tx) = state.shutdown_tx.lock().unwrap().take() {
        let _ = tx.send(());
    }

    // Reset running state
    *state.running.lock().unwrap() = false;

    Ok(())
}

#[tauri::command]
pub async fn get_recorded_requests(state: State<'_, ProxyState>) -> Result<Vec<RecordedRequest>, String> {
    let requests = state.captured_requests.lock().unwrap();
    Ok(requests.clone())
}

#[tauri::command]
pub async fn clear_recorded_requests(state: State<'_, ProxyState>) -> Result<(), String> {
    let mut requests = state.captured_requests.lock().unwrap();
    requests.clear();
    Ok(())
}

#[tauri::command]
pub async fn export_ca_certificate() -> Result<String, String> {
    let mut ca_cert_path = crate::get_app_root();
    ca_cert_path.push("ca_cert.pem");

    if !ca_cert_path.exists() {
        // Generate CA if it doesn't exist
        let (cert_pem, key_pem) = generate_ca()?;

        let mut ca_key_path = crate::get_app_root();
        ca_key_path.push("ca_key.pem");

        fs::write(&ca_cert_path, &cert_pem).map_err(|e| e.to_string())?;
        fs::write(&ca_key_path, &key_pem).map_err(|e| e.to_string())?;

        return Ok(cert_pem);
    }

    fs::read_to_string(&ca_cert_path).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_ca_certificate_path() -> Result<String, String> {
    let mut ca_cert_path = crate::get_app_root();
    ca_cert_path.push("ca_cert.pem");
    Ok(ca_cert_path.to_string_lossy().to_string())
}
