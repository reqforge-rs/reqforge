use reqwest::multipart as reqwest_multipart;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;
use rand::Rng;
use rand::prelude::IndexedRandom;
use base64::prelude::*;
use sha2::{Sha256, Sha384, Sha512, Digest};
use hmac::{Hmac, Mac};
use aes::Aes128;
use aes::Aes256;
use cbc::cipher::{KeyIvInit, BlockEncryptMut, BlockDecryptMut, block_padding::Pkcs7};

type Aes128CbcEnc = cbc::Encryptor<Aes128>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes128CbcDec = cbc::Decryptor<Aes128>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;
use md5::Md5;
use sha1::Sha1;
use md4::Md4;
use uuid::Uuid;
use rhai::{Engine as RhaiEngine, Scope};
use base64::Engine as Base64Engine;
use wreq_util::Emulation;
use wreq::multipart as wreq_multipart;
use num_bigint::BigUint;


#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum BlockType { Request, Parse, KeyCheck, RandomString, ConstantString, ConstantList, GetRandomItem, CurrentUnixTime, DateToUnixTime, UnixTimeToDate, UnixTimeToIso8601, Base64Encode, Base64Decode, GenerateCodeVerifier, GenerateCodeChallenge, GenerateState, GenerateNonce, GenerateFirefoxUA, GenerateGuid, GenerateUUID4, TlsRequest, TlsWreq, Hash, ClearCookies, JumpIF, JumpLabel, Script, Replace, UrlEncode, UrlDecode, RandomInteger, ZipLists, BytesToBase64, ForgeRockAuth, HmacSign, AesEncrypt, AesDecrypt, Pbkdf2Derive, RsaEncrypt, Base64ToBytes, EncodeHtmlEntities, DecodeHtmlEntities, Delay, RandomUserAgent, Checksum, ToLowercase, ToUppercase, Translate }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block { pub id: String, pub block_type: BlockType, pub data: Value }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Config { pub name: String, pub blocks: Vec<Block>, pub blueprint: Option<Value> }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestDetails { pub url: String, pub method: String, pub request_headers: HashMap<String, String>, pub request_body: String, pub response_status: u16, pub response_url: String, pub response_headers: HashMap<String, String>, pub response_cookies: HashMap<String, String>, pub response_body: String }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ExecutionLog { 
    pub step: String, 
    pub message: String, 
    pub status: String, 
    pub details: Option<RequestDetails>, 
    pub block_id: Option<String>,
    pub variables: Option<HashMap<String, String>>,
    pub duration_ms: u64
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DebugResult { pub logs: Vec<ExecutionLog>, pub variables: HashMap<String, String>, pub captured_data: Vec<String> }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyCondition { Contains, NotContains, Equal, NotEqual }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Key { pub value: String, pub condition: KeyCondition }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MultipartField {
    pub name: String,
    #[serde(alias = "data")]
    pub value: String,
    pub filename: Option<String>,
    pub content_type: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FrontendMultipartField {
    pub name: String,
    #[serde(alias = "data")]
    pub value: String,
    pub is_file: bool,
    pub content_type: Option<String>,
    pub filename: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeychainMode { OR, AND }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Keychain { pub result_status: String, pub mode: KeychainMode, pub keys: Vec<Key>, pub source: Option<String> }


#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct StructuredTlsApiPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_client_identifier: Option<String>,
    pub follow_redirects: bool,
    pub with_default_cookie_jar: bool,
    #[serde(rename = "withRandomTLSExtensionOrder")]
    pub with_random_tls_extension_order: bool,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    pub is_rotating_proxy: bool,
    pub header_order: Vec<String>,
    pub headers: HashMap<String, String>,
    pub insecure_skip_verify: bool,
    pub timeout_seconds: u64,
    pub timeout_milliseconds: u64,
    pub request_url: String,
    pub request_method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    #[serde(rename = "forceHttp1")]
    pub force_http1: bool,
    #[serde(rename = "disableHttp2")]
    pub disable_http2: bool,
    #[serde(rename = "disableHttp3")]
    pub disable_http3: bool,
    pub with_debug: bool,
    #[serde(rename = "disableIPV6")]
    pub disable_ipv6: bool,
    // New fields from API docs
    pub catch_panics: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_pinning_hosts: Option<HashMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_tls_client: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_options: Option<Value>,
    pub is_byte_request: bool,
    pub is_byte_response: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_cookies: Option<Vec<Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_host_override: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_headers: Option<HashMap<String, Vec<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_headers: Option<HashMap<String, Vec<String>>>,
    #[serde(rename = "disableIPV4")]
    pub disable_ipv4: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name_overwrite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_output_block_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "streamOutputEOFSymbol")]
    pub stream_output_eof_symbol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_output_path: Option<String>,
    pub without_cookie_jar: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct StructuredTlsApiResponse {
    #[serde(default)]
    #[allow(dead_code)]
    id: String,
    #[serde(default)]
    session_id: String,
    status: u16,
    #[serde(default)]
    target: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    cookies: HashMap<String, String>,
}

pub struct Context { pub variables: HashMap<String, String>, pub logs: Vec<ExecutionLog>, pub proxy: Option<String>, pub bot_status: String, pub client: reqwest::Client, pub current_auto_redirect: bool, pub current_max_redirects: usize, pub captured_data: Vec<String>, pub tls_session_id: Option<String> }

impl Context {
    pub fn new(proxy: Option<String>) -> Self {
        let mut cb = reqwest::Client::builder().timeout(Duration::from_secs(30)).cookie_store(false).danger_accept_invalid_certs(true).user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36");
        if let Some(p_str) = &proxy { if let Ok(p) = parse_proxy(p_str) { cb = cb.proxy(p); } }
        Self { variables: HashMap::new(), logs: Vec::new(), proxy, bot_status: "SUCCESS".to_string(), client: cb.build().unwrap_or_default(), current_auto_redirect: true, current_max_redirects: 10, captured_data: Vec::new(), tls_session_id: None }
    }
    pub fn replace_vars(&self, input: &str) -> String {
        let mut result = input.to_string();
        for (key, val) in &self.variables { result = result.replace(&format!("<{}>", key), val); }
            result
        }
        
        }

fn format_proxy_to_url(p: &str) -> String {
    let p_clean = p.trim();
    // Keep original scheme if present, or default to http
    let (scheme, remainder) = if let Some(idx) = p_clean.find("://") {
        (&p_clean[..idx], &p_clean[idx+3..])
    } else {
        ("http", p_clean)
    };

    // If it's already a valid URL with @, just return it (or normalized)
    if remainder.contains('@') {
        return p_clean.to_string();
    }

    let parts: Vec<&str> = remainder.split(':').collect();
    
    if parts.len() == 2 {
        // host:port
        return format!("{}://{}:{}", scheme, parts[0], parts[1]);
    }
    
    if parts.len() == 4 {
        // Ambiguous: host:port:user:pass OR user:pass:host:port
        // Heuristic 1: Check for IP/Domain in pos 0 vs pos 2
        let p0_is_host = parts[0].contains('.') || parts[0].contains("localhost");
        let p2_is_host = parts[2].contains('.') || parts[2].contains("localhost");
        
        // Heuristic 2: Check for Port in pos 1 vs pos 3
        let p1_is_port = parts[1].parse::<u16>().is_ok();
        let p3_is_port = parts[3].parse::<u16>().is_ok();

        if (p0_is_host && !p2_is_host) || (p1_is_port && !p3_is_port) {
            // Format: host:port:user:pass
            return format!("{}://{}:{}@{}:{}", scheme, parts[2], parts[3], parts[0], parts[1]);
        } else {
            // Assume Format: user:pass:host:port
            return format!("{}://{}:{}@{}:{}", scheme, parts[0], parts[1], parts[2], parts[3]);
        }
    }

    // Fallback
    p_clean.to_string()
}

fn parse_proxy(p: &str) -> Result<reqwest::Proxy, String> { let url = format_proxy_to_url(p); reqwest::Proxy::all(&url).map_err(|e| e.to_string()) }
fn base64_url_encode(input: &[u8]) -> String { BASE64_URL_SAFE_NO_PAD.encode(input) }
fn generate_random_crypto_string(len: usize) -> String { let mut b = vec![0u8; len]; rand::rng().fill(&mut b[..]); base64_url_encode(&b) }
fn try_unescape_json_string(text: &str) -> String { if let Ok(u) = serde_json::from_str::<String>(text) { return u; } if let Ok(u) = serde_json::from_str::<String>(&format!("\"{}\"", text)) { return u; } text.to_string() }

fn smart_encode_url(url: String) -> String {
    if let Some(pos) = url.find('?') {
        let (base, query) = url.split_at(pos + 1);
        return format!("{}{}", base, query.replace('/', "%2F"));
    }
    url
}



const ALL_EMULATIONS: &[Emulation] = &[
    Emulation::Chrome100, Emulation::Chrome101, Emulation::Chrome104, Emulation::Chrome105, Emulation::Chrome106,
    Emulation::Chrome107, Emulation::Chrome108, Emulation::Chrome109, Emulation::Chrome110, Emulation::Chrome114,
    Emulation::Chrome116, Emulation::Chrome117, Emulation::Chrome118, Emulation::Chrome119, Emulation::Chrome120,
    Emulation::Chrome123, Emulation::Chrome124, Emulation::Chrome126, Emulation::Chrome127, Emulation::Chrome128,
    Emulation::Chrome129, Emulation::Chrome130, Emulation::Chrome131, Emulation::Chrome132, Emulation::Chrome133,
    Emulation::Chrome134, Emulation::Chrome135, Emulation::Chrome136, Emulation::Chrome137,
    Emulation::Firefox109, Emulation::Firefox117, Emulation::Firefox128, Emulation::Firefox133,
    Emulation::Firefox135, Emulation::Firefox136, Emulation::Firefox139,
    Emulation::FirefoxPrivate135, Emulation::FirefoxPrivate136, Emulation::FirefoxAndroid135,
    Emulation::Safari15_3, Emulation::Safari15_5, Emulation::Safari15_6_1, Emulation::Safari16,
    Emulation::Safari16_5, Emulation::Safari17_0, Emulation::Safari17_2_1, Emulation::Safari17_4_1,
    Emulation::Safari17_5, Emulation::Safari18, Emulation::Safari18_2,
    Emulation::SafariIos16_5, Emulation::SafariIos17_2, Emulation::SafariIos17_4_1, Emulation::SafariIos18_1_1, Emulation::SafariIPad18,
    Emulation::Edge101, Emulation::Edge122, Emulation::Edge127, Emulation::Edge131, Emulation::Edge134,
    Emulation::Opera116, Emulation::Opera117, Emulation::Opera118, Emulation::Opera119,
    Emulation::OkHttp3_9, Emulation::OkHttp3_11, Emulation::OkHttp3_13, Emulation::OkHttp3_14,
    Emulation::OkHttp4_9, Emulation::OkHttp4_10, Emulation::OkHttp4_12, Emulation::OkHttp5,
];

fn parse_wreq_emulation(s: &str) -> Emulation {
    match s.to_lowercase().as_str() {
        "random" => ALL_EMULATIONS[rand::rng().random_range(0..ALL_EMULATIONS.len())].clone(),
        "chrome100" => Emulation::Chrome100, "chrome101" => Emulation::Chrome101, "chrome104" => Emulation::Chrome104,
        "chrome105" => Emulation::Chrome105, "chrome106" => Emulation::Chrome106, "chrome107" => Emulation::Chrome107,
        "chrome108" => Emulation::Chrome108, "chrome109" => Emulation::Chrome109, "chrome110" => Emulation::Chrome110,
        "chrome114" => Emulation::Chrome114, "chrome116" => Emulation::Chrome116, "chrome117" => Emulation::Chrome117,
        "chrome118" => Emulation::Chrome118, "chrome119" => Emulation::Chrome119, "chrome120" => Emulation::Chrome120,
        "chrome123" => Emulation::Chrome123, "chrome124" => Emulation::Chrome124, "chrome126" => Emulation::Chrome126,
        "chrome127" => Emulation::Chrome127, "chrome128" => Emulation::Chrome128, "chrome129" => Emulation::Chrome129,
        "chrome130" => Emulation::Chrome130, "chrome131" => Emulation::Chrome131, "chrome132" => Emulation::Chrome132,
        "chrome133" => Emulation::Chrome133, "chrome134" => Emulation::Chrome134, "chrome135" => Emulation::Chrome135,
        "chrome136" => Emulation::Chrome136, "chrome137" => Emulation::Chrome137,
        "firefox109" => Emulation::Firefox109, "firefox117" => Emulation::Firefox117, "firefox128" => Emulation::Firefox128,
        "firefox133" => Emulation::Firefox133, "firefox135" => Emulation::Firefox135, "firefox136" => Emulation::Firefox136,
        "firefox139" => Emulation::Firefox139,
        "firefoxprivate135" => Emulation::FirefoxPrivate135, "firefoxprivate136" => Emulation::FirefoxPrivate136,
        "firefoxandroid135" => Emulation::FirefoxAndroid135,
        "safari15_3" | "safari15.3" => Emulation::Safari15_3, "safari15_5" | "safari15.5" => Emulation::Safari15_5,
        "safari15_6_1" | "safari15.6.1" => Emulation::Safari15_6_1, "safari16" => Emulation::Safari16,
        "safari16_5" | "safari16.5" => Emulation::Safari16_5, "safari17_0" | "safari17.0" => Emulation::Safari17_0,
        "safari17_2_1" | "safari17.2.1" => Emulation::Safari17_2_1, "safari17_4_1" | "safari17.4.1" => Emulation::Safari17_4_1,
        "safari17_5" | "safari17.5" => Emulation::Safari17_5, "safari18" => Emulation::Safari18,
        "safari18_2" | "safari18.2" => Emulation::Safari18_2, "safariios16_5" | "safariios16.5" => Emulation::SafariIos16_5,
        "safariios17_2" | "safariios17.2" => Emulation::SafariIos17_2, "safariios17_4_1" | "safariios17.4.1" => Emulation::SafariIos17_4_1,
        "safariios18_1_1" | "safariios18.1.1" => Emulation::SafariIos18_1_1, "safariipad18" => Emulation::SafariIPad18,
        "edge101" => Emulation::Edge101, "edge122" => Emulation::Edge122, "edge127" => Emulation::Edge127,
        "edge131" => Emulation::Edge131, "edge134" => Emulation::Edge134,
        "opera116" => Emulation::Opera116, "opera117" => Emulation::Opera117, "opera118" => Emulation::Opera118, "opera119" => Emulation::Opera119,
        "okhttp3_9" | "okhttp3.9" => Emulation::OkHttp3_9, "okhttp3_11" | "okhttp3.11" => Emulation::OkHttp3_11,
        "okhttp3_13" | "okhttp3.13" => Emulation::OkHttp3_13, "okhttp3_14" | "okhttp3.14" => Emulation::OkHttp3_14,
        "okhttp4_9" | "okhttp4.9" => Emulation::OkHttp4_9, "okhttp4_10" | "okhttp4.10" => Emulation::OkHttp4_10,
        "okhttp4_12" | "okhttp4.12" => Emulation::OkHttp4_12, "okhttp5" => Emulation::OkHttp5,
        _ => Emulation::Chrome133
    }
}

fn rhai_http_get(url: &str, proxy: Option<&str>) -> Result<String, String> {
    let mut builder = reqwest::blocking::Client::builder();
    if let Some(p_str) = proxy {
        if let Ok(p) = parse_proxy(p_str) { builder = builder.proxy(p); }
    }
    let client = builder.build().unwrap_or_default();
    let res = client.get(url).send().map_err(|e| e.to_string())?;
    let body = res.text().map_err(|e| e.to_string())?;
    Ok(body)
}

fn rhai_http_post(url: &str, body: &str, proxy: Option<&str>) -> Result<String, String> {
    let mut builder = reqwest::blocking::Client::builder();
    if let Some(p_str) = proxy {
        if let Ok(p) = parse_proxy(p_str) { builder = builder.proxy(p); }
    }
    let client = builder.build().unwrap_or_default();
    let res = client.post(url).body(body.to_string()).send().map_err(|e| e.to_string())?;
    let res_body = res.text().map_err(|e| e.to_string())?;
    Ok(res_body)
}

fn rhai_uuid4() -> String {
    Uuid::new_v4().to_string()
}

fn rhai_guid() -> String {
    Uuid::new_v4().to_string().to_uppercase()
}

fn rhai_random_int(min: i64, max: i64) -> i64 {
    use rand::Rng;
    rand::rng().random_range(min..=max)
}

fn rhai_base64_encode(s: &str) -> String {
    use base64::engine::general_purpose::STANDARD;
    STANDARD.encode(s.as_bytes())
}

fn rhai_base64_decode(s: &str) -> Result<String, String> {
    use base64::engine::general_purpose::STANDARD;
    let bytes = STANDARD.decode(s).map_err(|e| e.to_string())?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

fn rhai_md5(s: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn rhai_sha256(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn rhai_url_encode(s: &str) -> String {
    urlencoding::encode(s).to_string()
}

fn rhai_url_decode(s: &str) -> Result<String, String> {
    urlencoding::decode(s).map(|s| s.to_string()).map_err(|e| e.to_string())
}

fn build_custom_multipart(fields: Vec<MultipartField>, boundary: &str, ctx: &Context) -> Vec<u8> {
    let mut body = Vec::new();
    for field in fields {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        if let Some(filename) = &field.filename {
            let content_type = field.content_type.as_deref().unwrap_or("application/octet-stream");
            body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n", field.name, filename).as_bytes());
            body.extend_from_slice(format!("Content-Type: {}\r\n\r\n", content_type).as_bytes());
            if let Ok(bytes) = BASE64_STANDARD.decode(&field.value) {
                body.extend_from_slice(&bytes);
            }
        } else {
            body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"\r\n", field.name).as_bytes());
            if let Some(ct) = &field.content_type {
                body.extend_from_slice(format!("Content-Type: {}\r\n", ct).as_bytes());
            }
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(ctx.replace_vars(&field.value).as_bytes());
        }
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    body
}

fn build_custom_multipart_frontend(fields: Vec<FrontendMultipartField>, boundary: &str, ctx: &Context) -> Vec<u8> {
    let mut body = Vec::new();
    for field in fields {
        body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
        if field.is_file {
            let content_type = field.content_type.as_deref().unwrap_or("application/octet-stream");
            let filename = field.filename.clone().unwrap_or_else(|| "upload".to_string());
            body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\n", field.name, filename).as_bytes());
            body.extend_from_slice(format!("Content-Type: {}\r\n\r\n", content_type).as_bytes());
            if let Ok(bytes) = BASE64_STANDARD.decode(&field.value) {
                body.extend_from_slice(&bytes);
            }
        } else {
            body.extend_from_slice(format!("Content-Disposition: form-data; name=\"{}\"\r\n", field.name).as_bytes());
            if let Some(ct) = &field.content_type {
                body.extend_from_slice(format!("Content-Type: {}\r\n", ct).as_bytes());
            }
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(ctx.replace_vars(&field.value).as_bytes());
        }
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
    body
}

fn extract_json_value(json: &Value, path: &str) -> Option<String> {
    let mut curr = json;
    for part in path.split('.') {
        if part.is_empty() { continue; }
        if part.ends_with(']') {
            if let Some(open_idx) = part.find('[') {
                let k = &part[..open_idx];
                if k != "" { curr = curr.get(k)?; }
                let i = part[open_idx+1..part.len()-1].parse::<usize>().ok()?;
                curr = curr.get(i)?;
            } else { return None; }
        } else { curr = curr.get(part)?; }
    }
    match curr { Value::String(s) => Some(s.clone()), Value::Number(n) => Some(n.to_string()), Value::Bool(b) => Some(b.to_string()), Value::Null => Some("null".into()), _ => Some(curr.to_string()) }
}

use std::sync::OnceLock;

static FORWARDER_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

pub async fn execute_config<F>(config: Config, input_data: String, proxy: String, on_log: Option<F>, ua_manager: &crate::UserAgentManager) -> DebugResult 
where F: Fn(ExecutionLog) + Send + Sync + 'static {
    execute_config_with_client(config, input_data, proxy, on_log, &ua_manager).await
}

fn parse_jitter_range(s: &str, seed: u64) -> Option<i64> {
    if s.contains('-') {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() == 2 {
            let min = parts[0].parse::<i64>().ok()?;
            let max = parts[1].parse::<i64>().ok()?;
            if min <= max {
                use rand::{SeedableRng, Rng};
                let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
                return Some(rng.random_range(min..=max));
            }
        }
    }
    s.parse::<i64>().ok()
}

fn solve_pow_sha1(uuid: &str, difficulty: usize) -> u64 {
    let target = "0".repeat(difficulty);
    let mut nonce = 0u64;
    loop {
        let msg = format!("{}{}", uuid, nonce);
        let mut hasher = Sha1::new();
        hasher.update(msg.as_bytes());
        let res = hex::encode(hasher.finalize());
        if res.starts_with(&target) {
            return nonce;
        }
        nonce += 1;
        if nonce > 10000000 { return 0; } // Safety break
    }
}

pub async fn execute_config_with_client<F>(config: Config, input: String, proxy: String, log_callback: Option<F>, ua_manager: &crate::UserAgentManager) -> DebugResult 
where F: Fn(ExecutionLog) + Send + Sync + 'static {
    let mut ctx = Context::new(if proxy.trim().is_empty() { None } else { Some(proxy.clone()) });
    
    // Create a stable seed for jitter based on input data (e.g. user:pass) or session
    let jitter_seed = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        input.hash(&mut hasher);
        hasher.finish()
    };

    let on_log = log_callback; // Alias for internal use
    let mut block_start_time = std::time::Instant::now();

    let log_and_emit = |ctx: &mut Context, step: &str, message: &str, status: &str, details: Option<RequestDetails>, block_id: Option<String>, start_time: std::time::Instant| {
        let duration = start_time.elapsed().as_millis() as u64;
        let log = ExecutionLog { 
            step: step.to_string(), 
            message: message.to_string(), 
            status: status.to_string(), 
            details, 
            block_id,
            variables: Some(ctx.variables.clone()),
            duration_ms: duration
        };
        ctx.logs.push(log.clone());
        if let Some(ref f) = on_log { f(log); }
    };
    ctx.variables.insert("INPUT".into(), input.clone());
    if input.contains(':') { let p: Vec<&str> = input.splitn(2, ':').collect(); if p.len() == 2 { ctx.variables.insert("USER".into(), p[0].into()); ctx.variables.insert("PASS".into(), p[1].into()); } }
    log_and_emit(&mut ctx, "Start", &format!("Starting config: {}", config.name), "Info", None, None, block_start_time);

    // Pre-pass: collect JumpLabel positions
    let mut labels: HashMap<String, usize> = HashMap::new();
    for (i, block) in config.blocks.iter().enumerate() {
        if matches!(block.block_type, BlockType::JumpLabel) {
            if let Some(label) = block.data.get("label").and_then(|v| v.as_str()) {
                labels.insert(label.to_string(), i);
            }
        }
    }

    let mut block_idx = 0;
    while block_idx < config.blocks.len() {
        block_start_time = std::time::Instant::now();
        let block = &config.blocks[block_idx];
        let bid = Some((block_idx + 1).to_string());

        // Skip disabled blocks
        if block.data.get("disabled").and_then(|v| v.as_bool()).unwrap_or(false) {
            log_and_emit(&mut ctx, &format!("{:?}", block.block_type), "Skipped (disabled)", "Info", None, bid, block_start_time);
            block_idx += 1;
            continue;
        }

        match block.block_type {
            BlockType::RandomUserAgent => {
                let platform = block.data.get("platform").and_then(|v| v.as_str()).unwrap_or("ALL").to_lowercase();
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("userAgent");

                let ua = ua_manager.get_random_user_agent(&platform).unwrap_or_else(|| {
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()
                });
                
                ctx.variables.insert(var_name.into(), ua.clone());
                log_and_emit(&mut ctx, "RandomUserAgent", &format!("({}): {}", var_name, ua), "Success", None, bid, block_start_time);
            }
            BlockType::GenerateCodeVerifier => { 
                let var_name = "codeVerifier";
                let v = generate_random_crypto_string(32); 
                ctx.variables.insert(var_name.into(), v.clone()); 
                log_and_emit(&mut ctx, "GenerateCodeVerifier", &format!("({}): {}", var_name, v), "Success", None, bid, block_start_time); 
            }
            BlockType::GenerateCodeChallenge => { 
                let var_name = "codeChallenge";
                let mut hasher = Sha256::new(); 
                hasher.update(ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or("")).as_bytes()); 
                let c = base64_url_encode(&hasher.finalize()); 
                ctx.variables.insert(var_name.into(), c.clone()); 
                log_and_emit(&mut ctx, "GenerateCodeChallenge", &format!("({}): {}", var_name, c), "Success", None, bid, block_start_time); 
            }
            BlockType::GenerateGuid => {
                let var = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("guid");
                let uppercase = block.data.get("uppercase").and_then(|v| v.as_bool()).unwrap_or(false);
                let mut g = Uuid::new_v4().to_string();
                if uppercase { g = g.to_uppercase(); }
                ctx.variables.insert(var.into(), g.clone());
                log_and_emit(&mut ctx, "GenerateGuid", &format!("({}): {}", var, g), "Success", None, bid, block_start_time);
            }
            BlockType::GenerateUUID4 => {
                let var = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("UUID");
                let uppercase = block.data.get("uppercase").and_then(|v| v.as_bool()).unwrap_or(false);
                let mut uuid = Uuid::new_v4().to_string();
                if uppercase { uuid = uuid.to_uppercase(); }
                ctx.variables.insert(var.to_string(), uuid.clone());
                log_and_emit(&mut ctx, "GenerateUUID4", &format!("({}): {}", var, uuid), "Success", None, bid, block_start_time);
            }
            BlockType::ClearCookies => {
                ctx.variables.remove("COOKIES");
                let mut cb = reqwest::Client::builder().timeout(Duration::from_secs(30)).cookie_store(false).danger_accept_invalid_certs(true).user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36");
                if let Some(p_str) = &ctx.proxy { if let Ok(p) = parse_proxy(p_str) { cb = cb.proxy(p); } }
                ctx.client = cb.build().unwrap_or_default();
                ctx.current_auto_redirect = true;
                ctx.current_max_redirects = 10;
                log_and_emit(&mut ctx, "ClearCookies", "Cookies cleared", "Success", None, bid, block_start_time);
            }
            BlockType::Request => {
                let auto_redirect = block.data.get("auto_redirect").and_then(|v| v.as_bool()).unwrap_or(true);
                let max_redirects = block.data.get("max_redirects").and_then(|v| v.as_u64()).unwrap_or(8) as usize;

                
                let http_ver_str = block.data.get("http_version").and_then(|v| v.as_str()).unwrap_or("Auto");
                let tls_ver_str = block.data.get("tls_version").and_then(|v| v.as_str()).unwrap_or("Auto");

                // Default reqwest logic: initialize local client if needed
                if ctx.current_auto_redirect {
                    let mut ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36".to_string();
                    let mut cb = reqwest::Client::builder()
                        .timeout(Duration::from_secs(30))
                        .cookie_store(false)
                        .danger_accept_invalid_certs(true)
                        .redirect(reqwest::redirect::Policy::none())
                        .user_agent(ua);

                    // Apply HTTP version
                    match http_ver_str {
                        "1.1" => { cb = cb.http1_only(); }
                        "2" => { cb = cb.http2_prior_knowledge(); }
                        _ => {} // Auto
                    }

                    // Apply TLS version
                    match tls_ver_str {
                        "1.2" => { 
                            cb = cb.min_tls_version(reqwest::tls::Version::TLS_1_2)
                                   .max_tls_version(reqwest::tls::Version::TLS_1_2); 
                        }
                        "1.3" => { 
                            cb = cb.min_tls_version(reqwest::tls::Version::TLS_1_3)
                                   .max_tls_version(reqwest::tls::Version::TLS_1_3); 
                        }
                        _ => {} // Auto
                    }

                    // Proxy logic: Block-level > Global Context > None
                    let block_proxy = block.data.get("proxy_url").and_then(|v| v.as_str()).unwrap_or("");
                    if !block_proxy.trim().is_empty() {
                        if let Ok(p) = parse_proxy(&ctx.replace_vars(block_proxy)) { cb = cb.proxy(p); }
                    } else if let Some(p_str) = &ctx.proxy { 
                        if let Ok(p) = parse_proxy(p_str) { cb = cb.proxy(p); } 
                    }
                    
                    ctx.client = cb.build().unwrap_or_default();
                    ctx.current_auto_redirect = false;
                }

                let method_name = block.data.get("method").and_then(|v| v.as_str()).unwrap_or("GET").to_uppercase();
                let initial_url = smart_encode_url(ctx.replace_vars(block.data.get("url").and_then(|v| v.as_str()).unwrap_or("")));
                let body = ctx.replace_vars(block.data.get("body").and_then(|v| v.as_str()).unwrap_or(""));

                // Parse user-defined headers (used for initial request)
                let mut user_headers: Vec<(String, String)> = Vec::new();
                if let Some(h_val) = block.data.get("headers").and_then(|v| v.as_str()) {
                    for line in h_val.lines() {
                        if let Some((k, v)) = line.split_once(':') {
                            let key = k.trim();
                            if key.eq_ignore_ascii_case("Content-Length") || key.eq_ignore_ascii_case("Host") { continue; }
                            let mut val = ctx.replace_vars(v.trim());
                            user_headers.push((key.to_string(), val));
                        }
                    }
                }





                // Initialize cookie map from existing COOKIES variable
                let mut cookie_map: HashMap<String, String> = HashMap::new();
                if let Some(existing) = ctx.variables.get("COOKIES") {
                    for pair in existing.split("; ") {
                        if let Some((k, v)) = pair.split_once('=') {
                            cookie_map.insert(k.trim().to_string(), v.trim().to_string());
                        }
                    }
                }

                let mut current_url = initial_url.clone();
                let mut redirect_count = 0;
                let mut final_status: u16 = 0;
                let mut final_url = initial_url.clone();
                let mut final_headers_map: HashMap<String, String> = HashMap::new();
                let mut final_headers_str = String::new();
                let mut final_body = String::new();
                let mut final_res_cookies: HashMap<String, String> = HashMap::new();
                let mut req_hs_log: HashMap<String, String> = HashMap::new();
                let mut had_error = false;
                let mut request_body_log = body.clone(); // Declared outside loop

                loop {
                    // Build headers for this request
                    let mut hs = reqwest::header::HeaderMap::new();
                    let mut req_hs: HashMap<String, String> = HashMap::new();

                    // Add user headers (only on first request, redirects use minimal headers)
                    if redirect_count == 0 {
                        for (key, val) in &user_headers {
                            if let (Ok(n), Ok(hv)) = (reqwest::header::HeaderName::from_bytes(key.as_bytes()), reqwest::header::HeaderValue::from_str(val)) {
                                hs.insert(n, hv);
                                req_hs.insert(key.clone(), val.clone());
                            }
                        }
                    }

                    // Add default Content-Type if not set
                    if !req_hs.keys().any(|k| k.eq_ignore_ascii_case("Content-Type")) {
                        hs.insert(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_static("application/x-www-form-urlencoded"));
                        req_hs.insert("Content-Type".into(), "application/x-www-form-urlencoded".into());
                    }

                    // Inject current cookies
                    let cookie_str: String = cookie_map.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("; ");
                    if !cookie_str.is_empty() && !req_hs.keys().any(|k| k.eq_ignore_ascii_case("Cookie")) {
                        if let Ok(hv) = reqwest::header::HeaderValue::from_str(&cookie_str) {
                            hs.insert(reqwest::header::COOKIE, hv);
                            req_hs.insert("Cookie".into(), cookie_str.clone());
                        }
                    }

                    // Auto-add Origin header if not provided
                    if !req_hs.keys().any(|k| k.eq_ignore_ascii_case("Origin")) {
                        if let Ok(parsed) = reqwest::Url::parse(&current_url) {
                            if let Some(host) = parsed.host_str() {
                                let origin = format!("{}://{}", parsed.scheme(), host);
                                if let Ok(hv) = reqwest::header::HeaderValue::from_str(&origin) {
                                    hs.insert(reqwest::header::ORIGIN, hv);
                                    req_hs.insert("Origin".into(), origin);
                                }
                            }
                        }
                    }

                    let mut custom_boundary = None;
                    for (k, v) in &req_hs {
                        if k.eq_ignore_ascii_case("Content-Type") {
                            if let Some(idx) = v.to_lowercase().find("boundary=") {
                                let b = &v[idx + 9..];
                                custom_boundary = Some(b.trim_matches(|c| c == '"' || c == ' ' || c == ';').to_string());
                            }
                        }
                    }

                    let is_multipart = block.data.get("multipart_fields").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false);
                    if is_multipart {
                        hs.remove(reqwest::header::CONTENT_TYPE);
                        hs.remove(reqwest::header::CONTENT_LENGTH);
                    }

                    if redirect_count == 0 { req_hs_log = req_hs.clone(); }

                    // Build request - only send body on first request
                    let method = if redirect_count == 0 {
                        reqwest::Method::from_bytes(method_name.as_bytes()).unwrap_or(reqwest::Method::GET)
                    } else {
                        reqwest::Method::GET // Redirects always use GET
                    };
                    let mut rb = ctx.client.request(method.clone(), &current_url).headers(hs); // hs is moved here

                    if redirect_count == 0 {
                        let mut body_handled = false;
                        if let Some(multipart_fields_val) = block.data.get("multipart_fields") {
                            if let Ok(multipart_fields) = serde_json::from_value::<Vec<MultipartField>>(multipart_fields_val.clone()) {
                                if !multipart_fields.is_empty() {
                                    body_handled = true;
                                    if let Some(b) = custom_boundary {
                                        let manual_body = build_custom_multipart(multipart_fields, &b, &ctx);
                                        rb = rb.header("Content-Type", format!("multipart/form-data; boundary={}", b));
                                        request_body_log = String::from_utf8_lossy(&manual_body).to_string();
                                        rb = rb.body(manual_body);
                                    } else {
                                        let mut form = reqwest_multipart::Form::new();
                                        let mut log_parts = Vec::new();
                                        for field in multipart_fields {
                                            if let Some(filename) = field.filename {
                                                if let Ok(bytes) = BASE64_STANDARD.decode(&field.value) {
                                                    let content_type = field.content_type.unwrap_or_else(|| "application/octet-stream".to_string());
                                                    let part = reqwest_multipart::Part::bytes(bytes)
                                                        .file_name(filename.clone())
                                                        .mime_str(&content_type).unwrap(); // Use unwrap after providing default
                                                    form = form.part(field.name.clone(), part);
                                                    log_parts.push(format!("{}: [FILE: {}]", field.name, filename));
                                                } else {
                                                    log_and_emit(&mut ctx, "Request", &format!("Failed to base64 decode multipart field: {}", field.name), "Error", None, bid.clone(), block_start_time);
                                                }
                                            } else {
                                                let field_val = ctx.replace_vars(&field.value);
                                                let mut part = reqwest_multipart::Part::text(field_val.clone());
                                                if let Some(ct) = field.content_type {
                                                    part = part.mime_str(&ct).unwrap_or_else(|_| reqwest_multipart::Part::text(field_val.clone()));
                                                }
                                                form = form.part(field.name.clone(), part);
                                                log_parts.push(format!("{}: {}", field.name, field_val));
                                            }
                                        }
                                        rb = rb.multipart(form);
                                        request_body_log = format!("MULTIPART FORM DATA:\n{}", log_parts.join("\n"));
                                    }
                                }
                            } else {
                                log_and_emit(&mut ctx, "Request", "Failed to parse multipart fields from block data", "Error", None, bid.clone(), block_start_time);
                            }
                        }
                        if !body_handled && !body.is_empty() {
                            rb = rb.body(body.clone());
                        }
                    }

                    match rb.send().await {
                        Ok(res) => {
                            let st = res.status();
                            final_status = st.as_u16();
                            final_url = res.url().to_string();

                            // Capture headers
                            final_headers_map.clear();
                            final_headers_str.clear();
                            for (k, v) in res.headers() {
                                let val = v.to_str().unwrap_or("").to_string();
                                final_headers_str.push_str(&format!("{}: {}\n", k, val));
                                final_headers_map.insert(k.to_string(), val.clone());
                                let var_name = format!("HEADER_{}", k.as_str().to_uppercase().replace('-', "_"));
                                ctx.variables.insert(var_name, val.clone());
                            }

                            // Capture Location header
                            if let Some(loc) = final_headers_map.get("location") {
                                ctx.variables.insert("LOCATION".to_string(), loc.clone());
                            }

                            // Capture ALL Set-Cookie headers exactly like OpenBullet2
                            // OpenBullet2 parses: name=value from "name=value; Path=/; HttpOnly"
                            for cookie_header in res.headers().get_all(reqwest::header::SET_COOKIE) {
                                let value = cookie_header.to_str().unwrap_or("").trim();
                                if value.is_empty() { continue; }

                                // Find separator positions (OpenBullet2 style)
                                let separator_pos = value.find('=');
                                let end_cookie_pos = value.find(';');

                                if let Some(sep) = separator_pos {
                                    let cookie_name = value[..sep].trim().to_string();
                                    let cookie_value = if let Some(end) = end_cookie_pos {
                                        if end > sep + 1 {
                                            value[sep + 1..end].trim().to_string()
                                        } else {
                                            value[sep + 1..].trim().to_string()
                                        }
                                    } else {
                                        value[sep + 1..].trim().to_string()
                                    };

                                    if !cookie_name.is_empty() {
                                        cookie_map.insert(cookie_name.clone(), cookie_value.clone());
                                        final_res_cookies.insert(cookie_name, cookie_value);
                                    }
                                }
                            }

                            // Update COOKIES variable immediately (so it persists across redirects)
                            let cookies_str: String = cookie_map.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("; ");
                            ctx.variables.insert("COOKIES".into(), cookies_str);
                            for (ck, cv) in &cookie_map {
                                ctx.variables.insert(format!("COOKIE_{}", ck), cv.clone());
                            }

                            // Check if we should follow redirect
                            let is_redirect = st.is_redirection();
                            let has_location = final_headers_map.contains_key("location");

                            if is_redirect && has_location && auto_redirect && redirect_count < max_redirects {
                                // Follow the redirect
                                let location = final_headers_map.get("location").unwrap();
                                // Handle relative URLs
                                current_url = if location.starts_with("http") {
                                    location.clone()
                                } else if location.starts_with("/") {
                                    if let Ok(base) = reqwest::Url::parse(&current_url) {
                                        format!("{}://{}{}", base.scheme(), base.host_str().unwrap_or(""), location)
                                    } else {
                                        location.clone()
                                    }
                                } else {
                                    location.clone()
                                };
                                redirect_count += 1;
                                // Don't read body on redirect - continue to next iteration
                                continue;
                            }

                            // Final response - read body
                            if block.data.get("read_response").and_then(|v| v.as_bool()).unwrap_or(true) {
                                final_body = res.text().await.unwrap_or_default();
                            }
                            break;
                        }
                        Err(e) => {
                            log_and_emit(&mut ctx, "Request", &format!("Error: {}", e), "Error", None, bid.clone(), block_start_time);
                            ctx.bot_status = "ERROR".into();
                            had_error = true;
                            break;
                        }
                    }
                }

                if !had_error {
                    let st_code = final_status.to_string();
                    ctx.variables.insert("RAWSOURCE".into(), hex::encode(&final_body));
                    ctx.variables.insert("SOURCE".into(), final_body.clone());
                    ctx.variables.insert("STATUS".into(), st_code.clone());
                    ctx.variables.insert("URL".into(), final_url.clone());
                    ctx.variables.insert("RURL".into(), current_url.clone());
                    ctx.variables.insert("HEADERS".into(), final_headers_str.clone());

                    // Log cookie names for debugging
                    let cookie_names: Vec<&String> = cookie_map.keys().collect();

                    let rd = RequestDetails {
                        url: initial_url,
                        method: method_name,
                        request_headers: req_hs_log,
                        request_body: request_body_log,
                        response_status: final_status,
                        response_url: final_url.clone(),
                        response_headers: final_headers_map,
                        response_cookies: cookie_map.clone(), // Show ALL accumulated cookies
                        response_body: final_body.clone()
                    };
                    let source_preview = if final_body.len() > 30 { format!("{}...", &final_body[..30]) } else { final_body.clone() };
                    log_and_emit(&mut ctx, "Request", &format!("Status: {} (redirects: {}, source: {})", st_code, redirect_count, source_preview), if final_status >= 200 && final_status < 400 { "Success" } else { "Fail" }, Some(rd), bid, block_start_time);
                }
            }
            BlockType::Parse => {
                let src = ctx.variables.get(block.data.get("source").and_then(|v| v.as_str()).unwrap_or("SOURCE")).cloned().unwrap_or_default();
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("parsed").to_string();
                let capture = block.data.get("capture").and_then(|v| v.as_bool()).unwrap_or(false);
                let recursive = block.data.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false);
                let mode = block.data.get("mode").and_then(|v| v.as_str()).unwrap_or("LR");

                if mode == "JSON" {
                    if let Ok(json) = serde_json::from_str::<Value>(&src) {
                        if let Some(v) = extract_json_value(&json, block.data.get("json_path").and_then(|v| v.as_str()).unwrap_or("")) {
                            ctx.variables.insert(var_name.clone(), v.clone());
                            if capture { ctx.captured_data.push(format!("{} : {}", var_name, v)); }
                            log_and_emit(&mut ctx, "Parse", &format!("({}): {}", var_name, v), "Success", None, bid, block_start_time);
                        } else {
                            ctx.variables.insert(var_name.clone(), String::new());
                            log_and_emit(&mut ctx, "Parse", &format!("({}): JSON path not found (continuing)", var_name), "Warning", None, bid, block_start_time);
                        }
                    } else {
                        ctx.variables.insert(var_name.clone(), String::new());
                        log_and_emit(&mut ctx, "Parse", &format!("({}): Invalid JSON source (continuing)", var_name), "Warning", None, bid, block_start_time);
                    }
                } else if mode == "Regex" {
                    let pattern_raw = block.data.get("regex_pattern").and_then(|v| v.as_str()).unwrap_or("");
                    let pattern = ctx.replace_vars(pattern_raw);
                    let format = block.data.get("regex_output").and_then(|v| v.as_str()).unwrap_or("$1");
                    
                    let case_insensitive = block.data.get("regex_case_insensitive").and_then(|v| v.as_bool()).unwrap_or(false);
                    let dot_all = block.data.get("regex_dot_all").and_then(|v| v.as_bool()).unwrap_or(true);

                    let mut builder = regex::RegexBuilder::new(&pattern);
                    builder.case_insensitive(case_insensitive);
                    builder.multi_line(true);
                    builder.dot_matches_new_line(dot_all);

                    match builder.build() {
                        Ok(re) => {
                            if recursive {
                                let mut results = Vec::new();
                                for caps in re.captures_iter(&src) {
                                    let mut output = String::new();
                                    caps.expand(format, &mut output);
                                    results.push(output);
                                }
                                
                                if !results.is_empty() {
                                    let joined = results.join("\n");
                                    ctx.variables.insert(var_name.clone(), joined.clone());
                                    if capture { ctx.captured_data.push(format!("{} : {}", var_name, joined)); }
                                    log_and_emit(&mut ctx, "Parse", &format!("({}): Parsed {} items via Regex", var_name, results.len()), "Success", None, bid, block_start_time);
                                } else {
                                    ctx.variables.insert(var_name.clone(), String::new());
                                    log_and_emit(&mut ctx, "Parse", &format!("({}): No Regex matches found", var_name), "Warning", None, bid, block_start_time);
                                }
                            } else {
                                if let Some(caps) = re.captures(&src) {
                                    let mut output = String::new();
                                    caps.expand(format, &mut output);
                                    ctx.variables.insert(var_name.clone(), output.clone());
                                    if capture { ctx.captured_data.push(format!("{} : {}", var_name, output)); }
                                    log_and_emit(&mut ctx, "Parse", &format!("({}): {}", var_name, output), "Success", None, bid, block_start_time);
                                } else {
                                    ctx.variables.insert(var_name.clone(), String::new());
                                    log_and_emit(&mut ctx, "Parse", &format!("({}): Regex match not found", var_name), "Warning", None, bid, block_start_time);
                                }
                            }
                        }
                        Err(e) => {
                            ctx.variables.insert(var_name.clone(), String::new());
                            log_and_emit(&mut ctx, "Parse", &format!("({}): Invalid Regex: {}", var_name, e), "Error", None, bid, block_start_time);
                        }
                    }
                } else {
                    let l = ctx.replace_vars(block.data.get("left").and_then(|v| v.as_str()).unwrap_or(""));
                    let r = ctx.replace_vars(block.data.get("right").and_then(|v| v.as_str()).unwrap_or(""));

                    if recursive {
                        // Recursive mode: find all matches
                        let mut results: Vec<String> = Vec::new();
                        let mut search_start = 0;
                        let max_iterations = 1000;

                        for _ in 0..max_iterations {
                            if let Some(rel_start) = src[search_start..].find(&l) {
                                let abs_start = search_start + rel_start + l.len();
                                let rest = &src[abs_start..];
                                let val = if r.is_empty() { rest.to_string() } else { rest.split(&r).next().unwrap_or(rest).to_string() };
                                results.push(val.clone());
                                search_start = abs_start + val.len() + r.len();
                                if search_start >= src.len() { break; }
                            } else {
                                break;
                            }
                        }

                        if !results.is_empty() {
                            let joined = results.join("\n");
                            ctx.variables.insert(var_name.clone(), joined.clone());
                            if capture { ctx.captured_data.push(format!("{} : {}", var_name, joined)); }
                            log_and_emit(&mut ctx, "Parse", &format!("({}): Parsed {} items", var_name, results.len()), "Success", None, bid, block_start_time);
                        } else {
                            ctx.variables.insert(var_name.clone(), String::new());
                            log_and_emit(&mut ctx, "Parse", &format!("({}): No matches found (continuing)", var_name), "Warning", None, bid, block_start_time);
                        }
                    } else {
                        // Single match mode (original behavior)
                        if let Some(start) = src.find(&l) {
                            let rest = &src[start + l.len()..];
                            let val = if r.is_empty() { rest } else { rest.split(&r).next().unwrap_or(rest) };
                            ctx.variables.insert(var_name.clone(), val.to_string());
                            if capture { ctx.captured_data.push(format!("{} : {}", var_name, val)); }
                            log_and_emit(&mut ctx, "Parse", &format!("({}): {}", var_name, val), "Success", None, bid, block_start_time);
                        } else {
                            ctx.variables.insert(var_name.clone(), String::new());
                            log_and_emit(&mut ctx, "Parse", &format!("({}): Left string not found (continuing)", var_name), "Warning", None, bid, block_start_time);
                        }
                    }
                }
            }
            BlockType::KeyCheck => {
                let chains_val = block.data.get("keychains").cloned().unwrap_or_default();
                if let Ok(chains) = serde_json::from_value::<Vec<Keychain>>(chains_val) {
                    if !chains.is_empty() {
                        let mut matched = false;
                        for c in chains {
                            let src = ctx.variables.get(c.source.as_deref().unwrap_or("SOURCE")).cloned().unwrap_or_default();
                            let mut ok = match c.mode { KeychainMode::AND => true, _ => false };
                            for k in c.keys { let v = ctx.replace_vars(&k.value); let m = match k.condition { KeyCondition::Contains => src.contains(&v), KeyCondition::NotContains => !src.contains(&v), KeyCondition::Equal => src == v, _ => src != v }; match c.mode { KeychainMode::AND => { if !m { ok = false; break; } }, _ => { if m { ok = true; break; } } } }
                            if ok { ctx.bot_status = c.result_status.to_uppercase(); matched = true; let msg = format!("Match: {}", ctx.bot_status); log_and_emit(&mut ctx, "KeyCheck", &msg, "Success", None, bid, block_start_time); break; }
                        }
                        if !matched {
                            if block.data.get("ban_if_no_match").and_then(|v| v.as_bool()).unwrap_or(true) {
                                ctx.bot_status = "BAN".into();
                            } else {
                                ctx.bot_status = "NONE".into();
                            }
                        }
                    }
                }
                if ctx.bot_status != "SUCCESS" && ctx.bot_status != "NONE" { break; }
            }
            BlockType::TlsRequest => {
                // Support both field naming conventions for compatibility
                let url_raw = block.data.get("url")
                    .or_else(|| block.data.get("request_url"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("https://example.com");
                let url = smart_encode_url(ctx.replace_vars(url_raw));

                let method = ctx.replace_vars(
                    block.data.get("method")
                        .or_else(|| block.data.get("request_method"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("GET")
                ).to_uppercase();
                
                // Jitter configuration
                let with_jitter = block.data.get("with_jitter").and_then(|v| v.as_bool()).unwrap_or(false);

                // Body handling
                let is_byte_request = block.data.get("is_byte_request").and_then(|v| v.as_bool()).unwrap_or(false);
                let body_raw = block.data.get("request_body").and_then(|v| v.as_str()).unwrap_or("");
                let body = if body_raw.is_empty() { None } else { Some(ctx.replace_vars(body_raw)) };
                
                let tls_id_raw = block.data.get("tls_client_identifier")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                // Clean the identifier: trim whitespace, remove quotes, URL decode
                let mut tls_id = ctx.replace_vars(tls_id_raw)
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .replace("%5F", "_")
                    .replace("%20", " ")
                    .trim()
                    .to_lowercase();
                
                // Jitter: Random TLS identifier logic
                if tls_id.eq_ignore_ascii_case("random") || (with_jitter && tls_id.is_empty()) {
                    let high_quality_profiles = [
                        "chrome_120", "chrome_124", "chrome_131", "chrome_131_PSK", "chrome_133", "chrome_133_PSK",
                        "firefox_120", "firefox_123", "firefox_132", "firefox_133",
                        "safari_ios_17_0", "safari_ios_18_0"
                    ];
                    use rand::SeedableRng;
                    let mut rng = rand::rngs::StdRng::seed_from_u64(jitter_seed);
                    tls_id = high_quality_profiles.choose(&mut rng).unwrap_or(&"chrome_133").to_string();
                }



                // Helper for parsing comma separated lists with variable support
                let parse_list = |key: &str| -> Option<Vec<String>> {
                    block.data.get(key).and_then(|v| v.as_str()).map(|s| {
                        ctx.replace_vars(s).split(',')
                            .map(|item| item.trim().to_string())
                            .filter(|item| !item.is_empty())
                            .collect()
                    }).filter(|v: &Vec<String>| !v.is_empty())
                };

                // Construct Custom TLS Client
                let mut custom_tls = serde_json::Map::new();
                if let Some(ja3) = block.data.get("ja3_string").and_then(|v| v.as_str()) {
                    let ja3_val = ctx.replace_vars(ja3);
                    // JA3 string must have exactly 5 comma-separated parts to be valid
                    // Format: TLSVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
                    if !ja3_val.is_empty() && ja3_val.split(',').count() == 5 {
                        custom_tls.insert("ja3String".into(), Value::String(ja3_val));
                    }
                } // Correctly closed the if let Some(ja3) block.
                if let Some(algo) = block.data.get("cert_compression_algo").and_then(|v| v.as_str()) {
                    if !algo.is_empty() {
                        let val = ctx.replace_vars(algo);
                        custom_tls.insert("certCompressionAlgo".into(), Value::String(val));
                    }
                }
                if let Some(flow) = block.data.get("connection_flow").and_then(|v| v.as_str()) {
                    if let Ok(f) = ctx.replace_vars(flow).parse::<i64>() { custom_tls.insert("connectionFlow".into(), Value::Number(f.into())); }
                }
                if let Some(limit) = block.data.get("record_size_limit").and_then(|v| v.as_str()) {
                    if let Ok(l) = ctx.replace_vars(limit).parse::<i64>() { custom_tls.insert("recordSizeLimit".into(), Value::Number(l.into())); }
                }
                if let Some(mut v) = parse_list("supported_signature_algorithms") { 
                    if with_jitter {
                        use rand::{SeedableRng, seq::SliceRandom};
                        let mut rng = rand::rngs::StdRng::seed_from_u64(jitter_seed);
                        v.shuffle(&mut rng);
                    }
                    custom_tls.insert("supportedSignatureAlgorithms".into(), serde_json::to_value(v).unwrap()); 
                }
                if let Some(mut v) = parse_list("supported_delegated_credentials_algorithms") { 
                    if with_jitter {
                        use rand::{SeedableRng, seq::SliceRandom};
                        let mut rng = rand::rngs::StdRng::seed_from_u64(jitter_seed);
                        v.shuffle(&mut rng);
                    }
                    custom_tls.insert("supportedDelegatedCredentialsAlgorithms".into(), serde_json::to_value(v).unwrap()); 
                }
                if let Some(mut v) = parse_list("supported_versions") { 
                    if with_jitter {
                        use rand::{SeedableRng, seq::SliceRandom};
                        let mut rng = rand::rngs::StdRng::seed_from_u64(jitter_seed);
                        v.shuffle(&mut rng);
                    }
                    custom_tls.insert("supportedVersions".into(), serde_json::to_value(v).unwrap()); 
                }
                if let Some(v) = parse_list("key_share_curves") { custom_tls.insert("keyShareCurves".into(), serde_json::to_value(v).unwrap()); }
                if let Some(v) = parse_list("alpn_protocols") { custom_tls.insert("alpnProtocols".into(), serde_json::to_value(v).unwrap()); }
                if let Some(v) = parse_list("alps_protocols") { custom_tls.insert("alpsProtocols".into(), serde_json::to_value(v).unwrap()); }
                if let Some(v) = parse_list("pseudo_header_order") { custom_tls.insert("pseudoHeaderOrder".into(), serde_json::to_value(v).unwrap()); }
                if let Some(cipher_suites_str) = block.data.get("cipher_suites").and_then(|v| v.as_str()) {
                    let ciphers_raw = ctx.replace_vars(cipher_suites_str);
                    let mut v: Vec<String> = ciphers_raw.lines()
                        .flat_map(|line| line.split(','))
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    
                    if !v.is_empty() {
                        if with_jitter {
                            use rand::{SeedableRng, seq::SliceRandom};
                            let mut rng = rand::rngs::StdRng::seed_from_u64(jitter_seed);
                            v.shuffle(&mut rng);
                        }
                        custom_tls.insert("cipherSuites".into(), serde_json::to_value(v).unwrap());
                    }
                }
                if let Some(v) = parse_list("ech_candidate_payloads") { 
                    let uint_list: Vec<u16> = v.iter().filter_map(|s| s.parse().ok()).collect();
                    custom_tls.insert("ECHCandidatePayloads".into(), serde_json::to_value(uint_list).unwrap()); 
                }
                
                // Advanced Priority Objects
                if let Some(pf_str) = block.data.get("h2_priority_frames").and_then(|v| v.as_str()) {
                    let pf_val = ctx.replace_vars(pf_str);
                    if !pf_val.is_empty() {
                        let mut frames = Vec::new();
                        for frame_str in pf_val.split(',') {
                            let parts: Vec<&str> = frame_str.split(':').collect();
                            if parts.len() >= 3 {
                                let mut frame = serde_json::Map::new();
                                if let Ok(id) = parts[0].parse::<u32>() { frame.insert("streamID".into(), id.into()); }
                                
                                let mut param = serde_json::Map::new();
                                if let Ok(w) = parts[1].parse::<u32>() { param.insert("weight".into(), w.into()); }
                                if let Ok(d) = parts[2].parse::<u32>() { param.insert("streamDep".into(), d.into()); }
                                param.insert("exclusive".into(), false.into());
                                
                                frame.insert("priorityParam".into(), Value::Object(param));
                                frames.push(Value::Object(frame));
                            }
                        }
                        if !frames.is_empty() {
                            custom_tls.insert("priorityFrames".into(), Value::Array(frames));
                        }
                    }
                }

                if let Some(hp_val) = block.data.get("header_priority") {
                    let mut final_hp = Value::Null;
                    if hp_val.is_object() {
                        final_hp = hp_val.clone();
                    } else if let Some(hp_str) = hp_val.as_str() {
                        if let Ok(hp_obj) = serde_json::from_str::<Value>(&ctx.replace_vars(hp_str)) {
                            final_hp = hp_obj;
                        }
                    }

                    if final_hp.is_object() {
                        // Ensure nested structure for headerPriority too
                        let mut hp_map = final_hp.as_object().unwrap().clone();
                        if !hp_map.contains_key("priorityParam") && (hp_map.contains_key("weight") || hp_map.contains_key("streamDep")) {
                            let mut param = serde_json::Map::new();
                            if let Some(w) = hp_map.remove("weight") { param.insert("weight".into(), w); }
                            if let Some(d) = hp_map.remove("streamDep") { param.insert("streamDep".into(), d); }
                            if let Some(e) = hp_map.remove("exclusive") { param.insert("exclusive".into(), e); }
                            else { param.insert("exclusive".into(), false.into()); }
                            hp_map.insert("priorityParam".into(), Value::Object(param));
                        }
                        custom_tls.insert("headerPriority".into(), Value::Object(hp_map));
                    }
                }
                
                if let Some(val) = block.data.get("ech_candidate_cipher_suites") { custom_tls.insert("ECHCandidateCipherSuites".into(), val.clone()); }
                
                // H2 Settings
                if let Some(h2_str) = block.data.get("h2_settings_str").and_then(|v| v.as_str()) {
                    let mut h2_map = serde_json::Map::new();
                    for line in h2_str.lines() {
                        if let Some((k, v)) = line.split_once(':') {
                            let val_str = ctx.replace_vars(v.trim());
                            let final_val = if with_jitter {
                                parse_jitter_range(&val_str, jitter_seed).unwrap_or(0)
                            } else {
                                val_str.parse::<i64>().unwrap_or(0)
                            };
                            // Some versions expect string keys that are numeric IDs, some expect names.
                            // We keep the provided key name/ID.
                            h2_map.insert(k.trim().to_string(), Value::Number(final_val.into()));
                        }
                    }
                    if !h2_map.is_empty() { custom_tls.insert("h2Settings".into(), Value::Object(h2_map)); }
                }
                if let Some(v) = parse_list("h2_settings_order") { custom_tls.insert("h2SettingsOrder".into(), serde_json::to_value(v).unwrap()); }

                // Jitter: Window Update Increment
                if let Some(wu) = block.data.get("h2_window_update_increment").and_then(|v| v.as_str()) {
                    let val_str = ctx.replace_vars(wu);
                    let final_val = if with_jitter {
                        parse_jitter_range(&val_str, jitter_seed)
                    } else {
                        val_str.parse::<i64>().ok()
                    };
                    if let Some(v) = final_val {
                        custom_tls.insert("h2WindowUpdateIncrement".into(), Value::Number(v.into()));
                    }
                }

                // Extension Weaver Order Jitter
                if let Some(mut v) = parse_list("extension_order_str") {
                    if with_jitter {
                        use rand::{SeedableRng, seq::SliceRandom};
                        let mut rng = rand::rngs::StdRng::seed_from_u64(jitter_seed);
                        v.shuffle(&mut rng);
                    }
                    let uint_list: Vec<u16> = v.iter().filter_map(|s| s.parse().ok()).collect();
                    custom_tls.insert("extensionOrder".into(), serde_json::to_value(uint_list).unwrap());
                }

                // Transport Options - only include if user explicitly sets non-default values
                let mut transport = serde_json::Map::new();
                if block.data.get("disable_keep_alives").and_then(|v| v.as_bool()).unwrap_or(false) {
                    transport.insert("disableKeepAlives".into(), Value::Bool(true));
                }
                if block.data.get("disable_compression").and_then(|v| v.as_bool()).unwrap_or(false) {
                    transport.insert("disableCompression".into(), Value::Bool(true));
                }
                if let Some(m) = block.data.get("max_idle_conns").and_then(|v| v.as_str()) {
                    if let Ok(val) = ctx.replace_vars(m).parse::<i64>() { transport.insert("maxIdleConns".into(), Value::Number(val.into())); }
                }
                if let Some(it) = block.data.get("idle_conn_timeout").and_then(|v| v.as_str()) {
                    if let Ok(val) = ctx.replace_vars(it).parse::<i64>() { transport.insert("idleConnTimeout".into(), Value::Number(val.into())); }
                }

                // General options
                let follow_redirects = block.data.get("follow_redirects").and_then(|v| v.as_bool()).unwrap_or(false);
                let random_tls_extension_order = if with_jitter { true } else { block.data.get("random_tls_extension_order").and_then(|v| v.as_bool()).unwrap_or(false) };
                let insecure_skip_verify = block.data.get("insecure_skip_verify").and_then(|v| v.as_bool()).unwrap_or(false);
                let force_http1 = block.data.get("force_http1").and_then(|v| v.as_bool()).unwrap_or(false);
                let timeout_seconds = ctx.replace_vars(block.data.get("timeout_seconds_str").and_then(|v| v.as_str()).unwrap_or("30")).parse::<u64>().unwrap_or(30);
                
                let mut hs = HashMap::new();
                if let Some(h_str) = block.data.get("headers").and_then(|v| v.as_str()) {
                    for line in h_str.lines() {
                        if let Some((k, v)) = line.split_once(':') {
                            let mut val = ctx.replace_vars(v.trim());
                            hs.insert(k.trim().to_string(), val);
                        }
                    }
                }





                // Inject COOKIES variable as Cookie header
                if let Some(cookies) = ctx.variables.get("COOKIES") {
                    if !cookies.is_empty() {
                        if !hs.keys().any(|k| k.eq_ignore_ascii_case("Cookie")) {
                            hs.insert("Cookie".to_string(), cookies.clone());
                        }
                    }
                }

                let mut header_order: Vec<String> = hs.keys().cloned().collect();
                if block.data.get("randomize_header_order").and_then(|v| v.as_bool()).unwrap_or(true) {
                    use rand::seq::SliceRandom;
                    header_order.shuffle(&mut rand::rng());
                }

                let block_proxy_raw = block.data.get("proxy_url").and_then(|v| v.as_str()).unwrap_or("");
                let fp = if !block_proxy_raw.trim().is_empty() {
                    Some(format_proxy_to_url(&ctx.replace_vars(block_proxy_raw)))
                } else {
                    ctx.proxy.as_ref().map(|p| format_proxy_to_url(p))
                };

                let session_id = ctx.replace_vars(block.data.get("custom_session_id").and_then(|v| v.as_str()).unwrap_or(""));
                let final_session_id = if !session_id.is_empty() {
                    session_id
                } else {
                    ctx.tls_session_id.clone().unwrap_or_else(|| Uuid::new_v4().to_string())
                };

                // Determine mode: preset vs custom
                // - If tls_id is a valid preset name → use preset mode
                // - If tls_id indicates custom mode → use custom mode (if valid JA3 exists) or fallback to default
                let is_custom_mode = tls_id.is_empty()
                    || tls_id == "custom"
                    || tls_id == "none"
                    || tls_id == "manual"
                    || tls_id == "custom_profile"
                    || tls_id == "customprofile"
                    || tls_id.starts_with("custom");

                // Custom mode requires a valid JA3 string to build a complete TLS profile
                // Without JA3, the Go library can't construct a valid ClientHelloSpec
                let has_valid_ja3 = custom_tls.get("ja3String").is_some();
                let has_complete_custom = has_valid_ja3 && !custom_tls.is_empty();

                // Determine what to send:
                // 1. Custom mode with valid JA3: send custom settings, no identifier
                // 2. Preset mode: send preset identifier, no custom settings
                // 3. Fallback: use chrome_133
                let (final_identifier, final_custom_tls) = if is_custom_mode && has_complete_custom {
                    // Custom mode with complete settings
                    (None, Some(Value::Object(custom_tls.clone())))
                } else if !is_custom_mode && !tls_id.is_empty() {
                    // Preset mode
                    (Some(tls_id.clone()), None)
                } else {
                    // Fallback to default preset
                    (Some("chrome_133".to_string()), None)
                };

                let payload = StructuredTlsApiPayload {
                    tls_client_identifier: final_identifier,
                    follow_redirects,
                    with_default_cookie_jar: block.data.get("with_default_cookie_jar").and_then(|v| v.as_bool()).unwrap_or(true),
                    with_random_tls_extension_order: random_tls_extension_order,
                    session_id: final_session_id,
                    proxy_url: fp.clone(),
                    is_rotating_proxy: fp.is_some() && block.data.get("is_rotating_proxy").and_then(|v| v.as_bool()).unwrap_or(true),
                    header_order,
                    headers: hs.clone(),
                    insecure_skip_verify,
                    timeout_seconds,
                    timeout_milliseconds: 0,
                    request_url: url.clone(),
                    request_method: method.clone(),
                    request_body: body.clone(),
                    force_http1,
                    disable_http2: block.data.get("disable_http2").and_then(|v| v.as_bool()).unwrap_or(false),
                    disable_http3: block.data.get("disable_http3").and_then(|v| v.as_bool()).unwrap_or(false),
                    with_debug: block.data.get("with_debug").and_then(|v| v.as_bool()).unwrap_or(true),
                    disable_ipv6: block.data.get("disable_ipv6").and_then(|v| v.as_bool()).unwrap_or(false),
                    catch_panics: block.data.get("catch_panics").and_then(|v| v.as_bool()).unwrap_or(true),
                    certificate_pinning_hosts: None,
                    custom_tls_client: final_custom_tls,
                    transport_options: if transport.is_empty() { None } else { Some(Value::Object(transport)) },
                    is_byte_request,
                    is_byte_response: block.data.get("is_byte_response").and_then(|v| v.as_bool()).unwrap_or(false),
                    request_cookies: None,
                    request_host_override: block.data.get("request_host_override").and_then(|v| v.as_str()).map(|s| ctx.replace_vars(s)),
                    default_headers: None,
                    connect_headers: None,
                    disable_ipv4: block.data.get("disable_ipv4").and_then(|v| v.as_bool()).unwrap_or(false),
                    local_address: block.data.get("local_address").and_then(|v| v.as_str()).map(|s| ctx.replace_vars(s)),
                    server_name_overwrite: block.data.get("server_name_overwrite").and_then(|v| v.as_str()).map(|s| ctx.replace_vars(s)),
                    stream_output_block_size: None,
                    stream_output_eof_symbol: None,
                    stream_output_path: None,
                    without_cookie_jar: block.data.get("without_cookie_jar").and_then(|v| v.as_bool()).unwrap_or(false),
                };
                
                // Retrieve the global forwarder client, initializing it if necessary
                let forwarder_client = FORWARDER_CLIENT.get_or_init(|| {
                    reqwest::Client::builder()
                        .timeout(Duration::from_secs(40))
                        .pool_idle_timeout(Duration::from_secs(90))
                        .pool_max_idle_per_host(100)
                        .build()
                        .unwrap_or_default()
                });

                match forwarder_client.post("http://127.0.0.1:9090/api/forward").header("x-api-key", "my-auth-key-1").json(&payload).send().await {
                    Ok(res) => {
                        let full_text = res.text().await.unwrap_or_default();
                        
                        // Prepare partial RequestDetails showing the forwarder request
                        let mut forwarder_headers = HashMap::new();
                        forwarder_headers.insert("x-api-key".to_string(), "my-auth-key-1".to_string());
                        forwarder_headers.insert("Content-Type".to_string(), "application/json".to_string());

                        let payload_json = serde_json::to_string_pretty(&payload).unwrap_or_default();

                        let mut rd = RequestDetails { 
                            url: "http://127.0.0.1:9090/api/forward".to_string(), 
                            method: "POST".to_string(), 
                            request_headers: forwarder_headers, 
                            request_body: payload_json, 
                            response_status: 0, 
                            response_url: url.clone(), 
                            response_headers: HashMap::new(), 
                            response_cookies: HashMap::new(), 
                            response_body: full_text.clone() 
                        };

                        if let Ok(parsed) = serde_json::from_str::<StructuredTlsApiResponse>(&full_text) {
                            // Store session ID for cookie persistence across TLS requests
                            if !parsed.session_id.is_empty() {
                                ctx.tls_session_id = Some(parsed.session_id.clone());
                            }

                            let st = parsed.status;
                            let txt = parsed.body;
                            let final_url = if parsed.target.is_empty() { url.clone() } else { parsed.target.clone() };

                            if payload.is_byte_response {
                                ctx.variables.insert("RAWSOURCE".into(), txt.clone());
                                // Try to decode if possible, but SOURCE usually expects string
                                ctx.variables.insert("SOURCE".into(), txt.clone());
                            } else {
                                ctx.variables.insert("SOURCE".into(), txt.clone());
                            }

                            let mut hs_str = String::new();
                            for (k, v) in &parsed.headers { hs_str.push_str(&format!("{}: {}\n", k, v)); }
                            // Parse existing cookies into a map for proper updating (no duplicates)
                            let mut cookie_map: HashMap<String, String> = HashMap::new();
                            if let Some(existing) = ctx.variables.get("COOKIES") {
                                for pair in existing.split("; ") {
                                    if let Some((k, v)) = pair.split_once('=') {
                                        cookie_map.insert(k.trim().to_string(), v.trim().to_string());
                                    }
                                }
                            }
                            for (k, v) in &parsed.cookies { cookie_map.insert(k.clone(), v.clone()); }
                            let ck_str: String = cookie_map.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("; ");

                            ctx.variables.insert("SOURCE".into(), txt.clone());
                            ctx.variables.insert("STATUS".into(), st.to_string());
                            ctx.variables.insert("URL".into(), final_url.clone());
                            ctx.variables.insert("RURL".into(), url.clone());
                            ctx.variables.insert("HEADERS".into(), hs_str);
                            ctx.variables.insert("COOKIES".into(), ck_str);

                            if let Ok(cookies_json) = serde_json::to_string(&parsed.cookies) {
                                ctx.variables.insert("COOKIES_JSON".into(), cookies_json);
                            }

                            // Extract Location header for redirects (handles both string and array format)
                            if let Some(loc) = parsed.headers.get("Location").or_else(|| parsed.headers.get("location")) {
                                let location = if loc.starts_with('[') {
                                    // Parse as JSON array and get first element
                                    serde_json::from_str::<Vec<String>>(loc).ok().and_then(|v| v.into_iter().next()).unwrap_or_else(|| loc.clone())
                                } else {
                                    loc.clone()
                                };
                                ctx.variables.insert("LOCATION".into(), location);
                            }

                            // Store each header as individual variable: HEADER_<name>
                            for (hk, hv) in &parsed.headers {
                                let val = if hv.starts_with('[') {
                                    serde_json::from_str::<Vec<String>>(hv).ok().and_then(|v| v.into_iter().next()).unwrap_or_else(|| hv.clone())
                                } else {
                                    hv.clone()
                                };
                                ctx.variables.insert(format!("HEADER_{}", hk), val);
                            }

                            // Store each cookie as individual variable: COOKIE_<name>
                            for (ck, cv) in &cookie_map {
                                ctx.variables.insert(format!("COOKIE_{}", ck), cv.clone());
                            }

                            rd.response_status = st;
                            rd.response_body = txt.clone();
                            rd.response_headers = parsed.headers;
                            rd.response_cookies = parsed.cookies;
                            rd.response_url = final_url;

                            let source_preview = if txt.len() > 30 { format!("{}...", &txt[..30]) } else { txt.clone() };
                            log_and_emit(&mut ctx, "TlsRequest", &format!("Status: {} (redirects: 0, source: {})", st, source_preview), if st >= 200 && st < 300 { "Success" } else { "Fail" }, Some(rd), bid, block_start_time);
                        } else {
                            // Fallback to raw text unescaping if it's not a JSON object
                            let txt = try_unescape_json_string(&full_text);
                            ctx.variables.insert("SOURCE".into(), txt.clone());
                            rd.response_body = txt.clone();
                            // Set status to 200 if we got a response, even if non-JSON, or 0 if empty
                            rd.response_status = if full_text.is_empty() { 0 } else { 200 }; 
                            
                            let source_preview = if txt.len() > 30 { format!("{}...", &txt[..30]) } else { txt.clone() };
                            log_and_emit(&mut ctx, "TlsRequest", &format!("Status: 200 (redirects: 0, source: {})", source_preview), "Info", Some(rd), bid, block_start_time);
                        }
                    }
                    Err(e) => {
                        log_and_emit(&mut ctx, "TlsRequest", &format!("Forwarder Error: {}", e), "Error", None, bid, block_start_time);
                        ctx.bot_status = "ERROR".into();
                    }
                }
            }
            BlockType::TlsWreq => {
                // Support both field naming conventions for compatibility
                let url_raw = block.data.get("request_url")
                    .or_else(|| block.data.get("url"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("https://example.com");
                let initial_url = smart_encode_url(ctx.replace_vars(url_raw));

                let method_name = ctx.replace_vars(
                    block.data.get("request_method")
                        .or_else(|| block.data.get("method"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("GET")
                ).to_uppercase();

                let emulation_str = ctx.replace_vars(block.data.get("emulation").and_then(|v| v.as_str()).unwrap_or("chrome133"));
                let emulation = parse_wreq_emulation(&emulation_str);

                // Advanced options
                let follow_redirects = block.data.get("follow_redirects").and_then(|v| v.as_bool()).unwrap_or(true);
                let max_redirects = ctx.replace_vars(block.data.get("max_redirects_str").and_then(|v| v.as_str()).unwrap_or("10")).parse::<usize>().unwrap_or(10);
                let timeout_secs = ctx.replace_vars(block.data.get("timeout_seconds_str").and_then(|v| v.as_str()).unwrap_or("30")).parse::<u64>().unwrap_or(30);
                let force_http1 = block.data.get("force_http1").and_then(|v| v.as_bool()).unwrap_or(false);
                let _cookie_store_enabled = block.data.get("cookie_store").and_then(|v| v.as_bool()).unwrap_or(false); // We handle cookies manually now
                let randomize_header_order = block.data.get("randomize_header_order").and_then(|v| v.as_bool()).unwrap_or(false);



                // Parse user headers
                let mut user_headers: HashMap<String, String> = HashMap::new();
                if let Some(h_str) = block.data.get("headers").and_then(|v| v.as_str()) {
                    for line in h_str.lines() {
                        if let Some((k, v)) = line.split_once(':') {
                            let key = k.trim();
                            if !key.is_empty() {
                                let mut val = ctx.replace_vars(v.trim());
                                user_headers.insert(key.to_string(), val);
                            }
                        }
                    }
                }





                // Proxy handling
                let block_proxy_raw = block.data.get("proxy_url").and_then(|v| v.as_str()).unwrap_or("");
                let proxy_url = if !block_proxy_raw.trim().is_empty() {
                    Some(format_proxy_to_url(&ctx.replace_vars(block_proxy_raw)))
                } else {
                    ctx.proxy.as_ref().map(|p| format_proxy_to_url(p))
                };

                // Build Client (No auto-redirects, no internal cookie store - we manage it)
                let client_result: Result<wreq::Client, wreq::Error> = {
                    let mut builder = wreq::Client::builder()
                    .emulation(emulation)
                    .timeout(Duration::from_secs(timeout_secs))
                    .redirect(wreq::redirect::Policy::none()) // Manual redirects
                    .cookie_store(false); // Manual cookies

                    if force_http1 { builder = builder.http1_only(); }

                    if let Some(ref px) = proxy_url {
                        if let Ok(proxy) = wreq::Proxy::all(px) {
                            builder = builder.proxy(proxy);
                        }
                    }
                    builder.build()
                };

                match client_result {
                    Ok(client) => {
                        let mut current_url = initial_url.clone();
                        let mut redirect_count = 0;
                        let mut final_status: u16 = 0;
                        let mut final_headers_str = String::new();
                        let mut final_headers_map: HashMap<String, String> = HashMap::new();
                        let mut final_body = String::new();
                        let mut request_body_log = String::new();
                        let mut req_hs_log: HashMap<String, String> = HashMap::new();

                        // Initialize cookie map from existing variables
                        let mut cookie_map: HashMap<String, String> = HashMap::new();
                        if let Some(existing) = ctx.variables.get("COOKIES") {
                            for pair in existing.split("; ") {
                                if let Some((k, v)) = pair.split_once('=') {
                                    cookie_map.insert(k.trim().to_string(), v.trim().to_string());
                                }
                            }
                        }

                        let mut had_error = false;

                        // Start Redirect Loop
                        loop {
                            let mut headers_to_use = if redirect_count == 0 {
                                user_headers.clone()
                            } else {
                                // On redirect, clear most user headers, keep some basic ones if needed or rely on emulation
                                // For TlsWreq with emulation, we usually rely on the client to set standard headers.
                                // But if user provided custom headers, we might want to drop them on redirect (e.g. Content-Type).
                                HashMap::new() 
                            };

                            // Determine Method (GET on redirect)
                            let method = if redirect_count == 0 {
                                method_name.clone()
                            } else {
                                "GET".to_string()
                            };

                            // Auto-add Origin header if not provided (only for first request or if relevant)
                            if !headers_to_use.keys().any(|k| k.eq_ignore_ascii_case("Origin")) {
                                if let Ok(parsed) = reqwest::Url::parse(&current_url) {
                                    if let Some(host) = parsed.host_str() {
                                        let origin = format!("{}://{}", parsed.scheme(), host);
                                        headers_to_use.insert("Origin".into(), origin);
                                    }
                                }
                            }

                            // Inject Cookies
                            let cookie_str: String = cookie_map.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("; ");
                            if !cookie_str.is_empty() {
                                headers_to_use.insert("Cookie".to_string(), cookie_str.clone());
                            }

                            // Shuffle headers if needed
                            let headers_vec: Vec<_> = headers_to_use.iter().collect();
                            let headers_to_add: Vec<_> = if randomize_header_order {
                                use rand::seq::SliceRandom;
                                let mut shuffled = headers_vec;
                                shuffled.shuffle(&mut rand::rng());
                                shuffled
                            } else {
                                headers_vec
                            };

                            // Build Request
                            let mut req_builder = match method.as_str() {
                                "POST" => client.post(&current_url),
                                "PUT" => client.put(&current_url),
                                "DELETE" => client.delete(&current_url),
                                "PATCH" => client.patch(&current_url),
                                "HEAD" => client.head(&current_url),
                                _ => client.get(&current_url),
                            };

                            let is_multipart = block.data.get("multipart_fields").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false);
                            let mut custom_boundary = None;
                            
                            // Check for custom boundary in User Headers (only relevant if redirect_count == 0)
                            if redirect_count == 0 {
                                for (k, v) in &user_headers {
                                    if k.eq_ignore_ascii_case("Content-Type") {
                                        if let Some(idx) = v.to_lowercase().find("boundary=") {
                                            let b = &v[idx + 9..];
                                            custom_boundary = Some(b.trim_matches(|c| c == '"' || c == ' ' || c == ';').to_string());
                                        }
                                    }
                                }
                            }

                            for (k, v) in headers_to_add {
                                if k.eq_ignore_ascii_case("Host") || k.eq_ignore_ascii_case("Content-Length") { continue; }
                                // Drop Content-Type if we are building multipart manually later
                                if is_multipart && k.eq_ignore_ascii_case("Content-Type") { continue; }

                                if let Ok(hv) = wreq::header::HeaderValue::from_str(v) {
                                    if let Ok(hn) = wreq::header::HeaderName::from_bytes(k.as_bytes()) {
                                        req_builder = req_builder.header(hn, hv);
                                    }
                                }
                            }

                            if redirect_count == 0 {
                                req_hs_log = headers_to_use.clone();
                                
                                // Body Logic (Only on first request)
                                let mut body_handled = false;
                                if let Some(multipart_fields_val) = block.data.get("multipart_fields") {
                                    if let Ok(frontend_fields) = serde_json::from_value::<Vec<FrontendMultipartField>>(multipart_fields_val.clone()) {
                                        if !frontend_fields.is_empty() {
                                            body_handled = true;
                                            if let Some(b) = custom_boundary {
                                                let manual_body = build_custom_multipart_frontend(frontend_fields, &b, &ctx);
                                                req_builder = req_builder.header("Content-Type", format!("multipart/form-data; boundary={}", b));
                                                request_body_log = String::from_utf8_lossy(&manual_body).to_string();
                                                req_builder = req_builder.body(manual_body);
                                            } else {
                                                let mut form = wreq_multipart::Form::new();
                                                let mut log_parts = Vec::new();
                                                for field in frontend_fields {
                                                    if field.is_file {
                                                        if let Ok(bytes) = BASE64_STANDARD.decode(&field.value) {
                                                            let content_type = field.content_type.unwrap_or_else(|| "application/octet-stream".to_string());
                                                            let filename = field.filename.clone().unwrap_or_else(|| "upload".to_string());
                                                            let part = wreq_multipart::Part::bytes(bytes).file_name(filename.clone()).mime_str(&content_type).unwrap();
                                                            form = form.part(field.name.clone(), part);
                                                            log_parts.push(format!("{}: [FILE: {}]", field.name, filename));
                                                        } else {
                                                            log_and_emit(&mut ctx, "TlsWreq", &format!("Failed decode: {}", field.name), "Error", None, bid.clone(), block_start_time);
                                                            had_error = true;
                                                        }
                                                    } else {
                                                        let field_val = ctx.replace_vars(&field.value);
                                                        let mut part = wreq_multipart::Part::text(field_val.clone());
                                                        if let Some(ct) = field.content_type {
                                                            part = part.mime_str(&ct).unwrap_or_else(|_| wreq_multipart::Part::text(field_val.clone()));
                                                        }
                                                        form = form.part(field.name.clone(), part);
                                                        log_parts.push(format!("{}: {}", field.name, field_val));
                                                    }
                                                }
                                                if !had_error {
                                                    req_builder = req_builder.multipart(form);
                                                    request_body_log = format!("MULTIPART FORM DATA:\n{}", log_parts.join("\n"));
                                                }
                                            }
                                        }
                                    }
                                }
                                if !body_handled {
                                    if let Some(body_val) = block.data.get("request_body").and_then(|v| v.as_str()) {
                                        if !body_val.is_empty() {
                                            let final_body = ctx.replace_vars(body_val);
                                            req_builder = req_builder.body(final_body.clone());
                                            request_body_log = final_body;
                                        }
                                    }
                                }
                            }

                            if had_error {
                                log_and_emit(&mut ctx, "TlsWreq", "Skipped due to multipart build error", "Error", None, bid.clone(), block_start_time);
                                ctx.bot_status = "ERROR".into();
                                break;
                            }

                            // Execute Request
                            let req_result = req_builder.send().await;

                            match req_result {
                                Ok(res) => {
                                    let status = res.status();
                                    final_status = status.as_u16();
                                    
                                    // Capture Headers
                                    final_headers_map.clear();
                                    final_headers_str.clear();
                                    for (k, v) in res.headers().iter() {
                                        let val: String = v.to_str().unwrap_or("").to_string();
                                        final_headers_str.push_str(&format!("{}: {}\n", k.as_str(), val));
                                        final_headers_map.insert(k.as_str().to_string(), val.clone());
                                        let var_name = format!("HEADER_{}", k.as_str().to_uppercase().replace('-', "_"));
                                        ctx.variables.insert(var_name, val);
                                    }

                                    if let Some(loc) = final_headers_map.get("location") {
                                        ctx.variables.insert("LOCATION".to_string(), loc.clone());
                                    }

                                    // Capture Cookies (accumulate)
                                    for cookie_header in res.headers().get_all(wreq::header::SET_COOKIE).iter() {
                                        let value: &str = cookie_header.to_str().unwrap_or("").trim();
                                        if !value.is_empty() {
                                            // Simple parsing - robust enough for basic cases, similar to OpenBullet
                                            if let Some(sep) = value.find('=') {
                                                let name = value[..sep].trim().to_string();
                                                let end = value.find(';').unwrap_or(value.len());
                                                let val = value[sep + 1..end].trim().to_string();
                                                if !name.is_empty() {
                                                    cookie_map.insert(name.clone(), val.clone());
                                                    ctx.variables.insert(format!("COOKIE_{}", name), val);
                                                }
                                            }
                                        }
                                    }
                                    // Update COOKIES immediately
                                    let cookies_str = cookie_map.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("; ");
                                    ctx.variables.insert("COOKIES".into(), cookies_str);

                                    // Handle Redirects
                                    let is_redirect = status.is_redirection();
                                    let has_location = final_headers_map.contains_key("location");

                                    if is_redirect && has_location && follow_redirects && redirect_count < max_redirects {
                                        let location = final_headers_map.get("location").unwrap();
                                        
                                        // Handle relative URLs
                                        current_url = if location.starts_with("http") {
                                            location.clone()
                                        } else if location.starts_with("/") {
                                            if let Ok(base) = reqwest::Url::parse(&current_url) {
                                                format!("{}://{}{}", base.scheme(), base.host_str().unwrap_or(""), location)
                                            } else {
                                                location.clone()
                                            }
                                        } else {
                                            location.clone() // Assume absolute or handle complex relative later if needed
                                        };
                                        
                                        redirect_count += 1;
                                        continue; // Loop again with new URL
                                    }

                                    // Final Response
                                    final_body = res.text().await.unwrap_or_default();
                                    break; // Exit loop
                                }
                                Err(e) => {
                                    log_and_emit(&mut ctx, "TlsWreq", &format!("Request Error: {}", e), "Error", None, bid.clone(), block_start_time);
                                    ctx.bot_status = "ERROR".into();
                                    had_error = true;
                                    break;
                                }
                            }
                        } // end loop

                        if !had_error {
                            ctx.variables.insert("SOURCE".into(), final_body.clone());
                            ctx.variables.insert("STATUS".into(), final_status.to_string());
                            ctx.variables.insert("URL".into(), current_url.clone()); // Final URL
                            ctx.variables.insert("RURL".into(), current_url.clone()); // Standardize RURL as Final URL
                            ctx.variables.insert("HEADERS".into(), final_headers_str);
                            
                            // Capture BytesToBase64 raw source if needed (optional feature mentioned in memory)
                            let hex_body = hex::encode(&final_body); // This might be wrong if body is binary, but .text() was called.
                            // If we needed binary, we should have called .bytes() but wreq text() consumes body.
                            // For now, consistent with original implementation which used .text().
                            ctx.variables.insert("RAWSOURCE".into(), hex_body);

                            let rd = RequestDetails {
                                url: initial_url.clone(),
                                method: method_name.clone(),
                                request_headers: req_hs_log,
                                request_body: request_body_log,
                                response_status: final_status,
                                response_url: current_url,
                                response_headers: final_headers_map,
                                response_cookies: cookie_map,
                                response_body: final_body.clone()
                            };
                            let source_preview = if final_body.len() > 30 { format!("{}...", &final_body[..30]) } else { final_body.clone() };
                            log_and_emit(&mut ctx, "TlsWreq", &format!("Status: {} (redirects: {}, source: {})", final_status, redirect_count, source_preview), if final_status >= 200 && final_status < 400 { "Success" } else { "Fail" }, Some(rd), bid, block_start_time);
                        }
                    }
                    Err(e) => {
                        log_and_emit(&mut ctx, "TlsWreq", &format!("Client Build Error: {}", e), "Error", None, bid, block_start_time);
                        ctx.bot_status = "ERROR".into();
                    }
                }
            }
            BlockType::Hash => {
                let algo = block.data.get("algorithm").and_then(|v| v.as_str()).unwrap_or("SHA256");
                let inp = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let b = inp.as_bytes();
                let res = match algo { "MD4" => format!("{:x}", { let mut h = Md4::new(); h.update(b); h.finalize() }), "MD5" => format!("{:x}", { let mut h = Md5::new(); h.update(b); h.finalize() }), "SHA1" => format!("{:x}", { let mut h = Sha1::new(); h.update(b); h.finalize() }), "SHA256" => format!("{:x}", { let mut h = Sha256::new(); h.update(b); h.finalize() }), "SHA384" => format!("{:x}", { let mut h = Sha384::new(); h.update(b); h.finalize() }), _ => format!("{:x}", { let mut h = Sha512::new(); h.update(b); h.finalize() }) };
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("hashed");
                ctx.variables.insert(var_name.into(), res.clone());
                log_and_emit(&mut ctx, "Hash", &format!("({}): [{}] {}", var_name, algo, res), "Success", None, bid, block_start_time);
            }
            BlockType::RandomString => {
                let mask = block.data.get("mask").and_then(|v| v.as_str()).unwrap_or("");
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("random");
                let custom_charset = block.data.get("custom_charset").and_then(|v| v.as_str()).unwrap_or("");
                let mut result = String::new();
                let mut chars = mask.chars().peekable();
                let mut rng = rand::rng();
                while let Some(c) = chars.next() {
                    if c == '?' {
                        if let Some(&next_char) = chars.peek() {
                            let charset = match next_char { 'l' => "abcdefghijklmnopqrstuvwxyz", 'u' => "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 'd' => "0123456789", 'f' => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 's' => r##"!\"#$%&"()*+,-./:;<=>?@[\\]^_`{|}~"##, 'h' => "0123456789abcdef", 'H' => "0123456789ABCDEF", 'm' => "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 'n' => "abcdefghijklmnopqrstuvwxyz0123456789", 'i' => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 'a' => r##"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&"()*+,-./:;<=>?@[\\]^_`{|}~"##, 'c' => custom_charset, _ => "" };
                            if !charset.is_empty() { let idx = rng.random_range(0..charset.len()); if let Some(c) = charset.chars().nth(idx) { result.push(c); } chars.next(); } else { result.push('?'); }
                        } else { result.push('?'); }
                    } else { result.push(c); }
                }
                ctx.variables.insert(var_name.into(), result.clone());
                log_and_emit(&mut ctx, "RandomString", &format!("({}): {}", var_name, result), "Success", None, bid, block_start_time);
            }
            BlockType::ConstantString => {
                let v = ctx.replace_vars(block.data.get("value").and_then(|v| v.as_str()).unwrap_or(""));
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("constString");
                ctx.variables.insert(var_name.into(), v.clone());
                log_and_emit(&mut ctx, "ConstantString", &format!("({}): {}", var_name, v), "Success", None, bid, block_start_time);
            }
            BlockType::ConstantList => {
                let l = block.data.get("list").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("constList");
                ctx.variables.insert(var_name.into(), l);
                log_and_emit(&mut ctx, "ConstantList", &format!("({}): [List set]", var_name), "Success", None, bid, block_start_time);
            }
            BlockType::GetRandomItem => {
                let l_var = block.data.get("list_variable").and_then(|v| v.as_str()).unwrap_or("constList");
                let item = if let Some(content) = ctx.variables.get(l_var) { let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect(); if !lines.is_empty() { Some(lines[rand::rng().random_range(0..lines.len())].to_string()) } else { None } } else { None };
                if let Some(val) = item { 
                    let out_var = block.data.get("output_variable").and_then(|v| v.as_str()).unwrap_or("randomItem").to_string(); 
                    ctx.variables.insert(out_var.clone(), val.clone()); 
                    log_and_emit(&mut ctx, "GetRandomItem", &format!("({}): {}", out_var, val), "Success", None, bid, block_start_time); 
                }
            }
            BlockType::CurrentUnixTime => {
                let ts = chrono::Utc::now().timestamp().to_string();
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("unixTime");
                ctx.variables.insert(var_name.into(), ts.clone());
                log_and_emit(&mut ctx, "CurrentUnixTime", &format!("({}): {}", var_name, ts), "Success", None, bid, block_start_time);
            }
            BlockType::DateToUnixTime => {
                let inp = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let fmt = block.data.get("format").and_then(|v| v.as_str()).unwrap_or("%Y-%m-%d %H:%M:%S");
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("unixTime");
                if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&inp, fmt) { 
                    let ts = dt.and_utc().timestamp().to_string(); 
                    ctx.variables.insert(var_name.into(), ts.clone()); 
                    log_and_emit(&mut ctx, "DateToUnixTime", &format!("({}): {}", var_name, ts), "Success", None, bid, block_start_time); 
                }
            }
            BlockType::UnixTimeToDate => {
                let inp = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let fmt = block.data.get("format").and_then(|v| v.as_str()).unwrap_or("%Y-%m-%d %H:%M:%S");
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("date");
                if let Ok(ts) = inp.parse::<i64>() { if let Some(dt) = chrono::DateTime::from_timestamp(ts, 0) { let ds = dt.format(fmt).to_string(); ctx.variables.insert(var_name.into(), ds.clone()); log_and_emit(&mut ctx, "UnixTimeToDate", &format!("({}): {}", var_name, ds), "Success", None, bid, block_start_time); } }
            }
            BlockType::UnixTimeToIso8601 => {
                let inp = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("iso8601");
                if let Ok(ts) = inp.parse::<i64>() { if let Some(dt) = chrono::DateTime::from_timestamp(ts, 0) { let iso = dt.to_rfc3339(); ctx.variables.insert(var_name.into(), iso.clone()); log_and_emit(&mut ctx, "UnixTimeToIso8601", &format!("({}): {}", var_name, iso), "Success", None, bid, block_start_time); } }
            }
            BlockType::Base64Encode => {
                let e = BASE64_STANDARD.encode(&ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or("")));
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("base64");
                ctx.variables.insert(var_name.into(), e.clone());
                log_and_emit(&mut ctx, "Base64Encode", &format!("({}): {}", var_name, e), "Success", None, bid, block_start_time);
            }
            BlockType::Base64Decode => {
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("utf8");
                if let Ok(b) = BASE64_STANDARD.decode(&ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""))) { if let Ok(s) = String::from_utf8(b) { ctx.variables.insert(var_name.into(), s.clone()); log_and_emit(&mut ctx, "Base64Decode", &format!("({}): {}", var_name, s), "Success", None, bid, block_start_time); } }
            }

            BlockType::GenerateFirefoxUA => {
                let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:112.0) Gecko/20100101 Firefox/112.0".to_string();
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("userAgent");
                ctx.variables.insert(var_name.into(), ua.clone());
                log_and_emit(&mut ctx, "GenerateFirefoxUA", &format!("({}): {}", var_name, ua), "Success", None, bid, block_start_time);
            }
            BlockType::GenerateState => {
                let v = generate_random_crypto_string(16);
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("state");
                ctx.variables.insert(var_name.into(), v.clone());
                log_and_emit(&mut ctx, "GenerateState", &format!("({}): {}", var_name, v), "Success", None, bid, block_start_time);
            }
            BlockType::GenerateNonce => {
                let v = generate_random_crypto_string(16);
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("nonce");
                ctx.variables.insert(var_name.into(), v.clone());
                log_and_emit(&mut ctx, "GenerateNonce", &format!("({}): {}", var_name, v), "Success", None, bid, block_start_time);
            }
            BlockType::Delay => {
                let ms_str = ctx.replace_vars(block.data.get("milliseconds").and_then(|v| v.as_str()).unwrap_or("1000"));
                let ms = ms_str.parse::<u64>().unwrap_or(1000);
                log_and_emit(&mut ctx, "Delay", &format!("Waiting {} ms...", ms), "Info", None, bid.clone(), block_start_time);
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            BlockType::JumpLabel => {
                let label = block.data.get("label").and_then(|v| v.as_str()).unwrap_or("LABEL");
                log_and_emit(&mut ctx, "JumpLabel", &format!("#{}", label), "Info", None, bid, block_start_time);
            }
            BlockType::JumpIF => {
                let source_var = block.data.get("source").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("SOURCE");
                let condition = block.data.get("condition").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or("Contains");
                let value = ctx.replace_vars(block.data.get("value").and_then(|v| v.as_str()).unwrap_or(""));
                let target = block.data.get("target").and_then(|v| v.as_str()).unwrap_or("");
                let source_val = ctx.variables.get(source_var).cloned().unwrap_or_default();

                let matches = match condition {
                    "Contains" => source_val.contains(&value),
                    "NotContains" => !source_val.contains(&value),
                    "Equal" => source_val == value,
                    "NotEqual" => source_val != value,
                    _ => false,
                };

                if matches {
                    if let Some(&target_idx) = labels.get(target) {
                        log_and_emit(&mut ctx, "JumpIF", &format!("Condition met: {} {} \"{}\", jumping to #{}", source_var, condition, value, target), "Success", None, bid, block_start_time);
                        block_idx = target_idx;
                        continue; // Skip the increment at the end
                    } else {
                        log_and_emit(&mut ctx, "JumpIF", &format!("Label #{} not found!", target), "Error", None, bid, block_start_time);
                    }
                } else {
                    log_and_emit(&mut ctx, "JumpIF", &format!("Condition not met: {} {} \"{}\"", source_var, condition, value), "Info", None, bid, block_start_time);
                }
            }
            BlockType::Script => {
                let script = block.data.get("script").and_then(|v| v.as_str()).unwrap_or("");
                let mut engine = RhaiEngine::new();
                // HTTP functions capturing context proxy
                let proxy_clone = ctx.proxy.clone();
                let proxy_clone2 = ctx.proxy.clone();
                engine.register_fn("http_get", move |url: &str| {
                    rhai_http_get(url, proxy_clone.as_deref())
                });
                engine.register_fn("http_post", move |url: &str, body: &str| {
                    rhai_http_post(url, body, proxy_clone2.as_deref())
                });
                // UUID/GUID functions
                engine.register_fn("uuid4", rhai_uuid4);
                engine.register_fn("guid", rhai_guid);
                // Random functions
                engine.register_fn("random_int", rhai_random_int);
                // Encoding functions
                engine.register_fn("base64_encode", rhai_base64_encode);
                engine.register_fn("base64_decode", rhai_base64_decode);
                engine.register_fn("url_encode", rhai_url_encode);
                engine.register_fn("url_decode", rhai_url_decode);
                // Hash functions
                engine.register_fn("md5", rhai_md5);
                engine.register_fn("sha256", rhai_sha256);
                let mut scope = Scope::new();

                for (k, v) in &ctx.variables {
                    scope.push(k.clone(), v.clone());
                }

                match engine.eval_with_scope::<()>(&mut scope, script) {
                    Ok(_) => {
                        for (k, v, _) in scope.iter() {
                            ctx.variables.insert(k.to_string(), v.to_string());
                        }
                        log_and_emit(&mut ctx, "Script", "Script executed successfully", "Success", None, bid, block_start_time);
                    }
                    Err(e) => {
                        log_and_emit(&mut ctx, "Script", &format!("Script error: {}", e), "Error", None, bid, block_start_time);
                        ctx.bot_status = "ERROR".into();
                    }
                }
            }

            BlockType::Replace => {
                let source_var = block.data.get("source").and_then(|v| v.as_str()).unwrap_or("SOURCE");
                let source_val = ctx.variables.get(source_var).cloned().unwrap_or_default();
                let to_replace = ctx.replace_vars(block.data.get("to_replace").and_then(|v| v.as_str()).unwrap_or(""));
                let replacement = ctx.replace_vars(block.data.get("replacement").and_then(|v| v.as_str()).unwrap_or(""));
                let result = source_val.replace(&to_replace, &replacement);
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("replaced");
                ctx.variables.insert(var_name.into(), result.clone());
                log_and_emit(&mut ctx, "Replace", &format!("({}): Replaced \"{}\" with \"{}\"", var_name, to_replace, replacement), "Success", None, bid, block_start_time);
            }
            BlockType::ToLowercase => {
                let input = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let result = input.to_lowercase();
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("lowercase");
                ctx.variables.insert(var_name.into(), result.clone());
                log_and_emit(&mut ctx, "ToLowercase", &format!("({}): {}", var_name, result), "Success", None, bid, block_start_time);
            }
            BlockType::ToUppercase => {
                let input = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let result = input.to_uppercase();
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("uppercase");
                ctx.variables.insert(var_name.into(), result.clone());
                log_and_emit(&mut ctx, "ToUppercase", &format!("({}): {}", var_name, result), "Success", None, bid, block_start_time);
            }
            BlockType::Translate => {
                let input = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let translations_str = block.data.get("translations").and_then(|v| v.as_str()).unwrap_or("");
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("translated");
                let use_original = block.data.get("use_original").and_then(|v| v.as_bool()).unwrap_or(true);
                
                let mut translated_value = None;
                for line in translations_str.lines() {
                    let parts: Vec<&str> = if line.contains(':') {
                        line.splitn(2, ':').collect()
                    } else if line.contains('=') {
                        line.splitn(2, '=').collect()
                    } else {
                        continue;
                    };
                    
                    if parts.len() == 2 {
                        let k = parts[0].trim();
                        let v = parts[1].trim();
                        if k == input {
                            translated_value = Some(v.to_string());
                            break;
                        }
                    }
                }
                
                let result = translated_value.unwrap_or_else(|| {
                    if use_original { input.clone() } else { String::new() }
                });
                
                ctx.variables.insert(var_name.into(), result.clone());
                log_and_emit(&mut ctx, "Translate", &format!("({}): {}", var_name, result), "Success", None, bid, block_start_time);
            }
            BlockType::UrlEncode => {
                let inp = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let encoded: String = inp.chars().map(|c| { match c { 'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(), _ => format!("%{:02X}", c as u8) } }).collect();
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("urlEncoded");
                ctx.variables.insert(var_name.into(), encoded.clone());
                log_and_emit(&mut ctx, "UrlEncode", &format!("({}): {}", var_name, encoded), "Success", None, bid, block_start_time);
            }
            BlockType::UrlDecode => {
                let inp = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let decoded = urlencoding::decode(&inp).unwrap_or_else(|_| inp.clone().into()).into_owned();
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("urlDecoded");
                ctx.variables.insert(var_name.into(), decoded.clone());
                log_and_emit(&mut ctx, "UrlDecode", &format!("({}): {}", var_name, decoded), "Success", None, bid, block_start_time);
            }
            BlockType::RandomInteger => {
                let min = ctx.replace_vars(block.data.get("min").and_then(|v| v.as_str()).unwrap_or("0")).parse::<i64>().unwrap_or(0);
                let max = ctx.replace_vars(block.data.get("max").and_then(|v| v.as_str()).unwrap_or("100")).parse::<i64>().unwrap_or(100);
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("randomInt").to_string();
                let val = if min >= max { min } else { rand::rng().random_range(min..=max) };
                ctx.variables.insert(var_name.clone(), val.to_string());
                log_and_emit(&mut ctx, "RandomInteger", &format!("({}): {}", var_name, val), "Success", None, bid, block_start_time);
            }
            BlockType::ZipLists => {
                let list1_raw = ctx.variables.get(block.data.get("list1").and_then(|v| v.as_str()).unwrap_or("")).cloned().unwrap_or_default();
                let list2_raw = ctx.variables.get(block.data.get("list2").and_then(|v| v.as_str()).unwrap_or("")).cloned().unwrap_or_default();
                let separator = ctx.replace_vars(block.data.get("separator").and_then(|v| v.as_str()).unwrap_or(":"));
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("zipped").to_string();
                
                let l1: Vec<&str> = list1_raw.lines().collect();
                let l2: Vec<&str> = list2_raw.lines().collect();
                let mut zipped = Vec::new();
                for i in 0..l1.len().min(l2.len()) {
                    zipped.push(format!("{}{}{}", l1[i], separator, l2[i]));
                }
                let result = zipped.join("\n");
                ctx.variables.insert(var_name.clone(), result);
                log_and_emit(&mut ctx, "ZipLists", &format!("Zipped {} items into {}", zipped.len(), var_name), "Success", None, bid, block_start_time);
            }
            BlockType::BytesToBase64 => {
                let input = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("base64").to_string();
                // Assume input is hex string or raw bytes if we had them, but ctx.variables only stores strings.
                // If it's a hex string (common for binary data in variables):
                let bytes = if let Ok(b) = hex::decode(input.trim()) {
                    b
                } else {
                    input.as_bytes().to_vec()
                };
                let result = BASE64_STANDARD.encode(bytes);
                ctx.variables.insert(var_name.clone(), result);
                log_and_emit(&mut ctx, "BytesToBase64", &format!("Encoded to Base64 in {}", var_name), "Success", None, bid, block_start_time);
            }

            BlockType::ForgeRockAuth => {
                let mut source_var = block.data.get("source").and_then(|v| v.as_str()).unwrap_or("SOURCE");
                if source_var.is_empty() { source_var = "SOURCE"; }
                
                let source_json = ctx.variables.get(source_var).cloned().unwrap_or_default();
                let username_var = block.data.get("username_var").and_then(|v| v.as_str()).unwrap_or("USER");
                let password_var = block.data.get("password_var").and_then(|v| v.as_str()).unwrap_or("PASS");
                let out_var = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("forgeRockPayload");
                
                let solve_pow = block.data.get("solve_pow").and_then(|v| v.as_bool()).unwrap_or(false);
                let id_token_user = block.data.get("id_token_user").and_then(|v| v.as_str()).unwrap_or("IDToken3");
                let id_token_pass = block.data.get("id_token_pass").and_then(|v| v.as_str()).unwrap_or("IDToken4");
                let id_token_nonce = block.data.get("id_token_nonce").and_then(|v| v.as_str()).unwrap_or("IDToken1");
                let id_token_extra = block.data.get("id_token_extra").and_then(|v| v.as_str()).unwrap_or("IDToken5");
                let extra_val = ctx.replace_vars(block.data.get("extra_value").and_then(|v| v.as_str()).unwrap_or("2"));

                let user_val = ctx.variables.get(username_var).cloned().unwrap_or_default();
                let pass_val = ctx.variables.get(password_var).cloned().unwrap_or_default();

                if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&source_json) {
                    let mut solved_nonce = String::new();
                    
                    if solve_pow {
                        if let Some(callbacks) = json.get("callbacks").and_then(|c| c.as_array()) {
                            for cb in callbacks {
                                if let Some(outputs) = cb.get("output").and_then(|o| o.as_array()) {
                                    for output in outputs {
                                        if let Some(js_val) = output.get("value").and_then(|v| v.as_str()) {
                                            if js_val.contains("var work =") {
                                                // Extract using Regex for robustness (matches Python)
                                                let re_work = regex::Regex::new(r#"var work = "(.*?)";"#).unwrap();
                                                let re_diff = regex::Regex::new(r#"var difficulty = (\d+);"#).unwrap();
                                                
                                                let work = re_work.captures(js_val).and_then(|c| c.get(1)).map(|m| m.as_str()).unwrap_or("");
                                                let difficulty = re_diff.captures(js_val).and_then(|c| c.get(1)).and_then(|m| m.as_str().parse::<usize>().ok()).unwrap_or(0);
                                                
                                                if !work.is_empty() && difficulty > 0 {
                                                    let nonce = solve_pow_sha1(work, difficulty);
                                                    solved_nonce = nonce.to_string();
                                                    log_and_emit(&mut ctx, "ForgeRockAuth", &format!("Solved PoW (Work: {}, Diff: {}): Nonce: {}", work, difficulty, solved_nonce), "Info", None, bid.clone(), block_start_time);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if let Some(callbacks) = json.get_mut("callbacks").and_then(|c| c.as_array_mut()) {
                        for cb in callbacks {
                            let cb_outputs = cb.get("output").and_then(|o| o.as_array()).cloned();

                            if let Some(inputs) = cb.get_mut("input").and_then(|i| i.as_array_mut()) {
                                for input in inputs {
                                    if let Some(name) = input.get("name").and_then(|n| n.as_str()) {
                                        if name == id_token_nonce && !solved_nonce.is_empty() {
                                            input["value"] = serde_json::Value::String(solved_nonce.clone());
                                        } else if name == id_token_user {
                                            input["value"] = serde_json::Value::String(user_val.clone());
                                        } else if name == id_token_pass {
                                            input["value"] = serde_json::Value::String(pass_val.clone());
                                        } else if name == id_token_extra {
                                            input["value"] = serde_json::Value::String(extra_val.clone());
                                        } else {
                                            if let Some(ref outputs) = cb_outputs {
                                                if let Some(out_v) = outputs.get(0).and_then(|ov| ov.get("value")) {
                                                    input["value"] = out_v.clone();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        // Clean payload: only authId and callbacks
                        let clean_payload = serde_json::json!({
                            "authId": json.get("authId").unwrap_or(&serde_json::Value::Null),
                            "callbacks": json.get("callbacks").unwrap_or(&serde_json::Value::Array(vec![]))
                        });

                        let payload_str = clean_payload.to_string();
                        ctx.variables.insert(out_var.to_string(), payload_str);
                        log_and_emit(&mut ctx, "ForgeRockAuth", &format!("Payload generated in <{}> (PoW: {})", out_var, if solved_nonce.is_empty() { "No" } else { "Yes" }), "Success", None, bid, block_start_time);
                    } else {
                        log_and_emit(&mut ctx, "ForgeRockAuth", "No callbacks found", "Error", None, bid.clone(), block_start_time);
                        ctx.bot_status = "ERROR".into();
                    }
                } else {
                    let preview = if source_json.len() > 100 { &source_json[..100] } else { &source_json };
                    let err_msg = if source_json.trim().is_empty() {
                        "JSON Input Source is empty. Check if the previous request failed.".to_string()
                    } else if source_json.trim().starts_with('<') {
                        format!("Received HTML instead of JSON. Check your URL and Headers! Preview: {}", preview)
                    } else {
                        format!("Invalid JSON format. Preview: {}", preview)
                    };
                    log_and_emit(&mut ctx, "ForgeRockAuth", &err_msg, "Error", None, bid.clone(), block_start_time);
                    ctx.bot_status = "ERROR".into();
                }
            }
            BlockType::HmacSign => {
                let algo = block.data.get("algorithm").and_then(|v| v.as_str()).unwrap_or("SHA256");
                let key_input = ctx.replace_vars(block.data.get("key").and_then(|v| v.as_str()).unwrap_or(""));
                let message = ctx.replace_vars(block.data.get("message").and_then(|v| v.as_str()).unwrap_or(""));
                let key_format = block.data.get("key_format").and_then(|v| v.as_str()).unwrap_or("utf8");
                let output_format = block.data.get("output_format").and_then(|v| v.as_str()).unwrap_or("hex");
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("hmac");

                let key_bytes: Vec<u8> = match key_format {
                    "hex" => hex::decode(&key_input).unwrap_or_else(|_| key_input.as_bytes().to_vec()),
                    "base64" => BASE64_STANDARD.decode(&key_input).unwrap_or_else(|_| key_input.as_bytes().to_vec()),
                    _ => key_input.as_bytes().to_vec(),
                };

                let result: String = match algo.to_uppercase().as_str() {
                    "SHA1" => {
                        type HmacSha1 = Hmac<Sha1>;
                        let mut mac = HmacSha1::new_from_slice(&key_bytes).expect("HMAC can take key of any size");
                        mac.update(message.as_bytes());
                        let res = mac.finalize().into_bytes();
                        match output_format {
                            "base64" => BASE64_STANDARD.encode(&res),
                            "base64url" => BASE64_URL_SAFE_NO_PAD.encode(&res),
                            _ => hex::encode(&res),
                        }
                    }
                    "SHA384" => {
                        type HmacSha384 = Hmac<Sha384>;
                        let mut mac = HmacSha384::new_from_slice(&key_bytes).expect("HMAC can take key of any size");
                        mac.update(message.as_bytes());
                        let res = mac.finalize().into_bytes();
                        match output_format {
                            "base64" => BASE64_STANDARD.encode(&res),
                            "base64url" => BASE64_URL_SAFE_NO_PAD.encode(&res),
                            _ => hex::encode(&res),
                        }
                    }
                    "SHA512" => {
                        type HmacSha512 = Hmac<Sha512>;
                        let mut mac = HmacSha512::new_from_slice(&key_bytes).expect("HMAC can take key of any size");
                        mac.update(message.as_bytes());
                        let res = mac.finalize().into_bytes();
                        match output_format {
                            "base64" => BASE64_STANDARD.encode(&res),
                            "base64url" => BASE64_URL_SAFE_NO_PAD.encode(&res),
                            _ => hex::encode(&res),
                        }
                    }
                    _ => { // Default to SHA256
                        type HmacSha256 = Hmac<Sha256>;
                        let mut mac = HmacSha256::new_from_slice(&key_bytes).expect("HMAC can take key of any size");
                        mac.update(message.as_bytes());
                        let res = mac.finalize().into_bytes();
                        match output_format {
                            "base64" => BASE64_STANDARD.encode(&res),
                            "base64url" => BASE64_URL_SAFE_NO_PAD.encode(&res),
                            _ => hex::encode(&res),
                        }
                    }
                };
                ctx.variables.insert(var_name.into(), result.clone());
                log_and_emit(&mut ctx, "HmacSign", &format!("({}): [{}] {}", var_name, algo, result), "Success", None, bid, block_start_time);
            }
            BlockType::AesEncrypt => {
                let key_input = ctx.replace_vars(block.data.get("key").and_then(|v| v.as_str()).unwrap_or(""));
                let iv_input = ctx.replace_vars(block.data.get("iv").and_then(|v| v.as_str()).unwrap_or(""));
                let plaintext = ctx.replace_vars(block.data.get("plaintext").and_then(|v| v.as_str()).unwrap_or(""));
                let key_format = block.data.get("key_format").and_then(|v| v.as_str()).unwrap_or("utf8");
                let output_format = block.data.get("output_format").and_then(|v| v.as_str()).unwrap_or("base64");
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("encrypted");

                let key_bytes: Vec<u8> = match key_format {
                    "hex" => hex::decode(&key_input).unwrap_or_else(|_| key_input.as_bytes().to_vec()),
                    "base64" => BASE64_STANDARD.decode(&key_input).unwrap_or_else(|_| key_input.as_bytes().to_vec()),
                    _ => key_input.as_bytes().to_vec(),
                };
                let iv_bytes: Vec<u8> = match key_format {
                    "hex" => hex::decode(&iv_input).unwrap_or_else(|_| iv_input.as_bytes().to_vec()),
                    "base64" => BASE64_STANDARD.decode(&iv_input).unwrap_or_else(|_| iv_input.as_bytes().to_vec()),
                    _ => iv_input.as_bytes().to_vec(),
                };

                let result: Result<String, String> = (|| {
                    if iv_bytes.len() != 16 {
                        return Err("IV must be 16 bytes for AES-CBC".to_string());
                    }
                    let plaintext_bytes = plaintext.as_bytes();
                    // Buffer needs to be large enough for plaintext + padding (up to 16 bytes)
                    let mut buffer = vec![0u8; plaintext_bytes.len() + 16];
                    buffer[..plaintext_bytes.len()].copy_from_slice(plaintext_bytes);

                    let ciphertext = if key_bytes.len() == 32 {
                        let cipher = Aes256CbcEnc::new_from_slices(&key_bytes, &iv_bytes).map_err(|e| e.to_string())?;
                        cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext_bytes.len()).map_err(|e| format!("{:?}", e))?
                    } else if key_bytes.len() == 16 {
                        let cipher = Aes128CbcEnc::new_from_slices(&key_bytes, &iv_bytes).map_err(|e| e.to_string())?;
                        cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, plaintext_bytes.len()).map_err(|e| format!("{:?}", e))?
                    } else {
                        return Err(format!("Key must be 16 bytes (AES-128) or 32 bytes (AES-256), got {} bytes", key_bytes.len()));
                    };

                    Ok(match output_format {
                        "hex" => hex::encode(ciphertext),
                        _ => BASE64_STANDARD.encode(ciphertext),
                    })
                })();

                match result {
                    Ok(encrypted) => {
                        ctx.variables.insert(var_name.into(), encrypted.clone());
                        let preview = if encrypted.len() > 50 { format!("{}...", &encrypted[..50]) } else { encrypted.clone() };
                        log_and_emit(&mut ctx, "AesEncrypt", &format!("({}): {}", var_name, preview), "Success", None, bid, block_start_time);
                    }
                    Err(e) => {
                        log_and_emit(&mut ctx, "AesEncrypt", &format!("Error: {}", e), "Error", None, bid, block_start_time);
                        ctx.bot_status = "ERROR".into();
                    }
                }
            }
            BlockType::AesDecrypt => {
                let key_input = ctx.replace_vars(block.data.get("key").and_then(|v| v.as_str()).unwrap_or(""));
                let iv_input = ctx.replace_vars(block.data.get("iv").and_then(|v| v.as_str()).unwrap_or(""));
                let ciphertext_input = ctx.replace_vars(block.data.get("ciphertext").and_then(|v| v.as_str()).unwrap_or(""));
                let key_format = block.data.get("key_format").and_then(|v| v.as_str()).unwrap_or("utf8");
                let input_format = block.data.get("input_format").and_then(|v| v.as_str()).unwrap_or("base64");
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("decrypted");

                let key_bytes: Vec<u8> = match key_format {
                    "hex" => hex::decode(&key_input).unwrap_or_else(|_| key_input.as_bytes().to_vec()),
                    "base64" => BASE64_STANDARD.decode(&key_input).unwrap_or_else(|_| key_input.as_bytes().to_vec()),
                    _ => key_input.as_bytes().to_vec(),
                };
                let iv_bytes: Vec<u8> = match key_format {
                    "hex" => hex::decode(&iv_input).unwrap_or_else(|_| iv_input.as_bytes().to_vec()),
                    "base64" => BASE64_STANDARD.decode(&iv_input).unwrap_or_else(|_| iv_input.as_bytes().to_vec()),
                    _ => iv_input.as_bytes().to_vec(),
                };
                let ciphertext_bytes: Vec<u8> = match input_format {
                    "hex" => hex::decode(&ciphertext_input).unwrap_or_default(),
                    _ => BASE64_STANDARD.decode(&ciphertext_input).unwrap_or_default(),
                };

                let result: Result<String, String> = (|| {
                    if iv_bytes.len() != 16 {
                        return Err("IV must be 16 bytes for AES-CBC".to_string());
                    }
                    let mut buffer = ciphertext_bytes.clone();

                    let decrypted = if key_bytes.len() == 32 {
                        let cipher = Aes256CbcDec::new_from_slices(&key_bytes, &iv_bytes).map_err(|e| e.to_string())?;
                        cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer).map_err(|e| format!("{:?}", e))?
                    } else if key_bytes.len() == 16 {
                        let cipher = Aes128CbcDec::new_from_slices(&key_bytes, &iv_bytes).map_err(|e| e.to_string())?;
                        cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer).map_err(|e| format!("{:?}", e))?
                    } else {
                        return Err(format!("Key must be 16 bytes (AES-128) or 32 bytes (AES-256), got {} bytes", key_bytes.len()));
                    };

                    String::from_utf8(decrypted.to_vec()).map_err(|e| e.to_string())
                })();

                match result {
                    Ok(decrypted) => {
                        ctx.variables.insert(var_name.into(), decrypted.clone());
                        log_and_emit(&mut ctx, "AesDecrypt", &format!("Decrypted: {}", if decrypted.len() > 50 { format!("{}...", &decrypted[..50]) } else { decrypted }), "Success", None, bid, block_start_time);
                    }
                    Err(e) => {
                        log_and_emit(&mut ctx, "AesDecrypt", &format!("Error: {}", e), "Error", None, bid, block_start_time);
                        ctx.bot_status = "ERROR".into();
                    }
                }
            }
            BlockType::Pbkdf2Derive => {
                let password = ctx.replace_vars(block.data.get("password").and_then(|v| v.as_str()).unwrap_or(""));
                let salt_input = ctx.replace_vars(block.data.get("salt").and_then(|v| v.as_str()).unwrap_or(""));
                let salt_format = block.data.get("salt_format").and_then(|v| v.as_str()).unwrap_or("utf8");
                let iterations: u32 = block.data.get("iterations").and_then(|v| v.as_u64()).unwrap_or(10000) as u32;
                let key_length: usize = block.data.get("key_length").and_then(|v| v.as_u64()).unwrap_or(32) as usize;
                let algo = block.data.get("algorithm").and_then(|v| v.as_str()).unwrap_or("SHA256");
                let output_format = block.data.get("output_format").and_then(|v| v.as_str()).unwrap_or("hex");
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("derived_key");

                let salt_bytes: Vec<u8> = match salt_format {
                    "hex" => hex::decode(&salt_input).unwrap_or_else(|_| salt_input.as_bytes().to_vec()),
                    "base64" => BASE64_STANDARD.decode(&salt_input).unwrap_or_else(|_| salt_input.as_bytes().to_vec()),
                    _ => salt_input.as_bytes().to_vec(),
                };

                let mut derived_key = vec![0u8; key_length];

                match algo.to_uppercase().as_str() {
                    "SHA1" => {
                        pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), &salt_bytes, iterations, &mut derived_key);
                    }
                    "SHA384" => {
                        pbkdf2::pbkdf2_hmac::<Sha384>(password.as_bytes(), &salt_bytes, iterations, &mut derived_key);
                    }
                    "SHA512" => {
                        pbkdf2::pbkdf2_hmac::<Sha512>(password.as_bytes(), &salt_bytes, iterations, &mut derived_key);
                    }
                    _ => { // Default SHA256
                        pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt_bytes, iterations, &mut derived_key);
                    }
                }

                let result = if output_format == "base64" { BASE64_STANDARD.encode(&derived_key) } else { hex::encode(&derived_key) };
                ctx.variables.insert(var_name.into(), result.clone());
                let preview = if result.len() > 32 { format!("{}...", &result[..32]) } else { result.clone() };
                log_and_emit(&mut ctx, "Pbkdf2Derive", &format!("({}): [{}] {} ({} iterations)", var_name, algo, preview, iterations), "Success", None, bid, block_start_time);
            }
            BlockType::RsaEncrypt => {
                let plaintext_b64 = ctx.replace_vars(block.data.get("plaintext").and_then(|v| v.as_str()).unwrap_or(""));
                let modulus_b64 = ctx.replace_vars(block.data.get("modulus").and_then(|v| v.as_str()).unwrap_or(""));
                let exponent_b64 = ctx.replace_vars(block.data.get("exponent").and_then(|v| v.as_str()).unwrap_or(""));
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("rsaEncrypted");

                match (|| -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
                    let plaintext = BASE64_STANDARD.decode(&plaintext_b64)?;
                    let modulus_bytes = BASE64_STANDARD.decode(&modulus_b64)?;
                    let exponent_bytes = BASE64_STANDARD.decode(&exponent_b64)?;

                    let n = BigUint::from_bytes_be(&modulus_bytes);
                    let e = BigUint::from_bytes_be(&exponent_bytes);

                    // Manual RSA encryption: ciphertext = plaintext^e mod n
                    // For raw RSA (no padding), convert plaintext to BigUint
                    let m = BigUint::from_bytes_be(&plaintext);

                    // Ensure message < modulus
                    if m >= n {
                        return Err("Plaintext too large for modulus".into());
                    }

                    let c = m.modpow(&e, &n);
                    let encrypted_bytes = c.to_bytes_be();

                    // Pad to modulus size
                    let mod_size = modulus_bytes.len();
                    let mut padded = vec![0u8; mod_size.saturating_sub(encrypted_bytes.len())];
                    padded.extend_from_slice(&encrypted_bytes);

                    Ok(BASE64_STANDARD.encode(&padded))
                })() {
                    Ok(result) => {
                        ctx.variables.insert(var_name.into(), result.clone());
                        log_and_emit(&mut ctx, "RsaEncrypt", &format!("Encrypted: {}...", &result[..32.min(result.len())]), "Success", None, bid, block_start_time);
                    }
                    Err(e) => {
                        log_and_emit(&mut ctx, "RsaEncrypt", &format!("Error: {}", e), "Error", None, bid, block_start_time);
                        ctx.bot_status = "ERROR".into();
                    }
                }
            }
            BlockType::Base64ToBytes => {
                let input = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("hexBytes");

                match BASE64_STANDARD.decode(&input) {
                    Ok(bytes) => {
                        let hex_str = hex::encode(&bytes);
                        ctx.variables.insert(var_name.into(), hex_str.clone());
                        log_and_emit(&mut ctx, "Base64ToBytes", &format!("Decoded to hex: {}...", &hex_str[..32.min(hex_str.len())]), "Success", None, bid, block_start_time);
                    }
                    Err(e) => {
                        log_and_emit(&mut ctx, "Base64ToBytes", &format!("Error: {}", e), "Error", None, bid, block_start_time);
                        ctx.bot_status = "ERROR".into();
                    }
                }
            }
            BlockType::EncodeHtmlEntities => {
                let input = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("htmlEncoded");

                // Manual HTML entity encoding
                let encoded = input
                    .replace('&', "&amp;")
                    .replace('<', "&lt;")
                    .replace('>', "&gt;")
                    .replace('"', "&quot;")
                    .replace('\'', "&#x27;");
                ctx.variables.insert(var_name.into(), encoded.clone());
                log_and_emit(&mut ctx, "EncodeHtmlEntities", &format!("Encoded: {}", if encoded.len() > 50 { format!("{}...", &encoded[..50]) } else { encoded }), "Success", None, bid, block_start_time);
            }
            BlockType::DecodeHtmlEntities => {
                let input = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("htmlDecoded");

                // Manual HTML entity decoding
                let decoded = input
                    .replace("&lt;", "<")
                    .replace("&gt;", ">")
                    .replace("&quot;", "\"")
                    .replace("&#x27;", "'")
                    .replace("&#39;", "'")
                    .replace("&apos;", "'")
                    .replace("&nbsp;", " ")
                    .replace("&amp;", "&"); // Must be last to avoid double-decoding
                ctx.variables.insert(var_name.into(), decoded.clone());
                log_and_emit(&mut ctx, "DecodeHtmlEntities", &format!("Decoded: {}", if decoded.len() > 50 { format!("{}...", &decoded[..50]) } else { decoded }), "Success", None, bid, block_start_time);
            }
            BlockType::Checksum => {
                let mut input_raw = ctx.replace_vars(block.data.get("input").and_then(|v| v.as_str()).unwrap_or(""));
                let salt = ctx.replace_vars(block.data.get("salt").and_then(|v| v.as_str()).unwrap_or("==?d:??@"));
                let var_name = block.data.get("variable").and_then(|v| v.as_str()).unwrap_or("gop3Payload");

                // Robust extraction: find the first '{' and last '}' to ignore surrounding text/noise
                if let (Some(start), Some(end)) = (input_raw.find('{'), input_raw.rfind('}')) {
                    if end > start {
                        input_raw = input_raw[start..=end].to_string();
                    }
                }

                // Clean up newlines and tabs that might break JSON parsing if they were introduced by formatting
                let input_json = input_raw.replace('\n', " ").replace('\r', " ").replace('\t', " ").trim().to_string();

                match serde_json::from_str::<Value>(&input_json) {
                    Ok(mut json_val) => {
                        // 1. Remove existing checksum if present
                        if let Some(obj) = json_val.as_object_mut() {
                            obj.remove("checksum");
                        }

                        // 2. Minify JSON (to generate checksum)
                        let minified_original = serde_json::to_string(&json_val).unwrap_or_default();
                        
                        // 3. Append salt and MD5
                        let data_to_hash = format!("{}{}", minified_original, salt);
                        let mut hasher = Md5::new();
                        hasher.update(data_to_hash.as_bytes());
                        let checksum = format!("{:x}", hasher.finalize()).to_uppercase();
                        
                        // 4. Add checksum to JSON
                        if let Some(obj) = json_val.as_object_mut() {
                            obj.insert("checksum".to_string(), Value::String(checksum.clone()));
                        }
                        
                        // 5. Final minified JSON
                        let final_json = serde_json::to_string(&json_val).unwrap_or_default();
                        
                        ctx.variables.insert(var_name.into(), final_json.clone());
                        log_and_emit(&mut ctx, "Checksum", &format!("({}): {}", var_name, final_json), "Success", None, bid, block_start_time);
                    }
                    Err(e) => {
                        log_and_emit(&mut ctx, "Checksum", &format!("({}): Invalid JSON input: {}", var_name, e), "Error", None, bid, block_start_time);
                        ctx.bot_status = "ERROR".into();
                    }
                }
            }

        }
        if ctx.bot_status != "SUCCESS" && ctx.bot_status != "NONE" { break; }
        block_idx += 1;
    }
    let final_status = ctx.bot_status.clone();
    log_and_emit(&mut ctx, "End", &format!("Bot ended: {}", final_status), &final_status, None, None, block_start_time);
    DebugResult { logs: ctx.logs, variables: ctx.variables, captured_data: ctx.captured_data }
}
