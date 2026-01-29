use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RepeaterRequest {
    pub method: String,
    pub url: String,
    pub headers: IndexMap<String, String>,
    pub body: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct RepeaterResponse {
    pub status: u16,
    pub headers: IndexMap<String, String>,
    pub body: String,
    pub duration_ms: u64,
    pub response_url: String,
}

#[tauri::command]
pub async fn send_repeater_request(req: RepeaterRequest) -> Result<RepeaterResponse, String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| e.to_string())?;

    let method = reqwest::Method::from_str(&req.method.to_uppercase())
        .map_err(|_| "Invalid HTTP method".to_string())?;

    let mut headers = HeaderMap::new();
    for (k, v) in req.headers {
        if let (Ok(name), Ok(val)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
            headers.insert(name, val);
        }
    }

    let mut builder = client.request(method, &req.url).headers(headers);

    if let Some(body) = req.body {
        builder = builder.body(body);
    }

    let start = std::time::Instant::now();
    let response = builder.send().await.map_err(|e| e.to_string())?;
    let duration = start.elapsed().as_millis() as u64;

    let status = response.status().as_u16();
    let response_url = response.url().to_string();
    let mut resp_headers = IndexMap::new();
    for (k, v) in response.headers() {
        if let Ok(val) = v.to_str() {
            resp_headers.insert(k.as_str().to_string(), val.to_string());
        }
    }

    let body = response.text().await.map_err(|e| e.to_string())?;

    Ok(RepeaterResponse {
        status,
        headers: resp_headers,
        body,
        duration_ms: duration,
        response_url,
    })
}
