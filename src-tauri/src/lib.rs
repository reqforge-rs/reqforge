pub mod engine;
pub mod job_manager;
pub mod combo_editor;
pub mod proxy_recorder;
pub mod repeater;
use engine::{Config, DebugResult};
use combo_editor::{TransformConfig, TransformResult, TransformProgress};
use job_manager::{JobManager, JobSettings, JobStats, JobSummary};
use proxy_recorder::ProxyState;
use tauri::State;
use std::sync::Mutex;
use std::fs;
use std::path::PathBuf;
use tokio::task::AbortHandle;
use serde::{Serialize, Deserialize};
use rand::prelude::IndexedRandom;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UserAgent {
    pub app_name: String,
    pub language: String,
    pub platform: String,
    pub plugins_length: u32,
    pub screen_height: u32,
    pub screen_width: u32,
    pub user_agent: String,
    pub vendor: String,
    pub viewport_height: u32,
    pub viewport_width: u32,
    pub weight: f64,
    pub device_category: String,
}

#[derive(Clone)]
pub struct UserAgentManager {
    user_agents: Vec<UserAgent>,
}

pub fn get_app_root() -> PathBuf {
    // 1. AppImage specific handling (Linux)
    // The "APPIMAGE" env var points to the actual .AppImage file.
    // We want to store data next to it, not inside the read-only mount.
    #[cfg(target_os = "linux")]
    if let Ok(appimage) = std::env::var("APPIMAGE") {
        let path = PathBuf::from(appimage);
        if let Some(parent) = path.parent() {
            let data_dir = parent.join("reqforge_data");
            // If it exists, or if we can successfully create it, use it.
            if data_dir.exists() || std::fs::create_dir_all(&data_dir).is_ok() {
                return data_dir;
            }
        }
    }

    // 2. Portable mode (Windows/Mac/Linux non-AppImage)
    // Try to create/use "reqforge_data" next to the actual executable.
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let data_dir = parent.join("reqforge_data");
            // If it exists, use it.
            if data_dir.exists() {
                return data_dir;
            }
            // If it doesn't exist, try to create it. 
            // If successful (directory is writable), use it.
            // If this fails (e.g. Program Files, read-only mount), we fall through to standard paths.
            if std::fs::create_dir_all(&data_dir).is_ok() {
                return data_dir;
            }
        }
    }

    // 3. Fallback to standard OS paths
    #[cfg(target_os = "windows")]
    {
        if let Ok(app_data) = std::env::var("APPDATA") {
            let path = PathBuf::from(app_data).join("reqforge");
            if !path.exists() { let _ = std::fs::create_dir_all(&path); }
            return path;
        }
    }
    
    #[cfg(not(target_os = "windows"))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let path = if cfg!(target_os = "macos") {
                PathBuf::from(home).join("Library").join("Application Support").join("reqforge")
            } else {
                PathBuf::from(home).join(".config").join("reqforge")
            };
            if !path.exists() { let _ = std::fs::create_dir_all(&path); }
            return path;
        }
    }

    // Ultimate fallback
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

impl UserAgentManager {
    fn new() -> Self {
        let mut path = get_app_root();
        path.push("user-agents.json");

        // Fallback to local/current dir if not found in app_root (development mode support)
        if !path.exists() {
            let mut local_path = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            if local_path.ends_with("src-tauri") { local_path.pop(); }
            local_path.push("user-agents.json");
            if local_path.exists() {
                path = local_path;
            }
        }

        let user_agents = if path.exists() {
            let content = fs::read_to_string(path).unwrap_or_else(|_| "[]".to_string());
            serde_json::from_str(&content).unwrap_or_else(|_| vec![])
        } else {
            vec![]
        };

        Self { user_agents }
    }

    fn get_random_user_agent(&self, platform_filter: &str) -> Option<String> {
        let mut rng = rand::thread_rng();
        let filtered_agents: Vec<&UserAgent> = self.user_agents.iter().filter(|ua| {
            match platform_filter {
                "all" => true,
                "desktop" => ua.device_category == "desktop",
                "mobile" => ua.device_category == "mobile",
                "ipad" => ua.platform.to_lowercase().contains("ipad"),
                "iphone" => ua.platform.to_lowercase().contains("iphone"),
                "android" => ua.user_agent.to_lowercase().contains("android"),
                "linux" => ua.platform.to_lowercase().contains("linux"),
                "mac" => ua.platform.to_lowercase().contains("mac"),
                "windows" => ua.platform.to_lowercase().contains("win"),
                _ => true,
            }
        }).collect();

        filtered_agents.choose(&mut rng).map(|ua| ua.user_agent.clone())
    }
}

#[tauri::command]
async fn get_random_user_agent(platform: String, state: State<'_, UserAgentManager>) -> Result<String, String> {
    state.get_random_user_agent(&platform).ok_or_else(|| "No user agent found for the selected platform".to_string())
}





fn get_configs_dir() -> PathBuf {
    let mut path = get_app_root();
    path.push("Configs");
    path
}

fn get_combos_dir() -> PathBuf {
    let mut path = get_app_root();
    path.push("Combos");
    path
}

fn get_templates_dir() -> PathBuf {
    let mut path = get_app_root();
    path.push("Templates");
    path
}

fn get_highlight_keywords_path() -> PathBuf {
    let mut path = get_app_root();
    path.push("highlight_keywords.json");
    path
}

#[tauri::command]
async fn load_highlight_keywords() -> Result<Vec<String>, String> {
    let path = get_highlight_keywords_path();
    if !path.exists() {
        // Return default keywords
        return Ok(vec![
            "login".to_string(),
            "sign-in".to_string(),
            "signin".to_string(),
            "auth".to_string(),
            "token".to_string(),
            "session".to_string(),
            "oauth".to_string(),
            "cookie".to_string(),
        ]);
    }
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    serde_json::from_str(&content).map_err(|e| e.to_string())
}

#[tauri::command]
async fn save_highlight_keywords(keywords: Vec<String>) -> Result<(), String> {
    let path = get_highlight_keywords_path();
    let content = serde_json::to_string_pretty(&keywords).map_err(|e| e.to_string())?;
    fs::write(&path, content).map_err(|e| e.to_string())
}

#[derive(Serialize, Deserialize)]
struct ComboMetadata {
    name: String,
    lines: usize,
}

/// Count lines in a file efficiently using buffered I/O
fn count_file_lines(path: &std::path::Path) -> std::io::Result<usize> {
    use std::io::{BufRead, BufReader};
    let file = fs::File::open(path)?;
    let reader = BufReader::with_capacity(1024 * 1024, file); // 1MB buffer
    let mut count = 0;
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            count += 1;
        }
    }
    Ok(count)
}

#[tauri::command]
async fn list_combos() -> Result<Vec<ComboMetadata>, String> {
    let dir = get_combos_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        return Ok(vec![]);
    }
    let mut combos = Vec::new();
    let entries = fs::read_dir(&dir).map_err(|e| e.to_string())?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                // Use streaming line count instead of loading entire file
                let lines = count_file_lines(&path).unwrap_or(0);
                combos.push(ComboMetadata { name: name.to_string(), lines });
            }
        }
    }
    Ok(combos)
}

#[tauri::command]
async fn save_combo(name: String, content: String) -> Result<(), String> {
    let dir = get_combos_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(name);
    fs::write(path, content).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn delete_combo(name: String) -> Result<(), String> {
    let path = get_combos_dir().join(name);
    if path.exists() {
        fs::remove_file(path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
async fn read_text_file(path: String) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_combos_path() -> String {
    get_combos_dir().to_string_lossy().to_string()
}

struct DebugState {
    handle: Mutex<Option<AbortHandle>>,
}

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[tauri::command]
async fn run_debug(app: tauri::AppHandle, config: Config, input: String, proxy: String, debug_state: State<'_, DebugState>, ua_manager: State<'_, UserAgentManager>) -> Result<DebugResult, String> {
    use tauri::Emitter;
    let task = {
        let mut handle_lock = debug_state.handle.lock().unwrap();
        if let Some(h) = handle_lock.take() {
            h.abort();
        }

        let app_clone = app.clone();
        let ua_manager_clone = ua_manager.inner().clone();
        let task = tokio::task::spawn(async move {
            engine::execute_config(config, input, proxy, Some(move |log: engine::ExecutionLog| {
                let _ = app_clone.emit("debug-log", log);
            }), &ua_manager_clone).await
        });

        *handle_lock = Some(task.abort_handle());
        task
    }; 

    let res = task.await.map_err(|_| "Debug task aborted or failed".to_string())?;
    
    {
        let mut handle_lock = debug_state.handle.lock().unwrap();
        *handle_lock = None;
    }
    
    Ok(res)
}

#[tauri::command]
async fn stop_debug(debug_state: State<'_, DebugState>) -> Result<(), String> {
    let mut handle_lock = debug_state.handle.lock().unwrap();
    if let Some(h) = handle_lock.take() {
        h.abort();
    }
    Ok(())
}

#[tauri::command]
async fn create_job(settings: JobSettings, state: State<'_, JobManager>) -> Result<(), String> {
    state.create_job(settings).map_err(|e| e.to_string())
}

#[tauri::command]
async fn update_job(settings: JobSettings, state: State<'_, JobManager>) -> Result<(), String> {
    state.update_job(settings)
}

#[tauri::command]
async fn delete_job(job_id: String, state: State<'_, JobManager>) -> Result<(), String> {
    state.delete_job(job_id)
}

#[tauri::command]
async fn get_jobs_list(state: State<'_, JobManager>) -> Result<Vec<JobSummary>, String> {
    Ok(state.get_jobs_list())
}

#[tauri::command]
async fn start_job(job_id: String, state: State<'_, JobManager>, ua_manager: State<'_, UserAgentManager>) -> Result<(), String> {
    state.start_job(job_id, ua_manager.inner())
}

#[tauri::command]
async fn stop_job(job_id: String, state: State<'_, JobManager>) -> Result<(), String> {
    state.stop_job(job_id)
}

#[tauri::command]
async fn get_job_stats(job_id: String, state: State<'_, JobManager>) -> Result<JobStats, String> {
    state.get_job_stats(job_id)
}

#[tauri::command]
async fn get_recent_hits(job_id: String, state: State<'_, JobManager>) -> Result<Vec<String>, String> {
    state.get_recent_hits(job_id)
}

#[tauri::command]
async fn get_recent_customs(job_id: String, state: State<'_, JobManager>) -> Result<Vec<String>, String> {
    state.get_recent_customs(job_id)
}

#[tauri::command]
async fn get_recent_tocheck(job_id: String, state: State<'_, JobManager>) -> Result<Vec<String>, String> {
    state.get_recent_tocheck(job_id)
}

#[tauri::command]
async fn save_config(config: serde_json::Value) -> Result<(), String> {
    let dir = get_configs_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let id = config.get("id").and_then(|v| v.as_str()).ok_or("Missing config id")?;
    let name = config.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed");

    // Delete existing file with same config ID (to handle renames)
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(existing) = serde_json::from_str::<serde_json::Value>(&content) {
                        if existing.get("id").and_then(|v| v.as_str()) == Some(id) {
                            let _ = fs::remove_file(&path);
                            break;
                        }
                    }
                }
            }
        }
    }

    // Sanitize filename
    let safe_name: String = name.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let filename = format!("{}_{}.json", safe_name, &id[..6.min(id.len())]);

    let path = dir.join(&filename);
    let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    fs::write(&path, json).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
async fn load_configs() -> Result<Vec<serde_json::Value>, String> {
    let dir = get_configs_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        return Ok(vec![]);
    }

    let mut configs = Vec::new();
    let entries = fs::read_dir(&dir).map_err(|e| e.to_string())?;

    for entry in entries {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
                        configs.push(config);
                    }
                }
            }
        }
    }

    // Sort by lastModified descending
    configs.sort_by(|a, b| {
        let a_time = a.get("lastModified").and_then(|v| v.as_i64()).unwrap_or(0);
        let b_time = b.get("lastModified").and_then(|v| v.as_i64()).unwrap_or(0);
        b_time.cmp(&a_time)
    });

    Ok(configs)
}

#[tauri::command]
async fn delete_config_file(config_id: String) -> Result<(), String> {
    let dir = get_configs_dir();
    if !dir.exists() { return Ok(()); }

    let entries = fs::read_dir(&dir).map_err(|e| e.to_string())?;

    for entry in entries {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(config) = serde_json::from_str::<serde_json::Value>(&content) {
                        if config.get("id").and_then(|v| v.as_str()) == Some(&config_id) {
                            fs::remove_file(&path).map_err(|e| e.to_string())?;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[tauri::command]
fn get_configs_path() -> String {
    get_configs_dir().to_string_lossy().to_string()
}

#[tauri::command]
async fn save_template(config: serde_json::Value) -> Result<(), String> {
    let dir = get_templates_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let id = config.get("id").and_then(|v| v.as_str()).ok_or("Missing template id")?;
    let name = config.get("name").and_then(|v| v.as_str()).unwrap_or("unnamed");

    // Delete existing file with same template ID (to handle renames)
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(existing) = serde_json::from_str::<serde_json::Value>(&content) {
                        if existing.get("id").and_then(|v| v.as_str()) == Some(id) {
                            let _ = fs::remove_file(&path);
                            break;
                        }
                    }
                }
            }
        }
    }

    // Sanitize filename
    let safe_name: String = name.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let filename = format!("{}_{}.json", safe_name, &id[..6.min(id.len())]);

    let path = dir.join(&filename);
    let json = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    fs::write(&path, json).map_err(|e| e.to_string())?;

    Ok(())
}

#[tauri::command]
async fn load_templates() -> Result<Vec<serde_json::Value>, String> {
    let dir = get_templates_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        return Ok(vec![]);
    }

    let mut templates = Vec::new();
    let entries = fs::read_dir(&dir).map_err(|e| e.to_string())?;

    for entry in entries {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(template) = serde_json::from_str::<serde_json::Value>(&content) {
                        templates.push(template);
                    }
                }
            }
        }
    }

    // Sort by lastModified descending
    templates.sort_by(|a, b| {
        let a_time = a.get("lastModified").and_then(|v| v.as_i64()).unwrap_or(0);
        let b_time = b.get("lastModified").and_then(|v| v.as_i64()).unwrap_or(0);
        b_time.cmp(&a_time)
    });

    Ok(templates)
}

#[tauri::command]
async fn delete_template(template_id: String) -> Result<(), String> {
    let dir = get_templates_dir();
    if !dir.exists() { return Ok(()); }

    let entries = fs::read_dir(&dir).map_err(|e| e.to_string())?;

    for entry in entries {
        if let Ok(entry) = entry {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(template) = serde_json::from_str::<serde_json::Value>(&content) {
                        if template.get("id").and_then(|v| v.as_str()) == Some(&template_id) {
                            fs::remove_file(&path).map_err(|e| e.to_string())?;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

#[tauri::command]
fn get_templates_path() -> String {
    get_templates_dir().to_string_lossy().to_string()
}

#[tauri::command]
async fn get_combo_preview(name: String, limit: Option<usize>) -> Result<Vec<String>, String> {
    let path = get_combos_dir().join(&name);
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let limit = limit.unwrap_or(20);
    let lines: Vec<String> = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(limit)
        .map(|s| s.to_string())
        .collect();
    Ok(lines)
}

/// Threshold for using streaming processing (10MB)
const LARGE_FILE_THRESHOLD: u64 = 10 * 1024 * 1024;

#[tauri::command]
async fn apply_combo_transforms(
    app: tauri::AppHandle,
    name: String,
    config: TransformConfig,
) -> Result<TransformResult, String> {
    use tauri::Emitter;

    let path = get_combos_dir().join(&name);

    // Check file size to decide processing method
    let metadata = fs::metadata(&path).map_err(|e| e.to_string())?;
    let file_size = metadata.len();

    if file_size > LARGE_FILE_THRESHOLD {
        // Use streaming for large files
        let app_clone = app.clone();
        let result = tokio::task::spawn_blocking(move || {
            combo_editor::apply_transforms_file(&path, &config, |progress: TransformProgress| {
                let _ = app_clone.emit("combo-transform-progress", progress);
            })
        })
        .await
        .map_err(|e| format!("Task failed: {}", e))?
        .map_err(|e| e.to_string())?;

        Ok(result)
    } else {
        // Use in-memory for small files (faster for small data)
        let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let lines: Vec<String> = content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|s| s.to_string())
            .collect();

        let (transformed, result) = combo_editor::apply_transforms(lines, &config);

        // Overwrite the original file
        let new_content = transformed.join("\n");
        fs::write(&path, new_content).map_err(|e| e.to_string())?;

        Ok(result)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProxyGroup {
    pub id: String,
    pub name: String,
    pub proxies: Vec<String>,
}

fn get_proxies_file_path() -> PathBuf {
    let mut path = get_app_root();
    path.push("proxies.json");
    path
}

#[tauri::command]
async fn save_proxies(groups: Vec<ProxyGroup>) -> Result<(), String> {
    let path = get_proxies_file_path();
    let json = serde_json::to_string_pretty(&groups).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
async fn load_proxies() -> Result<Vec<ProxyGroup>, String> {
    let path = get_proxies_file_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let groups: Vec<ProxyGroup> = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    Ok(groups)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(JobManager::new())
        .manage(UserAgentManager::new())
        .manage(DebugState { handle: Mutex::new(None) })
        .manage(ProxyState::new())
        .invoke_handler(tauri::generate_handler![
            greet,
            run_debug,
            stop_debug,
            create_job,
            update_job,
            delete_job,
            get_jobs_list,
            start_job,
            stop_job,
            get_job_stats,
            get_recent_hits,
            get_recent_customs,
            get_recent_tocheck,
            save_config,
            load_configs,
            delete_config_file,
            get_configs_path,
            save_template,
            load_templates,
            delete_template,
            get_templates_path,
            list_combos,
            save_combo,
            delete_combo,
            read_text_file,
            get_combos_path,
            get_combo_preview,
            apply_combo_transforms,
            get_random_user_agent,
            save_proxies,
            load_proxies,
            load_highlight_keywords,
            save_highlight_keywords,
            proxy_recorder::start_recorder,
            proxy_recorder::stop_recorder,
            proxy_recorder::get_recorded_requests,
            proxy_recorder::clear_recorded_requests,
            proxy_recorder::export_ca_certificate,
            proxy_recorder::get_ca_certificate_path,
            repeater::send_repeater_request
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
