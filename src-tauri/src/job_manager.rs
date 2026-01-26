use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use std::time::{Instant, Duration};
use serde::{Serialize, Deserialize};
use crate::engine::{self, Config};
use std::fs::{self, OpenOptions, File};
use std::io::{self, Write, BufRead, BufReader};
use std::path::PathBuf;
use memmap2::MmapOptions;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JobSettings {
    pub id: String, pub name: String, pub config: Config,
    #[serde(default)]
    pub config_id: Option<String>,
    pub bot_count: usize, pub proxy_mode: bool, pub shuffle_proxies: bool, pub concurrent_proxy_mode: bool, pub never_ban_proxy: bool, pub ban_loop_evasion: usize, pub proxy_group: String, pub combo_path: String, pub proxies: Vec<String>, pub skip_lines: bool, pub start_line: usize, pub ban_save_interval: usize,
    #[serde(default)]
    pub request_delay_ms: u64,
    #[serde(default)]
    pub proxy_cooldown_ms: u64,
    #[serde(default)]
    pub stop_on_proxy_exhaustion: bool,
    #[serde(default = "default_max_banned_logs")]
    pub max_banned_logs: usize,
    #[serde(default = "default_save_hits")]
    pub save_hits: Vec<String>,
    #[serde(default)]
    pub deduplicate_combos: bool,
    #[serde(default)]
    pub retry_on_timeout: bool,
    #[serde(default = "default_max_retries")]
    pub max_retries: usize,
    #[serde(default = "default_max_retries_as_ban")]
    pub max_retries_as_ban: usize,
}

fn default_max_banned_logs() -> usize { 50 }
fn default_save_hits() -> Vec<String> { vec!["SUCCESS".to_string(), "CUSTOM".to_string()] }
fn default_max_retries() -> usize { 3 }
fn default_max_retries_as_ban() -> usize { 3 }

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct JobStats {
    pub tested: u64, pub hits: u64, pub custom: u64, pub fails: u64, pub invalid: u64, pub banned: u64, pub to_check: u64, pub errors: u64, pub retries: u64, pub cpm: u64, pub active_bots: usize, pub total_lines: usize, pub last_line_index: usize,
}

#[derive(Debug)]
pub struct RuntimeStats {
    pub tested: AtomicU64,
    pub hits: AtomicU64,
    pub custom: AtomicU64,
    pub fails: AtomicU64,
    pub invalid: AtomicU64,
    pub banned: AtomicU64,
    pub to_check: AtomicU64,
    pub errors: AtomicU64,
    pub retries: AtomicU64,
    pub active_bots: AtomicUsize,
    pub last_line_index: AtomicUsize,
}

impl RuntimeStats {
    fn new() -> Self {
        Self {
            tested: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            custom: AtomicU64::new(0),
            fails: AtomicU64::new(0),
            invalid: AtomicU64::new(0),
            banned: AtomicU64::new(0),
            to_check: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            active_bots: AtomicUsize::new(0),
            last_line_index: AtomicUsize::new(0),
        }
    }

    fn from_stats(s: &JobStats) -> Self {
        Self {
            tested: AtomicU64::new(s.tested),
            hits: AtomicU64::new(s.hits),
            custom: AtomicU64::new(s.custom),
            fails: AtomicU64::new(s.fails),
            invalid: AtomicU64::new(s.invalid),
            banned: AtomicU64::new(s.banned),
            to_check: AtomicU64::new(s.to_check),
            errors: AtomicU64::new(s.errors),
            retries: AtomicU64::new(s.retries),
            active_bots: AtomicUsize::new(0),
            last_line_index: AtomicUsize::new(s.last_line_index),
        }
    }

    fn to_stats(&self, total_lines: usize) -> JobStats {
        JobStats {
            tested: self.tested.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            custom: self.custom.load(Ordering::Relaxed),
            fails: self.fails.load(Ordering::Relaxed),
            invalid: self.invalid.load(Ordering::Relaxed),
            banned: self.banned.load(Ordering::Relaxed),
            to_check: self.to_check.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            retries: self.retries.load(Ordering::Relaxed),
            active_bots: self.active_bots.load(Ordering::Relaxed),
            cpm: 0, // Calculated separately
            total_lines,
            last_line_index: self.last_line_index.load(Ordering::Relaxed),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JobSummary {
    pub id: String, pub name: String, pub status: String, pub stats: JobStats, pub settings: JobSettings,
}

fn log_job_event(job_id: &str, event: &str) {
    let mut p = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if p.ends_with("src-tauri") { p.pop(); }
    p.push("job_events.log");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
        let _ = writeln!(f, "[{}] Job {}: {}", chrono::Utc::now().to_rfc3339(), job_id, event);
    }
}

pub struct Job {
    pub settings: Arc<Mutex<JobSettings>>,
    pub stats: Arc<Mutex<JobStats>>, // Maintained for legacy/disk, but runtime uses runtime_stats
    pub runtime_stats: Arc<RuntimeStats>,
    pub running: Arc<Mutex<bool>>,
    pub recent_success: Arc<Mutex<Vec<String>>>,
    pub recent_custom: Arc<Mutex<Vec<String>>>,
    pub recent_tocheck: Arc<Mutex<Vec<String>>>,
    pub start_time: Arc<Mutex<Option<Instant>>>,
    pub session_start_tested: Arc<Mutex<u64>>,
}

#[derive(Clone)]
pub struct JobManager {
    pub jobs: Arc<Mutex<HashMap<String, Job>>>
}

impl JobManager {
    pub fn new() -> Self {
        let manager = Self { jobs: Arc::new(Mutex::new(HashMap::new())) };
        let _ = manager.load_from_disk();
        manager
    }

    fn get_persistence_path() -> PathBuf {
        let mut path = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        if path.ends_with("src-tauri") { path.pop(); }
        path.push("jobs.json");
        path
    }

    pub fn save_to_disk(&self) -> Result<(), String> {
        let summaries: Vec<JobSummary> = {
            let jobs_lock = self.jobs.lock().unwrap();
            jobs_lock.values().map(|j| {
                let settings = j.settings.lock().unwrap().clone();
                // Sync runtime stats to struct for saving
                let stats = j.runtime_stats.to_stats(j.stats.lock().unwrap().total_lines);
                
                let is_running = *j.running.lock().unwrap();
                JobSummary { id: settings.id.clone(), name: settings.name.clone(), status: if is_running { "Running".to_string() } else { "Idle".to_string() }, stats, settings }
            }).collect()
        };
        let json = serde_json::to_string_pretty(&summaries).map_err(|e| e.to_string())?;
        fs::write(Self::get_persistence_path(), json).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn load_from_disk(&self) -> Result<(), String> {
        let path = Self::get_persistence_path();
        if !path.exists() { return Ok(()); }
        let json = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let summaries: Vec<JobSummary> = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        let mut jobs = self.jobs.lock().unwrap();
        for s in summaries {
            let runtime_stats = Arc::new(RuntimeStats::from_stats(&s.stats));
            jobs.insert(s.id.clone(), Job { 
                settings: Arc::new(Mutex::new(s.settings)), 
                stats: Arc::new(Mutex::new(s.stats)), 
                runtime_stats,
                running: Arc::new(Mutex::new(false)), 
                recent_success: Arc::new(Mutex::new(Vec::new())), 
                recent_custom: Arc::new(Mutex::new(Vec::new())), 
                recent_tocheck: Arc::new(Mutex::new(Vec::new())), 
                start_time: Arc::new(Mutex::new(None)), 
                session_start_tested: Arc::new(Mutex::new(0)) 
            });
        }
        Ok(())
    }

    pub fn create_job(&self, settings: JobSettings) -> Result<(), String> {
        let mut stats = JobStats::default();
        // Try to read total lines count quickly
        if let Ok(file) = File::open(&settings.combo_path) {
            if let Ok(mmap) = unsafe { MmapOptions::new().map(&file) } {
                stats.total_lines = mmap.iter().filter(|&&b| b == b'\n').count();
                if mmap.last().map_or(false, |&b| b != b'\n') {
                    stats.total_lines += 1;
                }
            } else {
                // Fallback if mmap fails (e.g. empty file or permission)
                let content = fs::read_to_string(&settings.combo_path).unwrap_or_default();
                stats.total_lines = content.lines().filter(|l| !l.trim().is_empty()).count();
            }
        }

        let job = Job { 
            settings: Arc::new(Mutex::new(settings.clone())), 
            stats: Arc::new(Mutex::new(stats)), 
            runtime_stats: Arc::new(RuntimeStats::new()),
            running: Arc::new(Mutex::new(false)), 
            recent_success: Arc::new(Mutex::new(Vec::new())), 
            recent_custom: Arc::new(Mutex::new(Vec::new())), 
            recent_tocheck: Arc::new(Mutex::new(Vec::new())), 
            start_time: Arc::new(Mutex::new(None)), 
            session_start_tested: Arc::new(Mutex::new(0)) 
        };
        self.jobs.lock().unwrap().insert(settings.id, job);
        let _ = self.save_to_disk();
        Ok(())
    }

    pub fn update_job(&self, settings: JobSettings) -> Result<(), String> {
        {
            let mut jobs = self.jobs.lock().unwrap();
            let job = jobs.get_mut(&settings.id).ok_or("Job not found")?;
            if *job.running.lock().unwrap() { return Err("Running job".into()); }
            
            // Recount lines
            let mut total = 0;
            if let Ok(file) = File::open(&settings.combo_path) {
                if let Ok(mmap) = unsafe { MmapOptions::new().map(&file) } {
                    total = mmap.iter().filter(|&&b| b == b'\n').count();
                    if mmap.last().map_or(false, |&b| b != b'\n') { total += 1; }
                } else {
                    let content = fs::read_to_string(&settings.combo_path).unwrap_or_default();
                    total = content.lines().filter(|l| !l.trim().is_empty()).count();
                }
            }

            *job.settings.lock().unwrap() = settings;
            job.stats.lock().unwrap().total_lines = total;
        }
        let _ = self.save_to_disk();
        Ok(())
    }

    pub fn delete_job(&self, job_id: String) -> Result<(), String> {
        {
            let mut jobs = self.jobs.lock().unwrap();
            if let Some(job) = jobs.get(&job_id) {
                if *job.running.lock().unwrap() { return Err("Running job".into()); }
            } else { return Err("Not found".into()); }
            jobs.remove(&job_id);
        }
        let _ = self.save_to_disk();
        Ok(())
    }

    pub fn get_jobs_list(&self) -> Vec<JobSummary> {
        let jobs = self.jobs.lock().unwrap();
        jobs.values().map(|j| {
            let is_running = *j.running.lock().unwrap();
            
            // Construct stats from atomics for real-time view
            let mut stats = j.runtime_stats.to_stats(j.stats.lock().unwrap().total_lines);
            let settings = j.settings.lock().unwrap().clone();
            
            if is_running {
                if let Some(start) = *j.start_time.lock().unwrap() {
                    let sess_start = *j.session_start_tested.lock().unwrap();
                    let checked_now = stats.tested.saturating_sub(sess_start);
                    let elapsed = start.elapsed().as_secs_f64() / 60.0;
                    if elapsed > 0.01 { stats.cpm = (checked_now as f64 / elapsed) as u64; }
                }
            }
            JobSummary { id: settings.id.clone(), name: settings.name.clone(), status: if is_running { "Running".to_string() } else { "Idle".to_string() }, stats, settings }
        }).collect()
    }

    pub fn start_job(&self, job_id: String, ua_manager: &crate::UserAgentManager) -> Result<(), String> {
        let jobs = self.jobs.lock().unwrap();
        let job = jobs.get(&job_id).ok_or("Job not found")?;

        {
            let mut running = job.running.lock().unwrap();
            if *running { return Ok(()); }
            *running = true;
            log_job_event(&job_id, "STARTED");
            *job.start_time.lock().unwrap() = Some(Instant::now());
            job.recent_success.lock().unwrap().clear();
            job.recent_custom.lock().unwrap().clear();
            job.recent_tocheck.lock().unwrap().clear();
            
            // Reset runtime stats for session
            let rs = &job.runtime_stats;
            let settings = job.settings.lock().unwrap();
            
            if settings.skip_lines {
                rs.tested.store(settings.start_line as u64, Ordering::SeqCst);
                rs.hits.store(0, Ordering::SeqCst);
                rs.custom.store(0, Ordering::SeqCst);
                rs.fails.store(0, Ordering::SeqCst);
                rs.invalid.store(0, Ordering::SeqCst);
                rs.banned.store(0, Ordering::SeqCst);
                rs.to_check.store(0, Ordering::SeqCst);
                rs.errors.store(0, Ordering::SeqCst);
                rs.retries.store(0, Ordering::SeqCst);
                rs.last_line_index.store(settings.start_line, Ordering::SeqCst);
            } else {
                rs.tested.store(0, Ordering::SeqCst);
                rs.hits.store(0, Ordering::SeqCst);
                rs.custom.store(0, Ordering::SeqCst);
                rs.fails.store(0, Ordering::SeqCst);
                rs.invalid.store(0, Ordering::SeqCst);
                rs.banned.store(0, Ordering::SeqCst);
                rs.to_check.store(0, Ordering::SeqCst);
                rs.errors.store(0, Ordering::SeqCst);
                rs.retries.store(0, Ordering::SeqCst);
                rs.last_line_index.store(0, Ordering::SeqCst);
            }
            
            *job.session_start_tested.lock().unwrap() = rs.tested.load(Ordering::SeqCst);
        }

        let running_flag = job.running.clone();
        let runtime_stats = job.runtime_stats.clone();
        let settings_arc = job.settings.clone();
        let settings = settings_arc.lock().unwrap().clone();
        let recent_success = job.recent_success.clone();
        let recent_custom = job.recent_custom.clone();
        let recent_tocheck = job.recent_tocheck.clone();
        let manager = self.clone();
        let job_id_clone = job_id.clone();
        let ua_manager_worker = Arc::new(ua_manager.clone());

        tauri::async_runtime::spawn(async move {
            let m_clone = manager.clone();
            let r_clone = running_flag.clone();
            let saver_manager = m_clone.clone();
            tauri::async_runtime::spawn(async move {
                let mut int = tokio::time::interval(tokio::time::Duration::from_secs(5));
                loop { int.tick().await; if !*r_clone.lock().unwrap() { break; } let _ = saver_manager.save_to_disk(); }
            });

            // Open file for streaming
            let file = match File::open(&settings.combo_path) { Ok(f) => f, Err(_) => { *running_flag.lock().unwrap() = false; return; } };
            
            // Create Memory Map
            let mmap = match unsafe { MmapOptions::new().map(&file) } { Ok(m) => m, Err(_) => { *running_flag.lock().unwrap() = false; return; } };

            // Scan total lines quickly if needed (optional optimization for stats)
            let total_lines = mmap.iter().filter(|&&b| b == b'\n').count() + if mmap.last().map_or(false, |&b| b != b'\n') { 1 } else { 0 };
            
            log_job_event(&job_id_clone, &format!("STREAMING STARTED: {} lines found (Approx)", total_lines));

            // CHANNEL: Producer -> Consumer
            let (tx, rx) = async_channel::bounded(10000);

            // PRODUCER TASK
            let settings_prod = settings.clone();
            let job_id_prod = job_id_clone.clone();
            let r_prod = running_flag.clone();
            
            tauri::async_runtime::spawn(async move {
                let cursor = io::Cursor::new(mmap.as_ref());
                let reader = BufReader::new(cursor);
                
                let start_idx = if settings_prod.skip_lines { settings_prod.start_line } else { 0 };
                let mut current_idx = 0;
                
                let mut seen: HashSet<String> = HashSet::new(); // Local dedup for stream
                
                for line_res in reader.lines() {
                    if !*r_prod.lock().unwrap() { break; }
                    
                    if let Ok(line) = line_res {
                        if line.trim().is_empty() { continue; }
                        
                        // Handle start_line / skip
                        if current_idx < start_idx {
                            current_idx += 1;
                            continue;
                        }

                        // Deduplication
                        if settings_prod.deduplicate_combos {
                            if seen.contains(&line) {
                                continue;
                            }
                            seen.insert(line.clone());
                        }

                        // Send to workers (tuple: line, index, retries)
                        if let Err(_) = tx.send((line, current_idx, 0)).await {
                            break; // Channel closed
                        }
                        current_idx += 1;
                    }
                }
                log_job_event(&job_id_prod, "STREAMING FINISHED: All lines sent to workers");
            });

            // RETRY QUEUE
            let retry_queue = Arc::new(Mutex::new(VecDeque::new()));

            // PROXY SYSTEM
            let proxies_list = Arc::new(settings.proxies.clone());
            let proxy_cursor = Arc::new(AtomicUsize::new(0));
            let banned_proxies: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
            let proxy_cooldowns: Arc<Mutex<HashMap<String, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
            let proxies_exhausted = Arc::new(Mutex::new(false));
            
            let banned_save_counter: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));

            let mut handles = vec![];
            let consecutive_bans = Arc::new(Mutex::new(0));
            
            // SPAWN WORKERS
            for _ in 0..settings.bot_count {
                let r = running_flag.clone();
                let rs = runtime_stats.clone();
                let conf = settings.config.clone();
                
                // Consumer of the channel
                let rx_worker = rx.clone();
                let j_retries = retry_queue.clone();

                let p_list = proxies_list.clone();
                let p_cur = proxy_cursor.clone();
                let p_banned = banned_proxies.clone();
                let p_cooldowns = proxy_cooldowns.clone();
                let p_exhausted = proxies_exhausted.clone();
                
                let ban_counter = banned_save_counter.clone();
                let rec_success = recent_success.clone();
                let rec_custom = recent_custom.clone();
                let rec_tocheck = recent_tocheck.clone();
                let js = settings.clone();
                let cb_count = consecutive_bans.clone();
                let jid = job_id_clone.clone();
                let ua_manager_thread = ua_manager_worker.clone();

                handles.push(tauri::async_runtime::spawn(async move {
                    loop {
                        if !*r.lock().unwrap() { break; }

                        if js.proxy_mode && js.stop_on_proxy_exhaustion {
                            if *p_exhausted.lock().unwrap() { break; }
                        }

                        // FETCH WORK
                        // 1. Check retry queue
                        let retry_item = {
                            let mut rq = j_retries.lock().unwrap();
                            rq.pop_front()
                        };

                        let (line, line_idx, retries) = if let Some(item) = retry_item {
                            item
                        } else {
                            // 2. Fetch from Channel
                            match rx_worker.recv().await {
                                Ok(item) => item,
                                Err(_) => break, // Channel closed and empty
                            }
                        };

                        // Register active
                        rs.active_bots.fetch_add(1, Ordering::Relaxed);

                        // PROXY SELECTION
                        let mut p_str = String::new();
                        if js.proxy_mode {
                            let mut found_proxy = false;
                            let cooldown_duration = Duration::from_millis(js.proxy_cooldown_ms);
                            let p_len = p_list.len();

                            if p_len > 0 {
                                for _ in 0..10 {
                                    let idx = p_cur.fetch_add(1, Ordering::Relaxed);
                                    let candidate = &p_list[idx % p_len];
                                    
                                    if p_banned.read().unwrap().contains(candidate) { continue; }

                                    let on_cd = if js.proxy_cooldown_ms > 0 {
                                        let cooldowns = p_cooldowns.lock().unwrap();
                                        cooldowns.get(candidate).map(|t| t.elapsed() < cooldown_duration).unwrap_or(false)
                                    } else { false };

                                    if on_cd { continue; }

                                    p_str = candidate.clone();
                                    found_proxy = true;
                                    break;
                                }
                            }

                            if !found_proxy && js.stop_on_proxy_exhaustion {
                                let banned_count = p_banned.read().unwrap().len();
                                if banned_count >= p_len {
                                    let mut ex = p_exhausted.lock().unwrap();
                                    if !*ex {
                                        *ex = true;
                                        log_job_event(&jid, "PROXIES_EXHAUSTED - stopping workers");
                                    }
                                    rs.active_bots.fetch_sub(1, Ordering::Relaxed);
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                        }

                        if !p_str.is_empty() && js.proxy_cooldown_ms > 0 {
                            let mut cooldowns = p_cooldowns.lock().unwrap();
                            cooldowns.insert(p_str.clone(), Instant::now());
                        }

                        // EXECUTE
                        let res = engine::execute_config_with_client(conf.clone(), line.clone(), p_str.clone(), None::<fn(engine::ExecutionLog)>, &ua_manager_thread).await;
                        let status = res.logs.iter().rev().find(|l| l.step == "End").map(|l| l.status.to_uppercase()).unwrap_or("NONE".to_string());

                        if js.request_delay_ms > 0 {
                            tokio::time::sleep(Duration::from_millis(js.request_delay_ms)).await;
                        }

                        let last_details = res.logs.iter().rev().find(|l| l.step == "Request" || l.step == "TlsRequest").and_then(|l| l.details.as_ref());

                        // UPDATE STATS (Atomic)
                        rs.tested.fetch_add(1, Ordering::Relaxed);
                        rs.last_line_index.store(line_idx, Ordering::Relaxed);

                        match status.as_str() {
                            "SUCCESS" => {
                                { let mut cb = cb_count.lock().unwrap(); *cb = 0; }
                                if js.save_hits.contains(&"SUCCESS".to_string()) {
                                    save_hit(&conf.name, "SUCCESS", &line, &res.variables, &res.captured_data, None);
                                }
                                rs.hits.fetch_add(1, Ordering::Relaxed);
                                {
                                    let mut rs_l = rec_success.lock().unwrap();
                                    if rs_l.len() >= 100 { rs_l.remove(0); }
                                    let mut hit_str = format!("SUCCESS: {}", line);
                                    for cap in &res.captured_data { hit_str.push_str(&format!(" | {}", cap)); }
                                    rs_l.push(hit_str);
                                }
                            },
                            "CUSTOM" => {
                                { let mut cb = cb_count.lock().unwrap(); *cb = 0; }
                                if js.save_hits.contains(&"CUSTOM".to_string()) {
                                    save_hit(&conf.name, "CUSTOM", &line, &res.variables, &res.captured_data, None);
                                }
                                rs.custom.fetch_add(1, Ordering::Relaxed);
                                {
                                    let mut rc_l = rec_custom.lock().unwrap();
                                    if rc_l.len() >= 100 { rc_l.remove(0); }
                                    let mut hit_str = format!("CUSTOM: {}", line);
                                    for cap in &res.captured_data { hit_str.push_str(&format!(" | {}", cap)); }
                                    rc_l.push(hit_str);
                                }
                            },
                            "FAIL" => {
                                { let mut cb = cb_count.lock().unwrap(); *cb = 0; }
                                if js.save_hits.contains(&"FAIL".to_string()) {
                                    save_hit(&conf.name, "FAIL", &line, &res.variables, &res.captured_data, None);
                                }
                                rs.fails.fetch_add(1, Ordering::Relaxed);
                            },
                            "BAN" => {
                                let cb_val = { let mut cb = cb_count.lock().unwrap(); *cb += 1; *cb };
                                rs.banned.fetch_add(1, Ordering::Relaxed);

                                if js.proxy_mode && !js.never_ban_proxy && !p_str.is_empty() {
                                    let mut banned = p_banned.write().unwrap();
                                    banned.insert(p_str.clone());
                                    let mut cooldowns = p_cooldowns.lock().unwrap();
                                    cooldowns.remove(&p_str);
                                }

                                if js.save_hits.contains(&"BAN".to_string()) {
                                    save_hit(&conf.name, "BAN", &line, &res.variables, &res.captured_data, None);
                                }

                                if js.ban_loop_evasion > 0 && cb_val >= js.ban_loop_evasion {
                                    let src = res.variables.get("SOURCE").map(|s| s.as_str()).unwrap_or("");
                                    save_banned(&conf.name, &line, src, &ban_counter, js.max_banned_logs, last_details);

                                    if js.save_hits.contains(&"TOCHECK".to_string()) {
                                        save_hit(&conf.name, "TOCHECK", &line, &res.variables, &res.captured_data, None);
                                        let mut hits = rec_tocheck.lock().unwrap();
                                        hits.push(line.clone());
                                        if hits.len() > 100 { hits.remove(0); }
                                    }
                                    rs.to_check.fetch_add(1, Ordering::Relaxed);
                                    { let mut cb = cb_count.lock().unwrap(); *cb = 0; }
                                } else if js.proxy_mode && retries < js.max_retries {
                                    rs.retries.fetch_add(1, Ordering::Relaxed);
                                    let mut rq = j_retries.lock().unwrap();
                                    rq.push_back((line, line_idx, retries + 1));
                                    // Decrement tested because we are re-queueing? 
                                    // Usually "tested" means attempts. So keeping it +1 is fine.
                                } else {
                                    let src = res.variables.get("SOURCE").map(|s| s.as_str()).unwrap_or("");
                                    save_banned(&conf.name, &line, src, &ban_counter, js.max_banned_logs, last_details);
                                }
                            },
                            "RETRY" | "ERROR" => {
                                if status == "ERROR" { rs.errors.fetch_add(1, Ordering::Relaxed); }
                                if js.save_hits.contains(&"RETRY".to_string()) && status == "RETRY" {
                                    save_hit(&conf.name, "RETRY", &line, &res.variables, &res.captured_data, None);
                                }

                                let should_retry = status == "RETRY" || (status == "ERROR" && js.retry_on_timeout);
                                if should_retry && retries < js.max_retries {
                                    rs.retries.fetch_add(1, Ordering::Relaxed);
                                    let mut rq = j_retries.lock().unwrap();
                                    rq.push_back((line, line_idx, retries + 1));
                                } else if js.max_retries_as_ban > 0 && retries >= js.max_retries {
                                    let cb_val = { let mut cb = cb_count.lock().unwrap(); *cb += 1; *cb };
                                    rs.banned.fetch_add(1, Ordering::Relaxed);

                                    if js.ban_loop_evasion > 0 && cb_val >= js.ban_loop_evasion {
                                        let src = res.variables.get("SOURCE").map(|s| s.as_str()).unwrap_or("");
                                        save_banned(&conf.name, &line, src, &ban_counter, js.max_banned_logs, last_details);
                                        if js.save_hits.contains(&"TOCHECK".to_string()) {
                                            save_hit(&conf.name, "TOCHECK", &line, &res.variables, &res.captured_data, None);
                                            let mut hits = rec_tocheck.lock().unwrap();
                                            hits.push(line.clone());
                                            if hits.len() > 100 { hits.remove(0); }
                                        }
                                        rs.to_check.fetch_add(1, Ordering::Relaxed);
                                        { let mut cb = cb_count.lock().unwrap(); *cb = 0; }
                                    }
                                }
                            },
                            _ => {
                                if js.save_hits.contains(&"NONE".to_string()) {
                                    save_hit(&conf.name, "NONE", &line, &res.variables, &res.captured_data, None);
                                }
                                rs.to_check.fetch_add(1, Ordering::Relaxed);
                            },
                        }
                        
                        rs.active_bots.fetch_sub(1, Ordering::Relaxed);
                    }
                }));
            }
            for h in handles { let _ = h.await; }

            log_job_event(&job_id_clone, "FINISHED (all threads done)");
            *running_flag.lock().unwrap() = false;
            {
                let mut s_l = settings_arc.lock().unwrap();
                let t = runtime_stats.tested.load(Ordering::Relaxed);
                s_l.start_line = t as usize;
                s_l.skip_lines = true;
            }
            let _ = m_clone.save_to_disk();
        });
        Ok(())
    }

    pub fn stop_job(&self, job_id: String) -> Result<(), String> {
        {
            let jobs = self.jobs.lock().unwrap();
            let job = jobs.get(&job_id).ok_or("Job not found")?;
            *job.running.lock().unwrap() = false;
            let mut settings = job.settings.lock().unwrap();
            let tested = job.runtime_stats.tested.load(Ordering::Relaxed);
            settings.start_line = tested as usize;
            settings.skip_lines = true;
        }
        let _ = self.save_to_disk();
        Ok(())
    }

    pub fn get_job_stats(&self, job_id: String) -> Result<JobStats, String> {
        let jobs = self.jobs.lock().unwrap();
        let job = jobs.get(&job_id).ok_or("Job not found")?;
        let mut stats = job.runtime_stats.to_stats(job.stats.lock().unwrap().total_lines);
        if *job.running.lock().unwrap() {
            if let Some(start) = *job.start_time.lock().unwrap() {
                let sess_start = *job.session_start_tested.lock().unwrap();
                let checked_now = stats.tested.saturating_sub(sess_start);
                let elapsed = start.elapsed().as_secs_f64() / 60.0;
                if elapsed > 0.01 { stats.cpm = (checked_now as f64 / elapsed) as u64; }
            }
        }
        Ok(stats)
    }

    pub fn get_recent_hits(&self, job_id: String) -> Result<Vec<String>, String> {
        let jobs = self.jobs.lock().unwrap();
        let job = jobs.get(&job_id).ok_or("Job not found")?;
        let hits = job.recent_success.lock().unwrap().clone();
        Ok(hits)
    }

    pub fn get_recent_customs(&self, job_id: String) -> Result<Vec<String>, String> {
        let jobs = self.jobs.lock().unwrap();
        let job = jobs.get(&job_id).ok_or("Job not found")?;
        let hits = job.recent_custom.lock().unwrap().clone();
        Ok(hits)
    }

    pub fn get_recent_tocheck(&self, job_id: String) -> Result<Vec<String>, String> {
        let jobs = self.jobs.lock().unwrap();
        let job = jobs.get(&job_id).ok_or("Job not found")?;
        let hits = job.recent_tocheck.lock().unwrap().clone();
        Ok(hits)
    }
}

fn save_hit(conf: &str, status: &str, line: &str, _vars: &HashMap<String, String>, captured_data: &Vec<String>, details: Option<&engine::RequestDetails>) {
    let mut p = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if p.ends_with("src-tauri") { p.pop(); }
    p.push("Hits"); p.push(conf);
    if let Err(_) = fs::create_dir_all(&p) { return; }
    p.push(format!("{}.txt", status));
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
        let mut out = format!("{}", line);
        if !captured_data.is_empty() {
            for cap in captured_data {
                out.push_str(&format!(" | {}", cap));
            }
        }
        out.push('\n');

        if let Some(d) = details {
            out.push_str("-------------------- DEBUG DETAILS --------------------
");
            out.push_str(&format!("URL: {} {}\n", d.method, d.url));
            out.push_str(&format!("Status: {}\n", d.response_status));
            out.push_str("Request Headers:\n");
            for (k, v) in &d.request_headers { out.push_str(&format!("  {}: {}\n", k, v)); }
            if !d.request_body.is_empty() { out.push_str("Request Body:\n"); out.push_str(&d.request_body); out.push('\n'); }
            out.push_str("Response Headers:\n");
            for (k, v) in &d.response_headers { out.push_str(&format!("  {}: {}\n", k, v)); }
            out.push_str("Response Body:\n"); out.push_str(&d.response_body);
            out.push_str("\n-------------------------------------------------------\n\n");
        }
        let _ = f.write_all(out.as_bytes());
    }
}

fn save_banned(conf: &str, line: &str, source: &str, counter: &Arc<Mutex<usize>>, max: usize, details: Option<&engine::RequestDetails>) {
    let mut count = counter.lock().unwrap();
    if *count >= max { return; }
    *count += 1;
    drop(count);

    let mut p = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    if p.ends_with("src-tauri") { p.pop(); }
    p.push("Hits"); p.push(conf);
    if let Err(_) = fs::create_dir_all(&p) { return; }
    p.push("BANNED.txt");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
        if let Some(d) = details {
            let headers = d.response_headers.iter().map(|(k, v)| format!("{}: {}", k, v)).collect::<Vec<_>>().join(" | ");
            let _ = writeln!(f, "{} respURL: {} RespHeader: {} RespSOURCE: {}", line, d.response_url, headers, d.response_body);
        } else {
            let _ = writeln!(f, "{} respURL: N/A RespHeader: N/A RespSOURCE: {}", line, source);
        }
    }
}
