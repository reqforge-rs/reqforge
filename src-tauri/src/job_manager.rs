use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicU64, AtomicBool, Ordering};
use std::time::{Instant, Duration};
use serde::{Serialize, Deserialize};
use crate::engine::{self, Config};
use std::fs::{self, OpenOptions, File};
use std::io::{self, Write, BufRead, BufReader};
use std::path::PathBuf;
use memmap2::MmapOptions;

// Advanced threading imports
use crossbeam_queue::SegQueue;
use crossbeam_deque::{Injector, Stealer, Worker as WorkStealingWorker};
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::Semaphore;

// ============================================================================
// CONFIGURATION
// ============================================================================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JobSettings {
    pub id: String,
    pub name: String,
    pub config: Config,
    #[serde(default)]
    pub config_id: Option<String>,
    pub bot_count: usize,
    pub proxy_mode: bool,
    pub shuffle_proxies: bool,
    pub concurrent_proxy_mode: bool,
    pub never_ban_proxy: bool,
    pub ban_loop_evasion: usize,
    pub proxy_group: String,
    pub combo_path: String,
    pub proxies: Vec<String>,
    pub skip_lines: bool,
    pub start_line: usize,
    pub ban_save_interval: usize,
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
    // New threading options
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,
    #[serde(default = "default_enable_work_stealing")]
    pub enable_work_stealing: bool,
    #[serde(default = "default_batch_size")]
    pub io_batch_size: usize,
}

fn default_max_banned_logs() -> usize { 50 }
fn default_save_hits() -> Vec<String> { vec!["SUCCESS".to_string(), "CUSTOM".to_string()] }
fn default_max_retries() -> usize { 3 }
fn default_channel_capacity() -> usize { 50000 }
fn default_enable_work_stealing() -> bool { true }
fn default_batch_size() -> usize { 100 }

// ============================================================================
// STATISTICS - Lock-Free Atomic Counters
// ============================================================================

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct JobStats {
    pub tested: u64,
    pub hits: u64,
    pub custom: u64,
    pub fails: u64,
    pub invalid: u64,
    pub banned: u64,
    pub to_check: u64,
    pub errors: u64,
    pub retries: u64,
    pub cpm: u64,
    pub active_bots: usize,
    pub total_lines: usize,
    pub last_line_index: usize,
    // New stats for threading insight
    #[serde(default)]
    pub queue_depth: usize,
    #[serde(default)]
    pub retry_queue_depth: usize,
    #[serde(default)]
    pub proxies_available: usize,
}

/// High-performance lock-free runtime statistics
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
    // Backpressure monitoring
    pub queue_depth: AtomicUsize,
    pub retry_queue_depth: AtomicUsize,
    pub proxies_available: AtomicUsize,
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
            queue_depth: AtomicUsize::new(0),
            retry_queue_depth: AtomicUsize::new(0),
            proxies_available: AtomicUsize::new(0),
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
            queue_depth: AtomicUsize::new(0),
            retry_queue_depth: AtomicUsize::new(0),
            proxies_available: AtomicUsize::new(0),
        }
    }

    fn to_stats(&self, total_lines: usize) -> JobStats {
        JobStats {
            tested: self.tested.load(Ordering::Acquire),
            hits: self.hits.load(Ordering::Acquire),
            custom: self.custom.load(Ordering::Acquire),
            fails: self.fails.load(Ordering::Acquire),
            invalid: self.invalid.load(Ordering::Acquire),
            banned: self.banned.load(Ordering::Acquire),
            to_check: self.to_check.load(Ordering::Acquire),
            errors: self.errors.load(Ordering::Acquire),
            retries: self.retries.load(Ordering::Acquire),
            active_bots: self.active_bots.load(Ordering::Acquire),
            cpm: 0, // Calculated separately
            total_lines,
            last_line_index: self.last_line_index.load(Ordering::Acquire),
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            retry_queue_depth: self.retry_queue_depth.load(Ordering::Relaxed),
            proxies_available: self.proxies_available.load(Ordering::Relaxed),
        }
    }

    /// Increment tested counter with proper memory ordering
    #[inline(always)]
    fn inc_tested(&self) {
        self.tested.fetch_add(1, Ordering::Release);
    }

    #[inline(always)]
    fn inc_hits(&self) {
        self.hits.fetch_add(1, Ordering::Release);
    }

    #[inline(always)]
    fn inc_custom(&self) {
        self.custom.fetch_add(1, Ordering::Release);
    }

    #[inline(always)]
    fn inc_fails(&self) {
        self.fails.fetch_add(1, Ordering::Release);
    }

    #[inline(always)]
    fn inc_banned(&self) {
        self.banned.fetch_add(1, Ordering::Release);
    }

    #[inline(always)]
    fn inc_errors(&self) {
        self.errors.fetch_add(1, Ordering::Release);
    }

    #[inline(always)]
    fn inc_retries(&self) {
        self.retries.fetch_add(1, Ordering::Release);
    }

    #[inline(always)]
    fn inc_to_check(&self) {
        self.to_check.fetch_add(1, Ordering::Release);
    }
}

// ============================================================================
// WORK ITEM TYPES
// ============================================================================

/// Work item for the threading system
#[derive(Clone, Debug)]
pub struct WorkItem {
    pub line: String,
    pub line_idx: usize,
    pub retries: usize,
    pub priority: WorkPriority,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkPriority {
    Retry = 0,   // Highest priority
    Normal = 1,  // Regular work
}

// ============================================================================
// LOCK-FREE RETRY QUEUE
// ============================================================================

/// High-performance lock-free retry queue using crossbeam
pub struct LockFreeRetryQueue {
    queue: SegQueue<WorkItem>,
    len: AtomicUsize,
}

impl LockFreeRetryQueue {
    fn new() -> Self {
        Self {
            queue: SegQueue::new(),
            len: AtomicUsize::new(0),
        }
    }

    #[inline(always)]
    fn push(&self, item: WorkItem) {
        self.queue.push(item);
        self.len.fetch_add(1, Ordering::Release);
    }

    #[inline(always)]
    fn pop(&self) -> Option<WorkItem> {
        match self.queue.pop() {
            Some(item) => {
                self.len.fetch_sub(1, Ordering::Release);
                Some(item)
            }
            None => None,
        }
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ============================================================================
// WORK-STEALING SCHEDULER
// ============================================================================

/// Work-stealing scheduler for optimal load balancing
pub struct WorkStealingScheduler {
    /// Global injector queue for new work
    injector: Injector<WorkItem>,
    /// Per-worker local queues
    stealers: Vec<Stealer<WorkItem>>,
    /// Count of items in injector (approximate)
    injector_len: AtomicUsize,
}

impl WorkStealingScheduler {
    fn new(num_workers: usize) -> (Self, Vec<WorkStealingWorker<WorkItem>>) {
        let mut workers = Vec::with_capacity(num_workers);
        let mut stealers = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let w = WorkStealingWorker::new_fifo();
            stealers.push(w.stealer());
            workers.push(w);
        }

        let scheduler = Self {
            injector: Injector::new(),
            stealers,
            injector_len: AtomicUsize::new(0),
        };

        (scheduler, workers)
    }

    /// Push work to the global queue
    fn push(&self, item: WorkItem) {
        self.injector.push(item);
        self.injector_len.fetch_add(1, Ordering::Release);
    }

    /// Try to get work - first from local queue, then steal
    fn find_task(&self, local: &WorkStealingWorker<WorkItem>) -> Option<WorkItem> {
        // 1. Try local queue first
        if let Some(item) = local.pop() {
            return Some(item);
        }

        // 2. Try global injector
        loop {
            match self.injector.steal_batch_and_pop(local) {
                crossbeam_deque::Steal::Success(item) => {
                    self.injector_len.fetch_sub(1, Ordering::Relaxed);
                    return Some(item);
                }
                crossbeam_deque::Steal::Empty => break,
                crossbeam_deque::Steal::Retry => continue,
            }
        }

        // 3. Try stealing from other workers
        for stealer in &self.stealers {
            loop {
                match stealer.steal() {
                    crossbeam_deque::Steal::Success(item) => return Some(item),
                    crossbeam_deque::Steal::Empty => break,
                    crossbeam_deque::Steal::Retry => continue,
                }
            }
        }

        None
    }

    fn len(&self) -> usize {
        self.injector_len.load(Ordering::Relaxed)
    }
}

// ============================================================================
// PROXY MANAGEMENT - Lock-Free
// ============================================================================

/// High-performance proxy manager using DashMap
pub struct ProxyManager {
    proxies: Arc<Vec<String>>,
    cursor: AtomicUsize,
    banned: DashMap<String, ()>,
    cooldowns: DashMap<String, Instant>,
    cooldown_duration: Duration,
    exhausted: AtomicBool,
}

impl ProxyManager {
    fn new(proxies: Vec<String>, cooldown_ms: u64) -> Self {
        Self {
            proxies: Arc::new(proxies),
            cursor: AtomicUsize::new(0),
            banned: DashMap::new(),
            cooldowns: DashMap::new(),
            cooldown_duration: Duration::from_millis(cooldown_ms),
            exhausted: AtomicBool::new(false),
        }
    }

    /// Get next available proxy - lock-free
    fn get_proxy(&self) -> Option<String> {
        let len = self.proxies.len();
        if len == 0 {
            return None;
        }

        // Try up to len * 2 times to find a good proxy
        for _ in 0..len.saturating_mul(2).max(10) {
            let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % len;
            let proxy = &self.proxies[idx];

            // Check if banned (lock-free read)
            if self.banned.contains_key(proxy) {
                continue;
            }

            // Check cooldown (lock-free)
            if self.cooldown_duration.as_millis() > 0 {
                if let Some(entry) = self.cooldowns.get(proxy) {
                    if entry.value().elapsed() < self.cooldown_duration {
                        continue;
                    }
                }
            }

            // Update cooldown
            if self.cooldown_duration.as_millis() > 0 {
                self.cooldowns.insert(proxy.clone(), Instant::now());
            }

            return Some(proxy.clone());
        }

        None
    }

    /// Ban a proxy - lock-free write
    fn ban_proxy(&self, proxy: &str) {
        self.banned.insert(proxy.to_string(), ());
        self.cooldowns.remove(proxy);

        // Check exhaustion
        if self.banned.len() >= self.proxies.len() {
            self.exhausted.store(true, Ordering::Release);
        }
    }

    fn is_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::Acquire)
    }

    fn available_count(&self) -> usize {
        self.proxies.len().saturating_sub(self.banned.len())
    }
}

// ============================================================================
// RECENT HITS BUFFER - Lock-Free Ring Buffer
// ============================================================================

/// Lock-free bounded ring buffer for recent items
pub struct RecentBuffer {
    items: Mutex<Vec<String>>,
    capacity: usize,
}

impl RecentBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            items: Mutex::new(Vec::with_capacity(capacity)),
            capacity,
        }
    }

    fn push(&self, item: String) {
        let mut items = self.items.lock();
        if items.len() >= self.capacity {
            items.remove(0);
        }
        items.push(item);
    }

    fn get_all(&self) -> Vec<String> {
        self.items.lock().clone()
    }

    fn clear(&self) {
        self.items.lock().clear();
    }
}

// ============================================================================
// BATCH I/O WRITER
// ============================================================================

/// Batched I/O writer to reduce disk operations
pub struct BatchWriter {
    buffer: Mutex<Vec<(PathBuf, String)>>,
    batch_size: usize,
}

impl BatchWriter {
    fn new(batch_size: usize) -> Self {
        Self {
            buffer: Mutex::new(Vec::with_capacity(batch_size)),
            batch_size,
        }
    }

    fn write(&self, path: PathBuf, content: String) {
        let should_flush = {
            let mut buffer = self.buffer.lock();
            buffer.push((path, content));
            buffer.len() >= self.batch_size
        };

        if should_flush {
            self.flush();
        }
    }

    fn flush(&self) {
        let items: Vec<_> = {
            let mut buffer = self.buffer.lock();
            std::mem::take(&mut *buffer)
        };

        // Group by path for efficient I/O
        let mut grouped: HashMap<PathBuf, Vec<String>> = HashMap::new();
        for (path, content) in items {
            grouped.entry(path).or_default().push(content);
        }

        // Write in batches
        for (path, contents) in grouped {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
                for content in contents {
                    let _ = f.write_all(content.as_bytes());
                }
            }
        }
    }
}

// ============================================================================
// JOB STRUCTURES
// ============================================================================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct JobSummary {
    pub id: String,
    pub name: String,
    pub status: String,
    pub stats: JobStats,
    pub settings: JobSettings,
}

fn log_job_event(job_id: &str, event: &str) {
    let mut p = crate::get_app_root();
    p.push("job_events.log");
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
        let _ = writeln!(f, "[{}] Job {}: {}", chrono::Utc::now().to_rfc3339(), job_id, event);
    }
}

pub struct Job {
    pub settings: Arc<Mutex<JobSettings>>,
    pub stats: Arc<Mutex<JobStats>>,
    pub runtime_stats: Arc<RuntimeStats>,
    pub running: Arc<AtomicBool>,
    pub recent_success: Arc<RecentBuffer>,
    pub recent_custom: Arc<RecentBuffer>,
    pub recent_tocheck: Arc<RecentBuffer>,
    pub start_time: Arc<Mutex<Option<Instant>>>,
    pub session_start_tested: Arc<AtomicU64>,
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
        let mut path = crate::get_app_root();
        path.push("jobs.json");
        path
    }

    pub fn save_to_disk(&self) -> Result<(), String> {
        let summaries: Vec<JobSummary> = {
            let jobs_lock = self.jobs.lock();
            jobs_lock.values().map(|j| {
                let settings = j.settings.lock().clone();
                let stats = j.runtime_stats.to_stats(j.stats.lock().total_lines);
                let is_running = j.running.load(Ordering::Acquire);
                JobSummary {
                    id: settings.id.clone(),
                    name: settings.name.clone(),
                    status: if is_running { "Running".to_string() } else { "Idle".to_string() },
                    stats,
                    settings
                }
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
        let mut jobs = self.jobs.lock();
        for s in summaries {
            let runtime_stats = Arc::new(RuntimeStats::from_stats(&s.stats));
            jobs.insert(s.id.clone(), Job {
                settings: Arc::new(Mutex::new(s.settings)),
                stats: Arc::new(Mutex::new(s.stats)),
                runtime_stats,
                running: Arc::new(AtomicBool::new(false)),
                recent_success: Arc::new(RecentBuffer::new(100)),
                recent_custom: Arc::new(RecentBuffer::new(100)),
                recent_tocheck: Arc::new(RecentBuffer::new(100)),
                start_time: Arc::new(Mutex::new(None)),
                session_start_tested: Arc::new(AtomicU64::new(0))
            });
        }
        Ok(())
    }

    pub fn create_job(&self, settings: JobSettings) -> Result<(), String> {
        let mut stats = JobStats::default();
        if let Ok(file) = File::open(&settings.combo_path) {
            if let Ok(mmap) = unsafe { MmapOptions::new().map(&file) } {
                stats.total_lines = mmap.iter().filter(|&&b| b == b'\n').count();
                if mmap.last().map_or(false, |&b| b != b'\n') {
                    stats.total_lines += 1;
                }
            } else {
                let content = fs::read_to_string(&settings.combo_path).unwrap_or_default();
                stats.total_lines = content.lines().filter(|l| !l.trim().is_empty()).count();
            }
        }

        let job = Job {
            settings: Arc::new(Mutex::new(settings.clone())),
            stats: Arc::new(Mutex::new(stats)),
            runtime_stats: Arc::new(RuntimeStats::new()),
            running: Arc::new(AtomicBool::new(false)),
            recent_success: Arc::new(RecentBuffer::new(100)),
            recent_custom: Arc::new(RecentBuffer::new(100)),
            recent_tocheck: Arc::new(RecentBuffer::new(100)),
            start_time: Arc::new(Mutex::new(None)),
            session_start_tested: Arc::new(AtomicU64::new(0))
        };
        self.jobs.lock().insert(settings.id, job);
        let _ = self.save_to_disk();
        Ok(())
    }

    pub fn update_job(&self, settings: JobSettings) -> Result<(), String> {
        {
            let mut jobs = self.jobs.lock();
            let job = jobs.get_mut(&settings.id).ok_or("Job not found")?;
            if job.running.load(Ordering::Acquire) { return Err("Running job".into()); }

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

            *job.settings.lock() = settings;
            job.stats.lock().total_lines = total;
        }
        let _ = self.save_to_disk();
        Ok(())
    }

    pub fn delete_job(&self, job_id: String) -> Result<(), String> {
        {
            let mut jobs = self.jobs.lock();
            if let Some(job) = jobs.get(&job_id) {
                if job.running.load(Ordering::Acquire) { return Err("Running job".into()); }
            } else { return Err("Not found".into()); }
            jobs.remove(&job_id);
        }
        let _ = self.save_to_disk();
        Ok(())
    }

    pub fn get_jobs_list(&self) -> Vec<JobSummary> {
        let jobs = self.jobs.lock();
        jobs.values().map(|j| {
            let is_running = j.running.load(Ordering::Acquire);
            let mut stats = j.runtime_stats.to_stats(j.stats.lock().total_lines);
            let settings = j.settings.lock().clone();

            if is_running {
                if let Some(start) = *j.start_time.lock() {
                    let sess_start = j.session_start_tested.load(Ordering::Acquire);
                    let checked_now = stats.tested.saturating_sub(sess_start);
                    let elapsed = start.elapsed().as_secs_f64() / 60.0;
                    if elapsed > 0.01 { stats.cpm = (checked_now as f64 / elapsed) as u64; }
                }
            }
            JobSummary {
                id: settings.id.clone(),
                name: settings.name.clone(),
                status: if is_running { "Running".to_string() } else { "Idle".to_string() },
                stats,
                settings
            }
        }).collect()
    }

    pub fn start_job(&self, job_id: String, ua_manager: &crate::UserAgentManager) -> Result<(), String> {
        let jobs = self.jobs.lock();
        let job = jobs.get(&job_id).ok_or("Job not found")?;

        // Atomic compare-and-swap to prevent double-start
        if job.running.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            return Ok(()); // Already running
        }

        log_job_event(&job_id, "STARTED");

        {
            *job.start_time.lock() = Some(Instant::now());
            job.recent_success.clear();
            job.recent_custom.clear();
            job.recent_tocheck.clear();

            let rs = &job.runtime_stats;
            let settings = job.settings.lock();

            let start_val = if settings.skip_lines { settings.start_line as u64 } else { 0 };

            rs.tested.store(start_val, Ordering::SeqCst);
            rs.hits.store(0, Ordering::SeqCst);
            rs.custom.store(0, Ordering::SeqCst);
            rs.fails.store(0, Ordering::SeqCst);
            rs.invalid.store(0, Ordering::SeqCst);
            rs.banned.store(0, Ordering::SeqCst);
            rs.to_check.store(0, Ordering::SeqCst);
            rs.errors.store(0, Ordering::SeqCst);
            rs.retries.store(0, Ordering::SeqCst);
            rs.last_line_index.store(if settings.skip_lines { settings.start_line } else { 0 }, Ordering::SeqCst);
            rs.queue_depth.store(0, Ordering::SeqCst);
            rs.retry_queue_depth.store(0, Ordering::SeqCst);

            job.session_start_tested.store(start_val, Ordering::SeqCst);
        }

        let running_flag = job.running.clone();
        let runtime_stats = job.runtime_stats.clone();
        let settings_arc = job.settings.clone();
        let settings = settings_arc.lock().clone();
        let recent_success = job.recent_success.clone();
        let recent_custom = job.recent_custom.clone();
        let recent_tocheck = job.recent_tocheck.clone();
        let manager = self.clone();
        let job_id_clone = job_id.clone();
        let ua_manager_worker = Arc::new(ua_manager.clone());

        // Launch the main job executor
        tauri::async_runtime::spawn(async move {
            run_job_executor(
                job_id_clone,
                running_flag,
                runtime_stats,
                settings_arc,
                settings,
                recent_success,
                recent_custom,
                recent_tocheck,
                manager,
                ua_manager_worker,
            ).await;
        });

        Ok(())
    }

    pub fn stop_job(&self, job_id: String) -> Result<(), String> {
        {
            let jobs = self.jobs.lock();
            let job = jobs.get(&job_id).ok_or("Job not found")?;

            // Atomic stop
            job.running.store(false, Ordering::SeqCst);

            let mut settings = job.settings.lock();
            let tested = job.runtime_stats.tested.load(Ordering::Acquire);
            settings.start_line = tested as usize;
            settings.skip_lines = true;
        }
        let _ = self.save_to_disk();
        Ok(())
    }

    pub fn get_job_stats(&self, job_id: String) -> Result<JobStats, String> {
        let jobs = self.jobs.lock();
        let job = jobs.get(&job_id).ok_or("Job not found")?;
        let mut stats = job.runtime_stats.to_stats(job.stats.lock().total_lines);
        if job.running.load(Ordering::Acquire) {
            if let Some(start) = *job.start_time.lock() {
                let sess_start = job.session_start_tested.load(Ordering::Acquire);
                let checked_now = stats.tested.saturating_sub(sess_start);
                let elapsed = start.elapsed().as_secs_f64() / 60.0;
                if elapsed > 0.01 { stats.cpm = (checked_now as f64 / elapsed) as u64; }
            }
        }
        Ok(stats)
    }

    pub fn get_recent_hits(&self, job_id: String) -> Result<Vec<String>, String> {
        let jobs = self.jobs.lock();
        let job = jobs.get(&job_id).ok_or("Job not found")?;
        Ok(job.recent_success.get_all())
    }

    pub fn get_recent_customs(&self, job_id: String) -> Result<Vec<String>, String> {
        let jobs = self.jobs.lock();
        let job = jobs.get(&job_id).ok_or("Job not found")?;
        Ok(job.recent_custom.get_all())
    }

    pub fn get_recent_tocheck(&self, job_id: String) -> Result<Vec<String>, String> {
        let jobs = self.jobs.lock();
        let job = jobs.get(&job_id).ok_or("Job not found")?;
        Ok(job.recent_tocheck.get_all())
    }
}

// ============================================================================
// MAIN JOB EXECUTOR
// ============================================================================

async fn run_job_executor(
    job_id: String,
    running_flag: Arc<AtomicBool>,
    runtime_stats: Arc<RuntimeStats>,
    settings_arc: Arc<Mutex<JobSettings>>,
    settings: JobSettings,
    recent_success: Arc<RecentBuffer>,
    recent_custom: Arc<RecentBuffer>,
    recent_tocheck: Arc<RecentBuffer>,
    manager: JobManager,
    ua_manager: Arc<crate::UserAgentManager>,
) {
    // Spawn periodic saver task
    let saver_running = running_flag.clone();
    let saver_manager = manager.clone();
    tauri::async_runtime::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            if !saver_running.load(Ordering::Acquire) { break; }
            let _ = saver_manager.save_to_disk();
        }
    });

    // Open combo file
    let file = match File::open(&settings.combo_path) {
        Ok(f) => f,
        Err(e) => {
            log_job_event(&job_id, &format!("ERROR: Failed to open combo file: {}", e));
            running_flag.store(false, Ordering::SeqCst);
            return;
        }
    };

    let mmap = match unsafe { MmapOptions::new().map(&file) } {
        Ok(m) => m,
        Err(e) => {
            log_job_event(&job_id, &format!("ERROR: Failed to mmap file: {}", e));
            running_flag.store(false, Ordering::SeqCst);
            return;
        }
    };

    let total_lines = mmap.iter().filter(|&&b| b == b'\n').count()
        + if mmap.last().map_or(false, |&b| b != b'\n') { 1 } else { 0 };

    log_job_event(&job_id, &format!("STREAMING STARTED: {} lines, {} bots, work-stealing={}",
        total_lines, settings.bot_count, settings.enable_work_stealing));

    // Initialize components
    let retry_queue = Arc::new(LockFreeRetryQueue::new());
    let proxy_manager = Arc::new(ProxyManager::new(
        settings.proxies.clone(),
        settings.proxy_cooldown_ms,
    ));
    let batch_writer = Arc::new(BatchWriter::new(settings.io_batch_size));
    let consecutive_bans = Arc::new(AtomicUsize::new(0));
    let ban_counter = Arc::new(AtomicUsize::new(0));

    // Rate limiter semaphore (if delay is set)
    let rate_limiter = if settings.request_delay_ms > 0 {
        Some(Arc::new(Semaphore::new(settings.bot_count)))
    } else {
        None
    };

    // Create work distribution system
    let batch_writer_ref = batch_writer.clone();
    if settings.enable_work_stealing {
        run_with_work_stealing(
            job_id.clone(),
            running_flag.clone(),
            runtime_stats.clone(),
            settings.clone(),
            mmap,
            retry_queue,
            proxy_manager,
            batch_writer,
            consecutive_bans,
            ban_counter,
            rate_limiter,
            recent_success,
            recent_custom,
            recent_tocheck,
            ua_manager,
        ).await;
    } else {
        run_with_channels(
            job_id.clone(),
            running_flag.clone(),
            runtime_stats.clone(),
            settings.clone(),
            mmap,
            retry_queue,
            proxy_manager,
            batch_writer,
            consecutive_bans,
            ban_counter,
            rate_limiter,
            recent_success,
            recent_custom,
            recent_tocheck,
            ua_manager,
        ).await;
    }

    // Cleanup
    batch_writer_ref.flush();
    log_job_event(&job_id, "FINISHED (all workers done)");
    running_flag.store(false, Ordering::SeqCst);

    {
        let mut s_l = settings_arc.lock();
        let t = runtime_stats.tested.load(Ordering::Acquire);
        s_l.start_line = t as usize;
        s_l.skip_lines = true;
    }
    let _ = manager.save_to_disk();
}

// ============================================================================
// WORK-STEALING EXECUTION
// ============================================================================

async fn run_with_work_stealing(
    job_id: String,
    running_flag: Arc<AtomicBool>,
    runtime_stats: Arc<RuntimeStats>,
    settings: JobSettings,
    mmap: memmap2::Mmap,
    retry_queue: Arc<LockFreeRetryQueue>,
    proxy_manager: Arc<ProxyManager>,
    batch_writer: Arc<BatchWriter>,
    consecutive_bans: Arc<AtomicUsize>,
    ban_counter: Arc<AtomicUsize>,
    rate_limiter: Option<Arc<Semaphore>>,
    recent_success: Arc<RecentBuffer>,
    recent_custom: Arc<RecentBuffer>,
    recent_tocheck: Arc<RecentBuffer>,
    ua_manager: Arc<crate::UserAgentManager>,
) {
    let (scheduler, workers) = WorkStealingScheduler::new(settings.bot_count);
    let scheduler = Arc::new(scheduler);

    // Spawn producer task
    let producer_running = running_flag.clone();
    let producer_scheduler = scheduler.clone();
    let producer_stats = runtime_stats.clone();
    let prod_settings = settings.clone();

    tauri::async_runtime::spawn(async move {
        let cursor = io::Cursor::new(mmap.as_ref());
        let reader = BufReader::with_capacity(1024 * 1024, cursor); // 1MB buffer

        let start_idx = if prod_settings.skip_lines { prod_settings.start_line } else { 0 };
        let mut current_idx = 0;
        let mut seen: HashSet<String> = if prod_settings.deduplicate_combos {
            HashSet::with_capacity(100_000)
        } else {
            HashSet::new()
        };

        for line_res in reader.lines() {
            if !producer_running.load(Ordering::Acquire) { break; }

            if let Ok(line) = line_res {
                if line.trim().is_empty() { continue; }
                if current_idx < start_idx {
                    current_idx += 1;
                    continue;
                }

                if prod_settings.deduplicate_combos {
                    if seen.contains(&line) { continue; }
                    seen.insert(line.clone());
                }

                // Backpressure: wait if queue is too full
                while producer_scheduler.len() > prod_settings.channel_capacity {
                    if !producer_running.load(Ordering::Acquire) { return; }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }

                producer_scheduler.push(WorkItem {
                    line,
                    line_idx: current_idx,
                    retries: 0,
                    priority: WorkPriority::Normal,
                });
                producer_stats.queue_depth.store(producer_scheduler.len(), Ordering::Relaxed);
                current_idx += 1;
            }
        }
    });

    // Spawn worker tasks
    let mut handles = Vec::with_capacity(settings.bot_count);
    let done_signal = Arc::new(AtomicBool::new(false));

    for local_queue in workers {
        let r = running_flag.clone();
        let rs = runtime_stats.clone();
        let sched = scheduler.clone();
        let rq = retry_queue.clone();
        let pm = proxy_manager.clone();
        let bw = batch_writer.clone();
        let cb = consecutive_bans.clone();
        let bc = ban_counter.clone();
        let rl = rate_limiter.clone();
        let rs_buf = recent_success.clone();
        let rc_buf = recent_custom.clone();
        let rt_buf = recent_tocheck.clone();
        let ua = ua_manager.clone();
        let js = settings.clone();
        let jid = job_id.clone();
        let done = done_signal.clone();

        handles.push(tauri::async_runtime::spawn(async move {
            worker_loop(
                r, rs, sched, local_queue, rq, pm, bw, cb, bc, rl,
                rs_buf, rc_buf, rt_buf, ua, js, jid, done,
            ).await;
        }));
    }

    // Wait for all workers
    for h in handles {
        let _ = h.await;
    }
}

// ============================================================================
// CHANNEL-BASED EXECUTION (Fallback)
// ============================================================================

async fn run_with_channels(
    job_id: String,
    running_flag: Arc<AtomicBool>,
    runtime_stats: Arc<RuntimeStats>,
    settings: JobSettings,
    mmap: memmap2::Mmap,
    retry_queue: Arc<LockFreeRetryQueue>,
    proxy_manager: Arc<ProxyManager>,
    batch_writer: Arc<BatchWriter>,
    consecutive_bans: Arc<AtomicUsize>,
    ban_counter: Arc<AtomicUsize>,
    rate_limiter: Option<Arc<Semaphore>>,
    recent_success: Arc<RecentBuffer>,
    recent_custom: Arc<RecentBuffer>,
    recent_tocheck: Arc<RecentBuffer>,
    ua_manager: Arc<crate::UserAgentManager>,
) {
    let (tx, rx) = async_channel::bounded::<WorkItem>(settings.channel_capacity);

    // Spawn producer
    let producer_running = running_flag.clone();
    let producer_stats = runtime_stats.clone();
    let prod_settings = settings.clone();
    let prod_job_id = job_id.clone();

    tauri::async_runtime::spawn(async move {
        let cursor = io::Cursor::new(mmap.as_ref());
        let reader = BufReader::with_capacity(1024 * 1024, cursor);

        let start_idx = if prod_settings.skip_lines { prod_settings.start_line } else { 0 };
        let mut current_idx = 0;
        let mut seen: HashSet<String> = if prod_settings.deduplicate_combos {
            HashSet::with_capacity(100_000)
        } else {
            HashSet::new()
        };

        for line_res in reader.lines() {
            if !producer_running.load(Ordering::Acquire) { break; }

            if let Ok(line) = line_res {
                if line.trim().is_empty() { continue; }
                if current_idx < start_idx {
                    current_idx += 1;
                    continue;
                }

                if prod_settings.deduplicate_combos {
                    if seen.contains(&line) { continue; }
                    seen.insert(line.clone());
                }

                let item = WorkItem {
                    line,
                    line_idx: current_idx,
                    retries: 0,
                    priority: WorkPriority::Normal,
                };

                if tx.send(item).await.is_err() { break; }
                producer_stats.queue_depth.store(tx.len(), Ordering::Relaxed);
                current_idx += 1;
            }
        }
        log_job_event(&prod_job_id, "PRODUCER: All lines sent");
    });

    // Spawn workers
    let mut handles = Vec::with_capacity(settings.bot_count);

    for _ in 0..settings.bot_count {
        let r = running_flag.clone();
        let rs = runtime_stats.clone();
        let rx_worker = rx.clone();
        let rq = retry_queue.clone();
        let pm = proxy_manager.clone();
        let bw = batch_writer.clone();
        let cb = consecutive_bans.clone();
        let bc = ban_counter.clone();
        let rl = rate_limiter.clone();
        let rs_buf = recent_success.clone();
        let rc_buf = recent_custom.clone();
        let rt_buf = recent_tocheck.clone();
        let ua = ua_manager.clone();
        let js = settings.clone();
        let jid = job_id.clone();

        handles.push(tauri::async_runtime::spawn(async move {
            channel_worker_loop(
                r, rs, rx_worker, rq, pm, bw, cb, bc, rl,
                rs_buf, rc_buf, rt_buf, ua, js, jid,
            ).await;
        }));
    }

    for h in handles {
        let _ = h.await;
    }
}

// ============================================================================
// WORKER LOOPS
// ============================================================================

async fn worker_loop(
    running: Arc<AtomicBool>,
    stats: Arc<RuntimeStats>,
    scheduler: Arc<WorkStealingScheduler>,
    local_queue: WorkStealingWorker<WorkItem>,
    retry_queue: Arc<LockFreeRetryQueue>,
    proxy_manager: Arc<ProxyManager>,
    batch_writer: Arc<BatchWriter>,
    consecutive_bans: Arc<AtomicUsize>,
    ban_counter: Arc<AtomicUsize>,
    rate_limiter: Option<Arc<Semaphore>>,
    recent_success: Arc<RecentBuffer>,
    recent_custom: Arc<RecentBuffer>,
    recent_tocheck: Arc<RecentBuffer>,
    ua_manager: Arc<crate::UserAgentManager>,
    settings: JobSettings,
    job_id: String,
    done_signal: Arc<AtomicBool>,
) {
    let mut idle_count = 0;
    let max_idle = 100; // Exit after 100 consecutive empty polls

    loop {
        if !running.load(Ordering::Acquire) { break; }

        if settings.proxy_mode && settings.stop_on_proxy_exhaustion && proxy_manager.is_exhausted() {
            log_job_event(&job_id, "Worker exiting: proxies exhausted");
            break;
        }

        // Priority 1: Check retry queue (lock-free)
        let work_item = if let Some(item) = retry_queue.pop() {
            stats.retry_queue_depth.store(retry_queue.len(), Ordering::Relaxed);
            idle_count = 0;
            Some(item)
        } else {
            // Priority 2: Work-stealing scheduler
            scheduler.find_task(&local_queue)
        };

        let item = match work_item {
            Some(item) => {
                idle_count = 0;
                item
            }
            None => {
                idle_count += 1;
                if idle_count > max_idle && done_signal.load(Ordering::Acquire) {
                    break;
                }
                tokio::time::sleep(Duration::from_micros(100)).await;
                continue;
            }
        };

        // Process the work item
        process_work_item(
            &item,
            &stats,
            &retry_queue,
            &proxy_manager,
            &batch_writer,
            &consecutive_bans,
            &ban_counter,
            &rate_limiter,
            &recent_success,
            &recent_custom,
            &recent_tocheck,
            &ua_manager,
            &settings,
            &job_id,
        ).await;
    }
}

async fn channel_worker_loop(
    running: Arc<AtomicBool>,
    stats: Arc<RuntimeStats>,
    rx: async_channel::Receiver<WorkItem>,
    retry_queue: Arc<LockFreeRetryQueue>,
    proxy_manager: Arc<ProxyManager>,
    batch_writer: Arc<BatchWriter>,
    consecutive_bans: Arc<AtomicUsize>,
    ban_counter: Arc<AtomicUsize>,
    rate_limiter: Option<Arc<Semaphore>>,
    recent_success: Arc<RecentBuffer>,
    recent_custom: Arc<RecentBuffer>,
    recent_tocheck: Arc<RecentBuffer>,
    ua_manager: Arc<crate::UserAgentManager>,
    settings: JobSettings,
    job_id: String,
) {
    loop {
        if !running.load(Ordering::Acquire) { break; }

        if settings.proxy_mode && settings.stop_on_proxy_exhaustion && proxy_manager.is_exhausted() {
            break;
        }

        // Priority 1: Retry queue
        let item = if let Some(item) = retry_queue.pop() {
            stats.retry_queue_depth.store(retry_queue.len(), Ordering::Relaxed);
            item
        } else {
            // Priority 2: Channel
            match rx.recv().await {
                Ok(item) => item,
                Err(_) => break,
            }
        };

        process_work_item(
            &item,
            &stats,
            &retry_queue,
            &proxy_manager,
            &batch_writer,
            &consecutive_bans,
            &ban_counter,
            &rate_limiter,
            &recent_success,
            &recent_custom,
            &recent_tocheck,
            &ua_manager,
            &settings,
            &job_id,
        ).await;
    }
}

// ============================================================================
// WORK ITEM PROCESSING
// ============================================================================

async fn process_work_item(
    item: &WorkItem,
    stats: &Arc<RuntimeStats>,
    retry_queue: &Arc<LockFreeRetryQueue>,
    proxy_manager: &Arc<ProxyManager>,
    batch_writer: &Arc<BatchWriter>,
    consecutive_bans: &Arc<AtomicUsize>,
    ban_counter: &Arc<AtomicUsize>,
    rate_limiter: &Option<Arc<Semaphore>>,
    recent_success: &Arc<RecentBuffer>,
    recent_custom: &Arc<RecentBuffer>,
    recent_tocheck: &Arc<RecentBuffer>,
    ua_manager: &Arc<crate::UserAgentManager>,
    settings: &JobSettings,
    _job_id: &str,
) {
    // Track active bots
    stats.active_bots.fetch_add(1, Ordering::Relaxed);
    stats.proxies_available.store(proxy_manager.available_count(), Ordering::Relaxed);

    // Rate limiting
    let _permit = if let Some(limiter) = rate_limiter {
        Some(limiter.acquire().await.unwrap())
    } else {
        None
    };

    // Proxy selection (lock-free)
    let proxy = if settings.proxy_mode {
        proxy_manager.get_proxy().unwrap_or_default()
    } else {
        String::new()
    };

    // Execute request
    let res = engine::execute_config_with_client(
        settings.config.clone(),
        item.line.clone(),
        proxy.clone(),
        None::<fn(engine::ExecutionLog)>,
        ua_manager,
    ).await;

    let status = res.logs.iter().rev()
        .find(|l| l.step == "End")
        .map(|l| l.status.to_uppercase())
        .unwrap_or("NONE".to_string());

    // Request delay (after execution)
    if settings.request_delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(settings.request_delay_ms)).await;
    }

    let last_details = res.logs.iter().rev()
        .find(|l| l.step == "Request" || l.step == "TlsRequest")
        .and_then(|l| l.details.as_ref());

    // Update stats atomically
    stats.inc_tested();
    stats.last_line_index.store(item.line_idx, Ordering::Relaxed);

    match status.as_str() {
        "SUCCESS" => {
            consecutive_bans.store(0, Ordering::Relaxed);
            stats.inc_hits();

            if settings.save_hits.contains(&"SUCCESS".to_string()) {
                save_hit_batched(batch_writer, &settings.config.name, "SUCCESS", &item.line, &res.captured_data, None);
            }

            let mut hit_str = format!("SUCCESS: {}", item.line);
            for cap in &res.captured_data { hit_str.push_str(&format!(" | {}", cap)); }
            recent_success.push(hit_str);
        }
        "CUSTOM" => {
            consecutive_bans.store(0, Ordering::Relaxed);
            stats.inc_custom();

            if settings.save_hits.contains(&"CUSTOM".to_string()) {
                save_hit_batched(batch_writer, &settings.config.name, "CUSTOM", &item.line, &res.captured_data, None);
            }

            let mut hit_str = format!("CUSTOM: {}", item.line);
            for cap in &res.captured_data { hit_str.push_str(&format!(" | {}", cap)); }
            recent_custom.push(hit_str);
        }
        "FAIL" => {
            consecutive_bans.store(0, Ordering::Relaxed);
            stats.inc_fails();

            if settings.save_hits.contains(&"FAIL".to_string()) {
                save_hit_batched(batch_writer, &settings.config.name, "FAIL", &item.line, &res.captured_data, None);
            }
        }
        "BAN" => {
            let cb_val = consecutive_bans.fetch_add(1, Ordering::Relaxed) + 1;
            stats.inc_banned();

            if settings.proxy_mode && !settings.never_ban_proxy && !proxy.is_empty() {
                proxy_manager.ban_proxy(&proxy);
            }

            if settings.save_hits.contains(&"BAN".to_string()) {
                save_hit_batched(batch_writer, &settings.config.name, "BAN", &item.line, &res.captured_data, None);
            }

            if settings.ban_loop_evasion > 0 && cb_val >= settings.ban_loop_evasion {
                handle_ban_loop(
                    batch_writer, ban_counter, stats, recent_tocheck, settings,
                    &item.line, &res, last_details, consecutive_bans,
                );
            } else if settings.proxy_mode && settings.retry_on_timeout && item.retries < settings.max_retries {
                stats.inc_retries();
                retry_queue.push(WorkItem {
                    line: item.line.clone(),
                    line_idx: item.line_idx,
                    retries: item.retries + 1,
                    priority: WorkPriority::Retry,
                });
                stats.retry_queue_depth.store(retry_queue.len(), Ordering::Relaxed);
            } else {
                let src = res.variables.get("SOURCE").map(|s| s.as_str()).unwrap_or("");
                save_banned_batched(batch_writer, &settings.config.name, &item.line, src, ban_counter, settings.max_banned_logs, last_details);
            }
        }
        "RETRY" | "ERROR" => {
            if status == "ERROR" { stats.inc_errors(); }

            if settings.save_hits.contains(&"RETRY".to_string()) && status == "RETRY" {
                save_hit_batched(batch_writer, &settings.config.name, "RETRY", &item.line, &res.captured_data, None);
            }

            let should_retry = status == "RETRY" || (status == "ERROR" && settings.retry_on_timeout);
            if should_retry && item.retries < settings.max_retries {
                stats.inc_retries();
                retry_queue.push(WorkItem {
                    line: item.line.clone(),
                    line_idx: item.line_idx,
                    retries: item.retries + 1,
                    priority: WorkPriority::Retry,
                });
                stats.retry_queue_depth.store(retry_queue.len(), Ordering::Relaxed);
            }
        }
        _ => {
            if settings.save_hits.contains(&"NONE".to_string()) {
                save_hit_batched(batch_writer, &settings.config.name, "NONE", &item.line, &res.captured_data, None);
            }
            stats.inc_to_check();
        }
    }

    stats.active_bots.fetch_sub(1, Ordering::Relaxed);
}

fn handle_ban_loop(
    batch_writer: &Arc<BatchWriter>,
    ban_counter: &Arc<AtomicUsize>,
    stats: &Arc<RuntimeStats>,
    recent_tocheck: &Arc<RecentBuffer>,
    settings: &JobSettings,
    line: &str,
    res: &engine::DebugResult,
    last_details: Option<&engine::RequestDetails>,
    consecutive_bans: &Arc<AtomicUsize>,
) {
    let src = res.variables.get("SOURCE").map(|s: &String| s.as_str()).unwrap_or("");
    save_banned_batched(batch_writer, &settings.config.name, line, src, ban_counter, settings.max_banned_logs, last_details);

    if settings.save_hits.contains(&"TOCHECK".to_string()) {
        save_hit_batched(batch_writer, &settings.config.name, "TOCHECK", line, &res.captured_data, None);
        recent_tocheck.push(line.to_string());
    }
    stats.inc_to_check();
    consecutive_bans.store(0, Ordering::Relaxed);
}

// ============================================================================
// BATCHED I/O OPERATIONS
// ============================================================================

fn save_hit_batched(
    writer: &Arc<BatchWriter>,
    conf: &str,
    status: &str,
    line: &str,
    captured_data: &Vec<String>,
    details: Option<&engine::RequestDetails>,
) {
    let mut p = crate::get_app_root();
    p.push("Hits");
    p.push(conf);
    p.push(format!("{}.txt", status));

    let mut out = format!("{}", line);
    if !captured_data.is_empty() {
        for cap in captured_data {
            out.push_str(&format!(" | {}", cap));
        }
    }
    out.push('\n');

    if let Some(d) = details {
        out.push_str("-------------------- DEBUG DETAILS --------------------\n");
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

    writer.write(p, out);
}

fn save_banned_batched(
    writer: &Arc<BatchWriter>,
    conf: &str,
    line: &str,
    source: &str,
    counter: &Arc<AtomicUsize>,
    max: usize,
    details: Option<&engine::RequestDetails>,
) {
    let count = counter.fetch_add(1, Ordering::Relaxed);
    if count >= max { return; }

    let mut p = crate::get_app_root();
    p.push("Hits");
    p.push(conf);
    p.push("BANNED.txt");

    let out = if let Some(d) = details {
        let headers = d.response_headers.iter()
            .map(|(k, v)| format!("{}: {}", k, v))
            .collect::<Vec<_>>()
            .join(" | ");
        format!("{} respURL: {} RespHeader: {} RespSOURCE: {}\n", line, d.response_url, headers, d.response_body)
    } else {
        format!("{} respURL: N/A RespHeader: N/A RespSOURCE: {}\n", line, source)
    };

    writer.write(p, out);
}
