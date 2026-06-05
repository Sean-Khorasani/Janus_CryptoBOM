use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

pub static PREVIOUS_TOTAL_FILES: AtomicUsize = AtomicUsize::new(100);
pub static GLOBAL_EXCLUSIONS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

pub struct SharedScanState {
    pub current_phase: Mutex<String>,
    pub current_path: Mutex<String>,
    pub total_files_scanned: AtomicUsize,
    pub scan_progress: AtomicUsize, // 0 to 100
    pub logs_buffer: Mutex<Vec<String>>,
}

impl SharedScanState {
    pub fn global() -> &'static Self {
        static INSTANCE: OnceLock<SharedScanState> = OnceLock::new();
        INSTANCE.get_or_init(|| SharedScanState {
            current_phase: Mutex::new("Idle".to_string()),
            current_path: Mutex::new("".to_string()),
            total_files_scanned: AtomicUsize::new(0),
            scan_progress: AtomicUsize::new(0),
            logs_buffer: Mutex::new(Vec::new()),
        })
    }
}

pub fn update_progress(phase: &str, path: &std::path::Path) {
    let state = SharedScanState::global();
    if let Ok(mut p) = state.current_phase.lock() {
        *p = phase.to_string();
    }
    if let Ok(mut p) = state.current_path.lock() {
        *p = path.to_string_lossy().to_string();
    }
    let total = state.total_files_scanned.fetch_add(1, Ordering::SeqCst) + 1;
    let previous_total = PREVIOUS_TOTAL_FILES.load(Ordering::SeqCst);
    if previous_total > 0 {
        let progress = (total * 100) / previous_total;
        state.scan_progress.store(progress.min(99), Ordering::SeqCst);
    } else {
        state.scan_progress.store((total / 10).min(90), Ordering::SeqCst);
    }
}

pub fn set_phase(phase: &str) {
    let state = SharedScanState::global();
    if let Ok(mut p) = state.current_phase.lock() {
        *p = phase.to_string();
    }
    log_event(&format!("Transition to scan phase: {}", phase));
}

pub fn log_event(msg: &str) {
    let state = SharedScanState::global();
    if let Ok(mut logs) = state.logs_buffer.lock() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        logs.push(format!("[UNIX:{}] [INFO] {}", now, msg));
        if logs.len() > 100 {
            logs.remove(0);
        }
    }
}

pub fn get_exclusions() -> Vec<String> {
    let lock = GLOBAL_EXCLUSIONS.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(g) = lock.lock() {
        g.clone()
    } else {
        Vec::new()
    }
}

pub fn set_exclusions(excs: Vec<String>) {
    let lock = GLOBAL_EXCLUSIONS.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut g) = lock.lock() {
        *g = excs;
    }
}

pub fn run_self_test(cfg: &crate::config::AgentConfig) {
    log_event("Initializing Agent Diagnostics Self-Test...");
    log_event(&format!("Configuration loaded successfully. Controller endpoint: {}", cfg.controller_endpoint));
    log_event(&format!("Execution mode: {}", cfg.execution_mode));
    log_event(&format!("Scan interval: {} seconds", cfg.scan_interval_seconds));
    
    let cache_path = std::path::Path::new(&cfg.cache_path);
    if let Some(parent) = cache_path.parent() {
        if parent.exists() {
            log_event("[SELF-TEST] Offline cache folder accessible: PASS");
        } else {
            log_event("[SELF-TEST] Offline cache folder missing: WARNING");
        }
    }
    
    for root in &cfg.scan_roots {
        let p = std::path::Path::new(root);
        if p.exists() {
            log_event(&format!("[SELF-TEST] Scan root '{}' exists: PASS", root));
        } else {
            log_event(&format!("[SELF-TEST] Scan root '{}' not found: WARNING", root));
        }
    }
    
    log_event("Diagnostics Self-Test finished.");
}
