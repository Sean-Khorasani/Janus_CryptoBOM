use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

pub static PREVIOUS_TOTAL_FILES: AtomicUsize = AtomicUsize::new(100);
pub static GLOBAL_EXCLUSIONS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

// UX-001 scan control: cooperative cancel/pause flags checked by the scan loop.
static SCAN_CANCEL: AtomicBool = AtomicBool::new(false);
static SCAN_PAUSE: AtomicBool = AtomicBool::new(false);

/// Request the in-progress scan to stop early (it uploads partial results).
pub fn request_cancel() {
    SCAN_CANCEL.store(true, Ordering::SeqCst);
}
/// Clear the cancel flag — call at the start of each new scan.
pub fn clear_cancel() {
    SCAN_CANCEL.store(false, Ordering::SeqCst);
    SCAN_PAUSE.store(false, Ordering::SeqCst);
}
pub fn is_cancelled() -> bool {
    SCAN_CANCEL.load(Ordering::SeqCst)
}
pub fn set_paused(paused: bool) {
    SCAN_PAUSE.store(paused, Ordering::SeqCst);
}
pub fn is_paused() -> bool {
    SCAN_PAUSE.load(Ordering::SeqCst)
}

/// Cooperative checkpoint for the scan loop: blocks while paused, and returns
/// true if the scan should abort (cancel requested). Call once per file.
pub fn scan_checkpoint() -> bool {
    while is_paused() && !is_cancelled() {
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    is_cancelled()
}

// UX-001 scan-target: a one-shot scan-root override set by a scan-target command
// and consumed by the next scan (then cleared), so the scan targets just that path.
static SCAN_ROOT_OVERRIDE: OnceLock<Mutex<Option<String>>> = OnceLock::new();

fn scan_root_override_cell() -> &'static Mutex<Option<String>> {
    SCAN_ROOT_OVERRIDE.get_or_init(|| Mutex::new(None))
}

/// Set the path the next scan should target (scan-target command).
pub fn set_scan_root_override(path: String) {
    if let Ok(mut g) = scan_root_override_cell().lock() {
        *g = Some(path);
    }
}

/// Take (and clear) the pending scan-root override, if any.
pub fn take_scan_root_override() -> Option<String> {
    scan_root_override_cell()
        .lock()
        .ok()
        .and_then(|mut g| g.take())
}

pub struct SharedScanState {
    pub current_phase: Mutex<String>,
    pub current_path: Mutex<String>,
    pub total_files_scanned: AtomicUsize,
    pub files_skipped: AtomicUsize, // OPS-007: unchanged files skipped this scan
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
            files_skipped: AtomicUsize::new(0),
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
    if let Some(progress) = (total * 100).checked_div(previous_total) {
        state
            .scan_progress
            .store(progress.min(99), Ordering::SeqCst);
    } else {
        state
            .scan_progress
            .store((total / 10).min(90), Ordering::SeqCst);
    }
}

pub fn set_phase(phase: &str) {
    let state = SharedScanState::global();
    if let Ok(mut p) = state.current_phase.lock() {
        *p = phase.to_string();
    }
    if phase == "Idle" {
        state.scan_progress.store(0, Ordering::SeqCst);
        if let Ok(mut path) = state.current_path.lock() {
            path.clear();
        }
    }
    log_event(&format!("Transition to scan phase: {}", phase));
}

/// OPS-007: record how many files were skipped (content unchanged) this scan, for the
/// heartbeat so the dashboard can show scanned-vs-skipped.
pub fn set_files_skipped(n: usize) {
    SharedScanState::global()
        .files_skipped
        .store(n, std::sync::atomic::Ordering::SeqCst);
}

pub fn set_scan_complete(total_files: usize) {
    let state = SharedScanState::global();
    PREVIOUS_TOTAL_FILES.store(total_files.max(1), Ordering::SeqCst);
    state.scan_progress.store(100, Ordering::SeqCst);
    if let Ok(mut phase) = state.current_phase.lock() {
        *phase = "Uploading results".to_string();
    }
    if let Ok(mut path) = state.current_path.lock() {
        path.clear();
    }
    log_event(&format!(
        "Scan completed after processing {} paths",
        total_files
    ));
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
    log_event(&format!(
        "Configuration loaded successfully. Controller endpoint: {}",
        cfg.controller_endpoint
    ));
    log_event(&format!("Execution mode: {}", cfg.execution_mode));
    log_event(&format!(
        "Scan interval: {} seconds",
        cfg.scan_interval_seconds
    ));

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
            log_event(&format!(
                "[SELF-TEST] Scan root '{}' not found: WARNING",
                root
            ));
        }
    }

    log_event("Diagnostics Self-Test finished.");
}
