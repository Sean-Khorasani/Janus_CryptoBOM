use super::ScanResult;
use crate::{
    config::AgentConfig,
    proto::{CbomComponent, CryptoAlgorithm, CryptoRole, Evidence},
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use sysinfo::{ProcessesToUpdate, System};
use uuid::Uuid;

pub fn scan(cfg: &AgentConfig) -> Result<ScanResult> {
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut out = ScanResult::default();

    for (pid, process) in sys.processes() {
        let mut algorithms = Vec::new();
        let name = process.name().to_string_lossy().to_ascii_lowercase();
        let exe = process
            .exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let joined = format!("{} {}", name, exe.to_ascii_lowercase());
        for (needle, alg, family, role) in [
            (
                "openssl",
                "OpenSSL runtime",
                "OpenSSL",
                CryptoRole::Unspecified,
            ),
            ("nginx", "TLS termination", "TLS", CryptoRole::KeyExchange),
            ("apache", "TLS termination", "TLS", CryptoRole::KeyExchange),
            ("sshd", "SSH key exchange", "SSH", CryptoRole::KeyExchange),
            ("java", "JCA runtime", "JCA", CryptoRole::Unspecified),
            (
                "node",
                "Node crypto runtime",
                "node-crypto",
                CryptoRole::Unspecified,
            ),
        ] {
            if joined.contains(needle) {
                algorithms.push(CryptoAlgorithm {
                    name: alg.to_string(),
                    family: family.to_string(),
                    role: role as i32,
                    status: "process-metadata-observed".to_string(),
                    key_bits: 0,
                    curve: String::new(),
                    implementation_library: needle.to_string(),
                    source_file: exe.clone(),
                    source_line: 0,
                    source_column: 0,
                    symbol: process.name().to_string_lossy().to_string(),
                    confidence: 0.55,
                    quantum_vulnerable: false,

                    context_snippet: String::new(),
                });
            }
        }
        if algorithms.is_empty() {
            continue;
        }
        let target = format!("pid:{}:{}", pid, process.name().to_string_lossy());
        out.evidence.push(Evidence {
            evidence_id: Uuid::new_v4().to_string(),
            source_type: "runtime-process".to_string(),
            source_tool: "janus-agent-process-metadata".to_string(),
            target: target.clone(),
            collection_time_unix: now(),
            raw_artifact_sha256: hash(&target),
            confidence: 0.55,
            sensitivity_class: "metadata-only".to_string(),
        });
        out.components.push(CbomComponent {
            bom_ref: target,
            name: process.name().to_string_lossy().to_string(),
            version: String::new(),
            component_type: "process".to_string(),
            purl: String::new(),
            file_path: exe,
            language: "runtime".to_string(),
            algorithms,
            dependencies: Vec::new(),
            reachable: true,
        });
    }

    #[cfg(target_os = "linux")]
    scan_linux_maps(&mut out);

    #[cfg(target_os = "windows")]
    scan_windows_modules(&mut out);

    if cfg.enable_process_memory_scraping {
        scrape_process_memory_keys(&mut out);
    }

    Ok(out)
}

#[cfg(target_os = "windows")]
fn scan_windows_modules(out: &mut ScanResult) {
    use sysinfo::{ProcessesToUpdate, System};
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };

    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    for (pid, _) in sys.processes() {
        let u32_pid = pid.as_u32();
        let h_snapshot =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, u32_pid) };
        if h_snapshot == INVALID_HANDLE_VALUE {
            continue;
        }

        let mut entry: MODULEENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

        if unsafe { Module32First(h_snapshot, &mut entry) } != 0 {
            loop {
                let module_name = {
                    let len = entry
                        .szModule
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szModule.len());
                    let bytes: Vec<u8> = entry.szModule[..len].iter().map(|&c| c as u8).collect();
                    String::from_utf8_lossy(&bytes).to_string()
                };
                let lower_name = module_name.to_ascii_lowercase();
                if lower_name.contains("bcrypt.dll")
                    || lower_name.contains("ncrypt.dll")
                    || lower_name.contains("libcrypto")
                    || lower_name.contains("openssl")
                {
                    let module_path = {
                        let len = entry
                            .szExePath
                            .iter()
                            .position(|&c| c == 0)
                            .unwrap_or(entry.szExePath.len());
                        let bytes: Vec<u8> =
                            entry.szExePath[..len].iter().map(|&c| c as u8).collect();
                        String::from_utf8_lossy(&bytes).to_string()
                    };

                    out.components.push(CbomComponent {
                        bom_ref: format!("pid:{pid}:library:{module_name}"),
                        name: module_name.clone(),
                        version: String::new(),
                        component_type: "loaded-library".to_string(),
                        purl: String::new(),
                        file_path: module_path.clone(),
                        language: "native".to_string(),
                        algorithms: vec![CryptoAlgorithm {
                            name: "loaded-crypto-library".to_string(),
                            family: "runtime-library".to_string(),
                            role: CryptoRole::Unspecified as i32,
                            status: "process-module-observed".to_string(),
                            key_bits: 0,
                            curve: String::new(),
                            implementation_library: module_name,
                            source_file: module_path.clone(),
                            source_line: 0,
                            source_column: 0,
                            symbol: "process-module".to_string(),
                            confidence: 0.8,
                            quantum_vulnerable: false,

                            context_snippet: String::new(),
                        }],
                        dependencies: Vec::new(),
                        reachable: true,
                    });
                }

                if unsafe { Module32Next(h_snapshot, &mut entry) } == 0 {
                    break;
                }
            }
        }
        unsafe {
            CloseHandle(h_snapshot);
        }
    }
}

#[cfg(target_os = "linux")]
fn scan_linux_maps(out: &mut ScanResult) {
    use std::fs;
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid = entry.file_name().to_string_lossy().to_string();
            if !pid.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let maps = entry.path().join("maps");
            let text = match fs::read_to_string(&maps) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let mut libs = Vec::new();
            for line in text.lines() {
                let lower = line.to_ascii_lowercase();
                if lower.contains("libssl")
                    || lower.contains("libcrypto")
                    || lower.contains("boringssl")
                    || lower.contains("libgnutls")
                {
                    if let Some(path) = line.split_whitespace().last() {
                        libs.push(path.to_string());
                    }
                }
            }
            libs.sort();
            libs.dedup();
            for lib in libs {
                out.components.push(CbomComponent {
                    bom_ref: format!("pid:{pid}:library:{lib}"),
                    name: lib.rsplit('/').next().unwrap_or(&lib).to_string(),
                    version: String::new(),
                    component_type: "loaded-library".to_string(),
                    purl: String::new(),
                    file_path: lib.clone(),
                    language: "native".to_string(),
                    algorithms: vec![CryptoAlgorithm {
                        name: "loaded-crypto-library".to_string(),
                        family: "runtime-library".to_string(),
                        role: CryptoRole::Unspecified as i32,
                        status: "process-map-observed".to_string(),
                        key_bits: 0,
                        curve: String::new(),
                        implementation_library: lib.clone(),
                        source_file: lib.clone(),
                        source_line: 0,
                        source_column: 0,
                        symbol: "process-map".to_string(),
                        confidence: 0.7,
                        quantum_vulnerable: false,

                        context_snippet: String::new(),
                    }],
                    dependencies: Vec::new(),
                    reachable: true,
                });
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn scrape_process_memory_keys(out: &mut ScanResult) {
    use sysinfo::{ProcessesToUpdate, System};
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
    use windows_sys::Win32::System::Memory::{
        VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let pem1 = format!("{}-----", "-----BEGIN PRIVATE KEY");
    let pem2 = format!("{}-----", "-----BEGIN RSA PRIVATE KEY");

    for (pid, process) in sys.processes() {
        let u32_pid = pid.as_u32();

        let h_process =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, u32_pid) };
        if h_process.is_null() {
            continue;
        }

        let mut address = std::ptr::null();
        let mut mbi: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
        let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

        let mut found_keys = false;

        while unsafe { VirtualQueryEx(h_process, address, &mut mbi, mbi_size) } != 0 {
            if mbi.RegionSize == 0 {
                break;
            }
            let is_committed = mbi.State == MEM_COMMIT;
            let is_readable = (mbi.Protect & PAGE_NOACCESS) == 0
                && (mbi.Protect & PAGE_GUARD) == 0
                && (mbi.Protect
                    & (PAGE_READONLY
                        | PAGE_READWRITE
                        | PAGE_EXECUTE_READ
                        | PAGE_EXECUTE_READWRITE))
                    != 0;

            if is_committed
                && is_readable
                && mbi.RegionSize > 0
                && mbi.RegionSize <= 50 * 1024 * 1024
            {
                let mut buffer = vec![0u8; mbi.RegionSize];
                let mut bytes_read = 0;
                let ok = unsafe {
                    ReadProcessMemory(
                        h_process,
                        mbi.BaseAddress,
                        buffer.as_mut_ptr() as *mut _,
                        mbi.RegionSize,
                        &mut bytes_read,
                    )
                };

                if ok != 0 && bytes_read > 0 {
                    let chunk = &buffer[..bytes_read];
                    let has_pem = chunk.windows(pem1.len()).any(|w| w == pem1.as_bytes())
                        || chunk.windows(pem2.len()).any(|w| w == pem2.as_bytes());

                    if has_pem {
                        found_keys = true;
                        break;
                    }
                }
            }

            address = ((mbi.BaseAddress as usize).saturating_add(mbi.RegionSize))
                as *const std::ffi::c_void;
        }

        unsafe {
            CloseHandle(h_process);
        }

        if found_keys {
            let exe_path = process
                .exe()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let process_name = process.name().to_string_lossy().to_string();
            let target = format!("pid:{pid}:{process_name}");

            out.evidence.push(Evidence {
                evidence_id: Uuid::new_v4().to_string(),
                source_type: "process-memory-key".to_string(),
                source_tool: "janus-agent-memory-scraper".to_string(),
                target: target.clone(),
                collection_time_unix: now(),
                raw_artifact_sha256: hash(&target),
                confidence: 0.95,
                sensitivity_class: "metadata-only".to_string(),
            });

            out.components.push(CbomComponent {
                bom_ref: target,
                name: process_name,
                version: String::new(),
                component_type: "process-memory-key".to_string(),
                purl: String::new(),
                file_path: exe_path,
                language: "runtime".to_string(),
                algorithms: vec![CryptoAlgorithm {
                    name: "Unencrypted-Private-Key".to_string(),
                    family: "process-memory-key".to_string(),
                    role: CryptoRole::Unspecified as i32,
                    status: "scraped-from-memory".to_string(),
                    key_bits: 0,
                    curve: String::new(),
                    implementation_library: "process-memory".to_string(),
                    source_file: String::new(),
                    source_line: 0,
                    source_column: 0,
                    symbol: "private-key-header".to_string(),
                    confidence: 0.95,
                    quantum_vulnerable: false,
                    context_snippet: String::new(),
                }],
                dependencies: Vec::new(),
                reachable: true,
            });
        }
    }
}

#[cfg(target_os = "linux")]
fn scrape_process_memory_keys(out: &mut ScanResult) {
    use std::fs;
    use sysinfo::{ProcessesToUpdate, System};

    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    // PEM private key header patterns to search for
    let key_headers: &[&[u8]] = &[
        b"-----BEGIN PRIVATE KEY-----",
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"-----BEGIN EC PRIVATE KEY-----",
        b"-----BEGIN DSA PRIVATE KEY-----",
        b"-----BEGIN OPENSSH PRIVATE KEY-----",
    ];

    for (pid, process) in sys.processes() {
        // Only scan processes with crypto libraries loaded
        let name = process.name().to_string_lossy().to_ascii_lowercase();
        let exe = process
            .exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let is_crypto_relevant = [
            "openssl", "nginx", "apache", "sshd", "java", "node", "python",
        ]
        .iter()
        .any(|n| name.contains(n) || exe.contains(n));
        if !is_crypto_relevant {
            continue;
        }

        // Read /proc/<pid>/maps to find readable memory regions
        let maps_path = format!("/proc/{}/maps", pid.as_u32());
        let maps_content = match fs::read_to_string(&maps_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let mem_path = format!("/proc/{}/mem", pid.as_u32());
        let mem_file = match fs::File::open(&mem_path) {
            Ok(f) => f,
            Err(_) => continue,
        };

        for line in maps_content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let perms = parts[1];
            // Only scan readable, private regions (skip shared libraries for performance)
            if !perms.starts_with('r') || perms.contains('x') {
                continue;
            }

            // Parse address range
            let addr_range: Vec<&str> = parts[0].split('-').collect();
            if addr_range.len() != 2 {
                continue;
            }
            let start = match usize::from_str_radix(addr_range[0], 16) {
                Ok(a) => a,
                Err(_) => continue,
            };
            let end = match usize::from_str_radix(addr_range[1], 16) {
                Ok(a) => a,
                Err(_) => continue,
            };
            let region_size = end.saturating_sub(start);
            if region_size == 0 || region_size > 50 * 1024 * 1024 {
                continue;
            } // Skip empty/huge regions

            // Use pread to read from the specific offset
            let mut buf = vec![0u8; region_size.min(2 * 1024 * 1024)]; // Max 2MB per region
            use std::os::unix::fs::FileExt;
            if mem_file.read_at(&mut buf, start as u64).is_err() {
                continue;
            }

            for header in key_headers {
                if buf.windows(header.len()).any(|w| w == *header) {
                    let name = process.name().to_string_lossy().to_string();
                    out.components.push(CbomComponent {
                        bom_ref: format!("pid:{}:memory-key:{}", pid.as_u32(), name),
                        name: format!("Unencrypted private key in {} memory", name),
                        version: String::new(),
                        component_type: "process-memory-key".to_string(),
                        purl: String::new(),
                        file_path: exe.clone(),
                        language: "runtime".to_string(),
                        algorithms: vec![CryptoAlgorithm {
                            name: "Unencrypted-Private-Key".to_string(),
                            family: "process-memory-key".to_string(),
                            role: CryptoRole::Unspecified as i32,
                            status: "scraped-from-memory".to_string(),
                            key_bits: 0,
                            curve: String::new(),
                            implementation_library: "process-memory".to_string(),
                            source_file: format!("/proc/{}/mem", pid.as_u32()),
                            source_line: 0,
                            source_column: 0,
                            symbol: "private-key-header".to_string(),
                            confidence: 0.95,
                            quantum_vulnerable: false,
                            context_snippet: String::new(),
                        }],
                        dependencies: Vec::new(),
                        reachable: true,
                    });
                    break; // Found key in this region, move to next region
                }
            }
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
#[allow(dead_code)]
fn scrape_process_memory_keys(_out: &mut ScanResult) {}

fn hash(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
