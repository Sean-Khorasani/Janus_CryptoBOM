use super::ScanResult;
use crate::{
    config::AgentConfig,
    proto::{CbomComponent, CryptoAlgorithm, CryptoRole, Evidence},
};
use anyhow::Result;
use sha2::{Digest, Sha256};
use sysinfo::{ProcessesToUpdate, System};
use uuid::Uuid;

pub fn scan(_cfg: &AgentConfig) -> Result<ScanResult> {
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
            ("openssl", "OpenSSL runtime", "OpenSSL", CryptoRole::Unspecified),
            ("nginx", "TLS termination", "TLS", CryptoRole::KeyExchange),
            ("apache", "TLS termination", "TLS", CryptoRole::KeyExchange),
            ("sshd", "SSH key exchange", "SSH", CryptoRole::KeyExchange),
            ("java", "JCA runtime", "JCA", CryptoRole::Unspecified),
            ("node", "Node crypto runtime", "node-crypto", CryptoRole::Unspecified),
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

    Ok(out)
}

#[cfg(target_os = "windows")]
fn scan_windows_modules(out: &mut ScanResult) {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32
    };
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use sysinfo::{ProcessesToUpdate, System};

    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    for (pid, _) in sys.processes() {
        let u32_pid = pid.as_u32();
        let h_snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, u32_pid)
        };
        if h_snapshot == INVALID_HANDLE_VALUE {
            continue;
        }

        let mut entry: MODULEENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

        if unsafe { Module32First(h_snapshot, &mut entry) } != 0 {
            loop {
                let module_name = unsafe {
                    let len = entry.szModule.iter().position(|&c| c == 0).unwrap_or(entry.szModule.len());
                    let bytes: Vec<u8> = entry.szModule[..len].iter().map(|&c| c as u8).collect();
                    String::from_utf8_lossy(&bytes).to_string()
                };
                let lower_name = module_name.to_ascii_lowercase();
                if lower_name.contains("bcrypt.dll") 
                    || lower_name.contains("ncrypt.dll") 
                    || lower_name.contains("libcrypto") 
                    || lower_name.contains("openssl") 
                {
                    let module_path = unsafe {
                        let len = entry.szExePath.iter().position(|&c| c == 0).unwrap_or(entry.szExePath.len());
                        let bytes: Vec<u8> = entry.szExePath[..len].iter().map(|&c| c as u8).collect();
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
                if lower.contains("libssl") || lower.contains("libcrypto") || lower.contains("boringssl") || lower.contains("libgnutls") {
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
                    }],
                    dependencies: Vec::new(),
                    reachable: true,
                });
            }
        }
    }
}

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

