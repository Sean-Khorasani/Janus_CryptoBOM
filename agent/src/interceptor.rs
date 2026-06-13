#![cfg(target_os = "windows")]

use std::ffi::CStr;
use std::fs::OpenOptions;
use std::io::Write;

// ---------------------------------------------------------------------------
// Intercept mode helper
// ---------------------------------------------------------------------------

fn intercept_mode() -> String {
    std::env::var("JANUS_INTERCEPT_MODE").unwrap_or_else(|_| "passive".to_string())
}

fn is_active() -> bool {
    intercept_mode().eq_ignore_ascii_case("active")
}

/// True if `cipher_str` contains only classical (non-PQC) cipher identifiers
/// and therefore needs PQC hybrid injection in active mode.
fn needs_pqc_injection(cipher_str: &str) -> bool {
    let pqc = [
        "KYBER",
        "MLKEM",
        "ML-KEM",
        "X25519MLKEM",
        "BIKE",
        "Frodo",
        "SIKE",
        "OQS_",
        "PQ_",
        "L1_PQ",
        "HYBRID",
        "P256_KYBER",
    ];
    !pqc.iter().any(|p| cipher_str.contains(p))
}

/// Append PQC hybrid ciphers to a classical cipher list string.
fn inject_pqc_ciphers(cipher_str: &str) -> String {
    format!("{}:ECDHE+KYBER768:X25519MLKEM768", cipher_str)
}

/// Inject the X25519MLKEM768 group into a classic-only groups list.
fn inject_pqc_group(group_str: &str) -> String {
    // Prepend the hybrid group so it is preferred during negotiation.
    format!("X25519MLKEM768:{}", group_str)
}

// ---------------------------------------------------------------------------
// EVP cipher name resolution (unchanged)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
unsafe fn resolve_evp_cipher_name(cipher_ptr: *const std::ffi::c_void) -> String {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    if cipher_ptr.is_null() {
        return "NULL".to_string();
    }

    let dll_names: [*const u8; 5] = [
        b"libcrypto-3.dll\0".as_ptr(),
        b"libcrypto-3-x64.dll\0".as_ptr(),
        b"libcrypto-1_1.dll\0".as_ptr(),
        b"libcrypto-1_1-x64.dll\0".as_ptr(),
        b"libcrypto.dll\0".as_ptr(),
    ];

    for &dll in &dll_names {
        let h_module = GetModuleHandleA(dll);
        if !h_module.is_null() {
            let func_name = b"EVP_CIPHER_name\0";
            let proc = GetProcAddress(h_module, func_name.as_ptr());
            if let Some(proc_fn) = proc {
                let evp_cipher_name_fn: unsafe extern "C" fn(
                    *const std::ffi::c_void,
                )
                    -> *const std::ffi::c_char = std::mem::transmute(proc_fn);
                let name_ptr = evp_cipher_name_fn(cipher_ptr);
                if !name_ptr.is_null() {
                    if let Ok(c_str) = CStr::from_ptr(name_ptr).to_str() {
                        return c_str.to_string();
                    }
                }
            }

            let func_name_get0 = b"EVP_CIPHER_get0_name\0";
            let proc_get0 = GetProcAddress(h_module, func_name_get0.as_ptr());
            if let Some(proc_fn) = proc_get0 {
                let evp_cipher_get0_name_fn: unsafe extern "C" fn(
                    *const std::ffi::c_void,
                )
                    -> *const std::ffi::c_char = std::mem::transmute(proc_fn);
                let name_ptr = evp_cipher_get0_name_fn(cipher_ptr);
                if !name_ptr.is_null() {
                    if let Ok(c_str) = CStr::from_ptr(name_ptr).to_str() {
                        return c_str.to_string();
                    }
                }
            }
        }
    }

    format!("unknown-cipher-at-ptr-{}", cipher_ptr as usize)
}

#[cfg(not(target_os = "windows"))]
#[allow(unused_variables)]
unsafe fn resolve_evp_cipher_name(cipher_ptr: *const std::ffi::c_void) -> String {
    format!("unknown-cipher-at-ptr-{}", cipher_ptr as usize)
}

// ---------------------------------------------------------------------------
// Logging helper
// ---------------------------------------------------------------------------

fn log_interception(func: &str, detail: &str) {
    let log_msg = format!("Intercepted: {} | Detail: {}\n", func, detail);

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("janus-interceptor.log")
    {
        let _ = file.write_all(log_msg.as_bytes());
    }
}

// ---------------------------------------------------------------------------
// Original EVP hooks (unchanged)
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptInit(
    ctx: *mut std::ffi::c_void,
    cipher_type: *const std::ffi::c_void,
    key: *const u8,
    iv: *const u8,
) -> i32 {
    let alg = resolve_evp_cipher_name(cipher_type);
    log_interception("EVP_EncryptInit", &alg);

    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
        let dll_names: [*const u8; 5] = [
            b"libcrypto-3.dll\0".as_ptr(),
            b"libcrypto-3-x64.dll\0".as_ptr(),
            b"libcrypto-1_1.dll\0".as_ptr(),
            b"libcrypto-1_1-x64.dll\0".as_ptr(),
            b"libcrypto.dll\0".as_ptr(),
        ];
        for &dll in &dll_names {
            let h_module = GetModuleHandleA(dll);
            if !h_module.is_null() {
                let proc = GetProcAddress(h_module, b"EVP_EncryptInit\0".as_ptr());
                if let Some(proc_fn) = proc {
                    let orig_fn: unsafe extern "C" fn(
                        *mut std::ffi::c_void,
                        *const std::ffi::c_void,
                        *const u8,
                        *const u8,
                    ) -> i32 = std::mem::transmute(proc_fn);
                    return orig_fn(ctx, cipher_type, key, iv);
                }
            }
        }
    }

    1
}

#[cfg(target_os = "windows")]
#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptInit_ex(
    ctx: *mut std::ffi::c_void,
    cipher_type: *const std::ffi::c_void,
    impl_eng: *mut std::ffi::c_void,
    key: *const u8,
    iv: *const u8,
) -> i32 {
    let alg = resolve_evp_cipher_name(cipher_type);
    log_interception("EVP_EncryptInit_ex", &alg);

    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
        let dll_names: [*const u8; 5] = [
            b"libcrypto-3.dll\0".as_ptr(),
            b"libcrypto-3-x64.dll\0".as_ptr(),
            b"libcrypto-1_1.dll\0".as_ptr(),
            b"libcrypto-1_1-x64.dll\0".as_ptr(),
            b"libcrypto.dll\0".as_ptr(),
        ];
        for &dll in &dll_names {
            let h_module = GetModuleHandleA(dll);
            if !h_module.is_null() {
                let proc = GetProcAddress(h_module, b"EVP_EncryptInit_ex\0".as_ptr());
                if let Some(proc_fn) = proc {
                    let orig_fn: unsafe extern "C" fn(
                        *mut std::ffi::c_void,
                        *const std::ffi::c_void,
                        *mut std::ffi::c_void,
                        *const u8,
                        *const u8,
                    ) -> i32 = std::mem::transmute(proc_fn);
                    return orig_fn(ctx, cipher_type, impl_eng, key, iv);
                }
            }
        }
    }

    1
}

// ===========================================================================
// F5  — Runtime Algorithm Interception: TLS / OpenSSL hooks
// ===========================================================================

/// Resolve an original function from a libcrypto DLL on Windows.
/// Returns `None` on non-Windows platforms.
#[cfg(target_os = "windows")]
unsafe fn resolve_openssl_fn(name: &[u8]) -> Option<*mut std::ffi::c_void> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    let dll_names: [*const u8; 5] = [
        b"libcrypto-3.dll\0".as_ptr(),
        b"libcrypto-3-x64.dll\0".as_ptr(),
        b"libcrypto-1_1.dll\0".as_ptr(),
        b"libcrypto-1_1-x64.dll\0".as_ptr(),
        b"libcrypto.dll\0".as_ptr(),
    ];

    let mut null_name = name.to_vec();
    null_name.push(0);

    for &dll in &dll_names {
        let h_module = GetModuleHandleA(dll);
        if !h_module.is_null() {
            let proc = GetProcAddress(h_module, null_name.as_ptr());
            if let Some(proc_fn) = proc {
                return Some(proc_fn as *mut std::ffi::c_void);
            }
        }
    }
    None
}

#[cfg(not(target_os = "windows"))]
unsafe fn resolve_openssl_fn(_name: &[u8]) -> Option<*mut std::ffi::c_void> {
    None
}

/// Helper: convert a C string pointer to Rust &str (empty on failure).
unsafe fn cstr_to_str<'a>(ptr: *const std::ffi::c_char) -> &'a str {
    if ptr.is_null() {
        return "";
    }
    CStr::from_ptr(ptr).to_str().unwrap_or("")
}

// -----------------------------------------------------------------------
// SSL_CTX_set_cipher_list  — set the list of available TLS 1.2 ciphers
// -----------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_cipher_list(
    ctx: *mut std::ffi::c_void,
    str_: *const std::ffi::c_char,
) -> i32 {
    let original = cstr_to_str(str_);
    log_interception("SSL_CTX_set_cipher_list", original);

    let modified = if is_active() && needs_pqc_injection(original) {
        let injected = inject_pqc_ciphers(original);
        log_interception("SSL_CTX_set_cipher_list (PQC-injected)", &injected);
        Some(injected)
    } else {
        None
    };

    if cfg!(target_os = "windows") {
        if let Some(proc_fn) = resolve_openssl_fn(b"SSL_CTX_set_cipher_list") {
            let orig_fn: unsafe extern "C" fn(
                *mut std::ffi::c_void,
                *const std::ffi::c_char,
            ) -> i32 = std::mem::transmute(proc_fn);

            if let Some(ref modified) = modified {
                let c_str = std::ffi::CString::new(modified.as_str()).unwrap_or_default();
                return orig_fn(ctx, c_str.as_ptr());
            }
            return orig_fn(ctx, str_);
        }
    }
    0
}

// -----------------------------------------------------------------------
// SSL_set_cipher_list  — set ciphers per-SSL object
// -----------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[no_mangle]
pub unsafe extern "C" fn SSL_set_cipher_list(
    ssl: *mut std::ffi::c_void,
    str_: *const std::ffi::c_char,
) -> i32 {
    let original = cstr_to_str(str_);
    log_interception("SSL_set_cipher_list", original);

    let modified = if is_active() && needs_pqc_injection(original) {
        let injected = inject_pqc_ciphers(original);
        log_interception("SSL_set_cipher_list (PQC-injected)", &injected);
        Some(injected)
    } else {
        None
    };

    if cfg!(target_os = "windows") {
        if let Some(proc_fn) = resolve_openssl_fn(b"SSL_set_cipher_list") {
            let orig_fn: unsafe extern "C" fn(
                *mut std::ffi::c_void,
                *const std::ffi::c_char,
            ) -> i32 = std::mem::transmute(proc_fn);

            if let Some(ref modified) = modified {
                let c_str = std::ffi::CString::new(modified.as_str()).unwrap_or_default();
                return orig_fn(ssl, c_str.as_ptr());
            }
            return orig_fn(ssl, str_);
        }
    }
    0
}

// -----------------------------------------------------------------------
// SSL_CTX_set_ciphersuites  — set TLS 1.3 ciphersuites
// -----------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set_ciphersuites(
    ctx: *mut std::ffi::c_void,
    str_: *const std::ffi::c_char,
) -> i32 {
    let original = cstr_to_str(str_);
    log_interception("SSL_CTX_set_ciphersuites", original);

    let modified = if is_active() && needs_pqc_injection(original) {
        // For TLS 1.3, append a PQC-hybrid ciphersuite.
        let injected = format!("{}:TLS_AES_256_GCM_SHA384_KYBER768", original);
        log_interception("SSL_CTX_set_ciphersuites (PQC-injected)", &injected);
        Some(injected)
    } else {
        None
    };

    if cfg!(target_os = "windows") {
        if let Some(proc_fn) = resolve_openssl_fn(b"SSL_CTX_set_ciphersuites") {
            let orig_fn: unsafe extern "C" fn(
                *mut std::ffi::c_void,
                *const std::ffi::c_char,
            ) -> i32 = std::mem::transmute(proc_fn);

            if let Some(ref modified) = modified {
                let c_str = std::ffi::CString::new(modified.as_str()).unwrap_or_default();
                return orig_fn(ctx, c_str.as_ptr());
            }
            return orig_fn(ctx, str_);
        }
    }
    0
}

// -----------------------------------------------------------------------
// SSL_CTX_set1_groups_list  — set supported named groups (curves)
// -----------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[no_mangle]
pub unsafe extern "C" fn SSL_CTX_set1_groups_list(
    ctx: *mut std::ffi::c_void,
    str_: *const std::ffi::c_char,
) -> i32 {
    let original = cstr_to_str(str_);
    log_interception("SSL_CTX_set1_groups_list", original);

    let modified = if is_active() && needs_pqc_injection(original) {
        let injected = inject_pqc_group(original);
        log_interception("SSL_CTX_set1_groups_list (PQC-injected)", &injected);
        Some(injected)
    } else {
        None
    };

    if cfg!(target_os = "windows") {
        if let Some(proc_fn) = resolve_openssl_fn(b"SSL_CTX_set1_groups_list") {
            let orig_fn: unsafe extern "C" fn(
                *mut std::ffi::c_void,
                *const std::ffi::c_char,
            ) -> i32 = std::mem::transmute(proc_fn);

            if let Some(ref modified) = modified {
                let c_str = std::ffi::CString::new(modified.as_str()).unwrap_or_default();
                return orig_fn(ctx, c_str.as_ptr());
            }
            return orig_fn(ctx, str_);
        }
    }
    0
}
