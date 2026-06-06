use std::fs::OpenOptions;
use std::io::Write;

#[cfg(target_os = "windows")]
unsafe fn resolve_evp_cipher_name(cipher_ptr: *const std::ffi::c_void) -> String {
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, GetModuleHandleA};
    
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
                let evp_cipher_name_fn: unsafe extern "C" fn(*const std::ffi::c_void) -> *const std::ffi::c_char =
                    std::mem::transmute(proc_fn);
                let name_ptr = evp_cipher_name_fn(cipher_ptr);
                if !name_ptr.is_null() {
                    if let Ok(c_str) = std::ffi::CStr::from_ptr(name_ptr).to_str() {
                        return c_str.to_string();
                    }
                }
            }
            
            let func_name_get0 = b"EVP_CIPHER_get0_name\0";
            let proc_get0 = GetProcAddress(h_module, func_name_get0.as_ptr());
            if let Some(proc_fn) = proc_get0 {
                let evp_cipher_get0_name_fn: unsafe extern "C" fn(*const std::ffi::c_void) -> *const std::ffi::c_char =
                    std::mem::transmute(proc_fn);
                let name_ptr = evp_cipher_get0_name_fn(cipher_ptr);
                if !name_ptr.is_null() {
                    if let Ok(c_str) = std::ffi::CStr::from_ptr(name_ptr).to_str() {
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

fn log_interception(func: &str, cipher_ptr: *const std::ffi::c_void) {
    let alg = unsafe { resolve_evp_cipher_name(cipher_ptr) };
    let log_msg = format!("Intercepted: {} | Algorithm: {}\n", func, alg);
    
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .write(true)
        .append(true)
        .open("janus-interceptor.log")
    {
        let _ = file.write_all(log_msg.as_bytes());
    }
}

#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptInit(
    ctx: *mut std::ffi::c_void,
    cipher_type: *const std::ffi::c_void,
    key: *const u8,
    iv: *const u8,
) -> i32 {
    log_interception("EVP_EncryptInit", cipher_type);
    
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, GetModuleHandleA};
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
                    let orig_fn: unsafe extern "C" fn(*mut std::ffi::c_void, *const std::ffi::c_void, *const u8, *const u8) -> i32 =
                        std::mem::transmute(proc_fn);
                    return orig_fn(ctx, cipher_type, key, iv);
                }
            }
        }
    }
    
    1
}

#[no_mangle]
pub unsafe extern "C" fn EVP_EncryptInit_ex(
    ctx: *mut std::ffi::c_void,
    cipher_type: *const std::ffi::c_void,
    impl_eng: *mut std::ffi::c_void,
    key: *const u8,
    iv: *const u8,
) -> i32 {
    log_interception("EVP_EncryptInit_ex", cipher_type);
    
    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, GetModuleHandleA};
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
                    let orig_fn: unsafe extern "C" fn(*mut std::ffi::c_void, *const std::ffi::c_void, *mut std::ffi::c_void, *const u8, *const u8) -> i32 =
                        std::mem::transmute(proc_fn);
                    return orig_fn(ctx, cipher_type, impl_eng, key, iv);
                }
            }
        }
    }
    
    1
}
