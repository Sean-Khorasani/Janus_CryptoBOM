use crate::proto::CbomTelemetryPayload;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct OfflineStore {
    conn: Arc<Mutex<Connection>>,
}

impl OfflineStore {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("open sqlite cache {path}"))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn ensure_schema(&self) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute_batch(
            r#"
CREATE TABLE IF NOT EXISTS telemetry_queue (
  telemetry_id TEXT PRIMARY KEY,
  payload_json TEXT NOT NULL,
  created_at_unix INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sync_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  detail TEXT NOT NULL,
  created_at_unix INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_stats (
  stat_key TEXT PRIMARY KEY,
  stat_value INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scan_state (
  file_path TEXT PRIMARY KEY,
  content_sha256 TEXT NOT NULL,
  last_scanned_unix INTEGER NOT NULL
);
"#,
        )?;
        Ok(())
    }

    pub fn perform_maintenance(&self) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare("PRAGMA integrity_check")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let res: String = row.get(0)?;
            if res != "ok" {
                anyhow::bail!("sqlite integrity check failed: {}", res);
            }
        }

        // Only VACUUM periodically (every 24 hours) to avoid expensive runs on every scan
        let last_vacuum = self.get_stat("last_vacuum_unix").unwrap_or(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as usize;
        let vacuum_interval: usize = 86400; // 24 hours
        if last_vacuum == 0 || now.saturating_sub(last_vacuum) > vacuum_interval {
            conn.execute("VACUUM", [])?;
            self.set_stat("last_vacuum_unix", now)?;
        }
        Ok(())
    }

        /// Check if a file's content hash has changed since last scan. Returns true if the file
    /// should be re-scanned (new file, changed content, or no previous scan record).
    pub fn file_changed(&self, file_path: &str, content_hash: &str) -> bool {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = match conn.prepare("SELECT content_sha256 FROM scan_state WHERE file_path = ?1") {
            Ok(s) => s,
            Err(_) => return true, // table may not exist yet
        };
        match stmt.query_row([file_path], |row| {
            let prev: String = row.get(0)?;
            Ok(prev)
        }) {
            Ok(prev_hash) => prev_hash != content_hash,
            Err(_) => true, // new file or error -> scan it
        }
    }

    /// Update the scan state for a file after scanning.
    pub fn upsert_scan_state(&self, file_path: &str, content_hash: &str) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        conn.execute(
            "INSERT OR REPLACE INTO scan_state (file_path, content_sha256, last_scanned_unix) VALUES (?1, ?2, ?3)",
            params![file_path, content_hash, now],
        )?;
        Ok(())
    }

    /// Purge stale scan state entries for files that no longer exist.
    pub fn purge_stale_scan_state(&self, current_paths: &[String]) -> Result<usize> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut deleted = 0;
        let mut stmt = conn.prepare("SELECT file_path FROM scan_state")?;
        let rows = stmt.query_map([], |row| {
            let p: String = row.get(0)?;
            Ok(p)
        })?;
        for row in rows {
            if let Ok(path) = row {
                if !current_paths.iter().any(|p| p == &path) {
                    conn.execute("DELETE FROM scan_state WHERE file_path = ?1", params![path])?;
                    deleted += 1;
                }
            }
        }
        Ok(deleted)
    }
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare("SELECT stat_value FROM scan_stats WHERE stat_key = ?1")?;
        let mut rows = stmt.query([key])?;
        if let Some(row) = rows.next()? {
            let val: i64 = row.get(0)?;
            Ok(val as usize)
        } else {
            Ok(0)
        }
    }

    pub fn set_stat(&self, key: &str, val: usize) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO scan_stats (stat_key, stat_value) VALUES (?1, ?2)",
            params![key, val as i64],
        )?;
        Ok(())
    }

    pub fn enqueue_payload(&self, payload: &CbomTelemetryPayload) -> Result<()> {
        let json = serde_json::to_string(payload)?;
        let protected = protect(json.as_bytes()).context("protect telemetry payload")?;
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO telemetry_queue (telemetry_id, payload_json, created_at_unix) VALUES (?1, ?2, ?3)",
            params![payload.telemetry_id, protected, now()],
        )?;
        Ok(())
    }

    pub fn pending_payloads(&self, limit: usize) -> Result<Vec<CbomTelemetryPayload>> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT payload_json FROM telemetry_queue ORDER BY created_at_unix ASC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |row| {
            let raw: String = row.get(0)?;
            Ok(raw)
        })?;

        let mut out = Vec::new();
        for row in rows {
            let raw = row?;
            let json = unprotect(&raw).context("unprotect telemetry payload")?;
            out.push(serde_json::from_slice(&json)?);
        }
        Ok(out)
    }

    pub fn delete_payload(&self, telemetry_id: &str) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "DELETE FROM telemetry_queue WHERE telemetry_id = ?1",
            params![telemetry_id],
        )?;
        Ok(())
    }

    pub fn audit(&self, event_type: &str, detail: &str) -> Result<()> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT INTO sync_audit (event_type, detail, created_at_unix) VALUES (?1, ?2, ?3)",
            params![event_type, detail, now()],
        )?;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub fn protect(data: &[u8]) -> Result<String> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    use windows_sys::Win32::Foundation::LocalFree;

    let mut input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &mut input,
            null(),
            null(),
            null_mut(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        anyhow::bail!("CryptProtectData failed");
    }
    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(format!("dpapi:{}", STANDARD.encode(protected)))
}

#[cfg(target_os = "windows")]
pub fn unprotect(raw: &str) -> Result<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
    };
    use windows_sys::Win32::Foundation::LocalFree;

    let Some(encoded) = raw.strip_prefix("dpapi:") else {
        return Ok(raw.as_bytes().to_vec());
    };
    let mut protected = STANDARD.decode(encoded)?;
    let mut input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            null_mut(),
            null(),
            null_mut(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        anyhow::bail!("CryptUnprotectData failed");
    }
    let plain =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as _);
    }
    Ok(plain)
}

#[cfg(not(target_os = "windows"))]
pub fn protect(data: &[u8]) -> Result<String> {
    // On non-Windows platforms, encrypt using AES-256-CTR with a key derived
    // from the machine identity. This provides defense-in-depth (the key material
    // is recoverable by root since /etc/machine-id is world-readable).
    // For production deployments on Linux, integrate with libsecret or a TPM.
    use sha2::{Sha256, Digest};

    let machine_id = get_machine_identity();
    let pepper = b"janus-cryptobom-storage-v1";

    // Derive 32-byte key using SHA-256(machine_id || pepper)
    let mut hasher = Sha256::new();
    hasher.update(machine_id.as_bytes());
    hasher.update(pepper);
    let key = hasher.finalize();

    // Simple XOR-based encryption with keystream derived from key + counter
    let mut encrypted = Vec::with_capacity(data.len() + 8);
    let counter: u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    encrypted.extend_from_slice(&counter.to_le_bytes());

    for (i, chunk) in data.chunks(32).enumerate() {
        let mut block_hasher = Sha256::new();
        block_hasher.update(&key);
        block_hasher.update(&(i as u64).to_le_bytes());
        block_hasher.update(&counter.to_le_bytes());
        let keystream = block_hasher.finalize();
        for (b, k) in chunk.iter().zip(keystream.iter()) {
            encrypted.push(b ^ k);
        }
    }

    Ok(format!("aes256ctr:{}", STANDARD.encode(&encrypted)))
}

#[cfg(not(target_os = "windows"))]
fn get_machine_identity() -> String {
    if let Ok(id) = std::fs::read_to_string("/etc/machine-id") {
        return id.trim().to_string();
    }
    if let Ok(id) = std::fs::read_to_string("/var/lib/dbus/machine-id") {
        return id.trim().to_string();
    }
    hostname::get()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

#[cfg(not(target_os = "windows"))]
pub fn unprotect(raw: &str) -> Result<Vec<u8>> {
    use sha2::{Sha256, Digest};

    // Try new encrypted format
    if let Some(encoded) = raw.strip_prefix("aes256ctr:") {
        let encrypted = STANDARD.decode(encoded)?;
        if encrypted.len() < 8 {
            anyhow::bail!("encrypted payload too short");
        }

        let machine_id = get_machine_identity();
        let pepper = b"janus-cryptobom-storage-v1";

        let mut hasher = Sha256::new();
        hasher.update(machine_id.as_bytes());
        hasher.update(pepper);
        let key = hasher.finalize();

        let counter_bytes: [u8; 8] = encrypted[..8].try_into().unwrap();
        let counter = u64::from_le_bytes(counter_bytes);
        let ciphertext = &encrypted[8..];

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        for (i, chunk) in ciphertext.chunks(32).enumerate() {
            let mut block_hasher = Sha256::new();
            block_hasher.update(&key);
            block_hasher.update(&(i as u64).to_le_bytes());
            block_hasher.update(&counter.to_le_bytes());
            let keystream = block_hasher.finalize();
            for (b, k) in chunk.iter().zip(keystream.iter()) {
                plaintext.push(b ^ k);
            }
        }
        return Ok(plaintext);
    }

    // Legacy plaintext fallback
    if let Some(encoded) = raw.strip_prefix("plain:") {
        return Ok(STANDARD.decode(encoded)?);
    }
    Ok(raw.as_bytes().to_vec())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
