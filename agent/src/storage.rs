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
"#,
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
fn protect(data: &[u8]) -> Result<String> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_UI_FORBIDDEN, DATA_BLOB,
    };
    use windows_sys::Win32::System::Memory::LocalFree;

    let mut input = DATA_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut output = DATA_BLOB {
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
fn unprotect(raw: &str) -> Result<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Security::Cryptography::{
        CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, DATA_BLOB,
    };
    use windows_sys::Win32::System::Memory::LocalFree;

    let Some(encoded) = raw.strip_prefix("dpapi:") else {
        return Ok(raw.as_bytes().to_vec());
    };
    let mut protected = STANDARD.decode(encoded)?;
    let mut input = DATA_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_mut_ptr(),
    };
    let mut output = DATA_BLOB {
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
fn protect(data: &[u8]) -> Result<String> {
    Ok(format!("plain:{}", STANDARD.encode(data)))
}

#[cfg(not(target_os = "windows"))]
fn unprotect(raw: &str) -> Result<Vec<u8>> {
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
