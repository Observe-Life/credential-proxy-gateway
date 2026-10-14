//! Encrypted credential vault.
//!
//! Security model (design doc §6.1/§6.2):
//! - Master password -> Argon2id -> 32-byte key-encryption-key (KEK).
//! - A random 32-byte data-encryption-key (DEK) is generated on init and stored
//!   encrypted under the KEK. The DEK never touches disk in plaintext.
//! - Each credential field is sealed with XChaCha20Poly1305 under the DEK with a
//!   fresh random 24-byte nonce.
//! - Plaintext secrets exist only in memory and are wrapped in `Zeroizing`.
//! - AI-facing reads always go through redaction; only an explicit
//!   master-password-gated reveal returns plaintext.

use crate::error::{ConnectorError, ErrorCode, Result};
use crate::types::{AuthMethod, BecomeRootConfig, HostConfig, HostSpec, JumpHop};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rusqlite::{Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use zeroize::Zeroizing;

const MANAGEMENT_GRANT_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Default)]
struct ManagementGrant {
    expires_at: Option<Instant>,
}

impl ManagementGrant {
    fn open(&mut self, now: Instant) {
        self.expires_at = Some(now + MANAGEMENT_GRANT_TTL);
    }

    fn remaining_seconds(&self, now: Instant) -> u64 {
        self.expires_at.and_then(|end| end.checked_duration_since(now))
            .map(|duration| duration.as_secs()).unwrap_or(0)
    }

    fn is_open(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|end| end > now)
    }

    fn close(&mut self) {
        self.expires_at = None;
    }
}

const DEK_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    getrandom::fill(&mut buf).map_err(|e| ConnectorError::internal(format!("rng: {e}")))?;
    Ok(buf)
}

fn argon2() -> Argon2<'static> {
    // OWASP-recommended-ish defaults from the crate (19 MiB, t=2, p=1).
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::DEFAULT)
}

/// Derive the 32-byte KEK from the master password and salt.
fn derive_kek(master_password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut kek = Zeroizing::new([0u8; 32]);
    argon2()
        .hash_password_into(master_password.as_bytes(), salt, kek.as_mut_slice())
        .map_err(|e| ConnectorError::internal(format!("argon2: {e}")))?;
    Ok(kek)
}

fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce_bytes = random_bytes(NONCE_LEN)?;
    let nonce = XNonce::from_slice(&nonce_bytes);
    let mut ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| ConnectorError::internal("seal failed"))?;
    // Store nonce || ciphertext.
    let mut out = nonce_bytes;
    out.append(&mut ct);
    Ok(out)
}

fn open(key: &[u8; 32], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if blob.len() < NONCE_LEN {
        return Err(ConnectorError::internal("ciphertext too short"));
    }
    let (nonce_bytes, ct) = blob.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(key.into());
    let nonce = XNonce::from_slice(nonce_bytes);
    let pt = cipher.decrypt(nonce, ct).map_err(|_| {
        ConnectorError::new(
            ErrorCode::VaultBadPassword,
            "decryption failed (wrong key or corrupted vault)",
        )
    })?;
    Ok(Zeroizing::new(pt))
}

/// Holds the decrypted DEK while unlocked. Dropped (and zeroized) on lock.
struct Unlocked {
    dek: Zeroizing<[u8; 32]>,
}

pub struct Vault {
    conn: Mutex<Connection>,
    unlocked: Mutex<Option<Unlocked>>,
    management_unlocked: Mutex<ManagementGrant>,
    runtime_key_path: std::path::PathBuf,
}

impl Vault {
    /// Open (or create) the vault database at `path`. Does not unlock.
    pub fn open(path: &Path, runtime_key_path: &Path) -> Result<Vault> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS vault_meta (
                 id INTEGER PRIMARY KEY CHECK (id = 1),
                 salt BLOB NOT NULL,
                 dek_wrapped BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS hosts (
                 id TEXT PRIMARY KEY,
                 alias TEXT NOT NULL,
                 host TEXT NOT NULL,
                 port INTEGER NOT NULL,
                 user TEXT NOT NULL,
                 -- encrypted JSON of the full HostConfig (secrets included)
                 sealed BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS host_keys (
                 host TEXT NOT NULL,
                 port INTEGER NOT NULL,
                 fingerprint TEXT NOT NULL,
                 PRIMARY KEY (host, port)
             );",
        )?;
        let runtime_key_path = runtime_key_path.to_path_buf();
        let initialized: bool = {
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM vault_meta", [], |r| r.get(0))?;
            n > 0
        };
        let unlocked = if initialized {
            std::fs::read(&runtime_key_path).ok().and_then(|bytes| {
                if bytes.len() != DEK_LEN { return None; }
                let mut dek = Zeroizing::new([0u8; DEK_LEN]);
                dek.copy_from_slice(&bytes);
                Some(Unlocked { dek })
            })
        } else { None };
        Ok(Vault {
            conn: Mutex::new(conn),
            management_unlocked: Mutex::new(ManagementGrant::default()),
            runtime_key_path,
            unlocked: Mutex::new(unlocked),
        })
    }

    fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn is_initialized(&self) -> Result<bool> {
        let conn = self.lock_conn();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM vault_meta", [], |r| r.get(0))?;
        Ok(n > 0)
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    pub fn is_management_unlocked(&self) -> bool {
        self.management_unlocked.lock().map(|g| g.is_open(Instant::now())).unwrap_or(false)
    }

    /// Remaining lifetime of the human-authorized management grant.
    /// This exposes only a duration, never credential material.
    pub fn management_remaining_seconds(&self) -> u64 {
        self.management_unlocked.lock()
            .map(|grant| grant.remaining_seconds(Instant::now())).unwrap_or(0)
    }

    fn save_runtime_key(&self, dek: &[u8; DEK_LEN]) -> Result<()> {
        if let Some(parent) = self.runtime_key_path.parent() { std::fs::create_dir_all(parent)?; }
        let tmp = self.runtime_key_path.with_extension("tmp");
        std::fs::write(&tmp, dek)?;
        let mut perms = std::fs::metadata(&tmp)?.permissions();
        #[cfg(unix)]
        perms.set_mode(0o600);
        std::fs::set_permissions(&tmp, perms)?;
        std::fs::rename(tmp, &self.runtime_key_path)?;
        Ok(())
    }

    fn require_management(&self) -> Result<()> {
        if self.is_management_unlocked() { Ok(()) } else { Err(ConnectorError::new(ErrorCode::VaultLocked,"请提醒用户在凭证代理保险箱网页打开30分钟临时管理开关")) }
    }

    /// First-run: create the vault with a master password. Generates salt + DEK.
    pub fn init(&self, master_password: &str) -> Result<()> {
        if self.is_initialized()? {
            return Err(ConnectorError::new(
                ErrorCode::VaultAlreadyInit,
                "vault already initialized",
            ));
        }
        let salt = random_bytes(SALT_LEN)?;
        let kek = derive_kek(master_password, &salt)?;
        let dek = random_bytes(DEK_LEN)?;
        let dek_wrapped = seal(&kek, &dek)?;
        {
            let conn = self.lock_conn();
            conn.execute(
                "INSERT INTO vault_meta (id, salt, dek_wrapped) VALUES (1, ?1, ?2)",
                rusqlite::params![salt, dek_wrapped],
            )?;
        }
        // Unlock immediately after init.
        let mut dek_arr = Zeroizing::new([0u8; 32]);
        dek_arr.copy_from_slice(&dek);
        self.save_runtime_key(&dek_arr)?;
        *self.unlocked.lock().unwrap_or_else(|p| p.into_inner()) = Some(Unlocked { dek: dek_arr });
        self.management_unlocked.lock().unwrap_or_else(|p| p.into_inner()).open(Instant::now());
        Ok(())
    }

    /// Unlock with the master password: derive KEK, decrypt DEK, hold in memory.
    pub fn unlock(&self, master_password: &str) -> Result<()> {
        let (salt, dek_wrapped): (Vec<u8>, Vec<u8>) = {
            let conn = self.lock_conn();
            conn.query_row(
                "SELECT salt, dek_wrapped FROM vault_meta WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(|| {
                ConnectorError::new(ErrorCode::VaultBadPassword, "vault not initialized")
            })?
        };
        let kek = derive_kek(master_password, &salt)?;
        let dek = open(&kek, &dek_wrapped)?; // VaultBadPassword on wrong pw
        if dek.len() != DEK_LEN {
            return Err(ConnectorError::internal("corrupt DEK length"));
        }
        let mut dek_arr = Zeroizing::new([0u8; 32]);
        dek_arr.copy_from_slice(&dek);
        self.save_runtime_key(&dek_arr)?;
        *self.unlocked.lock().unwrap_or_else(|p| p.into_inner()) = Some(Unlocked { dek: dek_arr });
        self.management_unlocked.lock().unwrap_or_else(|p| p.into_inner()).open(Instant::now());
        Ok(())
    }

    /// Forget the in-memory DEK.
    pub fn lock(&self) {
        *self.unlocked.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.management_unlocked.lock().unwrap_or_else(|p| p.into_inner()).close();
    }

    pub fn lock_management(&self) {
        self.management_unlocked.lock().unwrap_or_else(|p| p.into_inner()).close();
    }

    pub fn open_management_grant(&self) -> Result<()> {
        if !self.is_unlocked() { return Err(ConnectorError::locked()); }
        self.management_unlocked.lock().unwrap_or_else(|p| p.into_inner()).open(Instant::now());
        Ok(())
    }

    fn service_table(&self) -> Result<()> {
        self.lock_conn().execute("CREATE TABLE IF NOT EXISTS mcp_services (id TEXT PRIMARY KEY, sealed BLOB NOT NULL)", [])?;
        Ok(())
    }

    pub fn put_service_record(&self, mut record: crate::services::ServiceRecord) -> Result<()> {
        self.require_management()?;
        record.validate()?;
        if record.credential.is_empty() {
            if let Ok(existing) = self.get_service_record(&record.id) { record.credential = existing.credential; }
        }
        self.service_table()?;
        let bytes = serde_json::to_vec(&record).map_err(|_| ConnectorError::internal("registration serialization failed"))?;
        let sealed = self.with_dek(|dek| seal(dek, &bytes))?;
        self.lock_conn().execute("INSERT INTO mcp_services (id,sealed) VALUES (?1,?2) ON CONFLICT(id) DO UPDATE SET sealed=excluded.sealed", rusqlite::params![record.id, sealed])?;
        Ok(())
    }

    pub fn get_service_record(&self, id: &str) -> Result<crate::services::ServiceRecord> {
        self.service_table()?;
        let sealed: Vec<u8> = self.lock_conn().query_row("SELECT sealed FROM mcp_services WHERE id=?1", [id], |r| r.get(0))?;
        let bytes = self.with_dek(|dek| open(dek, &sealed))?;
        serde_json::from_slice(&bytes).map_err(|_| ConnectorError::internal("registration unreadable"))
    }

    pub fn service_metadata(&self) -> Result<Vec<serde_json::Value>> {
        self.service_table()?;
        let ids: Vec<String> = {
            let conn = self.lock_conn();
            let mut stmt = conn.prepare("SELECT id FROM mcp_services ORDER BY id")?;
            let values = stmt.query_map([], |row| row.get(0))?.collect::<std::result::Result<Vec<_>,_>>()?;
            values
        };
        ids.iter().map(|id| self.get_service_record(id).map(|r| r.metadata())).collect()
    }

    pub fn remove_service_record(&self, id: &str) -> Result<()> {
        self.require_management()?;
        self.service_table()?;
        self.lock_conn().execute("DELETE FROM mcp_services WHERE id=?1", [id])?;
        Ok(())
    }

    /// Run a closure with the live DEK, or fail if locked.
    fn with_dek<T>(&self, f: impl FnOnce(&[u8; 32]) -> Result<T>) -> Result<T> {
        let guard = self.unlocked.lock().unwrap_or_else(|p| p.into_inner());
        match guard.as_ref() {
            Some(u) => f(&u.dek),
            None => Err(ConnectorError::locked()),
        }
    }

    /// Verify a master password without changing unlock state (for reveal gate).
    pub fn verify_master_password(&self, master_password: &str) -> Result<()> {
        let (salt, dek_wrapped): (Vec<u8>, Vec<u8>) = {
            let conn = self.lock_conn();
            conn.query_row(
                "SELECT salt, dek_wrapped FROM vault_meta WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?
        };
        let kek = derive_kek(master_password, &salt)?;
        open(&kek, &dek_wrapped)?;
        Ok(())
    }

    fn gen_id() -> Result<String> {
        let b = random_bytes(8)?;
        Ok(b.iter().map(|x| format!("{x:02x}")).collect())
    }

    /// Insert a new host, returning its assigned id.
    pub fn add_host(&self, spec: HostSpec) -> Result<String> {
        self.require_management()?;
        let id = Self::gen_id()?;
        let cfg = HostConfig {
            id: id.clone(),
            alias: spec.alias,
            host: spec.host,
            port: spec.port,
            user: spec.user,
            notes: spec.notes,
            auth: spec.auth,
            jump_hosts: spec.jump_hosts,
            env: spec.env,
            become_root: spec.become_root,
        };
        self.persist_host(&cfg)?;
        Ok(id)
    }

    /// Overwrite an existing host wholesale (AI may write new secrets here).
    pub fn update_host(&self, id: &str, spec: HostSpec) -> Result<()> {
        self.require_management()?;
        // Ensure it exists.
        let existing = self.get_host_config(id)?;
        let cfg = HostConfig {
            id: id.to_string(),
            alias: spec.alias,
            host: spec.host,
            port: spec.port,
            user: spec.user,
            notes: spec.notes,
            auth: merge_auth(existing.auth, spec.auth),
            jump_hosts: merge_jump_hosts(existing.jump_hosts, spec.jump_hosts),
            env: spec.env,
            become_root: merge_become_root(existing.become_root, spec.become_root),
        };
        self.persist_host(&cfg)
    }

    fn persist_host(&self, cfg: &HostConfig) -> Result<()> {
        let json = serde_json::to_vec(cfg)
            .map_err(|e| ConnectorError::internal(format!("serialize host: {e}")))?;
        let sealed = self.with_dek(|dek| seal(dek, &json))?;
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO hosts (id, alias, host, port, user, sealed) VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(id) DO UPDATE SET alias=?2, host=?3, port=?4, user=?5, sealed=?6",
            rusqlite::params![cfg.id, cfg.alias, cfg.host, cfg.port, cfg.user, sealed],
        )?;
        Ok(())
    }

    pub fn remove_host(&self, id: &str) -> Result<()> {
        self.require_management()?;
        let conn = self.lock_conn();
        let n = conn.execute("DELETE FROM hosts WHERE id = ?1", rusqlite::params![id])?;
        if n == 0 {
            return Err(ConnectorError::host_not_found(id));
        }
        Ok(())
    }

    /// Full host config WITH plaintext secrets. Internal/connection use and the
    /// master-password-gated reveal only — never hand this to AI directly.
    pub fn get_host_config(&self, id: &str) -> Result<HostConfig> {
        let sealed: Vec<u8> = {
            let conn = self.lock_conn();
            conn.query_row(
                "SELECT sealed FROM hosts WHERE id = ?1",
                rusqlite::params![id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or_else(|| ConnectorError::host_not_found(id))?
        };
        let json = self.with_dek(|dek| open(dek, &sealed))?;
        let cfg: HostConfig = serde_json::from_slice(&json)
            .map_err(|e| ConnectorError::internal(format!("deserialize host: {e}")))?;
        Ok(cfg)
    }

    /// All host configs (plaintext); callers redact before exposing to AI.
    pub fn list_host_configs(&self) -> Result<Vec<HostConfig>> {
        let ids: Vec<String> = {
            let conn = self.lock_conn();
            let mut stmt = conn.prepare("SELECT id FROM hosts ORDER BY alias")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(self.get_host_config(&id)?);
        }
        Ok(out)
    }

    /// Reveal plaintext credentials, gated on the master password (human only).
    pub fn reveal_credentials(
        &self,
        id: &str,
        master_password: &str,
    ) -> Result<(AuthMethod, Vec<JumpHop>)> {
        self.verify_master_password(master_password)?;
        let cfg = self.get_host_config(id)?;
        Ok((cfg.auth, cfg.jump_hosts))
    }

    // --- Host key TOFU ---

    /// Returns the recorded fingerprint for a host:port, if any.
    pub fn get_host_key(&self, host: &str, port: u16) -> Result<Option<String>> {
        let conn = self.lock_conn();
        let fp: Option<String> = conn
            .query_row(
                "SELECT fingerprint FROM host_keys WHERE host = ?1 AND port = ?2",
                rusqlite::params![host, port],
                |r| r.get(0),
            )
            .optional()?;
        Ok(fp)
    }

    /// Record a fingerprint on first use (TOFU).
    pub fn record_host_key(&self, host: &str, port: u16, fingerprint: &str) -> Result<()> {
        let conn = self.lock_conn();
        conn.execute(
            "INSERT INTO host_keys (host, port, fingerprint) VALUES (?1,?2,?3)
             ON CONFLICT(host, port) DO NOTHING",
            rusqlite::params![host, port, fingerprint],
        )?;
        Ok(())
    }
}

fn merge_auth(existing: AuthMethod, incoming: AuthMethod) -> AuthMethod {
    match (&existing, &incoming) {
        (AuthMethod::Password { .. }, AuthMethod::Password { password })
            if password == "***" || password.is_empty() =>
        {
            existing
        }
        (
            AuthMethod::PrivateKey { .. },
            AuthMethod::PrivateKey {
                key_pem,
                passphrase,
            },
        ) if key_pem == "***" || key_pem.is_empty() => match (existing, passphrase.as_deref()) {
            (
                AuthMethod::PrivateKey {
                    key_pem,
                    passphrase: old_passphrase,
                },
                Some("***") | None | Some(""),
            ) => AuthMethod::PrivateKey {
                key_pem,
                passphrase: old_passphrase,
            },
            (AuthMethod::PrivateKey { key_pem, .. }, Some(new_passphrase)) => {
                AuthMethod::PrivateKey {
                    key_pem,
                    passphrase: Some(new_passphrase.to_string()),
                }
            }
            (other, _) => other,
        },
        (AuthMethod::KeyboardInteractive { .. }, AuthMethod::KeyboardInteractive { answers })
            if answers.is_empty() || answers.iter().all(|a| a == "***") =>
        {
            existing
        }
        _ => incoming,
    }
}

fn merge_jump_hosts(existing: Vec<JumpHop>, incoming: Vec<JumpHop>) -> Vec<JumpHop> {
    incoming
        .into_iter()
        .enumerate()
        .map(|(idx, mut hop)| {
            if let Some(old) = existing.get(idx) {
                hop.auth = merge_auth(old.auth.clone(), hop.auth);
            }
            hop
        })
        .collect()
}

fn merge_become_root(
    existing: Option<BecomeRootConfig>,
    incoming: Option<BecomeRootConfig>,
) -> Option<BecomeRootConfig> {
    match (existing, incoming) {
        (Some(old), Some(mut new)) if new.password == "***" || new.password.is_empty() => {
            new.password = old.password;
            Some(new)
        }
        (_, new) => new,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AuthMethod, BecomeRootConfig};

    fn temp_vault() -> Vault {
        let dir =
            std::env::temp_dir().join(format!("vault-test-{}", super::Vault::gen_id().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        Vault::open(&dir.join("vault.db"), &dir.join("runtime-key")).unwrap()
    }

    #[test]
    fn init_unlock_roundtrip() {
        let v = temp_vault();
        assert!(!v.is_initialized().unwrap());
        v.init("hunter2").unwrap();
        assert!(v.is_initialized().unwrap());
        assert!(v.is_unlocked());
        v.lock();
        assert!(!v.is_unlocked());
        v.unlock("hunter2").unwrap();
        assert!(v.is_unlocked());
    }

    #[test]
    fn wrong_password_rejected() {
        let v = temp_vault();
        v.init("correct").unwrap();
        v.lock();
        let err = v.unlock("wrong").unwrap_err();
        assert_eq!(err.code, ErrorCode::VaultBadPassword);
        assert!(!v.is_unlocked());
    }

    #[test]
    fn host_crud_and_secret_seal() {
        let v = temp_vault();
        v.init("pw").unwrap();
        let spec = HostSpec {
            alias: "box1".into(),
            host: "1.2.3.4".into(),
            port: 22,
            user: "root".into(),
            notes: String::new(),
            auth: AuthMethod::Password {
                password: "s3cr3t".into(),
            },
            jump_hosts: vec![],
            env: Default::default(),
            become_root: None,
        };
        let id = v.add_host(spec).unwrap();
        let cfg = v.get_host_config(&id).unwrap();
        match &cfg.auth {
            AuthMethod::Password { password } => assert_eq!(password, "s3cr3t"),
            _ => panic!("wrong auth"),
        }
        // redaction hides the secret
        let red = cfg.redacted();
        match red.auth {
            AuthMethod::Password { password } => assert_eq!(password, "***"),
            _ => panic!(),
        }
        // reveal requires correct master password
        assert!(v.reveal_credentials(&id, "nope").is_err());
        let (auth, _) = v.reveal_credentials(&id, "pw").unwrap();
        matches!(auth, AuthMethod::Password { .. });

        v.remove_host(&id).unwrap();
        assert_eq!(
            v.get_host_config(&id).unwrap_err().code,
            ErrorCode::HostNotFound
        );
    }

    #[test]
    fn update_host_keeps_redacted_secrets_and_become_root_password() {
        let v = temp_vault();
        v.init("pw").unwrap();
        let id = v
            .add_host(HostSpec {
                alias: "box1".into(),
                host: "1.2.3.4".into(),
                port: 22,
                user: "ubuntu".into(),
                notes: String::new(),
                auth: AuthMethod::Password {
                    password: "ssh-secret".into(),
                },
                jump_hosts: vec![],
                env: Default::default(),
                become_root: Some(BecomeRootConfig {
                    enabled: true,
                    command: "su -".into(),
                    password: "root-secret".into(),
                    prompt_timeout_ms: 5000,
                }),
            })
            .unwrap();

        v.update_host(
            &id,
            HostSpec {
                alias: "renamed".into(),
                host: "1.2.3.4".into(),
                port: 22,
                user: "ubuntu".into(),
                notes: String::new(),
                auth: AuthMethod::Password {
                    password: "***".into(),
                },
                jump_hosts: vec![],
                env: Default::default(),
                become_root: Some(BecomeRootConfig {
                    enabled: true,
                    command: "su -".into(),
                    password: "***".into(),
                    prompt_timeout_ms: 9000,
                }),
            },
        )
        .unwrap();

        let cfg = v.get_host_config(&id).unwrap();
        match cfg.auth {
            AuthMethod::Password { password } => assert_eq!(password, "ssh-secret"),
            _ => panic!("wrong auth"),
        }
        let become_root = cfg.become_root.unwrap();
        assert_eq!(become_root.password, "root-secret");
        assert_eq!(become_root.prompt_timeout_ms, 9000);
    }

    #[test]
    fn locked_vault_refuses_host_ops() {
        let v = temp_vault();
        v.init("pw").unwrap();
        v.lock();
        let spec = HostSpec {
            alias: "x".into(),
            host: "h".into(),
            port: 22,
            user: "u".into(),
            notes: String::new(),
            auth: AuthMethod::Password {
                password: "p".into(),
            },
            jump_hosts: vec![],
            env: Default::default(),
            become_root: None,
        };
        assert_eq!(v.add_host(spec).unwrap_err().code, ErrorCode::VaultLocked);
    }

    #[test]
    fn host_key_tofu() {
        let v = temp_vault();
        v.init("pw").unwrap();
        assert!(v.get_host_key("h", 22).unwrap().is_none());
        v.record_host_key("h", 22, "SHA256:abc").unwrap();
        assert_eq!(v.get_host_key("h", 22).unwrap().unwrap(), "SHA256:abc");
        // second record is ignored (TOFU keeps first)
        v.record_host_key("h", 22, "SHA256:different").unwrap();
        assert_eq!(v.get_host_key("h", 22).unwrap().unwrap(), "SHA256:abc");
    }
}

#[cfg(test)]
mod management_grant_tests {
    use super::*;

    #[test]
    fn management_grant_defaults_closed_and_expires_after_30_minutes() {
        let start = Instant::now();
        let mut grant = ManagementGrant::default();
        assert!(!grant.is_open(start));
        grant.open(start);
        assert_eq!(grant.remaining_seconds(start), 1800);
        assert!(grant.is_open(start + Duration::from_secs(1799)));
        assert!(!grant.is_open(start + Duration::from_secs(1800)));
        assert_eq!(grant.remaining_seconds(start + Duration::from_secs(1801)), 0);
    }

    #[test]
    fn management_grant_manual_close_and_restart_do_not_keep_authority() {
        let start = Instant::now();
        let mut grant = ManagementGrant::default();
        grant.open(start);
        grant.close();
        assert!(!grant.is_open(start));
        assert!(!ManagementGrant::default().is_open(start));
    }
}

#[cfg(test)]
mod service_registry_tests {
    use super::*;
    use crate::services::ServiceRecord;

    #[test]
    fn registry_requires_grant_encrypts_and_redacts_secret() {
        let dir = std::env::temp_dir().join(format!("registry-test-{}", Vault::gen_id().unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        let vault = Vault::open(&dir.join("vault.db"), &dir.join("runtime-key")).unwrap();
        vault.init("test-master-password").unwrap();
        vault.lock_management();
        let mut record = ServiceRecord { id:"github".into(), name:"GitHub".into(), adapter:"github".into(), url:String::new(), credential:"secret-registry-test".into(), tools:serde_json::json!(["gh_status"]), notes:"test".into() };
        assert!(vault.put_service_record(record.clone()).is_err());
        vault.open_management_grant().unwrap();
        vault.put_service_record(record.clone()).unwrap();
        assert!(vault.is_management_unlocked());
        assert!(!vault.service_metadata().unwrap()[0].to_string().contains("secret-registry-test"));
        record.credential.clear();
        record.notes="edited".into();
        vault.put_service_record(record).unwrap();
        assert_eq!(vault.get_service_record("github").unwrap().credential,"secret-registry-test");
        vault.lock_management();
        assert!(vault.remove_service_record("github").is_err());
    }
}
