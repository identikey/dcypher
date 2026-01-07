//! SQLite ownership store

use std::sync::Mutex;

use async_trait::async_trait;
use blake3::Hash;
use rusqlite::Connection;

use super::schema::init_schema;
use crate::capability::Operation;
use crate::error::{AuthError, AuthResult};
use crate::fingerprint::PublicKeyFingerprint;
use crate::grant::AccessGrant;
use crate::ownership::OwnershipStore;

/// SQLite-backed ownership store
pub struct SqliteOwnershipStore {
    conn: Mutex<Connection>,
}

impl SqliteOwnershipStore {
    /// Open or create a database at the given path
    pub fn open(path: &str) -> AuthResult<Self> {
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory database (for testing)
    pub fn in_memory() -> AuthResult<Self> {
        let conn = Connection::open_in_memory()?;
        init_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
}

#[async_trait]
impl OwnershipStore for SqliteOwnershipStore {
    async fn register(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<()> {
        let conn = self.conn.lock().unwrap();

        // Check for existing different owner
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT owner_fingerprint FROM ownership WHERE file_hash = ?",
                [file_hash.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .ok();

        if let Some(existing_owner) = existing {
            if existing_owner != owner.as_bytes().as_slice() {
                return Err(AuthError::AlreadyExists(format!(
                    "File {file_hash} already owned by different key"
                )));
            }
            return Ok(()); // Idempotent
        }

        conn.execute(
            "INSERT INTO ownership (file_hash, owner_fingerprint, created_at) VALUES (?, ?, ?)",
            (
                file_hash.as_bytes().as_slice(),
                owner.as_bytes().as_slice(),
                Self::now(),
            ),
        )?;

        Ok(())
    }

    async fn is_owner(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<bool> {
        let conn = self.conn.lock().unwrap();

        let result: Option<Vec<u8>> = conn
            .query_row(
                "SELECT owner_fingerprint FROM ownership WHERE file_hash = ?",
                [file_hash.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .ok();

        Ok(result
            .map(|v| v == owner.as_bytes().as_slice())
            .unwrap_or(false))
    }

    async fn list_owned(&self, owner: &PublicKeyFingerprint) -> AuthResult<Vec<Hash>> {
        let conn = self.conn.lock().unwrap();

        let mut stmt =
            conn.prepare("SELECT file_hash FROM ownership WHERE owner_fingerprint = ?")?;

        let hashes = stmt
            .query_map([owner.as_bytes().as_slice()], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(bytes)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|bytes| {
                if bytes.len() == 32 {
                    let arr: [u8; 32] = bytes.try_into().ok()?;
                    Some(Hash::from(arr))
                } else {
                    None
                }
            })
            .collect();

        Ok(hashes)
    }

    async fn transfer(
        &self,
        from: &PublicKeyFingerprint,
        to: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        if !self.is_owner(from, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can transfer".into()));
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE ownership SET owner_fingerprint = ? WHERE file_hash = ?",
            (to.as_bytes().as_slice(), file_hash.as_bytes().as_slice()),
        )?;

        Ok(())
    }

    async fn grant_access(&self, grant: AccessGrant) -> AuthResult<()> {
        if !self.is_owner(&grant.owner, &grant.file_hash).await? {
            return Err(AuthError::NotAuthorized(
                "Only owner can grant access".into(),
            ));
        }

        let ops_json: Vec<&str> = grant.operations.iter().map(|o| o.as_str()).collect();
        let ops_str =
            serde_json::to_string(&ops_json).map_err(|e| AuthError::Storage(e.to_string()))?;

        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT OR REPLACE INTO access_grants 
               (file_hash, owner_fingerprint, grantee_fingerprint, operations, expires_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?)"#,
            (
                grant.file_hash.as_bytes().as_slice(),
                grant.owner.as_bytes().as_slice(),
                grant.grantee.as_bytes().as_slice(),
                &ops_str,
                grant.expires_at as i64,
                grant.created_at as i64,
            ),
        )?;

        Ok(())
    }

    async fn revoke_access(
        &self,
        owner: &PublicKeyFingerprint,
        grantee: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<()> {
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can revoke".into()));
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM access_grants WHERE file_hash = ? AND grantee_fingerprint = ?",
            (
                file_hash.as_bytes().as_slice(),
                grantee.as_bytes().as_slice(),
            ),
        )?;

        Ok(())
    }

    async fn has_access(
        &self,
        pubkey: &PublicKeyFingerprint,
        file_hash: &Hash,
        operation: Operation,
    ) -> AuthResult<bool> {
        // Owner has all access
        if self.is_owner(pubkey, file_hash).await? {
            return Ok(true);
        }

        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        let result: Option<String> = conn
            .query_row(
                r#"SELECT operations FROM access_grants 
               WHERE file_hash = ? AND grantee_fingerprint = ?
               AND (expires_at = 0 OR expires_at > ?)"#,
                (
                    file_hash.as_bytes().as_slice(),
                    pubkey.as_bytes().as_slice(),
                    now,
                ),
                |row| row.get(0),
            )
            .ok();

        if let Some(ops_json) = result {
            let ops: Vec<String> =
                serde_json::from_str(&ops_json).map_err(|e| AuthError::Storage(e.to_string()))?;
            Ok(ops.contains(&operation.as_str().to_string()))
        } else {
            Ok(false)
        }
    }

    async fn list_grants(
        &self,
        owner: &PublicKeyFingerprint,
        file_hash: &Hash,
    ) -> AuthResult<Vec<AccessGrant>> {
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized(
                "Only owner can list grants".into(),
            ));
        }

        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT grantee_fingerprint, operations, expires_at, created_at
               FROM access_grants WHERE file_hash = ?"#,
        )?;

        let grants = stmt
            .query_map([file_hash.as_bytes().as_slice()], |row| {
                let grantee_bytes: Vec<u8> = row.get(0)?;
                let ops_json: String = row.get(1)?;
                let expires_at: i64 = row.get(2)?;
                let created_at: i64 = row.get(3)?;
                Ok((grantee_bytes, ops_json, expires_at, created_at))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(grantee_bytes, ops_json, expires_at, created_at)| {
                let grantee_arr: [u8; 32] = grantee_bytes.try_into().ok()?;
                let ops: Vec<String> = serde_json::from_str(&ops_json).ok()?;
                let operations: Vec<Operation> =
                    ops.iter().filter_map(|s| Operation::parse(s)).collect();

                Some(AccessGrant {
                    file_hash: *file_hash,
                    owner: *owner,
                    grantee: PublicKeyFingerprint::from_bytes(grantee_arr),
                    operations,
                    expires_at: expires_at as u64,
                    created_at: created_at as u64,
                })
            })
            .collect();

        Ok(grants)
    }

    async fn list_shared_with(&self, grantee: &PublicKeyFingerprint) -> AuthResult<Vec<Hash>> {
        let conn = self.conn.lock().unwrap();
        let now = Self::now();

        let mut stmt = conn.prepare(
            r#"SELECT DISTINCT file_hash FROM access_grants 
               WHERE grantee_fingerprint = ?
               AND (expires_at = 0 OR expires_at > ?)"#,
        )?;

        let hashes = stmt
            .query_map([grantee.as_bytes().as_slice(), &now.to_le_bytes()], |row| {
                let bytes: Vec<u8> = row.get(0)?;
                Ok(bytes)
            })?
            .filter_map(|r| r.ok())
            .filter_map(|bytes| {
                if bytes.len() == 32 {
                    let arr: [u8; 32] = bytes.try_into().ok()?;
                    Some(Hash::from(arr))
                } else {
                    None
                }
            })
            .collect();

        Ok(hashes)
    }

    async fn unregister(&self, owner: &PublicKeyFingerprint, file_hash: &Hash) -> AuthResult<()> {
        if !self.is_owner(owner, file_hash).await? {
            return Err(AuthError::NotAuthorized("Only owner can unregister".into()));
        }

        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM ownership WHERE file_hash = ?",
            [file_hash.as_bytes().as_slice()],
        )?;
        conn.execute(
            "DELETE FROM access_grants WHERE file_hash = ?",
            [file_hash.as_bytes().as_slice()],
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp(n: u8) -> PublicKeyFingerprint {
        PublicKeyFingerprint::from_bytes([n; 32])
    }

    #[tokio::test]
    async fn test_sqlite_ownership_roundtrip() {
        let store = SqliteOwnershipStore::in_memory().unwrap();
        let owner = fp(1);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();
        assert!(store.is_owner(&owner, &file).await.unwrap());

        let owned = store.list_owned(&owner).await.unwrap();
        assert_eq!(owned.len(), 1);
    }

    #[tokio::test]
    async fn test_sqlite_grant_access() {
        let store = SqliteOwnershipStore::in_memory().unwrap();
        let owner = fp(1);
        let grantee = fp(2);
        let file = blake3::hash(b"test");

        store.register(&owner, &file).await.unwrap();

        let grant = AccessGrant::new(
            file,
            owner,
            grantee,
            vec![Operation::Read, Operation::Write],
            None,
        );
        store.grant_access(grant).await.unwrap();

        assert!(
            store
                .has_access(&grantee, &file, Operation::Read)
                .await
                .unwrap()
        );
        assert!(
            store
                .has_access(&grantee, &file, Operation::Write)
                .await
                .unwrap()
        );
        assert!(
            !store
                .has_access(&grantee, &file, Operation::Delete)
                .await
                .unwrap()
        );
    }
}
