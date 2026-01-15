// Wallet file management

use anyhow::{Context as _, Result};
use dialoguer::Password;
use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;

use super::format::{decrypt_wallet, encrypt_wallet, WalletData};

pub struct Wallet {
    pub data: WalletData,
    path: PathBuf,
}

impl Wallet {
    /// Load wallet from default path or create new if it doesn't exist
    pub fn load(override_path: Option<&str>) -> Result<Self> {
        let path = match override_path {
            Some(p) => PathBuf::from(p),
            None => Self::default_path()?,
        };

        if !path.exists() {
            // Create new empty wallet
            return Ok(Self {
                data: WalletData::new(),
                path,
            });
        }

        let encrypted = fs::read(&path)
            .with_context(|| format!("Failed to read wallet from {}", path.display()))?;

        let password = Password::new().with_prompt("Wallet password").interact()?;

        let data = decrypt_wallet(&encrypted, &password)
            .context("Failed to decrypt wallet (wrong password?)")?;

        Ok(Self { data, path })
    }

    /// Save wallet to disk (prompts for password if new)
    pub fn save(&self, is_new: bool) -> Result<()> {
        let password = if is_new {
            let pass1 = Password::new()
                .with_prompt("New wallet password")
                .interact()?;
            let pass2 = Password::new().with_prompt("Confirm password").interact()?;

            if pass1 != pass2 {
                anyhow::bail!("Passwords do not match");
            }
            pass1
        } else {
            Password::new().with_prompt("Wallet password").interact()?
        };

        let encrypted = encrypt_wallet(&self.data, &password)?;

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        fs::write(&self.path, encrypted)
            .with_context(|| format!("Failed to write wallet to {}", self.path.display()))?;

        Ok(())
    }

    fn default_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("com", "identikey", "dcypher")
            .ok_or_else(|| anyhow::anyhow!("Could not determine home directory"))?;
        Ok(dirs.data_dir().join("wallet.dcyw"))
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    pub fn is_new(&self) -> bool {
        self.data.identities.is_empty()
    }
}
