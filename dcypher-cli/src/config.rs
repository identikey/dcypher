// Config file handling

use anyhow::Result;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Default)]
pub struct Config {
    pub default_server: Option<String>,
    pub active_identity: Option<String>,
    pub output_format: Option<String>,
    pub wallet_path: Option<String>,
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let contents = toml::to_string_pretty(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    fn config_path() -> Result<PathBuf> {
        let dirs = ProjectDirs::from("com", "identikey", "dcypher")
            .ok_or_else(|| anyhow::anyhow!("Could not determine config directory"))?;
        Ok(dirs.config_dir().join("config.toml"))
    }
}
