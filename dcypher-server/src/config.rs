use figment::{
    Figment,
    providers::{Env, Format, Toml},
};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(default)]
    pub storage: StorageConfig,

    #[serde(default)]
    pub nonce: NonceConfig,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[allow(dead_code)] // Will be used when S3 backend is wired
pub struct StorageConfig {
    #[serde(default = "default_backend")]
    pub backend: String, // "memory", "local", "s3"
    pub local_path: Option<String>,
    pub s3_bucket: Option<String>,
    pub s3_endpoint: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct NonceConfig {
    #[serde(default = "default_nonce_window_secs")]
    pub window_secs: u64,
}

impl Default for NonceConfig {
    fn default() -> Self {
        Self {
            window_secs: default_nonce_window_secs(),
        }
    }
}

fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    7222
} // Recryption proxy specific port
fn default_backend() -> String {
    "memory".into()
}
fn default_nonce_window_secs() -> u64 {
    300
} // 5 minutes

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let config: Config = Figment::new()
            .merge(Toml::file("dcypher-server.toml"))
            .merge(Env::prefixed("DCYPHER_"))
            .extract()?;
        Ok(config)
    }
}
