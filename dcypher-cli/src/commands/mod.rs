pub mod account;
pub mod config;
pub mod decrypt;
pub mod encrypt;
pub mod files;
pub mod helpers;
pub mod identity;
pub mod share;

/// Global context passed to all commands
pub struct Context {
    pub json_output: bool,
    pub identity_override: Option<String>,
    pub server_override: Option<String>,
    pub wallet_override: Option<String>,
    pub verbose: bool,
}
