use anyhow::{Context as AnyhowContext, Result};
use clap::Subcommand;
use colored::Colorize;
use serde::Serialize;
use std::fs;

use recrypt_core::pre::{PreBackend, PublicKey, SecretKey};

use super::helpers::{resolve_identity, resolve_server_url};
use super::Context;
use crate::client::ApiClient;
use crate::config::Config;
use crate::output::{print_json, print_success};
use crate::wallet::Wallet;

#[derive(Subcommand)]
pub enum ShareCommand {
    /// Create a share
    Create {
        /// File hash
        file_hash: String,
        /// Recipient fingerprint
        #[arg(long)]
        to: String,
    },
    /// List shares
    List {
        /// Show only outgoing shares
        #[arg(long)]
        from: bool,
        /// Show only incoming shares
        #[arg(long)]
        to: bool,
    },
    /// Download a shared file
    Download {
        /// Share ID
        share_id: String,
        /// Output file
        #[arg(long)]
        output: Option<String>,
    },
    /// Revoke a share
    Revoke {
        /// Share ID
        share_id: String,
    },
}

pub async fn run(action: ShareCommand, ctx: &Context) -> Result<()> {
    match action {
        ShareCommand::Create { file_hash, to } => create(file_hash, to, ctx).await,
        ShareCommand::List { from, to } => list(from, to, ctx).await,
        ShareCommand::Download { share_id, output } => download(share_id, output, ctx).await,
        ShareCommand::Revoke { share_id } => revoke(share_id, ctx).await,
    }
}

async fn create(file_hash: String, to_fingerprint: String, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;
    let config = Config::load()?;

    let identity_name = resolve_identity(ctx, &wallet)?;
    let identity = wallet
        .data
        .identities
        .get(&identity_name)
        .ok_or_else(|| anyhow::anyhow!("Identity '{identity_name}' not found"))?;

    let server_url = resolve_server_url(ctx, &config)?;

    // Fetch recipient's account to get their PRE public key
    let client = ApiClient::new(server_url);
    let recipient_account = client
        .get_account(&to_fingerprint)
        .await
        .context("Failed to fetch recipient account")?;

    // Parse keys using the identity's stored backend
    let my_backend_id = identity.pre_backend;
    let my_pre_sk_bytes = bs58::decode(&identity.pre.secret)
        .into_vec()
        .context("Failed to decode my PRE secret key")?;

    let recipient_pre_pk_str = recipient_account
        .pre_pk
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Recipient has no PRE public key"))?;

    let recipient_pre_pk_bytes = bs58::decode(recipient_pre_pk_str)
        .into_vec()
        .context("Failed to decode recipient PRE public key")?;

    // Both keys must use the same backend for recryption to work
    // TODO: In the future, we might support cross-backend recryption via key translation
    let my_pre_sk = SecretKey::new(my_backend_id, my_pre_sk_bytes);
    let recipient_pre_pk = PublicKey::new(my_backend_id, recipient_pre_pk_bytes);

    // Create backend and generate recrypt key
    let backend = super::create_backend_from_id(my_backend_id)?;
    let recrypt_key = backend
        .generate_recrypt_key(&my_pre_sk, &recipient_pre_pk)
        .context("Failed to generate recrypt key")?;

    // Create share
    let response = client
        .create_share(
            identity,
            file_hash.clone(),
            to_fingerprint.clone(),
            recrypt_key.to_bytes(), // Serialize recrypt key
            my_backend_id,          // Pass backend ID for server-side recrypt
        )
        .await?;

    if ctx.json_output {
        print_json(&response)?;
    } else {
        print_success(format!("Created share for {to_fingerprint}"));
        println!("  {}: {}", "Share ID".dimmed(), response.share_id);
        println!("  {}: {}", "File Hash".dimmed(), file_hash);
    }

    Ok(())
}

async fn list(filter_from: bool, filter_to: bool, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;
    let config = Config::load()?;

    let identity_name = resolve_identity(ctx, &wallet)?;
    let identity = wallet
        .data
        .identities
        .get(&identity_name)
        .ok_or_else(|| anyhow::anyhow!("Identity '{identity_name}' not found"))?;

    let server_url = resolve_server_url(ctx, &config)?;
    let client = ApiClient::new(server_url);

    let response = client.list_shares(identity).await?;

    if ctx.json_output {
        // If filtering, only show requested direction
        if filter_from && !filter_to {
            print_json(&response.outgoing)?;
        } else if filter_to && !filter_from {
            print_json(&response.incoming)?;
        } else {
            print_json(&response)?;
        }
    } else {
        // Pretty output
        if !filter_to && !response.outgoing.is_empty() {
            println!("{}", "Outgoing shares (you shared):".bold());
            for share in &response.outgoing {
                println!("  {}", share.share_id.bright_cyan());
                println!("    {}: {}", "To".dimmed(), share.to_fingerprint);
                println!("    {}: {}", "File".dimmed(), share.file_hash);
            }
            println!();
        }

        if !filter_from && !response.incoming.is_empty() {
            println!("{}", "Incoming shares (shared with you):".bold());
            for share in &response.incoming {
                println!("  {}", share.share_id.bright_cyan());
                println!("    {}: {}", "From".dimmed(), share.from_fingerprint);
                println!("    {}: {}", "File".dimmed(), share.file_hash);
            }
        }

        if response.outgoing.is_empty() && response.incoming.is_empty() {
            println!("{}", "No shares found.".dimmed());
        }
    }

    Ok(())
}

async fn download(share_id: String, output_override: Option<String>, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;
    let config = Config::load()?;

    let identity_name = resolve_identity(ctx, &wallet)?;
    let identity = wallet
        .data
        .identities
        .get(&identity_name)
        .ok_or_else(|| anyhow::anyhow!("Identity '{identity_name}' not found"))?;

    let server_url = resolve_server_url(ctx, &config)?;

    // Download share
    let client = ApiClient::new(server_url);
    let file_data = client.download_share(identity, &share_id).await?;

    // Determine output path
    let output_path = output_override.unwrap_or_else(|| format!("share_{share_id}.bin"));

    fs::write(&output_path, &file_data)
        .with_context(|| format!("Failed to write {output_path}"))?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            share_id: String,
            output: String,
            size: usize,
        }
        print_json(&Output {
            share_id,
            output: output_path,
            size: file_data.len(),
        })?;
    } else {
        print_success(format!(
            "Downloaded share to {} ({} bytes)",
            output_path,
            file_data.len()
        ));
    }

    Ok(())
}

async fn revoke(share_id: String, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;
    let config = Config::load()?;

    let identity_name = resolve_identity(ctx, &wallet)?;
    let identity = wallet
        .data
        .identities
        .get(&identity_name)
        .ok_or_else(|| anyhow::anyhow!("Identity '{identity_name}' not found"))?;

    let server_url = resolve_server_url(ctx, &config)?;

    let client = ApiClient::new(server_url);
    client.revoke_share(identity, &share_id).await?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            revoked: String,
        }
        print_json(&Output { revoked: share_id })?;
    } else {
        print_success(format!("Revoked share {share_id}"));
    }

    Ok(())
}
