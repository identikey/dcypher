use anyhow::{Context as AnyhowContext, Result};
use clap::Args;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use std::fs;

use recrypt_core::HybridEncryptor;
use recrypt_proto::MultiFormat;

use super::Context;
use crate::output::{print_json, print_success};
use crate::wallet::Wallet;

#[derive(Args)]
pub struct EncryptArgs {
    /// File to encrypt
    pub file: String,
    /// Recipient fingerprint or identity name
    #[arg(long)]
    pub r#for: String,
    /// Output file
    #[arg(long)]
    pub output: Option<String>,
}

pub async fn run(args: EncryptArgs, ctx: &Context) -> Result<()> {
    let wallet = Wallet::load(ctx.wallet_override.as_deref())?;

    // Resolve recipient
    let recipient_identity = wallet.data.identities.get(&args.r#for).ok_or_else(|| {
        anyhow::anyhow!(
            "Recipient '{}' not found in wallet. To encrypt for external recipients, \
             they must first be imported or you must use their fingerprint (not yet implemented).",
            args.r#for
        )
    })?;

    // Parse recipient's PRE public key using their stored backend
    let recipient_pre_pk_bytes = bs58::decode(&recipient_identity.pre.public)
        .into_vec()
        .context("Failed to decode recipient PRE public key")?;

    let recipient_backend_id = recipient_identity.pre_backend;
    let recipient_pre_pk =
        recrypt_core::pre::PublicKey::new(recipient_backend_id, recipient_pre_pk_bytes);

    // Read plaintext
    let plaintext =
        fs::read(&args.file).with_context(|| format!("Failed to read {}", args.file))?;

    // Create backend matching the recipient's identity
    let backend = super::create_backend_from_id(recipient_backend_id)?;
    let encryptor = HybridEncryptor::new(backend);

    let pb = if !ctx.json_output {
        let pb = ProgressBar::new(plaintext.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes}")
                .unwrap(),
        );
        Some(pb)
    } else {
        None
    };

    let encrypted = encryptor
        .encrypt(&recipient_pre_pk, &plaintext)
        .context("Encryption failed")?;

    if let Some(pb) = &pb {
        pb.finish_and_clear();
    }

    // Serialize
    let serialized = encrypted.to_protobuf()?;

    // Determine output path
    let output_path = args.output.unwrap_or_else(|| format!("{}.enc", args.file));

    fs::write(&output_path, serialized)
        .with_context(|| format!("Failed to write {output_path}"))?;

    if ctx.json_output {
        #[derive(Serialize)]
        struct Output {
            input: String,
            output: String,
            size: usize,
        }
        print_json(&Output {
            input: args.file,
            output: output_path,
            size: encrypted.ciphertext.len(),
        })?;
    } else {
        print_success(format!(
            "Encrypted {} → {} ({} bytes)",
            args.file,
            output_path,
            encrypted.ciphertext.len()
        ));
    }

    Ok(())
}
