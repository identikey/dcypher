import click
import json
import sys
from pathlib import Path
from dcypher.lib.key_manager import KeyManager
from bip_utils import Bip39MnemonicGenerator, Bip39WordsNum
from typing import List, Dict, Any


@click.group("identity")
def identity_group():
    """Manages user identities and wallets."""
    pass


@identity_group.command("new")
@click.option("--name", default="default", help="The name for the new identity.")
@click.option(
    "--path",
    type=click.Path(file_okay=False, dir_okay=True, writable=True),
    default=str(Path.home() / ".dcypher"),
    help="Directory to store identity files.",
)
@click.option("--overwrite", is_flag=True, help="Overwrite existing identity file.")
@click.option(
    "--context-file",
    type=click.Path(exists=True),
    help="Path to a PRE crypto context file. If provided, creates identity with PRE keys compatible with this context.",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    help="API base URL. If provided, automatically fetches the server's crypto context and creates PRE-enabled identity.",
)
def identity_new(name, path, overwrite, context_file, api_url):
    """Creates a new user identity file."""
    try:
        identity_dir = Path(path)

        # Determine crypto context source (priority: context_file > api_url)
        context_bytes = None
        context_source = None

        if context_file:
            click.echo(f"Loading crypto context from {context_file}...", err=True)
            with open(context_file, "rb") as f:
                context_bytes = f.read()
            context_source = f"file:{context_file}"
            click.echo(
                "✓ Crypto context loaded from file - will create PRE-enabled identity",
                err=True,
            )
        elif api_url:
            click.echo(f"Fetching crypto context from server {api_url}...", err=True)
            from dcypher.lib.api_client import DCypherClient, DCypherAPIError

            try:
                client = DCypherClient(api_url)
                context_bytes = client.get_pre_crypto_context()
                context_source = f"server:{api_url}"
                click.echo(
                    f"✓ Crypto context fetched from server ({len(context_bytes)} bytes) - will create PRE-enabled identity",
                    err=True,
                )
            except DCypherAPIError as e:
                raise click.ClickException(
                    f"Could not fetch crypto context from server: {e}. "
                    "Cannot create PRE-enabled identity without server context. "
                    "To create a non-PRE identity, omit the --api-url flag."
                )

        # Now that KeyManager requires either context_bytes or _test_context (not api_url),
        # we need to ensure we have context_bytes for PRE-enabled identities
        if api_url and context_bytes is None:
            raise click.ClickException(
                "Failed to fetch crypto context from server. Cannot create PRE-enabled identity."
            )

        if context_bytes is None and api_url is None:
            raise click.ClickException(
                "Either --context-file or --api-url must be provided to create an identity with PRE capabilities. "
                "This ensures the identity is compatible with the server's crypto context."
            )

        # ARCHITECTURAL FIX: KeyManager now requires context_bytes (not api_url) for proper separation
        mnemonic, file_path = KeyManager.create_identity_file(
            name, identity_dir, overwrite, context_bytes, context_source
        )

        if context_bytes:
            click.echo(
                "Identity created successfully with PRE capabilities! Please back up your mnemonic phrase securely!"
            )
            if context_source and context_source.startswith("server:"):
                click.echo(
                    "✓ Crypto context automatically fetched and stored in identity file"
                )
            else:
                click.echo(
                    "✓ Crypto context loaded from file and stored in identity file"
                )
        else:
            click.echo(
                "Identity created successfully. Please back up your mnemonic phrase securely!"
            )
        click.echo("-" * 60)
        click.echo(mnemonic)
        click.echo("-" * 60)
        click.echo(f"Identity file saved to: {file_path}")

        if context_bytes:
            click.echo(
                "✓ Identity is completely self-contained and universe-compatible"
            )
            click.echo("✓ Ready to use for all cryptographic operations immediately")
        else:
            click.echo(
                "💡 Tip: To add PRE capabilities later, use: dcypher init-pre --identity-path <path>"
            )
            click.echo(
                "💡 Or recreate with: dcypher identity new --name <name> --api-url <server>"
            )

    except FileExistsError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"An unexpected error occurred: {e}", err=True)
        sys.exit(1)


@identity_group.command("migrate")
@click.option(
    "--auth-keys-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to existing auth keys file to migrate.",
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False, dir_okay=True, writable=True),
    default=str(Path.home() / ".dcypher"),
    help="Directory to store the new identity file.",
)
@click.option(
    "--identity-name", default="migrated", help="Name for the migrated identity."
)
@click.option("--overwrite", is_flag=True, help="Overwrite existing identity file.")
def identity_migrate(auth_keys_path, output_dir, identity_name, overwrite):
    """Migrates an existing auth_keys file to the new identity system."""
    try:
        output_path = Path(output_dir)
        identity_file = output_path / f"{identity_name}.json"

        if identity_file.exists() and not overwrite:
            raise click.ClickException(
                f"Identity '{identity_name}' already exists at {identity_file}. Use --overwrite to replace it."
            )

        click.echo(f"Migrating auth keys from {auth_keys_path}...", err=True)

        # Load the existing auth keys
        auth_keys = KeyManager.load_auth_keys_bundle(Path(auth_keys_path))

        # Generate a new mnemonic for the identity
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_24)

        # Create PQ keys list with proper typing
        pq_keys_list: List[Dict[str, Any]] = []
        for pq_key in auth_keys["pq_keys"]:
            pq_keys_list.append(
                {
                    "alg": pq_key["alg"],
                    "sk_hex": pq_key["sk"].hex(),
                    "pk_hex": pq_key["pk_hex"],
                    "derivable": False,  # Migrated keys are not derivable
                }
            )

        # Create identity data structure
        identity_data = {
            "mnemonic": str(mnemonic),
            "version": "migrated",  # Mark as migrated from auth_keys
            "derivable": False,  # Migrated keys are not derivable from mnemonic
            "auth_keys": {
                "classic": {
                    "sk_hex": auth_keys["classic_sk"].to_string().hex(),
                    "pk_hex": KeyManager.get_classic_public_key(
                        auth_keys["classic_sk"]
                    ),
                },
                "pq": pq_keys_list,
            },
        }

        # Save the identity file
        output_path.mkdir(parents=True, exist_ok=True)
        with open(identity_file, "w") as f:
            json.dump(identity_data, f, indent=2)

        click.echo("Migration completed successfully!", err=True)
        click.echo(f"Identity file created: {identity_file}", err=True)
        click.echo("", err=True)
        click.echo("🔑 Your new mnemonic phrase (for backup purposes):", err=True)
        click.echo("-" * 60, err=True)
        click.echo(str(mnemonic), err=True)
        click.echo("-" * 60, err=True)
        click.echo("", err=True)
        click.echo("⚠️  Note: This is a MIGRATED identity.", err=True)
        click.echo("The keys are NOT derivable from the mnemonic phrase.", err=True)
        click.echo(
            "The mnemonic is only provided for consistency with the identity format.",
            err=True,
        )
        click.echo("", err=True)
        click.echo("You can now use this identity file with:")
        click.echo(f"  --identity-path {identity_file}")
        click.echo("", err=True)
        click.echo("For new identities with derivable keys, use:")
        click.echo("  dcypher identity new --name <name>")

    except Exception as e:
        raise click.ClickException(f"Migration failed: {e}")


@identity_group.command("info")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to identity file.",
)
def identity_info(identity_path):
    """Shows information about an identity file."""
    try:
        with open(identity_path, "r") as f:
            identity_data = json.load(f)

        click.echo(f"Identity Information for: {identity_path}", err=True)
        click.echo(f"  Version: {identity_data.get('version', 'unknown')}", err=True)
        click.echo(f"  Derivable: {identity_data.get('derivable', False)}", err=True)

        # Show rotation info if available
        if "rotation_count" in identity_data:
            click.echo(f"  Rotation Count: {identity_data['rotation_count']}", err=True)
            if "last_rotation" in identity_data:
                import time

                last_rotation = time.ctime(identity_data["last_rotation"])
                click.echo(f"  Last Rotation: {last_rotation}", err=True)
            if "rotation_reason" in identity_data:
                click.echo(
                    f"  Last Rotation Reason: {identity_data['rotation_reason']}",
                    err=True,
                )

        # Show mnemonic if present (be careful about this in production)
        if "mnemonic" in identity_data:
            if click.confirm("Show mnemonic phrase? (Keep this secure!)", err=True):
                click.echo(f"  Mnemonic: {identity_data['mnemonic']}", err=True)

        # Show key information
        auth_keys = identity_data.get("auth_keys", {})
        if "classic" in auth_keys:
            click.echo(
                f"  Classic Public Key: {auth_keys['classic']['pk_hex'][:16]}...",
                err=True,
            )

        if "pq" in auth_keys:
            click.echo(f"  Post-Quantum Keys:", err=True)
            for i, pq_key in enumerate(auth_keys["pq"]):
                click.echo(
                    f"    {i + 1}. {pq_key['alg']}: {pq_key['pk_hex'][:16]}...",
                    err=True,
                )

        # Show rotation history if available
        if "rotation_history" in identity_data and identity_data["rotation_history"]:
            click.echo(f"  Rotation History:", err=True)
            for rotation in identity_data["rotation_history"][-3:]:  # Show last 3
                import time

                timestamp = time.ctime(rotation["timestamp"])
                click.echo(
                    f"    {rotation['rotation_count']}: {timestamp} ({rotation['reason']})",
                    err=True,
                )

    except Exception as e:
        raise click.ClickException(f"Failed to read identity file: {e}")


@identity_group.command("rotate")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to identity file.",
)
@click.option(
    "--reason",
    default="manual",
    help="Reason for key rotation (for audit trail).",
)
@click.option(
    "--backup",
    is_flag=True,
    help="Create backup before rotation.",
)
def identity_rotate(identity_path, reason, backup):
    """Rotates keys in an identity file."""
    try:
        identity_file = Path(identity_path)

        if backup:
            backup_dir = identity_file.parent / "backups"
            click.echo(f"Creating backup before rotation...", err=True)
            backup_path = KeyManager.backup_identity_securely(identity_file, backup_dir)
            click.echo(f"Backup created: {backup_path}", err=True)

        click.echo(f"Rotating keys in {identity_path}...", err=True)
        result = KeyManager.rotate_keys_in_identity(identity_file, reason)

        click.echo(f"✅ Key rotation completed!", err=True)
        click.echo(f"  Rotation count: {result['rotation_count']}", err=True)
        click.echo(f"  New classic key: {result['new_classic_pk'][:16]}...", err=True)
        click.echo(f"  New PQ key: {result['new_pq_pk'][:16]}...", err=True)

        click.echo(f"⚠️  Update your account on the server with the new keys!", err=True)

    except Exception as e:
        raise click.ClickException(f"Key rotation failed: {e}")


@identity_group.command("backup")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to identity file.",
)
@click.option(
    "--backup-dir",
    type=click.Path(file_okay=False, dir_okay=True, writable=True),
    default="./backups",
    help="Directory to store backup files.",
)
@click.option(
    "--encryption-key",
    help="Custom encryption key (hex). If not provided, uses identity's own key.",
)
def identity_backup(identity_path, backup_dir, encryption_key):
    """Creates a secure backup of an identity file."""
    try:
        identity_file = Path(identity_path)
        backup_directory = Path(backup_dir)

        enc_key = None
        if encryption_key:
            enc_key = bytes.fromhex(encryption_key)

        click.echo(f"Creating secure backup of {identity_path}...", err=True)
        backup_path = KeyManager.backup_identity_securely(
            identity_file, backup_directory, enc_key
        )

        click.echo(f"✅ Backup created successfully!", err=True)
        click.echo(f"  Backup file: {backup_path}", err=True)
        click.echo(f"  Backup is encrypted and safe to store externally.", err=True)

    except Exception as e:
        raise click.ClickException(f"Backup failed: {e}")
