import click
from lib import pre
import json
import requests
import hashlib
import os
from base64 import b64decode
import re
from pathlib import Path
import ecdsa
import base64
import sys
import gzip
from lib.key_manager import KeyManager
from bip_utils import Bip39MnemonicGenerator, Bip39WordsNum
from typing import List, Dict, Any


API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")


@click.group()
def cli():
    """A CLI tool for demonstrating proxy re-encryption."""
    pass


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
def identity_new(name, path, overwrite):
    """Creates a new user identity file."""
    try:
        identity_dir = Path(path)
        mnemonic, file_path = KeyManager.create_identity_file(
            name, identity_dir, overwrite
        )

        click.echo(
            "Identity created successfully. Please back up your mnemonic phrase securely!"
        )
        click.echo("-" * 60)
        click.echo(mnemonic)
        click.echo("-" * 60)
        click.echo(f"Identity file saved to: {file_path}")

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


cli.add_command(identity_group)


@cli.command("gen-cc")
@click.option("--output", default="cc.json", help="Path to save the crypto context.")
@click.option("--plaintext-modulus", default=65537, type=int, help="Plaintext modulus.")
@click.option("--scaling-mod-size", default=60, type=int, help="Scaling modulus size.")
def gen_cc(output, plaintext_modulus, scaling_mod_size):
    """Generates crypto context."""
    click.echo("Generating crypto context...", err=True)
    cc = pre.create_crypto_context(
        plaintext_modulus=plaintext_modulus, scaling_mod_size=scaling_mod_size
    )
    serialized_cc = pre.serialize(cc)

    with open(output, "w") as f:
        json.dump({"cc": serialized_cc}, f)

    click.echo(f"Crypto context saved to {output}", err=True)


@cli.command("gen-signing-keys")
@click.option(
    "--output-prefix", default="idk_signing", help="Prefix for the output key files."
)
def gen_signing_keys(output_prefix):
    """Generates a classic ECDSA key pair for signing."""
    click.echo("Generating ECDSA signing key pair...", err=True)

    sk, pk_hex = KeyManager.generate_classic_keypair()

    pk_path = f"{output_prefix}.pub"
    sk_path = f"{output_prefix}.sec"

    with open(pk_path, "w") as f:
        f.write(pk_hex)

    with open(sk_path, "w") as f:
        f.write(sk.to_string().hex())

    click.echo(f"Signing public key saved to {pk_path}", err=True)
    click.echo(f"Signing secret key saved to {sk_path}", err=True)


@cli.command("gen-keys")
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option("--output-prefix", default="key", help="Prefix for the output key files.")
def gen_keys(cc_path, output_prefix):
    """Generates a public/private key pair."""
    try:
        click.echo(f"Loading crypto context from {cc_path}...", err=True)
        with open(cc_path, "r") as f:
            cc_data = json.load(f)
    except FileNotFoundError:
        raise click.ClickException(f"Crypto context file not found: {cc_path}")
    except PermissionError:
        raise click.ClickException(f"Permission denied accessing file: {cc_path}")
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in crypto context file: {e}")
    except Exception as e:
        raise click.ClickException(f"Error reading crypto context file: {e}")

    try:
        cc = pre.deserialize_cc(cc_data["cc"])
    except KeyError:
        raise click.ClickException("Invalid crypto context file: missing 'cc' field")
    except Exception as e:
        raise click.ClickException(f"Error deserializing crypto context: {e}")

    try:
        click.echo("Generating keys...", err=True)
        keys = pre.generate_keys(cc)

        serialized_pk = pre.serialize(keys.publicKey)
        serialized_sk = pre.serialize(keys.secretKey)

        pk_path = f"{output_prefix}.pub"
        sk_path = f"{output_prefix}.sec"

        with open(pk_path, "w") as f:
            json.dump({"key": serialized_pk}, f)

        with open(sk_path, "w") as f:
            json.dump({"key": serialized_sk}, f)

        click.echo(f"Public key saved to {pk_path}", err=True)
        click.echo(f"Secret key saved to {sk_path}", err=True)
    except Exception as e:
        raise click.ClickException(f"Error generating or saving keys: {e}")


@cli.command()
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option("--pk-path", help="Path to the public key file.", required=True)
@click.option(
    "--signing-key-path",
    help="Path to the ECDSA private key for signing message headers.",
    required=True,
)
@click.option("--data", help="String to encrypt.")
@click.option(
    "--input-file",
    type=click.Path(exists=True, dir_okay=False),
    help="Path to a file to encrypt.",
)
@click.option(
    "--output", default="ciphertext.idk", help="Path to save the IDK message file."
)
def encrypt(cc_path, pk_path, signing_key_path, data, input_file, output):
    """Encrypts data and packages it into a spec-compliant IDK message."""
    if not data and not input_file:
        raise click.UsageError("Either --data or --input-file must be provided.")
    if data and input_file:
        raise click.UsageError("Provide either --data or --input-file, not both.")

    # Dynamic import to avoid circular dependency if idk_message needs cli elements
    from lib import idk_message

    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    cc = pre.deserialize_cc(cc_data["cc"])

    click.echo(f"Loading public key from {pk_path}...", err=True)
    with open(pk_path, "r") as f:
        pk_data = json.load(f)
    pk = pre.deserialize_public_key(base64.b64decode(pk_data["key"]))

    click.echo(f"Loading signing key from {signing_key_path}...", err=True)
    with open(signing_key_path, "r") as f:
        sk_hex = f.read()
        sk_sign = ecdsa.SigningKey.from_string(
            bytes.fromhex(sk_hex), curve=ecdsa.SECP256k1
        )

    if input_file:
        with open(input_file, "rb") as f:
            input_data_bytes = f.read()
    else:
        input_data_bytes = data.encode("utf-8")

    click.echo("Encrypting data and creating IDK message parts...", err=True)
    message_parts = idk_message.create_idk_message_parts(
        data=input_data_bytes,
        cc=cc,
        pk=pk,
        signing_key=sk_sign,
    )

    with open(output, "w") as f:
        f.write("\n".join(message_parts))

    click.echo(f"IDK message saved to {output}", err=True)


@cli.command()
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option("--sk-path", help="Path to the secret key file.", required=True)
@click.option(
    "--verifying-key-path",
    help="Path to the ECDSA public key for verifying message signatures.",
    required=True,
)
@click.option(
    "--ciphertext-path", default="ciphertext.idk", help="Path to the IDK message file."
)
@click.option(
    "--output-file",
    type=click.Path(dir_okay=False),
    help="Path to save the decrypted output.",
)
def decrypt(cc_path, sk_path, verifying_key_path, ciphertext_path, output_file):
    """Parses, verifies, and decrypts a spec-compliant IDK message."""
    from lib import idk_message

    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    cc = pre.deserialize_cc(cc_data["cc"])

    click.echo(f"Loading secret key from {sk_path}...", err=True)
    with open(sk_path, "r") as f:
        sk_data = json.load(f)
    sk = pre.deserialize_secret_key(base64.b64decode(sk_data["key"]))

    click.echo(f"Loading verifying key from {verifying_key_path}...", err=True)
    with open(verifying_key_path, "r") as f:
        vk_hex = f.read()
        vk_verify = ecdsa.VerifyingKey.from_string(
            bytes.fromhex(vk_hex), curve=ecdsa.SECP256k1
        )

    click.echo(f"Loading IDK message from {ciphertext_path}...", err=True)
    with open(ciphertext_path, "r") as f:
        message_content = f.read()

    # Decrypt and write to output
    try:
        decrypted_data = idk_message.decrypt_idk_message(
            cc=cc, sk=sk, vk=vk_verify, message_str=message_content
        )
        Path(output_file).write_bytes(decrypted_data)
        click.echo(f"Success! Decrypted data written to {output_file}", err=True)
    except Exception as e:
        click.echo(f"Error during decryption: {e}", err=True)
        sys.exit(1)


@cli.command("gen-rekey")
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option(
    "--sk-path-from",
    help="Path to the secret key file of the 'from' party (e.g., Alice).",
    required=True,
)
@click.option(
    "--pk-path-to",
    help="Path to the public key file of the 'to' party (e.g., Bob).",
    required=True,
)
@click.option(
    "--output", default="rekey.json", help="Path to save the re-encryption key."
)
def gen_rekey(cc_path, sk_path_from, pk_path_to, output):
    """Generates a re-encryption key."""
    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    cc = pre.deserialize_cc(cc_data["cc"])

    click.echo(f"Loading 'from' secret key from {sk_path_from}...", err=True)
    with open(sk_path_from, "r") as f:
        sk_data = json.load(f)
    sk_from = pre.deserialize_secret_key(base64.b64decode(sk_data["key"]))

    click.echo(f"Loading 'to' public key from {pk_path_to}...", err=True)
    with open(pk_path_to, "r") as f:
        pk_data = json.load(f)
    pk_to = pre.deserialize_public_key(base64.b64decode(pk_data["key"]))

    click.echo("Generating re-encryption key...", err=True)
    rekey = pre.generate_re_encryption_key(cc, sk_from, pk_to)
    serialized_rekey = pre.serialize(rekey)

    with open(output, "w") as f:
        json.dump({"rekey": serialized_rekey}, f)

    click.echo(f"Re-encryption key saved to {output}", err=True)


@cli.command("re-encrypt")
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option(
    "--rekey-path", default="rekey.json", help="Path to the re-encryption key file."
)
@click.option(
    "--ciphertext-path", help="Path to the original ciphertext file.", required=True
)
@click.option(
    "--output",
    default="reciphertext.json",
    help="Path to save the re-encrypted ciphertext.",
)
def re_encrypt(cc_path, rekey_path, ciphertext_path, output):
    """Re-encrypts a ciphertext."""
    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)
    cc = pre.deserialize_cc(cc_data["cc"])

    click.echo(f"Loading re-encryption key from {rekey_path}...", err=True)
    with open(rekey_path, "r") as f:
        rekey_data = json.load(f)
    rekey = pre.deserialize_re_encryption_key(base64.b64decode(rekey_data["rekey"]))

    click.echo(f"Loading ciphertext from {ciphertext_path}...", err=True)
    with open(ciphertext_path, "r") as f:
        ciphertext_data = json.load(f)

    length = ciphertext_data.get("length")

    if "ciphertexts" not in ciphertext_data:
        raise click.ClickException(
            "Invalid or legacy ciphertext format. Re-encryption requires a JSON file "
            "with a 'ciphertexts' key. The IDK message format is not supported."
        )

    serialized_items = ciphertext_data["ciphertexts"]
    ciphertexts = [pre.deserialize_ciphertext(s_item) for s_item in serialized_items]

    click.echo("Re-encrypting ciphertext...", err=True)
    re_ciphertexts = pre.re_encrypt(cc, rekey, ciphertexts)
    serialized_re_ciphertexts = [pre.serialize(ct) for ct in re_ciphertexts]

    output_data = {"ciphertexts": serialized_re_ciphertexts}
    if length is not None:
        output_data["length"] = length

    with open(output, "w") as f:
        json.dump(output_data, f)

    click.echo(f"Re-encrypted ciphertext saved to {output}", err=True)


@cli.command("upload")
@click.option("--pk-path", type=str, required=True)
@click.option(
    "--auth-keys-path",
    type=click.Path(exists=True),
    help="Path to auth keys file (legacy)",
)
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    help="Path to identity file (preferred)",
)
@click.option("--file-path", type=click.Path(exists=True), required=True)
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option(
    "--signing-key-path",
    help="Path to the ECDSA private key for signing message headers.",
    required=True,
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def upload(
    pk_path,
    auth_keys_path,
    identity_path,
    file_path,
    cc_path,
    signing_key_path,
    api_url,
):
    """Uploads a file to the remote storage API."""
    from lib.api_client import DCypherClient, DCypherAPIError
    from lib import idk_message
    from lib import pre
    import gzip
    import hashlib

    # Validate that either auth_keys_path or identity_path is provided
    if not auth_keys_path and not identity_path:
        raise click.ClickException(
            "Must provide either --auth-keys-path or --identity-path"
        )

    if auth_keys_path and identity_path:
        click.echo(
            "Warning: Both auth-keys-path and identity-path provided. Using identity-path.",
            err=True,
        )

    # --- 1. Load Keys and Crypto Context ---
    click.echo("Loading keys and crypto context...", err=True)

    try:
        # Load crypto context
        with open(cc_path, "r") as f:
            cc_data = json.load(f)
        cc = pre.deserialize_cc(cc_data["cc"])

        # Load public key for encryption
        with open(pk_path, "r") as f:
            pk_data = json.load(f)
        pk_enc = pre.deserialize_public_key(base64.b64decode(pk_data["key"]))

        # Load signing key for IDK message headers
        with open(signing_key_path, "r") as f:
            sk_hex = f.read()
            sk_sign_idk = ecdsa.SigningKey.from_string(
                bytes.fromhex(sk_hex), curve=ecdsa.SECP256k1
            )

        # Initialize API client with appropriate key file
        if identity_path:
            client = DCypherClient(api_url, identity_path=identity_path)
        else:
            client = DCypherClient(api_url, auth_keys_path=auth_keys_path)

        # Get classic public key for API operations
        pk_classic_hex = client.get_classic_public_key()

    except Exception as e:
        raise click.ClickException(f"Error loading keys or crypto context: {e}")

    # --- 2. Create IDK message parts in memory ---
    click.echo("Encrypting file and creating IDK message parts...", err=True)
    with open(file_path, "rb") as f:
        file_content_bytes = f.read()

    message_parts = idk_message.create_idk_message_parts(
        data=file_content_bytes,
        cc=cc,
        pk=pk_enc,
        signing_key=sk_sign_idk,
    )
    part_one_content = message_parts[0]
    data_chunks = message_parts[1:]
    total_chunks = len(message_parts)

    click.echo(
        f"File split into {total_chunks} parts (1 header + {len(data_chunks)} data chunks)",
        err=True,
    )

    # --- 3. Parse the header to get file hash ---
    try:
        part_one_parsed = idk_message.parse_idk_message_part(part_one_content)
        file_hash = part_one_parsed["headers"]["MerkleRoot"]
        click.echo(f"File hash: {file_hash}", err=True)
        click.echo(f"Registering file with hash: {file_hash}", err=True)
    except Exception as e:
        raise click.ClickException(f"Failed to parse IDK message header: {e}")

    # --- 4. Upload to API ---
    try:
        click.echo("Registering file with API...", err=True)

        # Register the file
        result = client.register_file(
            pk_classic_hex,
            file_hash,
            part_one_content,
            Path(file_path).name,
            "application/octet-stream",
            len(file_content_bytes),
        )
        click.echo(f"File registered: {result.get('message', 'Success')}", err=True)

        # Upload data chunks
        if data_chunks:
            click.echo(f"Uploading {len(data_chunks)} data chunks...", err=True)
            for i, chunk_content in enumerate(data_chunks):
                # Compress chunk for upload
                compressed_chunk = gzip.compress(chunk_content.encode("utf-8"))

                # Calculate hash of the original (decompressed) chunk content (what server expects)
                # Server uses blake2b hash of the original content for verification
                chunk_hash = hashlib.blake2b(chunk_content.encode("utf-8")).hexdigest()

                click.echo(
                    f"  Uploading chunk {i + 1}/{len(data_chunks)} (hash: {chunk_hash[:16]}...)",
                    err=True,
                )

                result = client.upload_chunk(
                    pk_classic_hex,
                    file_hash,
                    compressed_chunk,
                    chunk_hash,
                    i + 1,  # chunk_index (1-based)
                    len(data_chunks),
                    compressed=True,
                )
        else:
            click.echo("Uploading 0 data chunks...", err=True)

        click.echo(f"✓ Upload completed successfully! File hash: {file_hash}")

    except DCypherAPIError as e:
        raise click.ClickException(f"API request failed: {e}")
    except Exception as e:
        raise click.ClickException(f"Upload failed: {e}")


@cli.command("download")
@click.option("--pk-path", type=str, required=True)
@click.option(
    "--auth-keys-path",
    type=click.Path(exists=True),
    help="Path to auth keys file (legacy)",
)
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    help="Path to identity file (preferred)",
)
@click.option("--file-hash", type=str, required=True)
@click.option(
    "--output-path",
    type=click.Path(dir_okay=False, writable=True),
    required=True,
    help="Path to save the downloaded file.",
)
@click.option(
    "--compressed",
    is_flag=True,
    help="Request compressed download from server.",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="https://api.dcypher.io",
    help="API base URL.",
)
def download(
    pk_path, auth_keys_path, identity_path, file_hash, output_path, compressed, api_url
):
    """Downloads a file from the remote storage API with integrity verification."""
    from lib.api_client import DCypherClient, DCypherAPIError
    from lib import idk_message

    # Validate that either auth_keys_path or identity_path is provided
    if not auth_keys_path and not identity_path:
        raise click.ClickException(
            "Must provide either --auth-keys-path or --identity-path"
        )

    if auth_keys_path and identity_path:
        click.echo(
            "Warning: Both auth-keys-path and identity-path provided. Using identity-path.",
            err=True,
        )

    click.echo(f"Starting download for file hash: {file_hash}...", err=True)

    try:
        # Initialize API client with appropriate key file
        if identity_path:
            client = DCypherClient(api_url, identity_path=identity_path)
        else:
            client = DCypherClient(api_url, auth_keys_path=auth_keys_path)

        # Get the classic public key from the keys
        pk_classic_hex = client.get_classic_public_key()

        # Download file using the client
        downloaded_content = client.download_file(pk_classic_hex, file_hash, compressed)

        # Check if server sent compressed data
        is_compressed = (
            compressed  # We requested compression, so assume we got it if requested
        )

        click.echo("Verifying downloaded content integrity...", err=True)

        # Decompress if necessary for verification
        if is_compressed:
            try:
                content_to_verify = gzip.decompress(downloaded_content)
                click.echo("Successfully decompressed downloaded content.", err=True)
            except Exception as e:
                raise click.ClickException(
                    f"Failed to decompress downloaded content: {e}"
                )
        else:
            content_to_verify = downloaded_content

        # Verify the IDK message integrity
        try:
            # Parse the IDK message to extract and verify the MerkleRoot
            parsed_part = idk_message.parse_idk_message_part(
                content_to_verify.decode("utf-8")
            )
            computed_hash = parsed_part["headers"]["MerkleRoot"]

            if computed_hash != file_hash:
                raise click.ClickException(
                    f"Integrity check failed! Expected hash {file_hash}, "
                    f"but downloaded content has hash {computed_hash}"
                )

            click.echo("✓ Content integrity verified successfully.", err=True)

        except UnicodeDecodeError:
            raise click.ClickException(
                "Downloaded content is not a valid IDK message (not UTF-8)"
            )
        except Exception as e:
            raise click.ClickException(f"Failed to verify IDK message integrity: {e}")

        # Write the verified content to the output file
        with open(output_path, "wb") as f:
            f.write(content_to_verify if not is_compressed else downloaded_content)

        click.echo(
            f"✓ File '{file_hash}' downloaded successfully to '{output_path}'.",
            err=True,
        )

    except DCypherAPIError as e:
        raise click.ClickException(f"API request failed: {e}")
    except Exception as e:
        raise click.ClickException(f"Error: {e}")


@cli.command("download-chunks")
@click.option("--pk-path", type=str, required=True)
@click.option("--auth-keys-path", type=click.Path(exists=True), required=True)
@click.option("--file-hash", type=str, required=True)
@click.option(
    "--output-path",
    type=click.Path(dir_okay=False, writable=True),
    required=True,
    help="Path to save the downloaded concatenated chunks file.",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def download_chunks(pk_path, auth_keys_path, file_hash, output_path, api_url):
    """Downloads all chunks for a file as a single concatenated gzip file."""
    from lib.api_client import DCypherClient, DCypherAPIError

    click.echo(
        f"Starting download for concatenated chunks of file hash: {file_hash}...",
        err=True,
    )

    try:
        # Initialize API client with auth keys
        client = DCypherClient(api_url, str(auth_keys_path))

        # Get the classic public key from the auth keys
        pk_classic_hex = client.get_classic_public_key()

        # Download chunks using the client
        downloaded_content = client.download_chunks(pk_classic_hex, file_hash)

        # Save the downloaded content
        with open(output_path, "wb") as f:
            f.write(downloaded_content)

        click.echo(
            f"Concatenated chunks for '{file_hash}' downloaded successfully to '{output_path}'.",
            err=True,
        )

    except DCypherAPIError as e:
        raise click.ClickException(f"API request failed: {e}")
    except Exception as e:
        raise click.ClickException(f"Error: {e}")


@cli.command("supported-algorithms")
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def supported_algorithms(api_url):
    """Lists supported post-quantum signature algorithms."""
    from lib.api_client import DCypherClient, DCypherAPIError

    try:
        client = DCypherClient(api_url)
        algorithms = client.get_supported_algorithms()

        click.echo("Supported post-quantum signature algorithms:", err=True)
        for alg in algorithms:
            click.echo(f"  - {alg}")

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to get supported algorithms: {e}")


@cli.command("list-accounts")
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def list_accounts(api_url):
    """Lists all accounts."""
    from lib.api_client import DCypherClient, DCypherAPIError

    try:
        client = DCypherClient(api_url)
        accounts = client.list_accounts()

        if not accounts:
            click.echo("No accounts found.", err=True)
        else:
            click.echo(f"Found {len(accounts)} account(s):", err=True)
            for account in accounts:
                click.echo(f"  - {account}")

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to list accounts: {e}")


@cli.command("list-files")
@click.option(
    "--auth-keys-path",
    type=click.Path(exists=True),
    help="Path to auth keys file (legacy)",
)
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    help="Path to identity file (preferred)",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def list_files(auth_keys_path, identity_path, api_url):
    """Lists files for the authenticated account."""
    from lib.api_client import DCypherClient, DCypherAPIError

    # Validate that either auth_keys_path or identity_path is provided
    if not auth_keys_path and not identity_path:
        raise click.ClickException(
            "Must provide either --auth-keys-path or --identity-path"
        )

    if auth_keys_path and identity_path:
        click.echo(
            "Warning: Both auth-keys-path and identity-path provided. Using identity-path.",
            err=True,
        )

    try:
        # Initialize API client with appropriate key file
        if identity_path:
            client = DCypherClient(api_url, identity_path=identity_path)
        else:
            client = DCypherClient(api_url, auth_keys_path=auth_keys_path)

        pk_classic_hex = client.get_classic_public_key()
        files = client.list_files(pk_classic_hex)

        if not files:
            click.echo("No files found.", err=True)
        else:
            click.echo(f"Found {len(files)} file(s):", err=True)
            for file_info in files:
                click.echo(
                    f"  - {file_info.get('filename', 'N/A')} (hash: {file_info.get('hash', 'N/A')})"
                )

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to list files: {e}")
    except Exception as e:
        raise click.ClickException(f"Error: {e}")


@cli.command("get-graveyard")
@click.option("--auth-keys-path", type=click.Path(exists=True), required=True)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def get_graveyard(auth_keys_path, api_url):
    """Gets retired keys (graveyard) for the authenticated account."""
    from lib.api_client import DCypherClient, DCypherAPIError

    try:
        client = DCypherClient(api_url, str(auth_keys_path))
        pk_classic_hex = client.get_classic_public_key()
        graveyard = client.get_account_graveyard(pk_classic_hex)

        if not graveyard:
            click.echo("No retired keys found.", err=True)
        else:
            click.echo(f"Found {len(graveyard)} retired key(s):", err=True)
            for key_info in graveyard:
                click.echo(
                    f"  - {key_info.get('alg', 'N/A')}: {key_info.get('public_key', 'N/A')[:20]}..."
                )

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to get graveyard: {e}")


if __name__ == "__main__":
    cli()
