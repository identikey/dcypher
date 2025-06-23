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


API_BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000")


@click.group()
def cli():
    """A CLI tool for demonstrating proxy re-encryption."""
    pass


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


@cli.command("gen-keys")
@click.option("--cc-path", default="cc.json", help="Path to the crypto context file.")
@click.option("--output-prefix", default="key", help="Prefix for the output key files.")
def gen_keys(cc_path, output_prefix):
    """Generates a public/private key pair."""
    click.echo(f"Loading crypto context from {cc_path}...", err=True)
    with open(cc_path, "r") as f:
        cc_data = json.load(f)

    cc = pre.deserialize_cc(cc_data["cc"])

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
@click.option("--auth-keys-path", type=click.Path(exists=True), required=True)
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
def upload(pk_path, auth_keys_path, file_path, cc_path, signing_key_path, api_url):
    """
    Encrypts and uploads a file to the remote storage API using a chunked method.
    """
    from lib import idk_message

    # --- 1. Prepare for encryption and upload ---
    click.echo("Preparing keys and crypto context...", err=True)
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

        # Load authentication keys
        auth_keys_data = json.loads(Path(auth_keys_path).read_text())
        classic_sk_auth = ecdsa.SigningKey.from_string(
            bytes.fromhex(Path(auth_keys_data["classic_sk_path"]).read_text()),
            curve=ecdsa.SECP256k1,
        )
        classic_vk_auth = classic_sk_auth.get_verifying_key()
        assert classic_vk_auth is not None
        pk_classic_hex = classic_vk_auth.to_string("uncompressed").hex()

        pq_keys_auth = []
        for pq_key_info in auth_keys_data["pq_keys"]:
            pq_keys_auth.append(
                {
                    "sk": Path(pq_key_info["sk_path"]).read_bytes(),
                    "pk_hex": pq_key_info["pk_hex"],
                    "alg": pq_key_info["alg"],
                }
            )
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
    total_chunks = len(message_parts)  # Part one + data chunks

    # Extract MerkleRoot which is the file_hash
    try:
        parsed_part = idk_message.parse_idk_message_part(part_one_content)
        file_hash = parsed_part["headers"]["MerkleRoot"]
    except Exception as e:
        raise click.ClickException(f"Error parsing IDK message header: {e}")

    # --- 3. Register the file with the first part ---
    click.echo(f"Registering file with hash: {file_hash}", err=True)

    # Initialize API client
    from lib.api_client import DCypherClient, DCypherAPIError

    client = DCypherClient(api_url, str(auth_keys_path))

    try:
        file_stat = os.stat(file_path)
        client.register_file(
            public_key=pk_classic_hex,
            file_hash=file_hash,
            idk_part_one=part_one_content,
            filename=Path(file_path).name,
            content_type="application/octet-stream",
            total_size=file_stat.st_size,
        )
        click.echo("File registered, first chunk uploaded.", err=True)
    except DCypherAPIError as e:
        raise click.ClickException(f"API request failed during registration: {e}")

    # --- 4. Upload remaining data chunks ---
    click.echo(f"Uploading {len(data_chunks)} data chunks...", err=True)
    for i, chunk_content in enumerate(data_chunks):
        chunk_index = i + 1  # Index 0 was the header
        chunk_content_bytes = chunk_content.encode("utf-8")

        # Compress the chunk before uploading
        compressed_chunk = gzip.compress(chunk_content_bytes, compresslevel=9)
        chunk_hash = hashlib.blake2b(chunk_content_bytes).hexdigest()

        click.echo(
            f"Uploading chunk {chunk_index}/{total_chunks - 1} (hash: {chunk_hash[:12]}...)",
            err=True,
        )

        try:
            client.upload_chunk(
                public_key=pk_classic_hex,
                file_hash=file_hash,
                chunk_data=compressed_chunk,
                chunk_hash=chunk_hash,
                chunk_index=chunk_index,
                total_chunks=total_chunks,
                compressed=True,
            )
        except DCypherAPIError as e:
            raise click.ClickException(
                f"API request failed for chunk {chunk_index}: {e}"
            )

    click.echo("All chunks uploaded successfully.", err=True)


@cli.command("download")
@click.option("--pk-path", type=str, required=True)
@click.option("--auth-keys-path", type=click.Path(exists=True), required=True)
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
def download(pk_path, auth_keys_path, file_hash, output_path, compressed, api_url):
    """Downloads a file from the remote storage API with integrity verification."""
    from lib.api_client import DCypherClient, DCypherAPIError
    from lib import idk_message

    click.echo(f"Starting download for file hash: {file_hash}...", err=True)

    try:
        # Initialize API client with auth keys
        client = DCypherClient(api_url, str(auth_keys_path))

        # Get the classic public key from the auth keys
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

        # Save the verified content (as originally downloaded, compressed or not)
        with open(output_path, "wb") as f:
            f.write(downloaded_content)

        # Provide helpful output information
        if is_compressed:
            original_size = len(content_to_verify)
            compressed_size = len(downloaded_content)
            click.echo(
                f"File '{file_hash}' downloaded and verified successfully to '{output_path}' "
                f"(compressed: {compressed_size} bytes, original: {original_size} bytes).",
                err=True,
            )
        else:
            click.echo(
                f"File '{file_hash}' downloaded and verified successfully to '{output_path}'.",
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
@click.option("--auth-keys-path", type=click.Path(exists=True), required=True)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def list_files(auth_keys_path, api_url):
    """Lists files for the authenticated account."""
    from lib.api_client import DCypherClient, DCypherAPIError

    try:
        client = DCypherClient(api_url, str(auth_keys_path))
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
