import click
import json
import gzip
import hashlib
from pathlib import Path
from lib.api_client import DCypherClient, DCypherAPIError
from lib import idk_message
from lib import pre
import base64
import ecdsa


@click.command("upload")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to identity file containing PRE and signing keys.",
)
@click.option("--file-path", type=click.Path(exists=True), required=True)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def upload(identity_path, file_path, api_url):
    """Uploads a file to the remote storage API using identity file."""
    click.echo("Initializing upload with identity file...", err=True)

    try:
        # Initialize API client
        client = DCypherClient(api_url, identity_path=identity_path)

        # CRITICAL FIX: Use the same context management approach as when PRE keys were generated
        # Since this file imports DCypherClient, we should use its context management
        # to ensure compatibility with the PRE keys stored in the identity file
        click.echo(
            "Getting crypto context (same approach as key generation)...", err=True
        )
        cc = client.get_crypto_context_object()

        # Load identity data to get keys
        click.echo("Loading keys from identity file...", err=True)
        with open(identity_path, "r") as f:
            identity_data = json.load(f)

        # Get PRE public key from identity
        if (
            "pre" not in identity_data["auth_keys"]
            or not identity_data["auth_keys"]["pre"]
        ):
            raise click.ClickException(
                "Identity file does not contain PRE keys. Run 'init-pre' first."
            )

        pre_pk_hex = identity_data["auth_keys"]["pre"]["pk_hex"]
        pre_pk_bytes = bytes.fromhex(pre_pk_hex)
        pk_enc = pre.deserialize_public_key(pre_pk_bytes)

        # Get signing key from identity (classic ECDSA key used for IDK message signing)
        classic_sk_hex = identity_data["auth_keys"]["classic"]["sk_hex"]
        sk_sign_idk = ecdsa.SigningKey.from_string(
            bytes.fromhex(classic_sk_hex), curve=ecdsa.SECP256k1
        )

        # Get classic public key for API operations
        pk_classic_hex = client.get_classic_public_key()

    except Exception as e:
        raise click.ClickException(f"Error loading identity or crypto context: {e}")

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


@click.command("download")
@click.option("--pk-path", type=str, required=True)
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to identity file",
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
def download(pk_path, identity_path, file_hash, output_path, compressed, api_url):
    """Downloads a file from the remote storage API with integrity verification."""
    click.echo(f"Starting download for file hash: {file_hash}...", err=True)

    try:
        # Initialize API client with identity file
        client = DCypherClient(api_url, identity_path=identity_path)

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


@click.command("download-chunks")
@click.option("--pk-path", type=str, required=True)
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to identity file",
)
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
def download_chunks(pk_path, identity_path, file_hash, output_path, api_url):
    """Downloads all chunks for a file as a single concatenated gzip file."""
    click.echo(
        f"Starting download for concatenated chunks of file hash: {file_hash}...",
        err=True,
    )

    try:
        # Initialize API client with identity file
        client = DCypherClient(api_url, identity_path=identity_path)

        # Get the classic public key from the keys
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
