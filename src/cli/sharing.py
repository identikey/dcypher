import click
from lib.api_client import DCypherClient, DCypherAPIError


@click.command("get-pre-context")
@click.option(
    "--output",
    default="pre_context.dat",
    help="Path to save the PRE crypto context file.",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def get_pre_context(output, api_url):
    """Downloads the PRE crypto context from the server."""
    try:
        client = DCypherClient(api_url)
        context_bytes = client.get_pre_crypto_context()

        with open(output, "wb") as f:
            f.write(context_bytes)

        click.echo(f"✓ PRE crypto context saved to {output}", err=True)
        click.echo(f"Size: {len(context_bytes)} bytes", err=True)

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to get PRE crypto context: {e}")


@click.command("init-pre")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to identity file to initialize PRE for.",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def init_pre(identity_path, api_url):
    """Initializes PRE capabilities for an identity file."""
    try:
        client = DCypherClient(api_url, identity_path=identity_path)

        click.echo("Initializing PRE capabilities for identity...", err=True)
        client.initialize_pre_for_identity()

        click.echo("✓ PRE keys added to identity file!", err=True)
        click.echo(
            "Your identity now supports proxy re-encryption operations.", err=True
        )

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to initialize PRE: {e}")
    except Exception as e:
        raise click.ClickException(f"Error: {e}")


@click.command("create-share")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to your identity file (you must be the file owner).",
)
@click.option(
    "--bob-public-key",
    type=str,
    required=True,
    help="Bob's classic public key (who you're sharing with).",
)
@click.option(
    "--file-hash",
    type=str,
    required=True,
    help="Hash of the file to share.",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def create_share(identity_path, bob_public_key, file_hash, api_url):
    """Creates a sharing policy to allow another user to access your file."""
    try:
        client = DCypherClient(api_url, identity_path=identity_path)

        click.echo(f"Creating share for file {file_hash}...", err=True)
        click.echo(f"Sharing with: {bob_public_key[:16]}...", err=True)

        # Get Bob's account info to retrieve his PRE public key
        click.echo("Looking up recipient's PRE public key...", err=True)
        try:
            bob_account = client.get_account(bob_public_key)
            bob_pre_pk_hex = bob_account.get("pre_public_key_hex")

            if not bob_pre_pk_hex:
                raise click.ClickException(
                    f"Recipient {bob_public_key[:16]}... does not have PRE capabilities enabled. "
                    "They need to run 'dcypher init-pre' first."
                )
        except Exception as e:
            raise click.ClickException(f"Failed to get recipient's account info: {e}")

        # Generate re-encryption key using Bob's PRE public key
        click.echo("Generating re-encryption key...", err=True)
        re_key_hex = client.generate_re_encryption_key(bob_pre_pk_hex)

        # Create the share
        result = client.create_share(bob_public_key, file_hash, re_key_hex)

        share_id = result.get("share_id")
        click.echo(f"✓ Share created successfully!", err=True)
        click.echo(f"  Share ID: {share_id}", err=True)
        click.echo(f"  File: {file_hash}", err=True)
        click.echo(f"  Shared with: {bob_public_key[:16]}...", err=True)

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to create share: {e}")
    except Exception as e:
        raise click.ClickException(f"Error: {e}")


@click.command("list-shares")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to your identity file.",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def list_shares(identity_path, api_url):
    """Lists all shares involving your account (sent and received)."""
    try:
        client = DCypherClient(api_url, identity_path=identity_path)
        pk_classic_hex = client.get_classic_public_key()

        shares = client.list_shares(pk_classic_hex)

        shares_sent = shares.get("shares_sent", [])
        shares_received = shares.get("shares_received", [])

        if shares_sent:
            click.echo(f"📤 Shares you've sent ({len(shares_sent)}):", err=True)
            for share in shares_sent:
                click.echo(
                    f"  • {share.get('share_id', 'N/A')}: {share.get('file_hash', 'N/A')[:16]}... → {share.get('bob_public_key', 'N/A')[:16]}...",
                    err=True,
                )
        else:
            click.echo("📤 No shares sent", err=True)

        if shares_received:
            click.echo(f"📥 Shares you've received ({len(shares_received)}):", err=True)
            for share in shares_received:
                click.echo(
                    f"  • {share.get('share_id', 'N/A')}: {share.get('file_hash', 'N/A')[:16]}... ← {share.get('alice_public_key', 'N/A')[:16]}...",
                    err=True,
                )
        else:
            click.echo("📥 No shares received", err=True)

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to list shares: {e}")
    except Exception as e:
        raise click.ClickException(f"Error: {e}")


@click.command("download-shared")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to your identity file.",
)
@click.option(
    "--share-id",
    type=str,
    required=True,
    help="ID of the share to download.",
)
@click.option(
    "--output-path",
    type=click.Path(dir_okay=False, writable=True),
    required=True,
    help="Path to save the downloaded shared file.",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def download_shared(identity_path, share_id, output_path, api_url):
    """Downloads a file that has been shared with you."""
    try:
        client = DCypherClient(api_url, identity_path=identity_path)

        click.echo(f"Downloading shared file with share ID: {share_id}...", err=True)

        # Download the shared file (re-encrypted)
        shared_content = client.download_shared_file(share_id)

        # Save the content
        with open(output_path, "wb") as f:
            f.write(shared_content)

        click.echo(
            f"✓ Shared file downloaded successfully to '{output_path}'", err=True
        )
        click.echo(
            f"Note: This is a re-encrypted version. You'll need to decrypt it with your PRE secret key.",
            err=True,
        )

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to download shared file: {e}")
    except Exception as e:
        raise click.ClickException(f"Error: {e}")


@click.command("revoke-share")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to your identity file (you must be the file owner).",
)
@click.option(
    "--share-id",
    type=str,
    required=True,
    help="ID of the share to revoke.",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def revoke_share(identity_path, share_id, api_url):
    """Revokes a sharing policy (removes access for the shared user)."""
    try:
        client = DCypherClient(api_url, identity_path=identity_path)

        click.echo(f"Revoking share: {share_id}...", err=True)

        result = client.revoke_share(share_id)

        click.echo(f"✓ Share revoked successfully!", err=True)
        click.echo(f"The shared user no longer has access to the file.", err=True)

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to revoke share: {e}")
    except Exception as e:
        raise click.ClickException(f"Error: {e}")
