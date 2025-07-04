import click
from pathlib import Path
from dcypher.lib.api_client import DCypherClient, DCypherAPIError
from dcypher.lib.key_manager import KeyManager


@click.command("supported-algorithms")
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def supported_algorithms(api_url):
    """Lists supported post-quantum signature algorithms."""
    try:
        client = DCypherClient(api_url)
        algorithms = client.get_supported_algorithms()

        click.echo("Supported post-quantum signature algorithms:", err=True)
        for alg in algorithms:
            click.echo(f"  - {alg}")

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to get supported algorithms: {e}")


@click.command("list-accounts")
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def list_accounts(api_url):
    """Lists all accounts."""
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


@click.command("create-account")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to identity file",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def create_account(identity_path, api_url):
    """Creates a new account on the server using your identity file."""
    try:
        # Initialize API client with identity file
        client = DCypherClient(api_url, identity_path=identity_path)

        # Load keys to get PQ key info for account creation
        keys_data = KeyManager.load_keys_unified(Path(identity_path))

        pk_classic_hex = client.get_classic_public_key()
        pq_keys = [
            {"pk_hex": key["pk_hex"], "alg": key["alg"]} for key in keys_data["pq_keys"]
        ]

        click.echo(
            f"Creating account with classic key: {pk_classic_hex[:16]}...", err=True
        )
        click.echo(f"Including {len(pq_keys)} post-quantum keys", err=True)

        result = client.create_account(pk_classic_hex, pq_keys)
        click.echo(f"✓ Account created successfully!", err=True)
        click.echo(f"  Account ID: {pk_classic_hex}", err=True)

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to create account: {e}")
    except Exception as e:
        raise click.ClickException(f"Error: {e}")


@click.command("get-account")
@click.option(
    "--public-key", type=str, required=True, help="Public key of the account to query."
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def get_account(public_key, api_url):
    """Gets detailed information about an account."""
    try:
        client = DCypherClient(api_url)
        account = client.get_account(public_key)

        click.echo(f"Account Information:", err=True)
        click.echo(f"  Public Key: {account.get('public_key', 'N/A')}", err=True)
        click.echo(f"  Created: {account.get('created_at', 'N/A')}", err=True)

        if "pq_keys" in account:
            click.echo(f"  Post-Quantum Keys:", err=True)
            for i, pq_key in enumerate(account["pq_keys"]):
                click.echo(
                    f"    {i + 1}. {pq_key.get('alg', 'N/A')}: {pq_key.get('public_key', 'N/A')[:16]}...",
                    err=True,
                )

        if "pre_public_key_hex" in account and account["pre_public_key_hex"]:
            click.echo(
                f"  PRE Public Key: {account['pre_public_key_hex'][:16]}...", err=True
            )

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to get account: {e}")


@click.command("list-files")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to identity file",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def list_files(identity_path, api_url):
    """Lists files for the authenticated account."""
    try:
        # Initialize API client with identity file
        client = DCypherClient(api_url, identity_path=identity_path)

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


@click.command("get-graveyard")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to identity file",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def get_graveyard(identity_path, api_url):
    """Gets retired keys (graveyard) for the authenticated account."""
    try:
        # Initialize API client with identity file
        client = DCypherClient(api_url, identity_path=identity_path)

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


@click.command("add-pq-keys")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to identity file",
)
@click.option(
    "--algorithms",
    type=str,
    required=True,
    help="Comma-separated list of PQ algorithms to add (e.g., 'Falcon-512,SPHINCS+-SHA2-128f')",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def add_pq_keys(identity_path, algorithms, api_url):
    """Adds new post-quantum keys to an existing account."""
    try:
        # Parse algorithms
        alg_list = [alg.strip() for alg in algorithms.split(",")]

        # Initialize API client with identity file
        client = DCypherClient(api_url, identity_path=identity_path)

        pk_classic_hex = client.get_classic_public_key()

        # Generate new keys for the specified algorithms (temporary, not persisted locally)
        import oqs

        new_keys = []
        oqs_objects = []  # Track for cleanup

        try:
            for alg in alg_list:
                click.echo(f"Generating new {alg} key pair...", err=True)
                sig = oqs.Signature(alg)
                pk = sig.generate_keypair()  # This returns the public key
                pk_hex = pk.hex()

                new_keys.append({"pk_hex": pk_hex, "alg": alg})
                oqs_objects.append(sig)

            click.echo(f"Adding {len(new_keys)} new PQ keys to account...", err=True)
            result = client.add_pq_keys(pk_classic_hex, new_keys)

            click.echo(f"✓ Successfully added PQ keys to account!", err=True)
            for key in new_keys:
                click.echo(f"  - {key['alg']}: {key['pk_hex'][:16]}...", err=True)

            click.echo("", err=True)
            click.echo(
                "⚠️  Important: The new keys were added to the server but NOT saved to your local identity file.",
                err=True,
            )
            click.echo(
                "You will need to manually add these keys to your local files if you want to use them for signing.",
                err=True,
            )
            click.echo(
                "Consider rotating your identity to generate new keys that are properly integrated.",
                err=True,
            )

        finally:
            # Clean up OQS objects
            for sig in oqs_objects:
                sig.free()

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to add PQ keys: {e}")
    except Exception as e:
        raise click.ClickException(f"Error: {e}")


@click.command("remove-pq-keys")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    required=True,
    help="Path to identity file",
)
@click.option(
    "--algorithms",
    type=str,
    required=True,
    help="Comma-separated list of PQ algorithms to remove (e.g., 'Falcon-512,SPHINCS+-SHA2-128f')",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL.",
)
def remove_pq_keys(identity_path, algorithms, api_url):
    """Removes post-quantum keys from an existing account."""
    try:
        # Parse algorithms
        alg_list = [alg.strip() for alg in algorithms.split(",")]

        # Initialize API client with identity file
        client = DCypherClient(api_url, identity_path=identity_path)

        pk_classic_hex = client.get_classic_public_key()

        click.echo(
            f"Removing {len(alg_list)} PQ key algorithms from account...", err=True
        )
        for alg in alg_list:
            click.echo(f"  - {alg}", err=True)

        result = client.remove_pq_keys(pk_classic_hex, alg_list)

        click.echo(f"✓ Successfully removed PQ keys from account!", err=True)

        # Note: This doesn't remove the keys from the local identity/auth file
        # Users should manually clean up or rotate their identity if needed
        click.echo(
            "Note: Keys removed from server but still present in local identity file.",
            err=True,
        )

    except DCypherAPIError as e:
        raise click.ClickException(f"Failed to remove PQ keys: {e}")
    except Exception as e:
        raise click.ClickException(f"Error: {e}")
