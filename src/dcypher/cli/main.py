import click

# Import command groups and individual commands from modules
from dcypher.cli.identity import identity_group
from dcypher.cli.crypto import (
    gen_cc,
    gen_signing_keys,
    gen_keys,
    encrypt,
    decrypt,
    gen_rekey,
    re_encrypt,
)
from dcypher.cli.files import upload, download, download_chunks
from dcypher.cli.accounts import (
    supported_algorithms,
    list_accounts,
    create_account,
    get_account,
    list_files,
    get_graveyard,
    add_pq_keys,
    remove_pq_keys,
)
from dcypher.cli.sharing import (
    get_pre_context,
    init_pre,
    create_share,
    list_shares,
    download_shared,
    revoke_share,
)

from dcypher.tui_main import tui_command


@click.group()
def cli():
    """A CLI tool for demonstrating proxy re-encryption."""
    pass


# Add the identity group (which contains multiple subcommands)
cli.add_command(identity_group)

# Add crypto commands
cli.add_command(gen_cc)
cli.add_command(gen_signing_keys)
cli.add_command(gen_keys)
cli.add_command(encrypt)
cli.add_command(decrypt)
cli.add_command(gen_rekey)
cli.add_command(re_encrypt)

# Add file commands
cli.add_command(upload)
cli.add_command(download)
cli.add_command(download_chunks)

# Add account commands
cli.add_command(supported_algorithms)
cli.add_command(list_accounts)
cli.add_command(list_files)
cli.add_command(get_graveyard)
cli.add_command(create_account)
cli.add_command(get_account)
cli.add_command(add_pq_keys)
cli.add_command(remove_pq_keys)

# Add sharing commands
cli.add_command(get_pre_context)
cli.add_command(init_pre)
cli.add_command(create_share)
cli.add_command(list_shares)
cli.add_command(download_shared)
cli.add_command(revoke_share)

# Add TUI command
cli.add_command(tui_command)


if __name__ == "__main__":
    cli()
