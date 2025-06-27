"""
dCypher TUI Entry Point
Command-line interface for launching the TUI
"""

import click
from pathlib import Path
from tui.app import run_tui


@click.command("tui")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    help="Path to identity file to load on startup"
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL"
)
@click.option(
    "--theme",
    type=click.Choice(["cyberpunk", "classic", "minimal"]),
    default="cyberpunk",
    help="UI theme to use"
)
def tui_command(identity_path, api_url, theme):
    """
    Launch the dCypher Terminal User Interface
    
    A cyberpunk-inspired TUI for quantum-resistant encryption operations.
    Provides full feature parity with the CLI in an interactive interface.
    """
    click.echo("🚀 Launching dCypher TUI...", err=True)
    click.echo(f"   Theme: {theme}", err=True)
    click.echo(f"   API URL: {api_url}", err=True)
    
    if identity_path:
        click.echo(f"   Identity: {identity_path}", err=True)
    
    try:
        run_tui(identity_path=identity_path, api_url=api_url)
    except KeyboardInterrupt:
        click.echo("\n👋 dCypher TUI terminated by user", err=True)
    except Exception as e:
        click.echo(f"❌ Error running TUI: {e}", err=True)
        raise click.ClickException(f"TUI failed to start: {e}")


if __name__ == "__main__":
    tui_command()