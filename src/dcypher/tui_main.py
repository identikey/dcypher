"""
dCypher TUI Entry Point
Command-line interface for launching the TUI with optional profiling
"""

import click
import os
from pathlib import Path
from dcypher.tui.app import run_tui


@click.command("terminal")
@click.option(
    "--identity-path",
    type=click.Path(exists=True),
    help="Path to identity file to load on startup",
)
@click.option(
    "--api-url",
    envvar="DCY_API_URL",
    default="http://127.0.0.1:8000",
    help="API base URL",
)
@click.option(
    "--theme",
    type=click.Choice(["cyberpunk", "classic", "minimal"]),
    default="cyberpunk",
    help="UI theme to use",
)
@click.option(
    "--profile",
    is_flag=True,
    help="Enable profiling for performance analysis",
)
@click.option(
    "--profile-backends",
    default="cprofile",
    help="Profiling backends to use (comma-separated): cprofile,py-spy,memory",
)
@click.option(
    "--profile-output",
    default="profiling_output",
    help="Directory to save profiling results",
)
@click.option(
    "--profile-real-time",
    is_flag=True,
    default=True,
    help="Enable real-time performance monitoring",
)
@click.option(
    "--profile-animations",
    is_flag=True,
    default=True,
    help="Enable specialized animation profiling",
)
def tui_command(
    identity_path,
    api_url,
    theme,
    profile,
    profile_backends,
    profile_output,
    profile_real_time,
    profile_animations,
):
    """
    Launch the dCypher Terminal User Interface

    A cyberpunk-inspired TUI for quantum-resistant encryption operations.
    Provides full feature parity with the CLI in an interactive interface.

    PROFILING OPTIONS:

    Enable profiling with --profile and customize with:

    --profile-backends: Choose profiling tools
      • cprofile: Built-in deterministic profiler (default)
      • py-spy: Low-overhead statistical profiler (requires external py-spy)
      • memory: Memory usage tracking with tracemalloc
      • line: Line-by-line profiling (requires line_profiler package)

    --profile-output: Directory for profiling results

    --profile-real-time: Real-time performance monitoring

    --profile-animations: Specialized ASCII animation profiling

    Examples:
      dcypher tui --profile                           # Basic profiling
      dcypher tui --profile --profile-backends cprofile,memory  # CPU + memory
      dcypher tui --profile --profile-backends py-spy  # External py-spy
    """

    # Setup profiling if requested
    profiling_config = None
    if profile:
        from dcypher.lib.profiling import ProfilingConfig, init_profiling

        # Parse backends
        backends = [b.strip() for b in profile_backends.split(",")]

        # Validate backends
        available_backends = ["cprofile", "py-spy", "memory", "line"]
        invalid_backends = [b for b in backends if b not in available_backends]
        if invalid_backends:
            click.echo(
                f"❌ Invalid profiling backends: {', '.join(invalid_backends)}",
                err=True,
            )
            click.echo(f"   Available: {', '.join(available_backends)}", err=True)
            raise click.ClickException("Invalid profiling backend specified")

        # Check external dependencies
        if "py-spy" in backends:
            import shutil

            if not shutil.which("py-spy"):
                click.echo(
                    "⚠️  py-spy not found in PATH. Install with: pip install py-spy",
                    err=True,
                )
                click.echo("   Continuing without py-spy backend...", err=True)
                backends = [b for b in backends if b != "py-spy"]

        if "line" in backends:
            try:
                import line_profiler  # type: ignore
            except ImportError:
                click.echo(
                    "⚠️  line_profiler not available. Install with: pip install line_profiler",
                    err=True,
                )
                click.echo("   Continuing without line profiler backend...", err=True)
                backends = [b for b in backends if b != "line"]

        # Create profiling config
        profiling_config = ProfilingConfig(
            enabled=True,
            output_dir=profile_output,
            backends=backends,
            memory_tracking="memory" in backends,
            real_time_stats=profile_real_time,
            auto_save=True,
        )

        # Initialize global profiler
        profiler_manager = init_profiling(profiling_config)
        profiler_manager.enable(backends)

        # Setup output directory
        os.makedirs(profile_output, exist_ok=True)

        # Print profiling info
        click.echo("🔬 Profiling enabled!", err=True)
        click.echo(f"   Backends: {', '.join(backends)}", err=True)
        click.echo(f"   Output: {profile_output}/", err=True)
        click.echo(f"   Real-time monitoring: {profile_real_time}", err=True)
        click.echo(f"   Animation profiling: {profile_animations}", err=True)

        # Generate py-spy command if requested
        if "py-spy" in backends:
            click.echo(
                f"   py-spy command: {profiler_manager.generate_py_spy_command()}",
                err=True,
            )

    # Standard startup messages
    click.echo("🚀 Launching dCypher TUI...", err=True)
    click.echo(f"   Theme: {theme}", err=True)
    click.echo(f"   API URL: {api_url}", err=True)

    if identity_path:
        click.echo(f"   Identity: {identity_path}", err=True)

    try:
        # Run TUI with profiling config
        run_tui(
            identity_path=identity_path,
            api_url=api_url,
            profiling_config=profiling_config,
            profile_animations=profile_animations if profile else False,
        )
    except KeyboardInterrupt:
        click.echo("\n👋 dCypher TUI terminated by user", err=True)

        # Print profiling summary if enabled
        if profile:
            from dcypher.lib.profiling import print_profiling_stats

            print_profiling_stats()
    except Exception as e:
        click.echo(f"❌ Error running TUI: {e}", err=True)

        # Print profiling summary if enabled
        if profile:
            from dcypher.lib.profiling import print_profiling_stats

            print_profiling_stats()

        raise click.ClickException(f"TUI failed to start: {e}")
    finally:
        # Cleanup profiling
        if profile:
            from dcypher.lib.profiling import get_profiler

            profiler = get_profiler()
            if profiler:
                profiler.disable()


if __name__ == "__main__":
    tui_command()
