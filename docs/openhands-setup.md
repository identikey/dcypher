# OpenHands Setup for DCypher

This document explains how DCypher integrates with OpenHands (All Hands AI) for AI-assisted development.

## Quick Start (Fresh Clone)

```bash
git clone <dcypher-repo>
cd dcypher
just setup-openhands    # Builds everything automatically
just doit               # Start OpenHands interface
```

That's it! The `just setup-openhands` command handles all the complexity.

## Force Rebuild (Override Remote Images)

If you have remote-pulled images that conflict with local builds:

```bash
just setup-openhands-force    # Force rebuild everything from scratch
# OR individually:
just build-openhands-force    # Force rebuild just OpenHands images
```

## What `just setup-openhands` Does

1. **Builds OpenHands Runtime** (`build-openhands-runtime`)
   - Installs Poetry dependencies in vendored OpenHands repo
   - Generates dynamic runtime Dockerfile
   - Builds `ghcr.io/all-hands-ai/runtime` image
   - Tags as `docker.all-hands.dev/all-hands-ai/runtime:0.48.0`

2. **Builds OpenHands App** (`build-openhands-app`)
   - Builds main OpenHands application image
   - Tags as `docker.all-hands.dev/all-hands-ai/openhands:0.48.0`

3. **Builds DCypher Custom Runtime** (`build-allhands`)
   - Extends OpenHands runtime with Zig + Just
   - Creates `dcypher-allhands:latest` image

## Individual Commands

For development and debugging:

```bash
# Build just the OpenHands dependencies
just build-openhands

# Force rebuild OpenHands (ignores cache)
just build-openhands-force

# Build just the DCypher custom image  
just build-allhands

# Start OpenHands interface
just doit

# Check image status and sources
just status-openhands

# Clean everything
just clean
```

## Architecture

```
┌─────────────────────────────────────────┐
│ docker.all-hands.dev/all-hands-ai/      │
│ openhands:0.48.0                        │
│ (Main OpenHands App)                    │
└─────────────────────────────────────────┘
                     │
                     │ uses sandbox
                     ▼
┌─────────────────────────────────────────┐
│ dcypher-allhands:latest                 │
│ (DCypher Custom Runtime)                │
│ • Zig 0.12.0                           │
│ • Just build tool                       │
│ • All OpenHands runtime features       │
└─────────────────────────────────────────┘
                     │
                     │ based on
                     ▼
┌─────────────────────────────────────────┐
│ docker.all-hands.dev/all-hands-ai/      │
│ runtime:0.48.0                         │
│ (OpenHands Base Runtime)                │
│ • Python 3.12 + Node.js               │
│ • OpenHands dependencies               │
│ • VS Code server                       │
└─────────────────────────────────────────┘
```

## Version Management

- OpenHands version: Controlled by `config.toml` `[versions]` section
- Extracted by `scripts/get_openhands_version.py`
- Currently: `0.48.0` (matches vendored repo)

## Troubleshooting

```bash
# Check image status and sources  
just status-openhands

# Clean and rebuild everything
just clean
just setup-openhands-force

# Force rebuild if you have conflicting remote images
just setup-openhands-force

# Check what images exist
docker images | grep -E "(openhands|runtime|dcypher)"

# Rebuild just OpenHands images
just clean-openhands
just build-openhands-force
```

## Image Source Detection

The system now uses **source-specific tagging** to distinguish between:

- **Local builds**: `0.48.0-vendored-8937b3f` (from our vendored repo)
- **Remote pulls**: `0.48.0` (pulled from remote registry)

**Key Benefits:**

- [YES] Local builds always override remote images
- [YES] Can identify which images were built from our vendored sources  
- [YES] Force rebuild option when needed
- [YES] Automatic detection prevents unnecessary rebuilds
