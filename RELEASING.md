# Releasing Recrypt

## Prerequisites

- Push access to the repository
- Docker Hub credentials configured in GitHub (see below)

## GitHub Repository Setup

### Secrets (one-time setup)

1. Go to repository Settings → Secrets and variables → Actions
2. Add repository secret:
   - `DOCKERHUB_TOKEN`: Docker Hub access token (Read/Write permissions)

### Variables (one-time setup)

1. Go to repository Settings → Secrets and variables → Actions → Variables
2. Add repository variable:
   - `DOCKERHUB_USERNAME`: Your Docker Hub username

### Creating a Docker Hub Token

1. Log in to [Docker Hub](https://hub.docker.com)
2. Go to Account Settings → Security → New Access Token
3. Name: `github-actions-recrypt`
4. Permissions: Read & Write
5. Copy the token immediately (shown only once)

## Release Process

### 1. Prepare the release

Ensure all changes are merged to `main` and CI is passing.

### 2. Create the release

```bash
# Check current version
just version

# Create release (updates Cargo.toml, commits, and tags)
just release 1.2.3
```

### 3. Push to trigger CI

```bash
git push && git push --tags
```

### 4. Monitor the release

- Go to Actions tab in GitHub
- Watch the `Release` and `Docker` workflows
- Check that artifacts are created correctly

### 5. Verify the release

- **GitHub Release**: Check releases page for binaries and checksums
- **Docker Hub**: Verify image tags appear on `recrypt-server` (`latest`, `1.2.3`, `1.2`)
- **Binaries**: Download and test on target platform

## Artifacts Produced

### Docker Image

Published to Docker Hub as `<username>/recrypt-server`:
- `latest` - Latest release
- `X.Y.Z` - Specific version (e.g., `1.2.3`)
- `X.Y` - Minor version (e.g., `1.2`)

### Binary Archives

Published to GitHub Releases:
- `recrypt-X.Y.Z-x86_64-unknown-linux-gnu.tar.gz` - Linux x86_64
- `recrypt-X.Y.Z-aarch64-unknown-linux-gnu.tar.gz` - Linux ARM64
- `recrypt-X.Y.Z-x86_64-apple-darwin.tar.gz` - macOS Intel
- `recrypt-X.Y.Z-aarch64-apple-darwin.tar.gz` - macOS ARM (Apple Silicon)
- `recrypt-X.Y.Z-x86_64-pc-windows-msvc.zip` - Windows x86_64 (best-effort)

Each archive contains:
- `recrypt` (or `recrypt.exe`) - CLI binary
- `recrypt-server` (or `recrypt-server.exe`) - Server binary

SHA256 checksums are provided as `.sha256` files.

## Troubleshooting

### Windows build fails

Windows support is best-effort. OpenFHE may not build correctly on Windows.
If Windows builds fail, other platforms will still release.

### ARM64 Linux build fails

The `cross` tool uses Docker/QEMU for ARM64 emulation. If it fails:
1. Check the Cross.toml configuration
2. Verify the pre-build script installs OpenFHE correctly
3. Consider marking ARM64 as allowed-to-fail

### Cache issues

If builds fail due to stale caches:
1. Go to Actions → Caches
2. Delete relevant cache entries
3. Re-run the workflow
