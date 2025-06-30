#!/bin/bash

set -euo pipefail

echo "CHECKING AND INSTALLING DEVELOPMENT DEPENDENCIES..."

# Check and install uv
if ! command -v uv &> /dev/null; then
    echo "Installing uv..."
    pip install uv
else
    echo "uv is already installed"
fi

# Check and install just
if ! command -v just &> /dev/null; then
    echo "Installing just..."
    sudo bash -c "curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to /usr/local/bin"
    sudo chmod +x /usr/local/bin/just
else
    echo "just is already installed"
fi

# Install required packages
PACKAGES="build-essential cmake pkg-config libssl-dev git curl wget"
PACKAGES_TO_INSTALL=""

for pkg in $PACKAGES; do
    if ! dpkg -l | grep -q "^ii  $pkg "; then
        PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
    fi
done

if [ ! -z "$PACKAGES_TO_INSTALL" ]; then
    echo "Installing missing packages:$PACKAGES_TO_INSTALL"
    sudo apt-get update && sudo apt-get install -y $PACKAGES_TO_INSTALL
else
    echo "All required packages are already installed"
fi

# Install VSCode extension only if not already installed
if ! code --list-extensions | grep -q "vscodevim.vim"; then
    echo "Installing VSCode Vim extension..."
    code --install-extension vscodevim.vim
else
    echo "VSCode Vim extension is already installed"
fi