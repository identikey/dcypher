#!/bin/bash

set -euo pipefail

echo "INSTALLING DEVELOPMENT DEPENDENCIES IN CONTAINER..."

# Check if running as root, if not, don't use sudo
if [ "$EUID" -eq 0 ]; then
    SUDO=""
    echo "Running as root"
else
    if command -v sudo &> /dev/null; then
        SUDO="sudo"
        echo "Running with sudo"
    else
        echo "Warning: Not running as root and sudo not available. Some installations may fail."
        SUDO=""
    fi
fi

# Check and install uv
if ! command -v uv &> /dev/null; then
    echo "Installing uv..."
    pip install uv
else
    echo "uv is already installed"
fi

# Check and install just - try multiple methods
if ! command -v just &> /dev/null; then
    echo "Installing just..."
    
    # Method 1: Try with curl (container-friendly)
    if command -v curl &> /dev/null; then
        echo "Trying to install just with curl..."
        curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | ${SUDO} bash -s -- --to /usr/local/bin
        ${SUDO} chmod +x /usr/local/bin/just
    # Method 2: Try with apt if available
    elif command -v apt-get &> /dev/null; then
        echo "Trying to install just with apt..."
        ${SUDO} apt-get update && ${SUDO} apt-get install -y just
    # Method 3: Try cargo if available
    elif command -v cargo &> /dev/null; then
        echo "Trying to install just with cargo..."
        cargo install just
    else
        echo "Warning: Could not install just - no suitable package manager found"
    fi
else
    echo "just is already installed"
fi

# Install required packages (only if we have package manager access)
if command -v apt-get &> /dev/null; then
    PACKAGES="build-essential cmake pkg-config libssl-dev git curl wget"
    PACKAGES_TO_INSTALL=""

    for pkg in $PACKAGES; do
        if ! dpkg -l | grep -q "^ii  $pkg "; then
            PACKAGES_TO_INSTALL="$PACKAGES_TO_INSTALL $pkg"
        fi
    done

    if [ ! -z "$PACKAGES_TO_INSTALL" ]; then
        echo "Installing missing packages:$PACKAGES_TO_INSTALL"
        ${SUDO} apt-get update && ${SUDO} apt-get install -y $PACKAGES_TO_INSTALL
    else
        echo "All required packages are already installed"
    fi
fi

echo "Installation complete!" 