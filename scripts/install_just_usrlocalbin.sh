
sudo bash -c "curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to /usr/local/bin"
sudo chmod +x /usr/local/bin/just

sudo apt-get update && sudo apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libssl-dev \
    git \
    curl \
    wget