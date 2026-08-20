FROM mcr.microsoft.com/devcontainers/go:2-1.26-bookworm

# Configure Go environment variables
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

# Create standard non-root development user
RUN useradd -m -s /bin/bash devcontainer

# Update base system packages and install essential utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install CLI tools required for modpack development
RUN go install github.com/packwiz/packwiz@latest \
    && go install github.com/Merith-TK/packwiz-wrapper/cmd/pw@main

# Ensure proper permissions for the devcontainer user
RUN chown -R devcontainer:devcontainer $GOPATH
