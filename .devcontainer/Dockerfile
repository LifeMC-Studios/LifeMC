FROM mcr.microsoft.com/devcontainers/go:2-1.26-bookworm

# Update base system packages and install essential utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Configure Go environment variables
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$PATH

# Install CLI tools required for modpack development
RUN go install github.com/packwiz/packwiz@latest \
    && go install github.com/Merith-TK/packwiz-wrapper/cmd/pw@main
