FROM mcr.microsoft.com/devcontainers/go@sha256:adc326255c019241228f9da4a1cb5d6a89abaaa0eb8d926a355b00af7daafd00

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
