#!/bin/bash

# Configure Go environment paths
export GOPATH=/home/vscode/go
export PATH=$GOPATH/bin:$PATH

# Move to the CLI source directory, tidy dependencies, and install the binary
cd src/tools
go mod tidy
go install .
