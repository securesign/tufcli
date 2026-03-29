# tufcli

A Go implementation of tuftool - a command-line utility for creating and managing The Update Framework (TUF) repositories.

## Overview

tufcli is a reimplementation of the Rust-based tuftool in Go, providing the same functionality for managing TUF repositories. TUF (The Update Framework) is a framework for securing software update systems.

## Installation

```bash
go build -o tufcli .
```

## Usage

```bash
# Show help
./tufcli --help

# Show version
./tufcli --version

# Set log level
./tufcli --log-level debug <command>
```

## Commands

### Repository Management

- `create` - Create a new TUF repository
- `clone` - Clone a TUF repository, including metadata and targets
- `update` - Update a TUF repository's metadata and optionally add targets
- `download` - Download a TUF repository's targets

### Metadata Management

- `root` - Manipulate examples/root.json metadata file
  - `init` - Initialize a new examples/root.json file
  - `add-key` - Add a key to examples/root.json
  - `remove-key` - Remove keys from roles
  - `expire` - Set the expiration date
  - `set-threshold` - Set signature threshold for a role
  - `bump-version` - Increment version number
  - `set-version` - Set specific version number
  - `gen-rsa-key` - Generate RSA keypair and add to roles
  - `sign` - Sign examples/root.json with private keys

### Delegation Management

- `delegation` - Manage delegated roles (requires `--signing-role` flag)
  - `create-role` - Create a delegated role
  - `add-role` - Add delegated role
  - `add-key` - Add a key to a delegated role
  - `remove-key` - Remove a key from a delegated role
  - `remove` - Remove a role
  - `update-delegated-targets` - Update delegated targets

### Advanced Operations

- `transfer-metadata` - Transfer metadata from a previous root to a new root
- `rhtas` - Manage RHTAS (Red Hat Trusted Artifact Signer) TUF repositories

## Development Status

Root metadata commands are complete and tested. Repository commands (create, update, download) are in progress.

## TUF Specification

This implementation targets TUF specification version 1.0.0.

## License

MIT OR Apache-2.0

## Original Implementation

This is a Go port of the original Rust implementation available at: https://github.com/awslabs/tough

## Examples

### Quick start (using gen-rsa-key shortcut)

```bash
./tufcli root init --path examples/root.json
./tufcli root gen-rsa-key --path examples/root.json --output examples/key.pem \
  --role root --role snapshot --role targets --role timestamp --bits 2048
./tufcli root set-threshold --path examples/root.json --role root --threshold 1
./tufcli root set-threshold --path examples/root.json --role snapshot --threshold 1
./tufcli root set-threshold --path examples/root.json --role targets --threshold 1
./tufcli root set-threshold --path examples/root.json --role timestamp --threshold 1
./tufcli root expire --path examples/root.json --time "in 1 year"
./tufcli root sign --path examples/root.json --key examples/key.pem
```

### Using existing keys

```bash
# Initialize root metadata
./tufcli root init --path examples/root.json

# Add existing key to all roles
./tufcli root add-key --path examples/root.json --key examples/key.pem \
  --role root --role snapshot --role targets --role timestamp

# Set thresholds
./tufcli root set-threshold --path examples/root.json --role root --threshold 1
./tufcli root set-threshold --path examples/root.json --role snapshot --threshold 1
./tufcli root set-threshold --path examples/root.json --role targets --threshold 1
./tufcli root set-threshold --path examples/root.json --role timestamp --threshold 1

# Set expiration and sign
./tufcli root expire --path examples/root.json --time "in 1 year"
./tufcli root sign --path examples/root.json --key examples/key.pem
```
