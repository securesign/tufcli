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
- `download` - Download a TUF repository's targets (see [below](#download))

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

### RHTAS (Red Hat Trusted Artifact Signer)

- `rhtas` - Manage RHTAS TUF repositories with Sigstore-specific targets

  Handles Fulcio, CTLog, Rekor, and TSA targets, and generates the associated `trusted_root.json` and `signing_config.v0.2.json` metadata bundles.

  **Required flags:** `--root` (`-r`), `--key` (`-k`), `--outdir` (`-o`)

  | Flag | Description |
  | --- | --- |
  | `--set-fulcio-target` | Add Fulcio certificate chain (with `--fulcio-uri`, `--fulcio-status`, `--oidc-uri`) |
  | `--set-ctlog-target` | Add CTLog public key (with `--ctlog-uri`, `--ctlog-status`) |
  | `--set-rekor-target` | Add Rekor public key (with `--rekor-uri`, `--rekor-status`) |
  | `--set-tsa-target` | Add TSA certificate chain (with `--tsa-uri`, `--tsa-status`) |
  | `--delete-fulcio-target` | Remove a Fulcio target (repeatable) |
  | `--delete-ctlog-target` | Remove a CTLog target (repeatable) |
  | `--delete-rekor-target` | Remove a Rekor target (repeatable) |
  | `--delete-tsa-target` | Remove a TSA target (repeatable) |
  | `--force-version` | Enable explicit version overrides |
  | `--targets-version` | Set targets.json version (requires `--force-version`) |
  | `--snapshot-version` | Set snapshot.json version (requires `--force-version`) |
  | `--timestamp-version` | Set timestamp.json version (requires `--force-version`) |
  | `--targets-expires` | Set targets metadata expiration |
  | `--snapshot-expires` | Set snapshot metadata expiration |
  | `--timestamp-expires` | Set timestamp metadata expiration |
  | `--operator` | Operator name for signing config (default: `sigstore.dev`) |
  | `--metadata-url` (`-m`) | Base URL of existing TUF repo to load metadata from (`file://` or `https://`) |
  | `--allow-expired-repo` | Allow loading expired metadata (unsafe, for testing) |
  | `--follow` (`-f`) | Follow symbolic links when copying target files |
  | `--target-path-exists` | Behavior when target exists: `skip` (default), `replace`, or `fail` |
  | `--incoming-metadata` (`-i`) | Path or URL to incoming delegated targets metadata |
  | `--role` | Delegated role name (requires `--incoming-metadata`) |

  See [RHTAS.md](RHTAS.md) for full documentation.

### Advanced Operations

- `transfer-metadata` - Transfer metadata from a previous root to a new root

### Download

Download targets from a TUF repository after verifying metadata integrity through the full TUF client workflow (root rotation, timestamp, snapshot, and targets verification).

The output directory must not already exist.

**Required flags:** `--metadata-url` (`-m`), `--targets-url` (`-t`)

| Flag | Description |
| --- | --- |
| `--root` (`-r`) | Path to root.json file for the repository |
| `--metadata-url` (`-m`) | TUF repository metadata base URL (required) |
| `--targets-url` (`-t`) | TUF repository targets base URL (required) |
| `--target-name` (`-n`) | Download only these targets (repeatable) |
| `--root-version` (`-v`) | Remote root.json version number (default: `1`) |
| `--allow-expired-repo` | Allow download for expired metadata (unsafe, for testing only) |
| `--allow-root-download` | Allow downloading root.json from the repository (unsafe) |

```bash
# Download all targets
./tufcli download /tmp/outdir \
  -r root.json \
  -m https://tuf.example.com/metadata \
  -t https://tuf.example.com/targets

# Download specific targets
./tufcli download /tmp/outdir \
  -r root.json \
  -m https://tuf.example.com/metadata \
  -t https://tuf.example.com/targets \
  -n trusted_root.json -n signing_config.v0.2.json

# Download without a local root (unsafe, for testing)
./tufcli download /tmp/outdir \
  -m https://tuf.example.com/metadata \
  -t https://tuf.example.com/targets \
  --allow-root-download

# Download with expired metadata (unsafe, for testing)
./tufcli download /tmp/outdir \
  -r root.json \
  -m https://tuf.example.com/metadata \
  -t https://tuf.example.com/targets \
  --allow-expired-repo
```

## Development Status

Root metadata commands are complete and tested. RHTAS commands are complete and tested. Download command is complete and tested. Repository commands (create, update) are in progress.

## TUF Specification

This implementation targets TUF specification version 1.0.0.

## License

MIT OR Apache-2.0

## Original Implementation

This is a Go port of the original Rust implementation available at: <https://github.com/awslabs/tough>

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

### Setting up an RHTAS repository

```bash
# Initialize and sign root.json first (see quick start above), then:

# Add a Fulcio certificate authority
./tufcli rhtas \
  -r root.json -k key.pem -o repo/ \
  --set-fulcio-target fulcio-chain.pem \
  --fulcio-uri https://fulcio.example.com \
  --oidc-uri https://oidc.example.com \
  --operator example.com

# Add a Rekor transparency log
./tufcli rhtas \
  -r root.json -k key.pem -o repo/ \
  --set-rekor-target rekor.pub \
  --rekor-uri https://rekor.example.com

# Add a CTLog
./tufcli rhtas \
  -r root.json -k key.pem -o repo/ \
  --set-ctlog-target ctlog.pub \
  --ctlog-uri https://ctlog.example.com

# Add a TSA
./tufcli rhtas \
  -r root.json -k key.pem -o repo/ \
  --set-tsa-target tsa-chain.pem \
  --tsa-uri https://tsa.example.com

# Delete a target
./tufcli rhtas \
  -r root.json -k key.pem -o repo/ \
  --delete-fulcio-target fulcio-chain.pem

# Custom expiration and version
./tufcli rhtas \
  -r root.json -k key.pem -o repo/ \
  --set-fulcio-target fulcio-chain.pem \
  --targets-expires "in 365 days" \
  --snapshot-expires "in 90 days" \
  --timestamp-expires "in 1 day"
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
