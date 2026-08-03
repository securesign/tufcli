# tufcli

[![Go Reference](https://pkg.go.dev/badge/github.com/securesign/tufcli.svg)](https://pkg.go.dev/github.com/securesign/tufcli)

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
- `transfer-metadata` - Transfer metadata from one root of trust to another

All metadata-writing commands (`create`, `update`, `transfer-metadata`, `rhtas`) accept `--hash-algo sha256|sha512` to select the hash algorithm used for target and metadata hashes (default: `sha256`). Use `sha512` when your TUF repository requires SHA-512 digests for consistent\_snapshot filenames and metadata references. Existing repositories using either algorithm are supported when loading via `--metadata-url`.

### Metadata Management

- `root` - Manipulate root.json metadata file
  - `init` - Initialize a new root.json file
  - `add-key` - Add a key to root.json
  - `remove-key` - Remove keys from roles
  - `expire` - Set the expiration date
  - `set-threshold` - Set signature threshold for a role
  - `bump-version` - Increment version number
  - `set-version` - Set specific version number
  - `gen-rsa-key` - Generate RSA keypair and add to roles
  - `sign` - Sign root.json with private keys

### Delegation Management

- `delegation` - Manage delegated roles (requires `--signing-role` flag)
  - `create-role` - Create a delegated role
  - `add-role` - Add delegated role
  - `add-key` - Add a key to a delegated role
  - `remove-key` - Remove a key from a delegated role
  - `remove` - Remove a role
  - `update-delegated-targets` - Update delegated targets

### Signing Config Management

- `signing-config` - Manage Sigstore signing configuration files (`signing_config.v0.2.json`)
  - `create` - Create a new signing config (empty, from `--base-config`, or `--with-default-services`)
  - `add-url` - Add a service URL (ca, oidc, rekor, tsa) with replace-or-append semantics
  - `remove-url` - Remove a service URL by exact match
  - `set-config` - Set service selection policy (ALL, ANY, EXACT) for rekor or tsa
  - `inspect` - Display signing config contents (text or JSON format)

### RHTAS (Red Hat Trusted Artifact Signer)

- `rhtas` - Manage RHTAS TUF repositories with Sigstore-specific targets

  Handles Fulcio, CTLog, Rekor, and TSA targets, and generates the associated `trusted_root.json` and `signing_config.v0.2.json` metadata bundles.

  **Required flags:** `--root` (`-r`), `--key` (`-k`) or `--vault-key`, `--outdir` (`-o`)

  | Flag | Description |
  | --- | --- |
  | `--vault-key` | Vault Transit key reference (`hashivault://keyname`, repeatable) |
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
  | `--hash-algo` | Hash algorithm for target and metadata hashes: `sha256` (default) or `sha512` |
  | `--incoming-metadata` (`-i`) | Path or URL to incoming delegated targets metadata |
  | `--role` | Delegated role name (requires `--incoming-metadata`) |

### Create

Create a new TUF repository with signed metadata and target files.

**Required flags:** `--root` (`-r`), `--key` (`-k`) or `--vault-key`, `--outdir` (`-o`), `--add-targets` (`-t`)

| Flag | Description |
| --- | --- |
| `--root` (`-r`) | Path to root.json file for the repository |
| `--key` (`-k`) | Key files to sign with (repeatable) |
| `--vault-key` | Vault Transit key reference (`hashivault://keyname`, repeatable) |
| `--outdir` (`-o`) | Output directory for the repository |
| `--add-targets` (`-t`) | Directory of targets to add |
| `--targets-expires` | Expiration of targets.json (RFC 3339 or relative like `in 7 days`) |
| `--targets-version` | Version of targets.json |
| `--snapshot-expires` | Expiration of snapshot.json |
| `--snapshot-version` | Version of snapshot.json |
| `--timestamp-expires` | Expiration of timestamp.json |
| `--timestamp-version` | Version of timestamp.json |
| `--hash-algo` | Hash algorithm for target and metadata hashes: `sha256` (default) or `sha512` |
| `--follow` (`-f`) | Follow symbolic links when adding targets |
| `--target-path-exists` | Behavior when target exists: `skip` (default), `replace`, or `fail` |

```bash
# Create a TUF repo with targets
./tufcli create \
  --root root.json \
  --key keys/root.pem \
  --key keys/snapshot.pem \
  --key keys/targets.pem \
  --key keys/timestamp.pem \
  --add-targets input/ \
  --targets-expires 'in 3 weeks' \
  --targets-version 1 \
  --snapshot-expires 'in 3 weeks' \
  --snapshot-version 1 \
  --timestamp-expires 'in 1 week' \
  --timestamp-version 1 \
  --outdir repo/

# Create with empty targets directory (metadata-only bootstrap)
./tufcli create \
  --root root.json \
  --key key.pem \
  --add-targets empty-dir/ \
  --targets-expires 'in 52 weeks' \
  --targets-version 1 \
  --snapshot-expires 'in 52 weeks' \
  --snapshot-version 1 \
  --timestamp-expires 'in 52 weeks' \
  --timestamp-version 1 \
  --outdir repo/
```

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

### Signing Config

Create and manage Sigstore signing configuration files standalone, without requiring a TUF repository. Output is byte-identical to `cosign signing-config create`.

```bash
# Create an empty signing config
./tufcli signing-config create -o signing_config.v0.2.json

# Add service endpoints
./tufcli signing-config add-url -c signing_config.v0.2.json \
  -t ca -u https://fulcio.example.com \
  --start-time 2025-01-01T00:00:00Z --operator example.com

./tufcli signing-config add-url -c signing_config.v0.2.json \
  -t rekor -u https://rekor.example.com \
  --start-time 2025-01-01T00:00:00Z --operator example.com

./tufcli signing-config add-url -c signing_config.v0.2.json \
  -t oidc -u https://oauth2.example.com \
  --start-time 2025-01-01T00:00:00Z --operator example.com

./tufcli signing-config add-url -c signing_config.v0.2.json \
  -t tsa -u https://tsa.example.com/api/v1/timestamp \
  --start-time 2025-01-01T00:00:00Z --operator example.com

# Set service selection policies
./tufcli signing-config set-config -c signing_config.v0.2.json -t rekor -s ANY
./tufcli signing-config set-config -c signing_config.v0.2.json -t tsa -s EXACT -n 1

# Inspect
./tufcli signing-config inspect -c signing_config.v0.2.json
./tufcli signing-config inspect -c signing_config.v0.2.json -f json

# Clone and modify a deployed config
./tufcli signing-config create -o modified.json --base-config deployed_config.json
./tufcli signing-config remove-url -c modified.json -t oidc -u https://old-provider.com

# Fetch public Sigstore defaults
./tufcli signing-config create -o defaults.json --with-default-services
```

## Development Status

Root metadata commands are complete and tested. RHTAS commands are complete and tested. Download command is complete and tested. Create command is complete and tested. Clone command is complete and tested. Update command is complete and tested. Transfer-metadata command is complete and tested. Signing config commands are complete and tested. Delegation commands are not yet implemented.

## Library Usage

tufcli can be used as a Go library. Every CLI command has a corresponding public API under `pkg/`.

### Install

```bash
go get github.com/securesign/tufcli
```

### Available packages

| Package | Import path | Description |
|---|---|---|
| **rootmeta** | `github.com/securesign/tufcli/pkg/rootmeta` | Root.json lifecycle: init, keys, thresholds, expiration, signing |
| **create** | `github.com/securesign/tufcli/pkg/repo/create` | Create new TUF repositories |
| **update** | `github.com/securesign/tufcli/pkg/repo/update` | Update existing repositories (targets, versions, expirations) |
| **clone** | `github.com/securesign/tufcli/pkg/repo/clone` | Clone remote TUF repositories |
| **download** | `github.com/securesign/tufcli/pkg/repo/download` | Download targets with full TUF verification |
| **transfer** | `github.com/securesign/tufcli/pkg/repo/transfer` | Transfer metadata between roots of trust |
| **rhtas** | `github.com/securesign/tufcli/pkg/rhtas` | RHTAS Sigstore target management (Fulcio, Rekor, TSA) |
| **signingconfig** | `github.com/securesign/tufcli/pkg/signingconfig` | Sigstore signing config management (cosign-compatible) |

### Example: Create a TUF repository

```go
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/securesign/tufcli/pkg/repo/create"
	"github.com/securesign/tufcli/pkg/rootmeta"
)

func main() {
	// 1. Initialize root.json
	rootmeta.Init(rootmeta.InitOptions{Path: "root.json"})
	rootmeta.Expire(rootmeta.ExpireOptions{Path: "root.json", Expires: time.Now().AddDate(1, 0, 0)})
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		rootmeta.SetThreshold(rootmeta.SetThresholdOptions{Path: "root.json", Role: role, Threshold: 1})
	}

	// 2. Generate a signing key
	keyID, _ := rootmeta.GenRsaKey(rootmeta.GenRsaKeyOptions{
		Path:    "root.json",
		KeyPath: "key.pem",
		Bits:    2048,
		Roles:   []string{"root", "snapshot", "targets", "timestamp"},
	})
	fmt.Printf("Generated key: %s\n", keyID)

	// 3. Sign root.json
	rootmeta.Sign(rootmeta.SignOptions{Path: "root.json", KeyPaths: []string{"key.pem"}})

	// 4. Create a repository with targets
	os.MkdirAll("targets-input", 0755)
	os.WriteFile("targets-input/artifact.txt", []byte("hello"), 0644)

	create.Create(&create.Options{
		RootPath:         "root.json",
		KeyPaths:         []string{"key.pem"},
		OutDir:           "my-repo",
		AddTargetsDir:    "targets-input",
		TargetsExpires:   time.Now().AddDate(0, 0, 21),
		TargetsVersion:   1,
		SnapshotExpires:  time.Now().AddDate(0, 0, 21),
		SnapshotVersion:  1,
		TimestampExpires: time.Now().AddDate(0, 0, 7),
		TimestampVersion: 1,
	})
	fmt.Println("Repository created at my-repo/")
}
```

### Example: Create a Sigstore signing config

```go
package main

import (
	"fmt"
	"time"

	"github.com/securesign/tufcli/pkg/signingconfig"
)

func main() {
	signingconfig.Create(signingconfig.CreateOptions{Output: "signing_config.v0.2.json"})

	signingconfig.AddURL(signingconfig.AddURLOptions{
		ConfigPath: "signing_config.v0.2.json",
		Type:       "ca",
		URL:        "https://fulcio.example.com",
		APIVersion: 1,
		Operator:   "example.com",
		StartTime:  time.Now(),
	})

	output, _ := signingconfig.Inspect(signingconfig.InspectOptions{
		ConfigPath: "signing_config.v0.2.json",
		Format:     "text",
	})
	fmt.Print(output)
}
```

### Suppressing output

The `clone`, `download`, and `transfer` commands accept an `Output io.Writer` field
for controlling progress messages. Library consumers can suppress output or redirect it:

```go
import (
	"bytes"
	"io"

	"github.com/securesign/tufcli/pkg/repo/clone"
)

// Silent mode — no progress output
clone.Clone(&clone.Options{Output: io.Discard, ...})

// Capture output into a buffer
var buf bytes.Buffer
clone.Clone(&clone.Options{Output: &buf, ...})

// Default (Output not set) — writes to os.Stderr, same as CLI
clone.Clone(&clone.Options{...})
```

## TUF Specification

This implementation targets TUF specification version 1.0.0.

## License

MIT OR Apache-2.0

## Original Implementation

This is a Go port of the original Rust implementation available at: <https://github.com/awslabs/tough>

## Examples

### Quick start (using gen-rsa-key shortcut)

The following is an example of how you can create and download a TUF repository using `tufcli`.

#### Create a root.json and signing Key

```bash
export WRK="${HOME}/examples"
mkdir -p "${WRK}"

# we will store our root.json in $WRK/root
mkdir "${WRK}/root"
# save the path to the root.json we are about to create, we will use it a lot
export ROOT="${WRK}/root/root.json"

# we will store our signing keys in $WRK/keys
mkdir "${WRK}/keys"

# instantiate a new root.json
./tufcli root init --path "${ROOT}"

# set the root file's expiration date
./tufcli root expire --path "${ROOT}" --time "in 1 year"

# set the signing threshold for each of the standard signing roles.Each of the following roles must have at least 1 valid signature
./tufcli root set-threshold --path "${ROOT}" --role root --threshold 1
./tufcli root set-threshold --path "${ROOT}" --role snapshot --threshold 1
./tufcli root set-threshold --path "${ROOT}" --role targets --threshold 1
./tufcli root set-threshold --path "${ROOT}" --role timestamp --threshold 1

# create an RSA key and store it as a file. this requires openssl on your system
# this command both creates the key and adds it to root.json for the root role
# for this example we will re-use the same key for the other standard roles
./tufcli root gen-rsa-key --path "${ROOT}" --output "${WRK}/keys/root.pem"  --role root --role snapshot --role targets --role timestamp --bits 2048

# sign root.json
./tufcli root sign --path "${ROOT}" --key "${WRK}/keys/root.pem" 
```

#### Create a new TUF Repo

Now that we have a root.json file, we can create and sign a TUF repository.

```bash
# create a directory to hold the targets that we will sign. we call this the
# 'input' directory because these are the targets that we want to put into
# our TUF repo
mkdir -p "${WRK}/input"

# create an empty TUF repo
./tufcli create \
  --root "${ROOT}" \
  --key "${WRK}/keys/root.pem" \
  --add-targets "${WRK}/input" \
  --targets-expires 'in 3 weeks' \
  --targets-version 1 \
  --snapshot-expires 'in 3 weeks' \
  --snapshot-version 1 \
  --timestamp-expires 'in 1 week' \
  --timestamp-version 1 \
  --outdir "${WRK}/tuf-repo"
```

#### Setting up an RHTAS repository

```bash
# Create Rekor public key
openssl ecparam -genkey -name prime256v1 -noout -out ${WRK}/input/rekor.pem
openssl ec -in ${WRK}/input/rekor.pem -pubout -out ${WRK}/input/rekor.pub
rm ${WRK}/input/rekor.pem

# Add a Rekor transparency log
./tufcli rhtas \
  --root "${ROOT}" \
  --key "${WRK}/keys/root.pem" \
  --outdir "${WRK}/tuf-repo" \
  --set-rekor-target "${WRK}/input/rekor.pub" \
  --rekor-uri https://rekor.sigstore.dev \
  --metadata-url file:///$WRK/tuf-repo/

# Delete a target
./tufcli rhtas \
   --root "${ROOT}" \
   --key "${WRK}/keys/root.pem" \
   --delete-fulcio-target "fulcio-chain.pem" \
   --outdir "${WRK}/tuf-repo" \
   --metadata-url file:///$WRK/tuf-repo/

# Custom expiration and version
./tufcli rhtas \
  -r root.json -k key.pem -o repo/ \
  --set-fulcio-target fulcio-chain.pem \
  --targets-expires "in 365 days" \
  --snapshot-expires "in 90 days" \
  --timestamp-expires "in 1 day"
```

#### Update TUF repo (update metadata expiration)

```bash
# Update metadata expiration dates
./tufcli update \
  --root "${ROOT}" \
  --key "${WRK}/keys/root.pem" \
  --targets-expires 'in 3 weeks' \
  --snapshot-expires 'in 3 weeks' \
  --timestamp-expires 'in 1 week' \
  --outdir "${WRK}/tuf-repo" \
  --metadata-url file:///$WRK/tuf-repo
```

#### Clone TUF Repo

Clone copies both metadata and targets into separate directories. Use
`--metadata-only` to skip target downloads.

```bash
# Clone metadata and targets
./tufcli clone \
  --root "${WRK}/tuf-repo/root.json" \
  --metadata-url "file://${WRK}/tuf-repo/" \
  --targets-url "file://${WRK}/tuf-repo/targets" \
  --metadata-dir "${WRK}/tuf-clone/metadata" \
  --targets-dir "${WRK}/tuf-clone/targets"

# Clone metadata only (no targets)
./tufcli clone \
  --root "${WRK}/tuf-repo/root.json" \
  --metadata-url "file://${WRK}/tuf-repo/" \
  --metadata-dir "${WRK}/tuf-clone-metadata" \
  --metadata-only
```

#### Transfer Metadata to a New Root

Transfer metadata from an existing repository to a new root of trust. This
copies all target entries (metadata only, not files) and signs under the new
root's keys.

```bash
# Create a new root for the transfer destination
export NEW_ROOT="${WRK}/new-root/root.json"
mkdir -p "${WRK}/new-root"
./tufcli root init --path "${NEW_ROOT}"
./tufcli root expire --path "${NEW_ROOT}" --time "in 1 year"
./tufcli root set-threshold --path "${NEW_ROOT}" --role root --threshold 1
./tufcli root set-threshold --path "${NEW_ROOT}" --role snapshot --threshold 1
./tufcli root set-threshold --path "${NEW_ROOT}" --role targets --threshold 1
./tufcli root set-threshold --path "${NEW_ROOT}" --role timestamp --threshold 1
./tufcli root gen-rsa-key --path "${NEW_ROOT}" --output "${WRK}/new-root/key.pem" \
  --role root --role snapshot --role targets --role timestamp --bits 2048
./tufcli root sign --path "${NEW_ROOT}" --key "${WRK}/new-root/key.pem"

# Transfer metadata from old repo to new root
./tufcli transfer-metadata \
  --current-root "${WRK}/tuf-repo/root.json" \
  --new-root "${NEW_ROOT}" \
  --key "${WRK}/new-root/key.pem" \
  --metadata-url "file://${WRK}/tuf-repo/" \
  --targets-url "file://${WRK}/tuf-repo/targets" \
  --targets-expires 'in 3 weeks' \
  --targets-version 1 \
  --snapshot-expires 'in 3 weeks' \
  --snapshot-version 1 \
  --timestamp-expires 'in 1 week' \
  --timestamp-version 1 \
  --outdir "${WRK}/transferred-repo"
```

#### Download TUF Repo
Now that we have created TUF repo, we can inspect it using download command. 
Download command is usually used to download a remote repo using HTTP/S url, but 
for this example we will use a file based url to download from local repo.

```sh
# download tuf repo
./tufcli download \
   --root "${WRK}/tuf-repo/root.json" \
   -t "file://${WRK}/tuf-repo/targets" \
   -m "file://${WRK}/tuf-repo/" \
   "${WRK}/tuf-download"
```

### Using existing keys

```bash
# Initialize root metadata
./tufcli root init --path "${ROOT}"

# Add existing key to all roles
./tufcli root add-key --path "${ROOT}" --key "${WRK}/keys/root.pem"  --role root --role snapshot --role targets --role timestamp

# Set thresholds
./tufcli root set-threshold --path "${ROOT}" --role root --threshold 1
./tufcli root set-threshold --path "${ROOT}" --role snapshot --threshold 1
./tufcli root set-threshold --path "${ROOT}" --role targets --threshold 1
./tufcli root set-threshold --path "${ROOT}" --role timestamp --threshold 1

# Set expiration and sign
./tufcli root expire --path "${ROOT}" --time "in 1 year"
./tufcli root sign --path "${ROOT}" --key "${WRK}/keys/root.pem" 
```

### Signing with HashiCorp Vault

tufcli supports online signing using keys stored in [HashiCorp Vault's Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit). Private keys never leave Vault — signing operations are performed remotely via the Vault API. This is the recommended setup for production TUF repositories where snapshot and timestamp keys should be managed by an online signing service.

Vault key references use the `hashivault://keyname` format. Connection parameters are read from standard Vault environment variables:

| Variable | Description | Default |
|---|---|---|
| `VAULT_ADDR` | Vault server address | *(required)* |
| `VAULT_TOKEN` | Authentication token | Falls back to token helper / `~/.vault-token` |
| `TRANSIT_SECRET_ENGINE_PATH` | Transit engine mount path | `transit` |

Supported key types: `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `ed25519`, `rsa-2048`, `rsa-3072`, `rsa-4096`.

#### Setting up Vault

```bash
# Start a dev Vault server (for testing only)
vault server -dev

# In another terminal, configure the Transit engine
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<dev-root-token>

vault secrets enable transit
vault write transit/keys/tuf-root type=ecdsa-p256
vault write transit/keys/tuf-online type=ecdsa-p256
```

#### Using Vault keys for all roles

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=<token>
export ROOT="${WRK}/root/root.json"

# Initialize root.json
./tufcli root init --path "${ROOT}"
./tufcli root expire --path "${ROOT}" --time "in 1 year"
./tufcli root set-threshold --path "${ROOT}" --role root --threshold 1
./tufcli root set-threshold --path "${ROOT}" --role snapshot --threshold 1
./tufcli root set-threshold --path "${ROOT}" --role targets --threshold 1
./tufcli root set-threshold --path "${ROOT}" --role timestamp --threshold 1

# Add Vault keys — the public key is fetched from Vault and registered in root.json
./tufcli root add-key --path "${ROOT}" \
  --vault-key hashivault://tuf-root \
  --role root

./tufcli root add-key --path "${ROOT}" \
  --vault-key hashivault://tuf-online \
  --role targets --role snapshot --role timestamp

# Sign root.json with the Vault key
./tufcli root sign --path "${ROOT}" --vault-key hashivault://tuf-root

# Create a TUF repository signed with Vault
./tufcli create \
  --root "${ROOT}" \
  --vault-key hashivault://tuf-online \
  --add-targets "${WRK}/input" \
  --targets-expires 'in 3 weeks' \
  --targets-version 1 \
  --snapshot-expires 'in 3 weeks' \
  --snapshot-version 1 \
  --timestamp-expires 'in 1 week' \
  --timestamp-version 1 \
  --outdir "${WRK}/tuf-repo"

# Update the repository with Vault signing
./tufcli update \
  --root "${ROOT}" \
  --vault-key hashivault://tuf-online \
  --targets-expires 'in 3 weeks' \
  --snapshot-expires 'in 3 weeks' \
  --timestamp-expires 'in 1 week' \
  --outdir "${WRK}/tuf-repo" \
  --metadata-url "file://${WRK}/tuf-repo/"
```

#### Mixing file-based and Vault keys

A common production pattern uses an offline file-based key for the root role and Vault-managed online keys for targets, snapshot, and timestamp:

```bash
# Add a local root key and Vault online keys
./tufcli root add-key --path "${ROOT}" \
  --key "${WRK}/keys/root.pem" --role root

./tufcli root add-key --path "${ROOT}" \
  --vault-key hashivault://tuf-online \
  --role targets --role snapshot --role timestamp

# Sign root with the local key
./tufcli root sign --path "${ROOT}" --key "${WRK}/keys/root.pem"

# Create a repo using both key types
./tufcli create \
  --root "${ROOT}" \
  --key "${WRK}/keys/root.pem" \
  --vault-key hashivault://tuf-online \
  --add-targets "${WRK}/input" \
  --targets-expires 'in 3 weeks' \
  --targets-version 1 \
  --snapshot-expires 'in 3 weeks' \
  --snapshot-version 1 \
  --timestamp-expires 'in 1 week' \
  --timestamp-version 1 \
  --outdir "${WRK}/tuf-repo"
```

#### Transfer metadata with Vault signing

```bash
./tufcli transfer-metadata \
  --current-root "${WRK}/tuf-repo/root.json" \
  --new-root "${NEW_ROOT}" \
  --vault-key hashivault://tuf-online \
  --metadata-url "file://${WRK}/tuf-repo/" \
  --targets-url "file://${WRK}/tuf-repo/targets" \
  --targets-expires 'in 3 weeks' \
  --targets-version 1 \
  --snapshot-expires 'in 3 weeks' \
  --snapshot-version 1 \
  --timestamp-expires 'in 1 week' \
  --timestamp-version 1 \
  --outdir "${WRK}/transferred-repo"
```

#### RHTAS with Vault signing

```bash
./tufcli rhtas \
  --root "${ROOT}" \
  --vault-key hashivault://tuf-online \
  --outdir "${WRK}/tuf-repo" \
  --set-rekor-target "${WRK}/input/rekor.pub" \
  --rekor-uri https://rekor.example.com \
  --metadata-url "file://${WRK}/tuf-repo/"
```
