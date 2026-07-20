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

### Create

Create a new TUF repository with signed metadata and target files.

**Required flags:** `--root` (`-r`), `--key` (`-k`), `--outdir` (`-o`), `--add-targets` (`-t`)

| Flag | Description |
| --- | --- |
| `--root` (`-r`) | Path to root.json file for the repository |
| `--key` (`-k`) | Key files to sign with (repeatable) |
| `--outdir` (`-o`) | Output directory for the repository |
| `--add-targets` (`-t`) | Directory of targets to add |
| `--targets-expires` | Expiration of targets.json (RFC 3339 or relative like `in 7 days`) |
| `--targets-version` | Version of targets.json |
| `--snapshot-expires` | Expiration of snapshot.json |
| `--snapshot-version` | Version of snapshot.json |
| `--timestamp-expires` | Expiration of timestamp.json |
| `--timestamp-version` | Version of timestamp.json |
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

## Development Status

Root metadata commands are complete and tested. RHTAS commands are complete and tested. Download command is complete and tested. Create command is complete and tested. Repository commands (clone, update), delegation commands, and transfer-metadata are not yet implemented.

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
