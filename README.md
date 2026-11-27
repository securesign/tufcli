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
  - `gen-rsa-key` - Generate RSA keypair and add to roles (`--encrypt-key` to passphrase-protect the private key)
  - `sign` - Sign root.json with private keys (supports encrypted PKCS#8 keys)

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

### Repository Lock

`create`, `update` and `rhtas` take an exclusive lock on `<outdir>/.tufcli.lock` for the whole run, so concurrent
writers on one repository (for example from different pods on a shared volume) never overlap. The lock is advisory
and is released when the command ends or the process dies.

- `lock --repo <dir> -- <command> [args...]` - Run any command (for example a shell script) while holding the same lock; blocks until free and returns the command's exit code (128+N if killed by signal N). On Linux and macOS the command inherits the lock: it stays held until the command and anything it left running have exited (even if the wrapper is killed), and tufcli write commands started inside on the same repository reuse it instead of waiting. On Windows the lock is held until the command exits and such nested writers would wait, so do not nest there. SIGTERM and SIGINT are forwarded to the command once (on an interactive terminal Ctrl-C already reaches it, so only SIGTERM is forwarded).

Only commands that write a repository in place lock: `create`, `update` and `rhtas`. `root`, `signing-config` and `delegation` edit individual files, and `transfer-metadata`, `clone` and `download` require a new output directory, so none of them lock. A script that edits files inside a live repository (for example a `root` command followed by a copy) must run its whole sequence under `tufcli lock`.

### Publication

`create`, `update` and `rhtas` sign everything first and then publish in order: target files and versioned
metadata, then `root.json`, then `timestamp.json` last, each file by atomic rename. A client reading the
repository at any moment sees either the previous or the new version, never a mix, and a failed run leaves the
previous version in place. A `rhtas` run that changes nothing writes nothing; `update` always publishes a new
snapshot and timestamp. Repositories without consistent
snapshots are refused, as is publishing older metadata than the live repository (a lower timestamp, snapshot,
targets or root version). The file of a target removed with `--delete-*-target` stays for an hour after the
version that removed it, for clients that were still reading the previous version, and a later `rhtas` run
removes it. For the same reason, deleting a target with `--force-version` needs a `--targets-version` higher
than the published one.

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

- `rhtas apply` - Apply an RFC 6902 JSON Patch to the RHTAS targets of a repository

  For tools that manage the repository declaratively (for example an operator): instead of one command per change,
  the caller sends the difference between what is published and what it wants, as a JSON Patch over the document
  described below. tufcli rebuilds that document from the repository, applies the patch, and when the document
  changes writes the per-key targets, `trusted_root.json` and `signing_config.v0.2.json`, then signs targets,
  snapshot and timestamp once each with a new version, published in order under the repository lock. The patch is
  applied all or nothing: a rejected operation publishes nothing. A patch that is already applied publishes nothing
  and reports `NoChange`, so a failed run can simply be retried.

  **Required flags:** `--root` (`-r`), `--key` (`-k`) or `--vault-key`, `--outdir` (`-o`), `--input` (`-i`, a
  file or `-` for stdin). Optional: `--operator` (recorded on new entries, default `sigstore.dev`), `--hash-algo`,
  `--allow-expired-repo`. Expiry dates are kept; refreshing them is a separate operation.

  **Document** (version `rhtas.tufcli/v1`). Targets are keyed by component (`ctlog`, `fulcio`, `rekor`, `tsa`) and
  target name. Every field is always present:

  ```json
  {
    "apiVersion": "rhtas.tufcli/v1",
    "components": {
      "ctlog": {},
      "fulcio": {
        "fulcio.crt.pem": {
          "uri": "https://fulcio.example.com",
          "oidcIssuers": ["https://oidc.example.com"],
          "validFor": {"start": "2025-01-01T00:00:00Z", "end": null},
          "material": "-----BEGIN CERTIFICATE-----\n..."
        }
      },
      "rekor": {},
      "tsa": {}
    }
  }
  ```

  | Field | Meaning |
  | --- | --- |
  | `uri` | Service URL string (Fulcio and TSA URI, Rekor and CTlog base URL). Use `""` to clear it |
  | `oidcIssuers` | OIDC issuers published with a Fulcio target; `[]` for the other components |
  | `validFor.start`, `validFor.end` | Window during which the material is trusted (RFC 3339); `end: null` means open. Written to `trusted_root.json` exactly as given |
  | `material` | Certificate chain (Fulcio, TSA) or public key (Rekor, CTlog), as PEM or base64-encoded DER, inline: no files are read. Compared by its SHA-256 digest of the DER, so the encoding does not matter |

  The document is built from the targets whose `sigstore` custom metadata has a `usage` of `Fulcio`, `TSA`,
  `CTFE` or `Rekor`, each matched to its `trusted_root.json` entry by key material; other targets are left alone.
  Target names are unique across components and cannot contain `/`, `\` or `~`. Published per-key targets get
  `sigstore` custom metadata (`status` `Expired` once the window has ended when the change is published, `Active`
  otherwise), and Fulcio targets also record their issuers under `rhtas.oidcIssuers`. Targets a patch does not
  touch keep their metadata exactly as published. For Fulcio targets written before this command, the issuers are
  the OIDC services with the same operator and the same window as the Fulcio entry, or with the same start and no
  end when the Fulcio window was closed by a rotation; an issuer with an end of its own is independent of it.

  In the signing config, tufcli owns the Fulcio, OIDC, Rekor and TSA services at the URLs (and issuers) of the
  targets a patch adds, changes or removes: they are replaced by one service per target there whose window has not
  ended, with that window, so a removed or ended key leaves no open service behind. A regenerated service keeps the
  API version configured for its URL (for example Rekor v2 set with `tufcli signing-config add-url --api-version 2`):
  the one of the previous service with the same start, else of the one with the latest start (the higher version
  when starts are equal); a URL seen for the first time gets version 1. Services at other URLs are kept as they are
  (for example ones added with `tufcli signing-config`).

  **Patch.** The first operation must test the document version; only `test`, `add`, `replace` and `remove` are
  accepted, and `test`, `add` and `replace` need a `value` (`null` for an open window). `oidcIssuers` is replaced
  as a whole list: editing single elements (for example appending with `/-`) is refused, because it would do
  something else when a patch is retried. Other `test` operations are guards on the current repository; when one
  fails but the rest of the patch is already in place (a retry of a published patch), the result is `NoChange`,
  otherwise the patch is rejected. A patch made only of tests is an assertion and fails when one does not hold:

  ```json
  [
    {"op": "test", "path": "/apiVersion", "value": "rhtas.tufcli/v1"},
    {"op": "replace", "path": "/components/rekor/rekor.pub/validFor/end", "value": "2025-05-30T14:20:05Z"},
    {"op": "add", "path": "/components/rekor/rekor-20250530T140211Z.pub", "value": {
      "uri": "https://rekor.example.com", "oidcIssuers": [],
      "validFor": {"start": "2025-05-30T14:20:05Z", "end": null},
      "material": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"}}
  ]
  ```

  | Operation | Effect |
  | --- | --- |
  | `add` of a target | Creates it; if it exists with the same material, applies the other fields; rejected if it exists with other material |
  | `replace` | Updates a field or target (for example closes or reopens a window); fails if the path is missing |
  | `remove` of a target | Deletes it (no tombstone: the name can be used again later); a no-op if it is missing |

  New key material is never accepted under an existing target name, and a name cannot move to another component
  in the same patch: a key change is a new target plus an end on the old one's window. Names of other targets in the
  repository cannot be taken. Entries the patch does not touch are unchanged, and only the targets it touches have
  to pass validation, so an odd published entry never blocks a patch (including one that repairs it). The file of a
  removed target stays for the grace period described under Publication; any later `apply`, `NoChange` included,
  removes it after that.

  **Result.** One JSON line on stdout, also written to `/dev/termination-log` when that file exists (Kubernetes),
  and a non-zero exit status on failure. If the termination log cannot be written, tufcli warns on stderr
  and preserves the command's exit status.

  ```json
  {"apiVersion":"rhtas.tufcli/v1","result":"Applied","targets":{"version":4,"expires":"2026-05-30T14:20:05Z"},"snapshot":{"version":4,"expires":"..."},"timestamp":{"version":4,"expires":"..."}}
  {"apiVersion":"rhtas.tufcli/v1","result":"Failed","error":{"reason":"OperationRejected","message":"...","operation":2,"path":"/components/rekor/rekor.pub/material"}}
  ```

  `result` is `Applied`, `NoChange` (versions are the current ones) or `Failed`. `error.reason` is one of
  `InvalidPatch`, `UnsupportedVersion`, `OperationRejected` (with the zero-based `operation` index and its `path`),
  `SignerNotAuthorized` (with the `role`), `NotConsistentSnapshot`, `InconsistentRepository`, `ConcurrentUpdate`,
  `Rollback` or `Failed`.

### Create

Create a new TUF repository with signed metadata and target files.

**Required flags:** `--root` (`-r`), `--key` (`-k`) or `--vault-key`, `--outdir` (`-o`), `--add-targets` (`-t`)

| Flag | Description |
| --- | --- |
| `--root` (`-r`) | Path to root.json file for the repository |
| `--key` (`-k`) | Signing key: file path, or `yubikey://slot/<id>` URI (repeatable) |
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
| `--follow` (`-f`) | Follow symbolic links inside the target directory when adding targets |
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

#### Declarative RHTAS changes with `rhtas apply`

`rhtas apply` changes the RHTAS targets with a JSON Patch (see `rhtas apply` above). This example is standalone:
run it from the repository root after building `./tufcli`. It needs `openssl` and `jq`.

```bash
export WRK="${HOME}/examples/rhtas-apply"
mkdir -p "${WRK}/input"

# Keys of the RHTAS services: a Fulcio certificate, a CTlog key and a Rekor key
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout "${WRK}/input/fulcio.key" -out "${WRK}/input/fulcio.crt.pem" -days 365 -subj "/CN=fulcio"
openssl ecparam -genkey -name prime256v1 -noout -out "${WRK}/input/ctfe.key"
openssl ec -in "${WRK}/input/ctfe.key" -pubout -out "${WRK}/input/ctfe.pub"
openssl ecparam -genkey -name prime256v1 -noout -out "${WRK}/input/rekor.key"
openssl ec -in "${WRK}/input/rekor.key" -pubout -out "${WRK}/input/rekor.pub"

# Create the repository the way the RHTAS operator does (the script calls tufcli from PATH)
PATH="${PWD}:${PATH}" ./rhtas/tuf-repo-init.sh \
  --export-keys "file://${WRK}/keys" \
  --fulcio-cert "${WRK}/input/fulcio.crt.pem" --fulcio-uri https://fulcio.example.com \
  --oidc-uri https://oidc.example.com \
  --ctlog-key "${WRK}/input/ctfe.pub" --ctlog-uri https://ctfe.example.com \
  --rekor-key "${WRK}/input/rekor.pub" --rekor-uri https://rekor.example.com \
  "${WRK}/tuf-repo"
```

Rekor now signs with a new key. Declare the change: close the window of the current key (`rekor.pub`) and
publish the new key under a new target name. The key is carried in the patch itself:

```bash
openssl ecparam -genkey -name prime256v1 -noout -out "${WRK}/input/rekor-2.key"
openssl ec -in "${WRK}/input/rekor-2.key" -pubout -out "${WRK}/input/rekor-2.pub"

NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > "${WRK}/rotate-rekor.json" <<PATCH
[
  {"op": "test", "path": "/apiVersion", "value": "rhtas.tufcli/v1"},
  {"op": "replace", "path": "/components/rekor/rekor.pub/validFor/end", "value": "${NOW}"},
  {"op": "add", "path": "/components/rekor/rekor-2.pub", "value": {
    "uri": "https://rekor.example.com",
    "oidcIssuers": [],
    "validFor": {"start": "${NOW}", "end": null},
    "material": $(jq -Rs . < "${WRK}/input/rekor-2.pub")
  }}
]
PATCH

./tufcli rhtas apply \
  --root "${WRK}/tuf-repo/root.json" \
  --key "${WRK}/keys/targets.pem" --key "${WRK}/keys/snapshot.pem" --key "${WRK}/keys/timestamp.pem" \
  --outdir "${WRK}/tuf-repo" \
  --input "${WRK}/rotate-rekor.json"
# {"apiVersion":"rhtas.tufcli/v1","result":"Applied","targets":{"version":2,...},"snapshot":{"version":2,...},"timestamp":{"version":2,...}}
```

Running the same patch again publishes nothing, so a failed run can simply be retried:

```bash
./tufcli rhtas apply \
  --root "${WRK}/tuf-repo/root.json" \
  --key "${WRK}/keys/targets.pem" --key "${WRK}/keys/snapshot.pem" --key "${WRK}/keys/timestamp.pem" \
  --outdir "${WRK}/tuf-repo" \
  --input "${WRK}/rotate-rekor.json"
# {"apiVersion":"rhtas.tufcli/v1","result":"NoChange","targets":{"version":2,...},...}
```

Replace the OIDC issuers published with Fulcio (the list is always replaced as a whole):

```bash
cat > "${WRK}/fulcio-issuers.json" <<PATCH
[
  {"op": "test", "path": "/apiVersion", "value": "rhtas.tufcli/v1"},
  {"op": "replace", "path": "/components/fulcio/fulcio.crt.pem/oidcIssuers",
   "value": ["https://oidc.example.com", "https://keycloak.example.com"]}
]
PATCH

./tufcli rhtas apply \
  --root "${WRK}/tuf-repo/root.json" \
  --key "${WRK}/keys/targets.pem" --key "${WRK}/keys/snapshot.pem" --key "${WRK}/keys/timestamp.pem" \
  --outdir "${WRK}/tuf-repo" \
  --input "${WRK}/fulcio-issuers.json"
# {"apiVersion":"rhtas.tufcli/v1","result":"Applied","targets":{"version":3,...},...}
```

When no client needs the old Rekor key any more, remove it:

```bash
cat > "${WRK}/remove-old-rekor.json" <<PATCH
[
  {"op": "test", "path": "/apiVersion", "value": "rhtas.tufcli/v1"},
  {"op": "remove", "path": "/components/rekor/rekor.pub"}
]
PATCH

./tufcli rhtas apply \
  --root "${WRK}/tuf-repo/root.json" \
  --key "${WRK}/keys/targets.pem" --key "${WRK}/keys/snapshot.pem" --key "${WRK}/keys/timestamp.pem" \
  --outdir "${WRK}/tuf-repo" \
  --input "${WRK}/remove-old-rekor.json"
# {"apiVersion":"rhtas.tufcli/v1","result":"Applied","targets":{"version":4,...},...}
```

A patch that breaks a rule publishes nothing and exits with status 1. Here, an existing target would get other key
material (a key change must be a new target, as above):

```bash
cat > "${WRK}/bad-patch.json" <<PATCH
[
  {"op": "test", "path": "/apiVersion", "value": "rhtas.tufcli/v1"},
  {"op": "replace", "path": "/components/rekor/rekor-2.pub/material",
   "value": $(jq -Rs . < "${WRK}/input/ctfe.pub")}
]
PATCH

./tufcli rhtas apply \
  --root "${WRK}/tuf-repo/root.json" \
  --key "${WRK}/keys/targets.pem" --key "${WRK}/keys/snapshot.pem" --key "${WRK}/keys/timestamp.pem" \
  --outdir "${WRK}/tuf-repo" \
  --input "${WRK}/bad-patch.json"
# {"apiVersion":"rhtas.tufcli/v1","result":"Failed","error":{"reason":"OperationRejected","message":"...","operation":1,"path":"/components/rekor/rekor-2.pub/material"}}
```

Check what was published: the Rekor keys and their windows in the current `trusted_root.json`:

```bash
TARGETS=$(ls "${WRK}"/tuf-repo/*.targets.json | sort -V | tail -1)
HASH=$(jq -r '.signed.targets["trusted_root.json"].hashes.sha256' "${TARGETS}")
jq '.tlogs[] | {baseUrl, validFor: .publicKey.validFor}' "${WRK}/tuf-repo/targets/${HASH}.trusted_root.json"
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

### Signing with Encrypted Keys

tufcli supports password-protected private keys in encrypted PKCS#8 format (`ENCRYPTED PRIVATE KEY` PEM). This works across all signing commands (`root sign`, `create`, `update`, `transfer-metadata`, `rhtas`).

#### Generating an encrypted key

Use the `--encrypt-key` flag with `gen-rsa-key` to create a passphrase-protected private key:

```bash
./tufcli root gen-rsa-key --path "${ROOT}" --output "${WRK}/keys/root.pem" \
  --role root --bits 2048 --encrypt-key
# You will be prompted for a passphrase (no echo)
```

Set `TUF_KEYGEN_PASSPHRASE` to skip the interactive prompt (useful in CI):

```bash
export TUF_KEYGEN_PASSPHRASE="my-passphrase"
./tufcli root gen-rsa-key --path "${ROOT}" --output "${WRK}/keys/root.pem" \
  --role root --bits 2048 --encrypt-key
```

#### Passphrase resolution

When signing with an encrypted key, tufcli resolves the passphrase in this order:

1. **Per-key environment variable** `TUF_KEY_PASSPHRASE_<index>` -- positional index matching the order of `--key` flags (0-based)
2. **Global environment variable** `TUF_KEY_PASSPHRASE` -- used as fallback for all keys
3. **Interactive terminal prompt** -- secure prompt with no echo (requires a TTY)

There is no `--password` flag by design -- accepting passphrases as CLI arguments is a security anti-pattern (shell history, `/proc` exposure).

#### Example: CI with environment variables

```bash
# Two encrypted keys: root.pem (index 0) and targets.pem (index 1)
export TUF_KEY_PASSPHRASE_0="root-key-pass"
export TUF_KEY_PASSPHRASE_1="targets-key-pass"

./tufcli root sign --path "${ROOT}" \
  --key "${WRK}/keys/root.pem" \
  --key "${WRK}/keys/targets.pem"
```

Or use a single passphrase for all keys:

```bash
export TUF_KEY_PASSPHRASE="shared-pass"

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

#### Example: Interactive signing

When no environment variable is set and stdin is a terminal, tufcli prompts for each encrypted key's passphrase:

```bash
./tufcli root sign --path "${ROOT}" --key "${WRK}/keys/root.pem"
# Enter passphrase for keys/root.pem:
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

### Signing with YubiKey (PIV)

tufcli supports hardware-backed signing using [YubiKey PIV](https://developers.yubico.com/PIV/) smart card slots. Private keys never leave the YubiKey — signing operations are performed on-device. This requires building with the `piv` build tag and installing the PCSC smart card library.

#### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install libpcsclite-dev

# Fedora/RHEL
sudo dnf install pcsc-lite-devel
```

Build with PIV support:

```bash
go build -tags piv -o tufcli .
```

#### YubiKey URI format

Key references use the `yubikey://slot/<id>` format. Supported PIV slots:

| Slot | Hex | Typical use |
|---|---|---|
| Authentication | `9a` | General authentication |
| Signature | `9c` | Digital signatures (default if omitted) |
| Key Management | `9d` | Encryption / key agreement |
| Card Authentication | `9e` | Contactless authentication |

#### PIN resolution

The PIV PIN is read from the `PIV_PIN` environment variable. There is no `--pin` flag by design — accepting PINs as CLI arguments is a security anti-pattern.

```bash
export PIV_PIN="123456"
```

#### Adding a YubiKey public key to root.json

No PIN is required to read the public key from a YubiKey slot:

```bash
./tufcli root add-key --path "${ROOT}" \
  --key yubikey://slot/9c \
  --role root --role targets --role snapshot --role timestamp
```

#### Signing with a YubiKey

```bash
export PIV_PIN="123456"

# Sign root.json
./tufcli root sign --path "${ROOT}" --key yubikey://slot/9c

# Create a TUF repository
./tufcli create \
  --root "${ROOT}" \
  --key yubikey://slot/9c \
  --add-targets "${WRK}/input" \
  --targets-expires 'in 3 weeks' \
  --targets-version 1 \
  --snapshot-expires 'in 3 weeks' \
  --snapshot-version 1 \
  --timestamp-expires 'in 1 week' \
  --timestamp-version 1 \
  --outdir "${WRK}/tuf-repo"
```

#### Mixing YubiKey with file-based or Vault keys

```bash
# Offline root on YubiKey, online roles in Vault
./tufcli root add-key --path "${ROOT}" \
  --key yubikey://slot/9c --role root

./tufcli root add-key --path "${ROOT}" \
  --vault-key hashivault://tuf-online \
  --role targets --role snapshot --role timestamp

export PIV_PIN="123456"
./tufcli root sign --path "${ROOT}" --key yubikey://slot/9c

./tufcli create \
  --root "${ROOT}" \
  --key yubikey://slot/9c \
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
