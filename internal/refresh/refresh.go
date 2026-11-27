/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package refresh

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/securesign/tufcli/internal/editor"
	"github.com/securesign/tufcli/internal/keys"
	"github.com/securesign/tufcli/internal/lock"
)

const (
	APIVersion      = "rhtas.tufcli/v1"
	ResultRefreshed = "Refreshed"
	ResultNotDue    = "NotDue"
	ResultFailed    = "Failed"

	// DefaultExpirationPolicy is used to recover expired dependent roles
	// when their own policy is not supplied.
	DefaultExpirationPolicy = 52 * 7 * 24 * time.Hour
)

var ErrInvalidOptions = errors.New("invalid refresh options")

// Options configures a refresh of an existing local repository.
type Options struct {
	Role             string
	RootPath         string
	OutDir           string
	ExpirationPolicy time.Duration
	RefreshInterval  time.Duration
	SnapshotPolicy   time.Duration
	TimestampPolicy  time.Duration
	AllowExpiredRepo bool
	KeyPaths         []string
	VaultKeyRefs     []string
	GetPassphrase    keys.PassphraseFunc
	Output           io.Writer
}

// RoleResult describes the version and expiry of metadata checked or signed.
type RoleResult struct {
	Version int64     `json:"version"`
	Expires time.Time `json:"expires"`
}

// Result is emitted as JSON for the refresh Job to consume.
type Result struct {
	APIVersion   string      `json:"apiVersion"`
	Result       string      `json:"result"`
	Role         string      `json:"role,omitempty"`
	Targets      *RoleResult `json:"targets,omitempty"`
	Snapshot     *RoleResult `json:"snapshot,omitempty"`
	Timestamp    *RoleResult `json:"timestamp,omitempty"`
	ExpiredRoles []string    `json:"expiredRoles,omitempty"`
	Error        *Error      `json:"error,omitempty"`
}

type Error struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
	Role    string `json:"role,omitempty"`
}

// Failure maps an error to the result understood by the refresh Job.
func Failure(role string, err error) Result {
	failure := &Error{Reason: "Failed", Message: err.Error()}
	var signerErr *keys.RoleSignerError
	switch {
	case errors.Is(err, ErrInvalidOptions):
		failure.Reason = "InvalidOptions"
	case errors.As(err, &signerErr):
		failure.Reason = "SignerNotAuthorized"
		failure.Role = signerErr.Role
	case errors.Is(err, editor.ErrNotConsistentSnapshot):
		failure.Reason = "NotConsistentSnapshot"
	case errors.Is(err, editor.ErrInconsistentRepository):
		failure.Reason = "InconsistentRepository"
	case errors.Is(err, editor.ErrLiveTimestampChanged):
		failure.Reason = "ConcurrentUpdate"
	case errors.Is(err, editor.ErrRollback):
		failure.Reason = "Rollback"
	case errors.Is(err, editor.ErrExpiredRepository):
		failure.Reason = "ExpiredRepository"
	}
	return Result{APIVersion: APIVersion, Result: ResultFailed, Role: role, Error: failure}
}

// Run checks the role's refresh policy under the repository lock and, if due,
// signs and publishes the role and its dependents.
func Run(opts Options) (Result, error) {
	if err := opts.validate(); err != nil {
		return Result{}, err
	}
	repoLock, err := lock.Acquire(opts.OutDir)
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = repoLock.Release() }()

	ed, err := editor.LoadLiveRepository(opts.RootPath, opts.OutDir, opts.Output)
	if err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	if err := ed.CheckExpiration(opts.AllowExpiredRepo); err != nil {
		return Result{}, err
	}

	targets, snapshot, timestamp := &ed.Targets().Signed, &ed.Snapshot().Signed, &ed.Timestamp().Signed
	states := map[string]RoleResult{
		"targets":   roleResult(targets.Version, targets.Expires),
		"snapshot":  roleResult(snapshot.Version, snapshot.Expires),
		"timestamp": roleResult(timestamp.Version, timestamp.Expires),
	}
	current := states[opts.Role]
	result := Result{APIVersion: APIVersion, Result: ResultNotDue, Role: opts.Role}
	if !due(current.Expires, now, opts.ExpirationPolicy, opts.RefreshInterval) {
		result.setRole(opts.Role, current)
		result.ExpiredRoles = expiredRoles(ed, now)
		return result, nil
	}

	if opts.Role == "targets" {
		targets.Version++
		targets.Expires = now.Add(opts.ExpirationPolicy)
		result.Targets = new(roleResult(targets.Version, targets.Expires))
	}
	if opts.Role != "timestamp" {
		snapshot.Version++
		snapshot.Expires = refreshedExpiry(snapshot.Expires, now, opts.Role == "snapshot", opts.ExpirationPolicy, opts.SnapshotPolicy)
		result.Snapshot = new(roleResult(snapshot.Version, snapshot.Expires))
	}
	timestamp.Version++
	timestamp.Expires = refreshedExpiry(timestamp.Expires, now, opts.Role == "timestamp", opts.ExpirationPolicy, opts.TimestampPolicy)
	result.Timestamp = new(roleResult(timestamp.Version, timestamp.Expires))

	if err := ed.SignAndWriteRefresh(opts.Role, opts.KeyPaths, opts.VaultKeyRefs, opts.GetPassphrase); err != nil {
		return Result{}, err
	}
	result.Result = ResultRefreshed
	result.ExpiredRoles = expiredRoles(ed, time.Now())
	return result, nil
}

func expiredRoles(ed *editor.Editor, now time.Time) []string {
	var expired []string
	for _, role := range []struct {
		name    string
		expires time.Time
	}{
		{"targets", ed.Targets().Signed.Expires},
		{"snapshot", ed.Snapshot().Signed.Expires},
		{"timestamp", ed.Timestamp().Signed.Expires},
	} {
		if !role.expires.After(now) {
			expired = append(expired, role.name)
		}
	}
	return expired
}

func (opts Options) validate() error {
	switch opts.Role {
	case "targets", "snapshot", "timestamp":
	default:
		return fmt.Errorf("%w: --role must be targets, snapshot or timestamp", ErrInvalidOptions)
	}
	if opts.RootPath == "" || opts.OutDir == "" {
		return fmt.Errorf("%w: --root and --outdir are required", ErrInvalidOptions)
	}
	if opts.RefreshInterval <= 0 || opts.ExpirationPolicy <= opts.RefreshInterval {
		return fmt.Errorf("%w: --expiration-policy must be greater than a positive --refresh-interval", ErrInvalidOptions)
	}
	if opts.SnapshotPolicy < 0 || opts.TimestampPolicy < 0 {
		return fmt.Errorf("%w: dependent expiration policies must be positive", ErrInvalidOptions)
	}
	return nil
}

func due(expires, now time.Time, policy, interval time.Duration) bool {
	return expires.Before(now.Add(policy-interval)) || expires.After(now.Add(policy))
}

func refreshedExpiry(expires, now time.Time, selected bool, policy, dependentPolicy time.Duration) time.Time {
	if selected {
		return now.Add(policy)
	}
	if expires.After(now) {
		return expires
	}
	if dependentPolicy == 0 {
		dependentPolicy = DefaultExpirationPolicy
	}
	return now.Add(dependentPolicy)
}

func roleResult(version int64, expires time.Time) RoleResult {
	return RoleResult{Version: version, Expires: expires.UTC()}
}

func (r *Result) setRole(role string, state RoleResult) {
	switch role {
	case "targets":
		r.Targets = &state
	case "snapshot":
		r.Snapshot = &state
	case "timestamp":
		r.Timestamp = &state
	}
}
