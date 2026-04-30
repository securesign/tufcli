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

package schema

import (
	"time"
)

// RoleType represents the type of role in TUF
type RoleType string

const (
	RoleTypeRoot      RoleType = "root"
	RoleTypeSnapshot  RoleType = "snapshot"
	RoleTypeTargets   RoleType = "targets"
	RoleTypeTimestamp RoleType = "timestamp"
)

// Key represents a TUF public key.
// Fields are ordered alphabetically by JSON tag to produce correct canonical JSON for signing.
type Key struct {
	KeyIDHashAlgs []string               `json:"keyid_hash_algorithms,omitempty"`
	KeyType       string                 `json:"keytype"`
	KeyVal        map[string]interface{} `json:"keyval"`
	Scheme        string                 `json:"scheme"`
}

// RoleKeys represents the keys and threshold for a role
type RoleKeys struct {
	KeyIDs    []string `json:"keyids"`
	Threshold uint64   `json:"threshold"`
}

// Root represents the root metadata.
// Fields are ordered alphabetically by JSON tag to produce correct canonical JSON for signing.
type Root struct {
	Type               string                `json:"_type"`
	ConsistentSnapshot bool                  `json:"consistent_snapshot"`
	Expires            time.Time             `json:"expires"`
	Keys               map[string]Key        `json:"keys"`
	Roles              map[RoleType]RoleKeys `json:"roles"`
	SpecVersion        string                `json:"spec_version"`
	Version            uint64                `json:"version"`
}

// Signature represents a signature on a metadata file
type Signature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// Signed wraps a metadata object with signatures
type Signed struct {
	Signed     Root        `json:"signed"`
	Signatures []Signature `json:"signatures"`
}
