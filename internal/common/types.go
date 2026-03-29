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

package common

// TUFRepository represents a TUF repository configuration
type TUFRepository struct {
	MetadataURL string
	TargetsURL  string
	OutputDir   string
}

// SigningKey represents a signing key for TUF metadata
type SigningKey struct {
	KeyID     string
	KeyType   string
	PublicKey []byte
}

// Target represents a target file in the TUF repository
type Target struct {
	Name   string
	Length int64
	Hashes map[string]string
	Custom map[string]interface{}
}
