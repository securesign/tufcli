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

package keys

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	vault "github.com/hashicorp/vault/api"
	config "github.com/hashicorp/vault/api/cliconfig"
	"github.com/mitchellh/go-homedir"
	"github.com/sigstore/sigstore/pkg/signature"
)

var vaultPrefixRegex = regexp.MustCompile(`^vault:v[0-9]+:`)

// vaultRSAPSSSigner wraps a Vault Transit signer to produce RSA-PSS signatures.
// The upstream sigstore hashivault library hardcodes signature_algorithm=pkcs1v15
// for all Transit sign calls, but TUF requires rsassa-pss-sha256 for RSA keys.
type vaultRSAPSSSigner struct {
	inner   signature.Signer
	client  *vault.Client
	keyPath string
	transit string
}

// newVaultRSAPSSSigner creates a wrapper that signs via Vault Transit with PSS.
var newVaultRSAPSSSigner = func(inner signature.Signer, ref string) (signature.Signer, error) {
	keyPath, err := parseVaultRef(ref)
	if err != nil {
		return nil, err
	}

	cfg := vault.DefaultConfig()
	if os.Getenv("VAULT_ADDR") == "" {
		if baoAddr := os.Getenv("BAO_ADDR"); baoAddr != "" {
			cfg.Address = baoAddr
		}
	}

	client, err := vault.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	token, err := resolveVaultToken()
	if err != nil {
		return nil, err
	}
	client.SetToken(token)

	transit := os.Getenv("TRANSIT_SECRET_ENGINE_PATH")
	if transit == "" {
		transit = "transit"
	}

	return &vaultRSAPSSSigner{
		inner:   inner,
		client:  client,
		keyPath: keyPath,
		transit: transit,
	}, nil
}

func (s *vaultRSAPSSSigner) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return s.inner.PublicKey(opts...)
}

func (s *vaultRSAPSSSigner) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	var digest []byte
	for _, opt := range opts {
		opt.ApplyDigest(&digest)
	}
	if digest == nil {
		h := crypto.SHA256.New()
		if _, err := io.Copy(h, message); err != nil {
			return nil, fmt.Errorf("failed to compute digest: %w", err)
		}
		digest = h.Sum(nil)
	}

	result, err := s.client.Logical().Write(
		fmt.Sprintf("/%s/sign/%s/sha2-256", s.transit, s.keyPath),
		map[string]any{
			"input":               base64.StdEncoding.EncodeToString(digest),
			"prehashed":           true,
			"signature_algorithm": "pss",
			"salt_length":         "hash",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("transit: failed to sign with RSA-PSS: %w", err)
	}
	if result == nil || result.Data == nil {
		return nil, fmt.Errorf("transit: sign response is empty")
	}

	sig, ok := result.Data["signature"]
	if !ok {
		return nil, fmt.Errorf("transit: response missing signature field")
	}

	encoded, ok := sig.(string)
	if !ok {
		return nil, fmt.Errorf("transit: signature is not a string")
	}

	return base64.StdEncoding.DecodeString(vaultPrefixRegex.ReplaceAllString(encoded, ""))
}

// resolveVaultToken mirrors the token resolution chain used by the upstream
// sigstore hashivault library: env vars → token helper → ~/.vault-token file.
func resolveVaultToken() (string, error) {
	if token := os.Getenv("VAULT_TOKEN"); token != "" {
		return token, nil
	}
	if token := os.Getenv("BAO_TOKEN"); token != "" {
		return token, nil
	}

	if helper, err := config.DefaultTokenHelper(); err == nil {
		if token, err := helper.Get(); err == nil && token != "" {
			return token, nil
		}
	}

	if homeDir, err := homedir.Dir(); err == nil {
		if tokenBytes, err := os.ReadFile(filepath.Join(homeDir, ".vault-token")); err == nil {
			if token := string(tokenBytes); token != "" {
				return token, nil
			}
		}
	}

	return "", fmt.Errorf("no Vault token found in env, helper, or ~/.vault-token")
}

func parseVaultRef(ref string) (string, error) {
	re := regexp.MustCompile(`^(?:hashivault|openbao)://(\w(?:[\w.\-]*\w)?)$`)
	m := re.FindStringSubmatch(ref)
	if len(m) < 2 {
		return "", fmt.Errorf("invalid vault reference: %s", ref)
	}
	return m[1], nil
}
