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
	"fmt"
	"os"

	"golang.org/x/term"
)

// PassphraseFunc returns the passphrase for the given key file path.
// It is called only when an encrypted private key is encountered.
type PassphraseFunc func(keyPath string) ([]byte, error)

// NewPassphraseFunc returns a PassphraseFunc that resolves passphrases by
// checking indexed environment variables (TUF_KEY_PASSPHRASE_0, etc.),
// then the global TUF_KEY_PASSPHRASE fallback, then prompting interactively.
// keyPaths is the ordered list of --key flag values used to determine the index.
func NewPassphraseFunc(keyPaths []string) PassphraseFunc {
	pathIndex := make(map[string]int, len(keyPaths))
	for i, p := range keyPaths {
		if _, exists := pathIndex[p]; !exists {
			pathIndex[p] = i
		}
	}
	return func(keyPath string) ([]byte, error) {
		if idx, ok := pathIndex[keyPath]; ok {
			if v := os.Getenv(fmt.Sprintf("TUF_KEY_PASSPHRASE_%d", idx)); v != "" {
				return []byte(v), nil
			}
		}
		if v := os.Getenv("TUF_KEY_PASSPHRASE"); v != "" {
			return []byte(v), nil
		}

		fd := int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			idx, ok := pathIndex[keyPath]
			if ok {
				return nil, fmt.Errorf("key %q is encrypted but no passphrase provided (set TUF_KEY_PASSPHRASE or TUF_KEY_PASSPHRASE_%d)", keyPath, idx)
			}
			return nil, fmt.Errorf("key %q is encrypted but no passphrase provided (set TUF_KEY_PASSPHRASE)", keyPath)
		}

		fmt.Fprintf(os.Stderr, "Enter passphrase for key %q: ", keyPath)
		pass, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("failed to read passphrase: %w", err)
		}
		return pass, nil
	}
}

// PromptNewPassphrase prompts the user to enter and confirm a new passphrase
// for encrypting a generated key. Returns an error if stdin is not a terminal
// and TUF_KEYGEN_PASSPHRASE is not set.
func PromptNewPassphrase() ([]byte, error) {
	if v := os.Getenv("TUF_KEYGEN_PASSPHRASE"); v != "" {
		return []byte(v), nil
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, fmt.Errorf("--encrypt-key requires a passphrase but stdin is not a terminal (set TUF_KEYGEN_PASSPHRASE)")
	}

	fmt.Fprint(os.Stderr, "Enter passphrase for new key: ")
	pass, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase: %w", err)
	}
	if len(pass) == 0 {
		return nil, fmt.Errorf("passphrase must not be empty")
	}

	fmt.Fprint(os.Stderr, "Confirm passphrase: ")
	confirm, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("failed to read passphrase confirmation: %w", err)
	}

	if string(pass) != string(confirm) {
		return nil, fmt.Errorf("passphrases do not match")
	}

	return pass, nil
}
