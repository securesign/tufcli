//go:build piv

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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
	"github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

func buildTUFKey(pub crypto.PublicKey) (*tufmeta.Key, string, error) {
	tufKey, err := tufmeta.KeyFromPublicKey(pub)
	if err != nil {
		return nil, "", fmt.Errorf("failed to convert public key to TUF key: %w", err)
	}

	keyID, err := finalizeTufKey(tufKey)
	if err != nil {
		return nil, "", err
	}

	return tufKey, keyID, nil
}

// PIVClient abstracts piv-go operations for testability.
type PIVClient interface {
	Certificate(slot piv.Slot) (*x509.Certificate, error)
	PrivateKey(slot piv.Slot, pub crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error)
	Close() error
}

type yubiKeyClient struct {
	yk *piv.YubiKey
}

func (c *yubiKeyClient) Certificate(slot piv.Slot) (*x509.Certificate, error) {
	return c.yk.Certificate(slot)
}

func (c *yubiKeyClient) PrivateKey(slot piv.Slot, pub crypto.PublicKey, auth piv.KeyAuth) (crypto.PrivateKey, error) {
	return c.yk.PrivateKey(slot, pub, auth)
}

func (c *yubiKeyClient) Close() error {
	return c.yk.Close()
}

// openYubiKey finds and opens a connected YubiKey. Package-level var for test injection.
var openYubiKey = defaultOpenYubiKey

func defaultOpenYubiKey() (PIVClient, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("failed to list smart cards: %w", err)
	}
	if len(cards) == 0 {
		return nil, fmt.Errorf("no YubiKey detected")
	}

	var cardName string
	for _, c := range cards {
		if strings.Contains(strings.ToLower(c), "yubi") {
			cardName = c
			break
		}
	}
	if cardName == "" {
		return nil, fmt.Errorf("no YubiKey detected among %d smart card(s)", len(cards))
	}

	yk, err := piv.Open(cardName)
	if err != nil {
		return nil, fmt.Errorf("failed to open YubiKey %q: %w", cardName, err)
	}
	return &yubiKeyClient{yk: yk}, nil
}

// PIVSigner implements signature.Signer by delegating crypto to a YubiKey PIV slot.
type PIVSigner struct {
	client  PIVClient
	slot    piv.Slot
	pub     crypto.PublicKey
	privKey crypto.Signer
}

func (s *PIVSigner) Close() error {
	return s.client.Close()
}

func (s *PIVSigner) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return s.pub, nil
}

func (s *PIVSigner) SignMessage(message io.Reader, _ ...signature.SignOption) ([]byte, error) {
	msgBytes, err := io.ReadAll(message)
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}

	switch s.pub.(type) {
	case ed25519.PublicKey:
		return s.privKey.Sign(rand.Reader, msgBytes, crypto.Hash(0))
	case *rsa.PublicKey:
		h := crypto.SHA256.New()
		h.Write(msgBytes)
		return s.privKey.Sign(rand.Reader, h.Sum(nil), &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash})
	default:
		h := crypto.SHA256.New()
		h.Write(msgBytes)
		return s.privKey.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
	}
}

var slotMap = map[string]piv.Slot{
	"9a": piv.SlotAuthentication,
	"9c": piv.SlotSignature,
	"9d": piv.SlotKeyManagement,
	"9e": piv.SlotCardAuthentication,
}

func parseYubiKeySlot(uri string) (piv.Slot, error) {
	trimmed := strings.TrimPrefix(uri, "yubikey:")
	trimmed = strings.TrimPrefix(trimmed, "//")
	trimmed = strings.TrimPrefix(trimmed, "/")
	trimmed = strings.TrimSuffix(trimmed, "/")

	if trimmed == "" {
		return piv.SlotSignature, nil
	}

	path := strings.TrimPrefix(trimmed, "slot/")
	if path == trimmed {
		return piv.Slot{}, fmt.Errorf("invalid YubiKey URI %q: expected yubikey://slot/<id>", uri)
	}

	slot, ok := slotMap[strings.ToLower(path)]
	if !ok {
		return piv.Slot{}, fmt.Errorf("unknown PIV slot %q: must be one of 9a, 9c, 9d, 9e", path)
	}
	return slot, nil
}

// loadPIVSigner opens a YubiKey, reads the certificate and private key handle
// from the given slot, and returns a signature.Signer along with the TUF key and key ID.
// PIN is read from the PIV_PIN environment variable.
func loadPIVSigner(uri string) (signature.Signer, *tufmeta.Key, string, error) {
	slot, err := parseYubiKeySlot(uri)
	if err != nil {
		return nil, nil, "", err
	}

	client, err := openYubiKey()
	if err != nil {
		return nil, nil, "", err
	}

	cert, err := client.Certificate(slot)
	if err != nil {
		client.Close()
		return nil, nil, "", fmt.Errorf("failed to get certificate from slot %x: %w", slot.Key, err)
	}

	pin := os.Getenv("PIV_PIN")
	if pin == "" {
		client.Close()
		return nil, nil, "", fmt.Errorf("PIV_PIN environment variable is required for YubiKey signing")
	}

	privKey, err := client.PrivateKey(slot, cert.PublicKey, piv.KeyAuth{PIN: pin})
	if err != nil {
		client.Close()
		return nil, nil, "", fmt.Errorf("failed to get private key from slot %x: %w", slot.Key, err)
	}

	cryptoSigner, ok := privKey.(crypto.Signer)
	if !ok {
		client.Close()
		return nil, nil, "", fmt.Errorf("private key from slot %x does not implement crypto.Signer", slot.Key)
	}

	signer := &PIVSigner{
		client:  client,
		slot:    slot,
		pub:     cert.PublicKey,
		privKey: cryptoSigner,
	}

	tufKey, keyID, err := buildTUFKey(cert.PublicKey)
	if err != nil {
		client.Close()
		return nil, nil, "", err
	}

	return signer, tufKey, keyID, nil
}

// parsePIVPublicKey extracts the public key from a YubiKey slot certificate
// and returns the TUF key and key ID. No PIN is required.
func parsePIVPublicKey(uri string) (*tufmeta.Key, string, error) {
	slot, err := parseYubiKeySlot(uri)
	if err != nil {
		return nil, "", err
	}

	client, err := openYubiKey()
	if err != nil {
		return nil, "", err
	}
	defer client.Close()

	cert, err := client.Certificate(slot)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get certificate from slot %x: %w", slot.Key, err)
	}

	return buildTUFKey(cert.PublicKey)
}
