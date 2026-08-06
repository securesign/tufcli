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
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 required for PKCS#8 interoperability (default PRF per RFC 8018)
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"hash"
)

// OIDs for PBES2 encrypted PKCS#8.
var (
	oidPBES2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}

	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	oidHMACWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
)

// ASN.1 structures for EncryptedPrivateKeyInfo (RFC 5958).
type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm algorithmIdentifier
	EncryptedData       []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pbes2Params struct {
	KeyDerivationFunc algorithmIdentifier
	EncryptionScheme  algorithmIdentifier
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	KeyLength      int                 `asn1:"optional"`
	PRF            algorithmIdentifier `asn1:"optional"`
}

func decryptPKCS8(der, password []byte) (interface{}, error) {
	var info encryptedPrivateKeyInfo
	if _, err := asn1.Unmarshal(der, &info); err != nil {
		return nil, fmt.Errorf("failed to parse EncryptedPrivateKeyInfo: %w", err)
	}

	if !info.EncryptionAlgorithm.Algorithm.Equal(oidPBES2) {
		return nil, fmt.Errorf("unsupported encryption algorithm: %v (only PBES2 is supported)", info.EncryptionAlgorithm.Algorithm)
	}

	var params pbes2Params
	if _, err := asn1.Unmarshal(info.EncryptionAlgorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("failed to parse PBES2 parameters: %w", err)
	}

	if !params.KeyDerivationFunc.Algorithm.Equal(oidPBKDF2) {
		return nil, fmt.Errorf("unsupported KDF: %v (only PBKDF2 is supported)", params.KeyDerivationFunc.Algorithm)
	}

	var kdfParams pbkdf2Params
	if _, err := asn1.Unmarshal(params.KeyDerivationFunc.Parameters.FullBytes, &kdfParams); err != nil {
		return nil, fmt.Errorf("failed to parse PBKDF2 parameters: %w", err)
	}

	const maxPBKDF2Iterations = 10_000_000
	if kdfParams.IterationCount <= 0 || kdfParams.IterationCount > maxPBKDF2Iterations {
		return nil, fmt.Errorf("PBKDF2 iteration count %d is out of allowed range (1–%d)", kdfParams.IterationCount, maxPBKDF2Iterations)
	}

	hashFunc := prfToHash(kdfParams.PRF.Algorithm)
	if hashFunc == nil {
		return nil, fmt.Errorf("unsupported PRF: %v", kdfParams.PRF.Algorithm)
	}

	keySize, err := aesCBCKeySize(params.EncryptionScheme.Algorithm)
	if err != nil {
		return nil, err
	}

	var iv []byte
	if _, err := asn1.Unmarshal(params.EncryptionScheme.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("failed to parse AES-CBC IV: %w", err)
	}

	derivedKey, err := pbkdf2.Key(hashFunc, string(password), kdfParams.Salt, kdfParams.IterationCount, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	plaintext, err := decryptAESCBC(derivedKey, iv, info.EncryptedData)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key: %w", err)
	}

	return x509.ParsePKCS8PrivateKey(plaintext)
}

func EncryptPKCS8(key interface{}, password []byte) ([]byte, error) {
	plaintext, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	const (
		saltSize   = 16
		ivSize     = aes.BlockSize
		keySize    = 32
		iterations = 600_000
	)

	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	iv := make([]byte, ivSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	derivedKey, err := pbkdf2.Key(sha256.New, string(password), salt, iterations, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	ciphertext, err := encryptAESCBC(derivedKey, iv, plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key: %w", err)
	}

	kdfParams := pbkdf2Params{
		Salt:           salt,
		IterationCount: iterations,
		PRF:            algorithmIdentifier{Algorithm: oidHMACWithSHA256},
	}
	kdfRaw, err := asn1.Marshal(kdfParams)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PBKDF2 parameters: %w", err)
	}

	ivRaw, err := asn1.Marshal(iv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal IV: %w", err)
	}

	pbes2 := pbes2Params{
		KeyDerivationFunc: algorithmIdentifier{
			Algorithm:  oidPBKDF2,
			Parameters: asn1.RawValue{FullBytes: kdfRaw},
		},
		EncryptionScheme: algorithmIdentifier{
			Algorithm:  oidAES256CBC,
			Parameters: asn1.RawValue{FullBytes: ivRaw},
		},
	}
	pbes2Raw, err := asn1.Marshal(pbes2)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PBES2 parameters: %w", err)
	}

	info := encryptedPrivateKeyInfo{
		EncryptionAlgorithm: algorithmIdentifier{
			Algorithm:  oidPBES2,
			Parameters: asn1.RawValue{FullBytes: pbes2Raw},
		},
		EncryptedData: ciphertext,
	}

	return asn1.Marshal(info)
}

func prfToHash(oid asn1.ObjectIdentifier) func() hash.Hash {
	switch {
	case len(oid) == 0:
		return sha1.New // default PRF per RFC 8018
	case oid.Equal(oidHMACWithSHA1):
		return sha1.New
	case oid.Equal(oidHMACWithSHA256):
		return sha256.New
	case oid.Equal(oidHMACWithSHA512):
		return sha512.New
	default:
		return nil
	}
}

func aesCBCKeySize(oid asn1.ObjectIdentifier) (int, error) {
	switch {
	case oid.Equal(oidAES128CBC):
		return 16, nil
	case oid.Equal(oidAES192CBC):
		return 24, nil
	case oid.Equal(oidAES256CBC):
		return 32, nil
	default:
		return 0, fmt.Errorf("unsupported encryption scheme: %v (only AES-CBC is supported)", oid)
	}
}

func decryptAESCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("invalid IV size: %d", len(iv))
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of AES block size")
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	return removePKCS7Padding(plaintext)
}

func encryptAESCBC(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	padded := addPKCS7Padding(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	return ciphertext, nil
}

func addPKCS7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

func removePKCS7Padding(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}
	padding := int(data[len(data)-1])
	if padding == 0 || padding > aes.BlockSize || padding > len(data) {
		return nil, fmt.Errorf("invalid padding")
	}
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return data[:len(data)-padding], nil
}
