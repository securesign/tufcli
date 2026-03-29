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

package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// WriteJSONFile writes a JSON object to a file atomically
func WriteJSONFile(path string, data interface{}) error {
	// Create parent directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	// Create temporary file
	tmpFile, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	// Marshal with custom time encoding
	jsonBytes, err := MarshalTUFJSON(data)
	if err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Write JSON to temp file
	if _, err := tmpFile.Write(jsonBytes); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write to temp file: %w", err)
	}

	// Close temp file
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	// Atomically rename temp file to target file
	if err := os.Rename(tmpFile.Name(), path); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// ReadJSONFile reads a JSON file into a data structure
func ReadJSONFile(path string, data interface{}) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(data); err != nil {
		return fmt.Errorf("failed to decode JSON: %w", err)
	}

	return nil
}

// HashFile computes the SHA256 hash of a file
func HashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to hash file: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// MarshalTUFJSON marshals data to JSON with TUF-compliant formatting
// Times are formatted in RFC 3339 format with 'Z' suffix
func MarshalTUFJSON(data interface{}) ([]byte, error) {
	// Use MarshalIndent for pretty printing
	jsonBytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

// WriteFile writes data to a file
func WriteFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("failed to create parent directory: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// TUFTime wraps time.Time for custom JSON marshaling
type TUFTime struct {
	time.Time
}

// MarshalJSON implements json.Marshaler for TUF time format
func (t TUFTime) MarshalJSON() ([]byte, error) {
	// Format as RFC 3339 with Z suffix (UTC)
	formatted := t.UTC().Format(time.RFC3339)
	return json.Marshal(formatted)
}

// UnmarshalJSON implements json.Unmarshaler for TUF time format
func (t *TUFTime) UnmarshalJSON(data []byte) error {
	var timeStr string
	if err := json.Unmarshal(data, &timeStr); err != nil {
		return err
	}
	parsed, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		return err
	}
	t.Time = parsed
	return nil
}
