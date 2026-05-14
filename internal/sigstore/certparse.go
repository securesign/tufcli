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

package sigstore

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	commonpb "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
)

// LoadDERBytes reads a PEM file and returns the DER-encoded bytes for each PEM block.
func LoadDERBytes(path string) ([][]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}

	var derBlocks [][]byte
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		derBlocks = append(derBlocks, block.Bytes)
	}

	if len(derBlocks) == 0 {
		return nil, fmt.Errorf("no PEM blocks found in %s", path)
	}

	return derBlocks, nil
}

// ExtractSubjectFromCert reads a PEM certificate and extracts the subject's
// Organization and CommonName. Returns empty strings on any error.
func ExtractSubjectFromCert(path string) commonpb.DistinguishedName {
	data, err := os.ReadFile(path)
	if err != nil {
		return commonpb.DistinguishedName{}
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return commonpb.DistinguishedName{}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return commonpb.DistinguishedName{}
	}

	org := ""
	if len(cert.Subject.Organization) > 0 {
		org = cert.Subject.Organization[0]
	}

	return commonpb.DistinguishedName{
		Organization: org,
		CommonName:   cert.Subject.CommonName,
	}
}
