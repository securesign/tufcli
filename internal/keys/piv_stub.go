//go:build !piv

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

	"github.com/sigstore/sigstore/pkg/signature"
	tufmeta "github.com/theupdateframework/go-tuf/v2/metadata"
)

func loadPIVSigner(_ string) (signature.Signer, *tufmeta.Key, string, error) {
	return nil, nil, "", fmt.Errorf("YubiKey support not compiled in: rebuild with -tags piv")
}

func parsePIVPublicKey(_ string) (*tufmeta.Key, string, error) {
	return nil, "", fmt.Errorf("YubiKey support not compiled in: rebuild with -tags piv")
}
