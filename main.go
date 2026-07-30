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

/*
tufcli is a command-line utility and Go library for creating and managing
The Update Framework (TUF) repositories.

# CLI Usage

	tufcli [command] [flags]

# Library Usage

tufcli can be used as a Go library. Every CLI command has a corresponding
public API:

	import "github.com/securesign/tufcli/pkg/rootmeta"        // root.json lifecycle
	import "github.com/securesign/tufcli/pkg/repo/create"      // create TUF repositories
	import "github.com/securesign/tufcli/pkg/repo/update"      // update repositories
	import "github.com/securesign/tufcli/pkg/repo/clone"       // clone remote repositories
	import "github.com/securesign/tufcli/pkg/repo/download"    // download targets with TUF verification
	import "github.com/securesign/tufcli/pkg/repo/transfer"    // transfer metadata between roots
	import "github.com/securesign/tufcli/pkg/rhtas"            // RHTAS Sigstore target management
	import "github.com/securesign/tufcli/pkg/signingconfig"    // Sigstore signing config management
*/
package main

import (
	"os"

	"github.com/securesign/tufcli/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
