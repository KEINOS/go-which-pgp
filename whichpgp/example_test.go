package whichpgp_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/KEINOS/go-which-pgp/whichpgp"
)

// Example demonstrates flavor detection for three minimal public keys.
func Example() {
	files := []string{
		"sample-v4-ed25519-leg.asc",       // Packet v4
		"sample-v4-ed25519.asc",           // Packet v4
		"sample-v5-certificate-trans.asc", // Packet v5
		"sample-v6-certificat.asc",        // Packet v6
	}

	for _, name := range files {
		pathFile := filepath.Join("..", "testdata", name)

		//nolint:gosec // G304: test reads fixed files under testdata via variable path
		data, err := os.ReadFile(pathFile)
		if err != nil {
			panic(err)
		}

		flavor, ver, err := whichpgp.DetectFlavorFromArmor(string(data))
		if err != nil {
			panic(err)
		}

		fmt.Printf("Flavor: %s, Version: %d\n", flavor, ver)
	}
	//
	// Output:
	// Flavor: LibrePGP (v4), Version: 4
	// Flavor: LibrePGP (v4), Version: 4
	// Flavor: LibrePGP (v5), Version: 5
	// Flavor: OpenPGP (v6 / RFC 9580), Version: 6
}

// Minimal synthetic keys for testing.
// Note that they are not intended for real-world use; they exist solely to
// exercise parsing and version detection paths.
func Example_minimal_synthetic_keys() {
	data := []string{
		`-----BEGIN PGP PUBLIC KEY BLOCK-----

xgEE
=A4sP
-----END PGP PUBLIC KEY BLOCK-----
`,
		`-----BEGIN PGP PUBLIC KEY BLOCK-----

xgEF
=hcf0
-----END PGP PUBLIC KEY BLOCK-----
`,
		`-----BEGIN PGP PUBLIC KEY BLOCK-----

xgEG
=iV4C
-----END PGP PUBLIC KEY BLOCK-----
`,
	}

	for _, armor := range data {
		flavor, ver, err := whichpgp.DetectFlavorFromArmor(armor)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Flavor: %s, Version: %d\n", flavor, ver)
	}
	//
	// Output:
	// Flavor: LibrePGP (v4), Version: 4
	// Flavor: LibrePGP (v5), Version: 5
	// Flavor: OpenPGP (v6 / RFC 9580), Version: 6
}
