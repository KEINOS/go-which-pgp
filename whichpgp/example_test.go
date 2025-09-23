// Example usages of public functions.
//
// We implement these examples as golden cases in tests to ensure the documented
// usage patterns remain valid over time.
package whichpgp_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/KEINOS/go-which-pgp/whichpgp"
)

const (
	// sampleArmorV4 is a minimal v4 PGP armor for examples.
	sampleArmorV4 = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xgEE
=A4sP
-----END PGP PUBLIC KEY BLOCK-----
`
)

// Basic example to demonstrate flavor detection for three minimal public keys.
func Example() {
	// See the README.md under "testdata" for details about these files.
	files := []string{
		"sample-v4-ed25519-leg.asc",       // Packet v4
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
	// Flavor: LibrePGP (v5), Version: 5
	// Flavor: OpenPGP (v6 / RFC 9580), Version: 6
}

// Example_advanced demonstrates the new type-safe API with Result struct.
// This provides more structured access to detection results and better error handling.
func Example_advanced() {
	// Use the new DetectFlavorFromBytes function which returns a structured Result
	result, err := whichpgp.DetectFlavorFromBytes([]byte(sampleArmorV4))
	if err != nil {
		panic(err)
	}

	// Access results through the structured Result type
	fmt.Printf("Flavor: %s\n", result.Flavor.String())
	fmt.Printf("Version: %d\n", result.PacketVersion)
	fmt.Printf("Full description: %s\n", result.String())

	// You can also use the Flavor enum for type-safe comparisons
	switch result.Flavor {
	case whichpgp.FlavorLibrePGP:
		fmt.Println("This is a LibrePGP key")
	case whichpgp.FlavorOpenPGP:
		fmt.Println("This is an OpenPGP key")
	case whichpgp.FlavorUnknown:
		fmt.Println("Unknown PGP flavor")
	}
	//
	// Output:
	// Flavor: LibrePGP
	// Version: 4
	// Full description: LibrePGP (v4)
	// This is a LibrePGP key
}

// Example_with_options demonstrates the functional option pattern for customizing detection behavior.
func Example_with_options() {
	// Example armor without CRC (normally would cause an error with strict validation)
	armorWithoutCRC := `-----BEGIN PGP PUBLIC KEY BLOCK-----

xgEE
-----END PGP PUBLIC KEY BLOCK-----
`

	// Use options to customize the detection behavior
	result, err := whichpgp.DetectFlavorFromBytes(
		[]byte(armorWithoutCRC),
		whichpgp.WithStrictCRC(false),    // Allow missing CRC
		whichpgp.WithMaxBytes(1024*1024), // Set max size limit to 1MB
		whichpgp.WithScanCap(512*1024),   // Set scan buffer cap to 512KB
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Detected: %s\n", result.String())

	// Example with strict CRC validation (would fail with the above armor)
	result, err = whichpgp.DetectFlavorFromBytes(
		[]byte(sampleArmorV4),
		whichpgp.WithStrictCRC(true), // Require valid CRC
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("With CRC validation: %s\n", result.String())
	//
	// Output:
	// Detected: LibrePGP (v4)
	// With CRC validation: LibrePGP (v4)
}

// Example_from_reader demonstrates detecting PGP flavor from any io.Reader.
// This is useful for processing streams, files, or network data without loading everything into memory.
func Example_from_reader() {
	// Create a reader from the string
	reader := strings.NewReader(sampleArmorV4)

	// Detect from the reader with custom buffer size
	result, err := whichpgp.DetectFlavorFromReader(
		reader,
		whichpgp.WithBufferSize(1024), // Use 1KB buffer for reading
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("From reader: %s\n", result.String())

	// Example with a file reader
	pathFile := filepath.Join("..", "testdata", "sample-v4-ed25519-leg.asc")

	file, err := os.Open(pathFile) //nolint:gosec // G304: test file path is safe
	if err != nil {
		// Skip if testdata not available
		fmt.Println("Testdata file example: LibrePGP (v4)")

		return
	}

	defer func() {
		closeErr := file.Close()
		if closeErr != nil {
			panic(closeErr)
		}
	}()

	result, err = whichpgp.DetectFlavorFromReader(file)
	if err != nil {
		panic(err)
	}

	fmt.Printf("From file: %s\n", result.String())
	//
	// Output:
	// From reader: LibrePGP (v4)
	// From file: LibrePGP (v4)
}

// Example_error_handling demonstrates proper error handling with the new API.
func Example_error_handling() {
	// Invalid armor data (missing proper structure)
	invalidArmor := `-----BEGIN PGP PUBLIC KEY BLOCK-----
invalid base64 data!@#$
-----END PGP PUBLIC KEY BLOCK-----`

	_, err := whichpgp.DetectFlavorFromBytes([]byte(invalidArmor))
	if err != nil {
		fmt.Printf("Error detected: %v\n", err)
	}

	// Reader that returns an error
	errorReader := &erroringReader{message: "simulated read error"}

	_, err = whichpgp.DetectFlavorFromReader(errorReader)
	if err != nil {
		fmt.Printf("Reader error: %v\n", err)
	}

	// Using backward compatibility function for comparison
	_, _, err = whichpgp.DetectFlavorFromArmor(invalidArmor)
	if err != nil {
		fmt.Printf("Legacy API error: %v\n", err)
	}
	//
	// Output:
	// Error detected: unexpected EOF in armor headers
	// Reader error: read stream: simulated read error
	// Legacy API error: unexpected EOF in armor headers
}

var errSimulatedRead = errors.New("simulated read error")

// erroringReader is a helper type for demonstrating error handling.
type erroringReader struct {
	message string
}

func (r *erroringReader) Read([]byte) (int, error) {
	return 0, errSimulatedRead
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
