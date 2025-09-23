[![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/KEINOS/go-which-pgp)](https://github.com/KEINOS/go-which-pgp/blob/main/go.mod)
[![Go Reference](https://pkg.go.dev/badge/github.com/KEINOS/go-which-pgp.svg)](https://pkg.go.dev/github.com/KEINOS/go-which-pgp/whichpgp)

# Go-Which-PGP

Go library to detect PGP flavor and packet version from ASCII-armored public keys.

- **OpenPGP** (v6; RFC-9580)
- **LibrePGP** (v4/v5; RFC-4880/draft-koch-librepgp)

## Usage

```sh
# Install the module
go get github.com/KEINOS/go-which-pgp
```

```go
// Use the package
import "github.com/KEINOS/go-which-pgp/whichpgp"
```

```go
package main

import (
    "fmt"
    "github.com/KEINOS/go-which-pgp/whichpgp"
)

func main() {
    // ASCII armored PGP public key block
    pubKey := `-----BEGIN PGP PUBLIC KEY BLOCK-----
**snip**
-----END PGP PUBLIC KEY BLOCK-----`

    // Direct string input and output
    flavor, version, err := whichpgp.DetectFlavorFromArmor(pubKey)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Flavor: %s, Version: %d\n", flavor, version)
    //
    // Output:
    // Flavor: LibrePGP (v5), Version: 5
}
```

```go
package main

import (
    "fmt"
    "github.com/KEINOS/go-which-pgp/whichpgp"
)

func main() {
    // ASCII armored PGP public key block
    pubKey := `-----BEGIN PGP PUBLIC KEY BLOCK-----
**snip**
-----END PGP PUBLIC KEY BLOCK-----`

    // Return structured result
    result, err := whichpgp.DetectFlavorFromBytes([]byte(pubKey))
    if err != nil {
        panic(err)
    }

    fmt.Printf("Flavor: %s\n", result.Flavor.String())
    fmt.Printf("Version: %d\n", result.PacketVersion)
    fmt.Printf("Description: %s\n", result.String())
    //
    // Output:
    // Flavor: OpenPGP
    // Version: 6
    // Description: OpenPGP (v6)
}
```

### Advanced Usage

You can control the behavior with options.

```go
pubKey := `-----BEGIN PGP PUBLIC KEY BLOCK-----
**snip**
-----END PGP PUBLIC KEY BLOCK-----`

// With options for customization
result, err := whichpgp.DetectFlavorFromBytes([]byte(pubKey),
    whichpgp.WithStrictCRC(false),    // Allow missing CRC
    whichpgp.WithMaxBytes(1024*1024), // Set size limit
    whichpgp.WithBufferSize(8192),    // Custom buffer size
)
```

```go
import (
    "os"
    "path/filepath"
)

filePath := filepath.Join("..", "testdata", "sample-v5-certificate-trans.asc")
file, err := os.Open(filePath)
if err != nil {
    panic(err)
}
defer file.Close()

// From io.Reader for streaming
result, err := whichpgp.DetectFlavorFromReader(file,
    whichpgp.WithStrictCRC(false),    // Allow missing CRC
    whichpgp.WithMaxBytes(1024*1024), // Set size limit
    whichpgp.WithBufferSize(8192),    // Custom buffer size
)
```

- 📖 **More examples:** [pkg.go.dev documentation](https://pkg.go.dev/github.com/KEINOS/go-which-pgp/whichpgp#pkg-examples)

## API Reference

The library provides three main functions for detecting PGP flavors:

### Available Functions

- **`DetectFlavorFromBytes(data []byte, opts ...Option) (Result, error)`** - Detects PGP flavor from byte data with optional configuration
- **`DetectFlavorFromReader(r io.Reader, opts ...Option) (Result, error)`** - Detects PGP flavor from any `io.Reader` source
- **`DetectFlavorFromString(data string, opts ...Option) (Result, error)`** - Convenience function for string inputs with options
- **`DetectFlavorFromArmor(armor string) (string, int, error)`** - Simple string-based detection API

### Result Structure

The new APIs return a structured `Result` type:

```go
type Result struct {
    Flavor        Flavor // Type-safe enum: FlavorUnknown, FlavorLibrePGP, FlavorOpenPGP
    PacketVersion uint8  // PGP packet version (4, 5, 6)
}

// Methods
result.String()        // Human-readable description: "LibrePGP (v4)"
result.Flavor.String() // Flavor name: "LibrePGP"
```

### Configuration Options

Customize behavior with functional options:

- `WithStrictCRC(bool)` - Require valid CRC checksums (default: false)
- `WithMaxBytes(int)` - Set maximum data size limit (default: 8 MiB)
- `WithBufferSize(int)` - Set buffer size for reader operations (default: 64 KiB)
- `WithScanCap(int)` - Set packet scanning limit for safety (default: 4 MiB)

### Supported PGP Flavors

| Flavor | Packet Versions | Description |
|--------|----------------|-------------|
| **LibrePGP** | v4, v5 | Based on draft specifications |
| **OpenPGP** | v6 | RFC 9580 standard |
| **Unknown** | - | Unrecognized or invalid format |

## Terminology

- **Flavor:** Logical family name for the ecosystem. This library returns either "LibrePGP" or "OpenPGP".
- **Public‑Key Packet Version:** Version of the public‑key packet format inside the key material (v4, v5, or v6). This is not a library or application version.
- **Relationship:** RFC 9580 standardizes OpenPGP with Packet v6. LibrePGP continues the v4/v5 packet lineage that has been developed in the community. This library focuses on detecting the ecosystem (flavor) and the packet version present in the provided key.

> [!IMPORTANT]
> **Policy note:** Packet versions are not a "higher-is-better" ranking. They represent different specification families and trade-offs. Choose the packet version that aligns with your interoperability and security policy.

## API behavior and assumptions

### Detection Logic

All detection functions follow these principles:

- **Return values:**
  - `DetectFlavorFromBytes`, `DetectFlavorFromReader` & `DetectFlavorFromString`: `Result` with `Flavor` enum and `PacketVersion` uint8
  - `DetectFlavorFromArmor`: human-readable description string (e.g., "LibrePGP (v4)", "OpenPGP (v6 / RFC 9580)") and version int (4, 5, or 6)

### Armor Processing

- **Headers:** Ignores all headers until a blank/whitespace-only line
- **Line endings:** Accepts LF/CRLF, multiple blank lines, and trailing blanks after END
- **Base64 body:** Tolerates embedded ASCII whitespace (space/tab/CR/LF)

### CRC-24 Validation

- **If CRC line exists:** Validates strictly - invalid CRC returns error
- **If CRC missing:** Allowed by default (use `WithStrictCRC(true)` to require)
- **Configurable:** Use `WithStrictCRC(false)` to ignore CRC validation entirely
  - See RFC 4880 (Armor/Checksum, e.g., Section 6.3) and RFC 9580
- Size limits and safety
  - Pre-decode size guard: rejects oversized base64 bodies early (DoS prevention)
  - Packet scan cap: internal scanning limited to ~4 MiB by default; error suggests increasing cap

## Development

```sh
go test ./...                     # Tests
golangci-lint run                 # Lint
go test -fuzz=Fuzz* -run=^$       # Fuzz testing
```

## License

MIT
