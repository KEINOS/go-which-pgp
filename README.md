![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/KEINOS/go-which-pgp)
[![Go Reference](https://pkg.go.dev/badge/github.com/KEINOS/go-which-pgp.svg)](https://pkg.go.dev/github.com/KEINOS/go-which-pgp/whichpgp)

# Go-Which-PGP

`whichpgp` is a Go library to detect the PGP flavor and the Public‑Key Packet version from an ASCII‑armored public key block.

- OpenPGP (Packet v6; RFC-9580/crypto-refresh)
- LibrePGP (Packet v4; RFC-4880, Packet v5; draft-koch-librepgp base)

## Install

```sh
go get github.com/KEINOS/go-which-pgp
```

## Quick start

```go
import (
    "fmt"
    "os"
    "path/filepath"

    "github.com/KEINOS/go-which-pgp/whichpgp"
)

func main() {
    files := []string{
        "sample-v4-ed25519-leg.asc",       // Packet v4
        "sample-v4-ed25519.asc",           // Packet v4
        "sample-v5-certificate-trans.asc", // Packet v5
        "sample-v6-certificat.asc",        // Packet v6
    }

    for _, name := range files {
        data, err := os.ReadFile(filepath.Join("..", "testdata", name))
        if err != nil { panic(err) }

        flavor, ver, err := whichpgp.DetectFlavorFromArmor(string(data))
        if err != nil { panic(err) }

        fmt.Printf("Flavor: %s, Packet version: %d\n", flavor, ver)
    }
    //
    // Output:
    // Flavor: LibrePGP (v4), Packet version: 4
    // Flavor: LibrePGP (v4), Packet version: 4
    // Flavor: LibrePGP (v5), Packet version: 5
    // Flavor: OpenPGP (v6 / RFC 9580), Packet version: 6
}
```

- View more examples: [whichpgp/example_test.go](https://pkg.go.dev/github.com/KEINOS/go-which-pgp/whichpgp#pkg-examples)

## Terminology

- **Flavor:** Logical family name for the ecosystem. This library returns either "LibrePGP" or "OpenPGP".
- **Public‑Key Packet Version:** Version of the public‑key packet format inside the key material (v4, v5, or v6). This is not a library or application version.
- **Relationship:** RFC 9580 standardizes OpenPGP with Packet v6. LibrePGP continues the v4/v5 packet lineage that has been developed in the community. This library focuses on detecting the ecosystem (flavor) and the packet version present in the provided key.

> [!IMPORTANT]
> **Policy note:** Packet versions are not a "higher-is-better" ranking. They represent different specification families and trade-offs. Choose the packet version that aligns with your interoperability and security policy.

## API behavior and assumptions

```go
whichpgp.DetectFlavorFromArmor(armored string) (flavor string, version int, err error)
```

- Returns:
  - flavor: "LibrePGP" or "OpenPGP"
  - version: Public‑Key Packet version (4, 5, or 6)

- Armor tolerance
  - Ignores headers until a blank/whitespace-only line
  - Accepts LF/CRLF, multiple blank lines, and trailing blanks after END
  - Base64 body tolerates embedded ASCII whitespace (space/tab/CR/LF)
- CRC-24 handling
  - If CRC line exists, validate strictly; if missing, allowed; if present but invalid, error
  - See RFC 4880 (Armor/Checksum, e.g., Section 6.3) and RFC 9580
- Size limits and safety
  - Pre-decode size guard: rejects oversized base64 bodies early (DoS prevention)
  - Packet scan cap: internal scanning limited to ~4 MiB by default; error suggests increasing cap

## Development

- Tests: `go test ./...`
- Lint: `golangci-lint run`
- Fuzz (Go 1.20+): `go test -fuzz=FuzzDetectFlavorFromArmor -run=^$` (optional)

## Contributing

- Branch to PR: `main`

## License

MIT
