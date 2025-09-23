package whichpgp_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/KEINOS/go-which-pgp/whichpgp"
)

// FuzzDetectFlavorFromArmor formats pseudo-armor with random spacing/EOL/headers
// and random payload, ensuring no panics and stable error handling.
func FuzzDetectFlavorFromArmor(f *testing.F) {
	// Seed with a few valid-looking payloads (v4 minimal) and noise.
	seeds := [][]byte{
		{0xC0 | 6, 0x01, 0x04},   // new fmt tag6, v4
		{0x98, 0x01, 0x04},       // old fmt tag6 (0x80 | 6<<2), 1-oct len
		{0x01, 0x02, 0x03, 0x04}, // noise
		make([]byte, 0),          // empty
	}

	for _, s := range seeds {
		f.Add(string(s))
	}

	f.Fuzz(func(_ *testing.T, raw string) {
		// Randomize EOL styles
		eols := []string{"\n", "\r\n"}
		eol := eols[len(raw)%len(eols)]

		// Pick whether to include CRC
		withCRC := len(raw)%3 == 0

		payload := []byte(raw)
		b64 := base64.StdEncoding.EncodeToString(payload)

		// Optional naive CRC24: we don't compute true CRC to avoid coupling; when
		// enabled, just add a fake 3-byte base64 which will likely fail CRC check
		// but must not panic.
		crcLine := ""
		if withCRC {
			crcLine = "=" + base64.StdEncoding.EncodeToString([]byte{0x00, 0x00, 0x00})
		}

		// Optional headers and multiple blank lines
		header := ""
		if len(raw)%2 == 0 {
			header = fmt.Sprintf("Comment: seed-%d%sVersion: x%s", len(raw), eol, eol)
		}

		blanks := ""
		if len(raw)%5 == 0 {
			blanks = eol + eol
		}

		armor := strings.Join([]string{
			"-----BEGIN PGP PUBLIC KEY BLOCK-----",
			header,
			"", // header terminator
			b64,
			crcLine,
			"-----END PGP PUBLIC KEY BLOCK-----",
			"",
		}, eol)
		armor += blanks

		// Detect should never panic. Errors are allowed.
		_, _, _ = whichpgp.DetectFlavorFromArmor(armor)
	})
}

// FuzzDetectFlavorFromBytes tests the primary bytes detection API with random input.
// This covers the core detection logic with various option combinations.
func FuzzDetectFlavorFromBytes(f *testing.F) {
	// Seed with valid armor structures and noise
	seeds := [][]byte{
		// Minimal valid v4 armor structure
		[]byte(`-----BEGIN PGP PUBLIC KEY BLOCK-----

xgEE
=A4sP
-----END PGP PUBLIC KEY BLOCK-----
`),
		// Minimal v5 structure
		[]byte(`-----BEGIN PGP PUBLIC KEY BLOCK-----

xwEF
=1234
-----END PGP PUBLIC KEY BLOCK-----
`),
		// Random binary data
		{0x98, 0x01, 0x00, 0xf8, 0x98}, // This caused infinite loop before fix
		{0xC0 | 6, 0x01, 0x05},         // new format tag6, v5
		{0x80 | 6<<2, 0x01, 0x04},      // old format tag6, v4
		make([]byte, 0),                // empty
		{0xFF, 0xFF, 0xFF},             // noise
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(_ *testing.T, data []byte) {
		// Test basic detection
		_, _ = whichpgp.DetectFlavorFromBytes(data)

		// Test with various options combinations
		opts := []whichpgp.Option{
			whichpgp.WithMaxBytes(len(data) + 1000),
			whichpgp.WithStrictCRC(len(data)%2 == 0),
			whichpgp.WithScanCap(1024 + len(data)%2048),
		}

		// Random subset of options
		selectedOpts := make([]whichpgp.Option, 0)

		for i, opt := range opts {
			if (len(data)+i)%3 == 0 {
				selectedOpts = append(selectedOpts, opt)
			}
		}

		_, _ = whichpgp.DetectFlavorFromBytes(data, selectedOpts...)
	})
}

// FuzzDetectFlavorFromReader tests the reader-based detection API with random input.
// This validates streaming detection and buffer handling.
func FuzzDetectFlavorFromReader(f *testing.F) {
	// Seed with various input patterns
	seeds := []string{
		// Valid armor structures
		`-----BEGIN PGP PUBLIC KEY BLOCK-----

xgEE
=A4sP
-----END PGP PUBLIC KEY BLOCK-----
`,
		// Large armor
		`-----BEGIN PGP PUBLIC KEY BLOCK-----

` + strings.Repeat("xgEE", 100) + `
=1234
-----END PGP PUBLIC KEY BLOCK-----
`,
		// Partial armor
		`-----BEGIN PGP PUBLIC KEY BLOCK-----
incomplete`,
		// Empty
		"",
		// Non-armor content
		"This is not armor at all!",
		// Binary-like content
		string([]byte{0x00, 0x01, 0x02, 0xFF, 0xFE}),
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(_ *testing.T, input string) {
		reader := strings.NewReader(input)

		// Test basic detection
		_, _ = whichpgp.DetectFlavorFromReader(reader)

		// Test with options
		reader2 := strings.NewReader(input)
		opts := []whichpgp.Option{
			whichpgp.WithBufferSize(32 + len(input)%256), // Variable buffer sizes
			whichpgp.WithMaxBytes(len(input) + 512),      // Reasonable limits
			whichpgp.WithStrictCRC(len(input)%3 == 0),    // Random CRC mode
		}

		// Random subset of options
		selectedOpts := make([]whichpgp.Option, 0)

		for i, opt := range opts {
			if (len(input)+i)%2 == 0 {
				selectedOpts = append(selectedOpts, opt)
			}
		}

		_, _ = whichpgp.DetectFlavorFromReader(reader2, selectedOpts...)
	})
}

// FuzzDetectFlavorFromString tests the string-based detection API with random input.
// This validates the convenience string wrapper.
func FuzzDetectFlavorFromString(f *testing.F) {
	// Seed with various string patterns
	seeds := []string{
		// Valid armor
		`-----BEGIN PGP PUBLIC KEY BLOCK-----

xgEE
=A4sP
-----END PGP PUBLIC KEY BLOCK-----
`,
		// Malformed armor
		`-----BEGIN PGP PUBLIC KEY BLOCK-----
invalid!@#$%
-----END PGP PUBLIC KEY BLOCK-----`,
		// Empty string
		"",
		// Unicode and special characters
		"hello world",
		"💀🔐🗝️",
		// Very long string
		strings.Repeat("ABCD", 1000),
		// Mixed content
		"Some text before\n" + `-----BEGIN PGP PUBLIC KEY BLOCK-----
xgEE
-----END PGP PUBLIC KEY BLOCK-----` + "\nSome text after",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(_ *testing.T, input string) {
		// Test basic detection
		_, _ = whichpgp.DetectFlavorFromString(input)

		// Test with random options
		opts := []whichpgp.Option{
			whichpgp.WithMaxBytes(len(input) + 100),
			whichpgp.WithStrictCRC(len(input)%4 == 0),
			whichpgp.WithScanCap(512 + len(input)%1024),
		}

		// Random subset
		selectedOpts := make([]whichpgp.Option, 0)

		for i, opt := range opts {
			if (len(input)*7+i)%3 == 0 {
				selectedOpts = append(selectedOpts, opt)
			}
		}

		_, _ = whichpgp.DetectFlavorFromString(input, selectedOpts...)
	})
}
