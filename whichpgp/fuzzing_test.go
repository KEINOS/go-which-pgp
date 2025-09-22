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
