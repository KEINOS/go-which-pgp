package whichpgp_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/KEINOS/go-which-pgp/whichpgp"
	"github.com/stretchr/testify/require"
)

// minimalV4Armor returns a compact v4 minimal public key armor as lines.
// Lines: BEGIN, blank, base64 payload, CRC, END.
func minimalV4ArmorLines() []string {
	return []string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		"xgEE",
		"=A4sP",
		"-----END PGP PUBLIC KEY BLOCK-----",
	}
}

func TestDetectFlavorFromArmor_BeginLineEOLTolerant(t *testing.T) {
	t.Parallel()

	base := minimalV4ArmorLines()

	// Helper to assert flavor/version for a given armor string.
	assertOK := func(t *testing.T, armor string) {
		t.Helper()

		flavor, ver, err := whichpgp.DetectFlavorFromArmor(armor)
		require.NoError(t, err)
		require.Equal(t, 4, ver)
		require.Contains(t, flavor, "LibrePGP (v4)")
	}

	t.Run("CRLF all lines", func(t *testing.T) {
		t.Parallel()

		armor := strings.Join(base, "\r\n") + "\r\n"
		assertOK(t, armor)
	})

	t.Run("trailing spaces after BEGIN", func(t *testing.T) {
		t.Parallel()

		lines := append([]string{}, base...)

		lines[0] += "   " // add trailing spaces before EOL
		armor := strings.Join(lines, "\n") + "\n"
		assertOK(t, armor)
	})

	t.Run("multiple blank lines after BEGIN", func(t *testing.T) {
		t.Parallel()

		lines := append([]string{}, base...)
		// Insert two extra blank lines after BEGIN line
		lines = append([]string{lines[0], "", ""}, lines[1:]...)
		armor := strings.Join(lines, "\n") + "\n"
		assertOK(t, armor)
	})

	t.Run("header lines and whitespace-only terminator", func(t *testing.T) {
		t.Parallel()

		lines := append([]string{}, base...)
		// Replace the single blank line with headers, whitespace-only, then blank line
		linesWithHeaders := []string{
			lines[0],
			"Comment: hello",
			"Version: 1",
			"   \t  ", // whitespace-only line should terminate headers
			"",        // extra blank line tolerated
		}
		linesWithHeaders = append(linesWithHeaders, lines[2:]...)
		armor := strings.Join(linesWithHeaders, "\n") + "\n"
		assertOK(t, armor)
	})

	t.Run("trailing blanks after END", func(t *testing.T) {
		t.Parallel()

		armor := strings.Join(base, "\n") + "\n\n\n"
		assertOK(t, armor)
	})
}

// buildOldFmtPacket returns a single-packet OpenPGP message (old-format tag 6)
// with the specified old-format length type. The body is a single byte 0x04 (v4).
// lengthType: 0=>1-octet, 1=>2-octet, 2=>4-octet.
func buildOldFmtPacket(lengthType int) []byte {
	const tag = 6

	header := byte(0x80 | (tag << 2) | (lengthType & 0x03))
	body := []byte{0x04}

	switch lengthType {
	case 0:
		// 1-octet length
		return append([]byte{header, byte(len(body))}, body...)
	case 1:
		// 2-octet length (big endian)
		return append([]byte{header, 0x00, byte(len(body))}, body...)
	case 2:
		// 4-octet length (big endian)
		return append([]byte{header, 0x00, 0x00, 0x00, byte(len(body))}, body...)
	default:
		return nil
	}
}

func armor(payload []byte) string {
	b64 := base64.StdEncoding.EncodeToString(payload)

	// Build minimal armor without CRC line.
	var b strings.Builder
	b.WriteString("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n")
	b.WriteString(b64)
	b.WriteString("\n-----END PGP PUBLIC KEY BLOCK-----\n")

	return b.String()
}

func TestDetectFlavorFromArmor_OldFormat_LengthVariants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		ltype int
	}{
		{name: "oldfmt-1octet", ltype: 0},
		{name: "oldfmt-2octet", ltype: 1},
		{name: "oldfmt-4octet", ltype: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			pkt := buildOldFmtPacket(tc.ltype)
			require.NotNil(t, pkt)

			armorText := armor(pkt)

			flavor, ver, err := whichpgp.DetectFlavorFromArmor(armorText)
			require.NoError(t, err)
			require.Equal(t, 4, ver)
			require.Contains(t, flavor, "LibrePGP (v4)")
		})
	}
}

// buildNewFmtPartialPacket builds a single new-format packet with a sequence of
// partial chunks (each size is a power of two) followed by a final chunk.
// - tag: packet tag (use non-6 to avoid early version return)
// - partialPows: list of p where chunk size is 1<<p for each partial chunk
// - finalKind: "one", "two", or "five" for final length encoding
// - finalSize: size of the final chunk in bytes.
func buildNewFmtPartialPacket(tag int, partialPows []int, finalKind string, finalSize int) []byte {
	// New-format header: 0xC0 | (tag & 0x3F)
	buf := []byte{byte(0xC0 | (tag & 0x3F))}

	// First partial chunk: length octet 224..254
	for _, p := range partialPows {
		buf = append(buf, byte(224+p))
		buf = append(buf, make([]byte, 1<<p)...)
	}

	switch finalKind {
	case "one":
		// One-octet length (<192)
		buf = append(buf, byte(finalSize))
	case "two":
		// Two-octet length (192..223 encoding range with extra octet)
		n := finalSize - 192
		first := 192 + (n / 256)
		second := n % 256
		buf = append(buf, byte(first), byte(second))
	case "five":
		// Five-octet length (255 + 4 bytes)
		buf = append(buf, 255)
		buf = append(buf,
			byte(finalSize>>24), byte(finalSize>>16), byte(finalSize>>8), byte(finalSize),
		)
	}

	// Final chunk body
	buf = append(buf, make([]byte, finalSize)...)

	return buf
}

// newFmtShortTag6 builds a minimal new-format tag 6 packet with 1-byte body {0x04}.
func newFmtShortTag6() []byte {
	return []byte{0xC0 | 6, 0x01, 0x04}
}

func TestDetectFlavorFromArmor_Partial_FinalVariants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		finalKind string
		finalSize int
	}{
		{name: "final-one-octet", finalKind: "one", finalSize: 5},
		{name: "final-two-octet", finalKind: "two", finalSize: 300},
		{name: "final-five-octet", finalKind: "five", finalSize: 70000},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Packet A: non-tag (1) with one partial chunk then final chunk variant
			pktA := buildNewFmtPartialPacket(1, []int{2}, tc.finalKind, tc.finalSize)
			// Packet B: tag 6 minimal
			pktB := newFmtShortTag6()

			payload := append([]byte{}, pktA...)
			payload = append(payload, pktB...)

			armorText := armor(payload)

			flavor, ver, err := whichpgp.DetectFlavorFromArmor(armorText)
			require.NoError(t, err)
			require.Equal(t, 4, ver)
			require.Contains(t, flavor, "LibrePGP (v4)")
		})
	}
}

func TestDetectFlavorFromArmor_Partial_CapExceeded(t *testing.T) {
	t.Parallel()

	// Two partial chunks of 2MiB each will exceed the 4MiB scan cap when combined.
	pkt := buildNewFmtPartialPacket(1, []int{21, 21}, "one", 1)

	armorText := armor(pkt)

	_, _, err := whichpgp.DetectFlavorFromArmor(armorText)
	require.Error(t, err)
	require.ErrorContains(t, err, "cap")
}

func TestDetectFlavorFromArmor_Base64_InternalWhitespace(t *testing.T) {
	t.Parallel()

	// Minimal v4 payload base64 is "xgEE"; inject spaces and tabs within the line.
	b64WithSpaces := "x g\tE  E"

	armorText := strings.Join([]string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		b64WithSpaces,
		"-----END PGP PUBLIC KEY BLOCK-----",
		"",
	}, "\n")

	flavor, ver, err := whichpgp.DetectFlavorFromArmor(armorText)
	require.NoError(t, err)
	require.Equal(t, 4, ver)
	require.Contains(t, flavor, "LibrePGP (v4)")
}

func TestDetectFlavorFromArmor_PreDecodeSizeGuard_TooLarge(t *testing.T) {
	t.Parallel()

	// Build a base64 body long enough that decoded size estimate (~len*3/4)
	// exceeds 8 MiB (2x scan cap). We use 12 MiB to be safely over.
	const (
		twelveMiB  = 12 * 1024 * 1024
		b64Block   = 4
		b64PadChar = 'A'
	)

	pad := twelveMiB % b64Block

	bodyLen := twelveMiB
	if pad != 0 {
		bodyLen += b64Block - pad
	}

	var builder strings.Builder

	builder.Grow(bodyLen)

	for range bodyLen { // Go 1.22+ integer range
		builder.WriteByte(b64PadChar)
	}

	armorText := strings.Join([]string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		builder.String(),
		"-----END PGP PUBLIC KEY BLOCK-----",
		"",
	}, "\n")

	_, _, err := whichpgp.DetectFlavorFromArmor(armorText)
	require.Error(t, err)
	require.ErrorContains(t, err, "too large")
}

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
