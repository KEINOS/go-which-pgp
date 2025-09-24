//nolint:varnamelen,funlen // Allow short names and long function length
package whichpgp_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/KEINOS/go-which-pgp/whichpgp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
//  Helper functions and types
// ============================================================================

// armor builds minimal armor around the given payload.
func armor(payload []byte) string {
	b64 := base64.StdEncoding.EncodeToString(payload)

	// Build minimal armor without CRC line.
	var b strings.Builder
	b.WriteString("-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n")
	b.WriteString(b64)
	b.WriteString("\n-----END PGP PUBLIC KEY BLOCK-----\n")

	return b.String()
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

// errorReader is a helper for testing error conditions.
type errorReader struct {
	err error
}

func (r *errorReader) Read([]byte) (int, error) {
	return 0, r.err
}

// minimalV4ArmorLines returns a compact v4 minimal public key armor as lines.
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

// newFmtShortTag6 builds a minimal new-format tag 6 packet with 1-byte body {0x04}.
func newFmtShortTag6() []byte {
	return []byte{0xC0 | 6, 0x01, 0x04}
}

// ============================================================================
//  Test functions (in ABC order)
// ============================================================================

func TestDetectFlavorFromBytes_BasicFunctionality(t *testing.T) {
	t.Parallel()

	// Use the minimal v4 armor from existing tests
	armorLines := []string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		"xgEE", // minimal v4 packet
		"=A4sP",
		"-----END PGP PUBLIC KEY BLOCK-----",
	}
	armor := strings.Join(armorLines, "\n") + "\n"

	result, err := whichpgp.DetectFlavorFromBytes([]byte(armor))
	require.NoError(t, err)

	assert.Equal(t, whichpgp.FlavorLibrePGP, result.Flavor)
	assert.Equal(t, uint8(4), result.PacketVersion)
	assert.Equal(t, "LibrePGP (v4)", result.String())
}

func TestDetectFlavorFromBytes_StrictCRC_MissingCRC(t *testing.T) {
	t.Parallel()

	// Armor without CRC line
	armorLines := []string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		"xgEE",
		"-----END PGP PUBLIC KEY BLOCK-----",
	}
	armor := strings.Join(armorLines, "\n") + "\n"

	t.Run("strict CRC disabled - should pass", func(t *testing.T) {
		t.Parallel()

		result, err := whichpgp.DetectFlavorFromBytes([]byte(armor), whichpgp.WithStrictCRC(false))
		require.NoError(t, err)

		assert.Equal(t, whichpgp.FlavorLibrePGP, result.Flavor)
	})

	t.Run("strict CRC enabled - should fail", func(t *testing.T) {
		t.Parallel()

		_, err := whichpgp.DetectFlavorFromBytes([]byte(armor), whichpgp.WithStrictCRC(true))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CRC-24 line required")
	})
}

func TestDetectFlavorFromBytes_WithOptions(t *testing.T) {
	t.Parallel()

	armorLines := []string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		"xgEE",
		"=A4sP",
		"-----END PGP PUBLIC KEY BLOCK-----",
	}
	armor := strings.Join(armorLines, "\n") + "\n"

	t.Run("with strict CRC - valid CRC should pass", func(t *testing.T) {
		t.Parallel()

		result, err := whichpgp.DetectFlavorFromBytes([]byte(armor), whichpgp.WithStrictCRC(true))
		require.NoError(t, err)

		assert.Equal(t, whichpgp.FlavorLibrePGP, result.Flavor)
		assert.Equal(t, uint8(4), result.PacketVersion)
	})

	t.Run("with max bytes limit", func(t *testing.T) {
		t.Parallel()

		// Set a very small limit
		_, err := whichpgp.DetectFlavorFromBytes([]byte(armor), whichpgp.WithMaxBytes(10))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too large")
	})

	t.Run("with scan cap", func(t *testing.T) {
		t.Parallel()

		result, err := whichpgp.DetectFlavorFromBytes([]byte(armor), whichpgp.WithScanCap(1024))
		require.NoError(t, err)

		assert.Equal(t, whichpgp.FlavorLibrePGP, result.Flavor)
	})
}

func TestDetectFlavorFromArmor_BackwardCompatibility(t *testing.T) {
	t.Parallel()

	armorLines := []string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		"xgEE",
		"=A4sP",
		"-----END PGP PUBLIC KEY BLOCK-----",
	}
	armor := strings.Join(armorLines, "\n") + "\n"

	// Test backward compatibility - should return the same results as before
	flavor, version, err := whichpgp.DetectFlavorFromArmor(armor)
	require.NoError(t, err)

	assert.Contains(t, flavor, "LibrePGP (v4)")
	assert.Equal(t, 4, version)

	// Compare with new API
	result, err := whichpgp.DetectFlavorFromBytes([]byte(armor))
	require.NoError(t, err)

	assert.Equal(t, flavor, result.String())
	assert.Equal(t, version, int(result.PacketVersion))
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

func TestDetectFlavorFromArmor_NewFormat_ZeroLengthBody_ShouldError(t *testing.T) {
	t.Parallel()

	// New-format tag 6, one-octet length = 0, no body.
	payload := []byte{0xC0 | 6, 0x00}
	armorText := armor(payload)

	_, _, err := whichpgp.DetectFlavorFromArmor(armorText)
	require.Error(t, err)
	require.ErrorContains(t, err, "too short")
	require.ErrorContains(t, err, "new fmt")
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

func TestDetectFlavorFromArmor_OldFormat_ZeroLengthBody_ShouldError(t *testing.T) {
	t.Parallel()

	buildZeroLenOldFmt := func(ltype int) []byte {
		// Old-format header: 0x80 | (tag<<2) | ltype
		const tag = 6

		header := byte(0x80 | (tag << 2) | (ltype & 0x03))
		switch ltype {
		case 0: // 1-octet length = 0
			return []byte{header, 0x00}
		case 1: // 2-octet length = 0
			return []byte{header, 0x00, 0x00}
		case 2: // 4-octet length = 0
			return []byte{header, 0x00, 0x00, 0x00, 0x00}
		default:
			return nil
		}
	}

	cases := []struct {
		name  string
		ltype int
	}{
		{name: "oldfmt-1octet-zero", ltype: 0},
		{name: "oldfmt-2octet-zero", ltype: 1},
		{name: "oldfmt-4octet-zero", ltype: 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			payload := buildZeroLenOldFmt(tc.ltype)
			armorText := armor(payload)

			_, _, err := whichpgp.DetectFlavorFromArmor(armorText)
			require.Error(t, err)
			require.ErrorContains(t, err, "too short")
			require.ErrorContains(t, err, "old fmt")
			// The old-format path is wrapped by the caller for context.
			require.ErrorContains(t, err, "failed to parse old-format packet")
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

func TestDetectFlavorFromReader_BasicFunctionality(t *testing.T) {
	t.Parallel()

	armorLines := []string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		"xgEE",
		"=A4sP",
		"-----END PGP PUBLIC KEY BLOCK-----",
	}
	armor := strings.Join(armorLines, "\n") + "\n"

	reader := strings.NewReader(armor)

	result, err := whichpgp.DetectFlavorFromReader(reader)
	require.NoError(t, err)

	assert.Equal(t, whichpgp.FlavorLibrePGP, result.Flavor)
	assert.Equal(t, uint8(4), result.PacketVersion)
}

func TestDetectFlavorFromReader_ErrorStream(t *testing.T) {
	t.Parallel()

	// Create a reader that returns an error
	errorReader := &errorReader{err: assert.AnError}

	_, err := whichpgp.DetectFlavorFromReader(errorReader)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read stream")
}

func TestDetectFlavorFromReader_LargeStream(t *testing.T) {
	t.Parallel()

	// Create a large stream with the armor at the beginning
	armorLines := []string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		"xgEE",
		"=A4sP",
		"-----END PGP PUBLIC KEY BLOCK-----",
	}
	armor := strings.Join(armorLines, "\n") + "\n"

	// Add some padding to simulate a larger stream
	padding := strings.Repeat("# This is padding\n", 100)
	fullContent := armor + padding

	reader := strings.NewReader(fullContent)

	result, err := whichpgp.DetectFlavorFromReader(reader, whichpgp.WithBufferSize(64))
	require.NoError(t, err)

	assert.Equal(t, whichpgp.FlavorLibrePGP, result.Flavor)
	assert.Equal(t, uint8(4), result.PacketVersion)
}

func TestDetectFlavorFromReader_WithOptions(t *testing.T) {
	t.Parallel()

	armorLines := []string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		"xgEE",
		"=A4sP",
		"-----END PGP PUBLIC KEY BLOCK-----",
	}
	armor := strings.Join(armorLines, "\n") + "\n"

	t.Run("with buffer size", func(t *testing.T) {
		t.Parallel()

		reader := strings.NewReader(armor)

		result, err := whichpgp.DetectFlavorFromReader(reader, whichpgp.WithBufferSize(16))
		require.NoError(t, err)

		assert.Equal(t, whichpgp.FlavorLibrePGP, result.Flavor)
	})

	t.Run("with max bytes limit exceeded", func(t *testing.T) {
		t.Parallel()

		reader := strings.NewReader(armor)

		_, err := whichpgp.DetectFlavorFromReader(reader, whichpgp.WithMaxBytes(10))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too large")
	})
}

func TestFlavor_String(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		flavor   whichpgp.Flavor
		expected string
	}{
		{
			name:     "FlavorUnknown",
			flavor:   whichpgp.FlavorUnknown,
			expected: "Unknown",
		},
		{
			name:     "FlavorLibrePGP",
			flavor:   whichpgp.FlavorLibrePGP,
			expected: "LibrePGP",
		},
		{
			name:     "FlavorOpenPGP",
			flavor:   whichpgp.FlavorOpenPGP,
			expected: "OpenPGP",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actual := tc.flavor.String()
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestOptions_ValidationAndDefaults(t *testing.T) {
	t.Parallel()

	armorLines := []string{
		"-----BEGIN PGP PUBLIC KEY BLOCK-----",
		"",
		"xgEE",
		"=A4sP",
		"-----END PGP PUBLIC KEY BLOCK-----",
	}
	armor := strings.Join(armorLines, "\n") + "\n"

	t.Run("invalid options should be ignored", func(t *testing.T) {
		t.Parallel()

		// Invalid values should be ignored and defaults used
		result, err := whichpgp.DetectFlavorFromBytes(
			[]byte(armor),
			whichpgp.WithMaxBytes(-1),    // invalid, should be ignored
			whichpgp.WithScanCap(0),      // invalid, should be ignored
			whichpgp.WithBufferSize(-10), // invalid, should be ignored
		)
		require.NoError(t, err)

		assert.Equal(t, whichpgp.FlavorLibrePGP, result.Flavor)
	})

	t.Run("multiple options should work together", func(t *testing.T) {
		t.Parallel()

		result, err := whichpgp.DetectFlavorFromBytes(
			[]byte(armor),
			whichpgp.WithMaxBytes(1024*1024),
			whichpgp.WithStrictCRC(false),
			whichpgp.WithScanCap(512*1024),
			whichpgp.WithBufferSize(32*1024),
		)
		require.NoError(t, err)

		assert.Equal(t, whichpgp.FlavorLibrePGP, result.Flavor)
	})
}

func TestResult_String(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		result   whichpgp.Result
		expected string
	}{
		{
			name: "LibrePGP v4",
			result: whichpgp.Result{
				Flavor:        whichpgp.FlavorLibrePGP,
				PacketVersion: 4,
			},
			expected: "LibrePGP (v4)",
		},
		{
			name: "LibrePGP v5",
			result: whichpgp.Result{
				Flavor:        whichpgp.FlavorLibrePGP,
				PacketVersion: 5,
			},
			expected: "LibrePGP (v5)",
		},
		{
			name: "OpenPGP v6",
			result: whichpgp.Result{
				Flavor:        whichpgp.FlavorOpenPGP,
				PacketVersion: 6,
			},
			expected: "OpenPGP (v6 / RFC 9580)",
		},
		{
			name: "Unknown flavor",
			result: whichpgp.Result{
				Flavor:        whichpgp.FlavorUnknown,
				PacketVersion: 99,
			},
			expected: "Unknown (v99)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actual := tc.result.String()
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestDetectFlavorFromArmor_MalformedInputs(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		armor       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "missing BEGIN marker",
			armor:       "invalid armor\n-----END PGP PUBLIC KEY BLOCK-----\n",
			expectError: true,
			errorMsg:    "BEGIN line not found",
		},
		{
			name:        "missing END marker",
			armor:       "-----BEGIN PGP PUBLIC KEY BLOCK-----\ninvalid\n",
			expectError: true,
			errorMsg:    "END line not found",
		},
		{
			name:        "empty armor block",
			armor:       "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n-----END PGP PUBLIC KEY BLOCK-----\n",
			expectError: true,
			errorMsg:    "empty data",
		},
		{
			name:        "invalid base64",
			armor:       "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n!@#$%\n-----END PGP PUBLIC KEY BLOCK-----\n",
			expectError: true,
			errorMsg:    "base64 decode",
		},
		{
			name:        "corrupted CRC",
			armor:       "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxgEE\n=AAAA\n-----END PGP PUBLIC KEY BLOCK-----\n",
			expectError: true,
			errorMsg:    "armor CRC24 mismatch",
		},
		{
			name:        "malformed CRC line",
			armor:       "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxgEE\n=invalid\n-----END PGP PUBLIC KEY BLOCK-----\n",
			expectError: false, // CRC is ignored if malformed
			errorMsg:    "",
		},
		{
			name:        "no blank line after headers",
			armor:       "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: test\nxgEE\n-----END PGP PUBLIC KEY BLOCK-----\n",
			expectError: true,
			errorMsg:    "unexpected EOF in armor headers",
		},
		{
			name:        "binary data instead of base64",
			armor:       "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n\x00\x01\x02\x03\n-----END PGP PUBLIC KEY BLOCK-----\n",
			expectError: true,
			errorMsg:    "base64 decode",
		},
		{
			name:        "extremely short base64",
			armor:       "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nx\n-----END PGP PUBLIC KEY BLOCK-----\n",
			expectError: true,
			errorMsg:    "base64 decode",
		},
		{
			name:        "base64 with invalid characters",
			armor:       "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nabc!@#\n-----END PGP PUBLIC KEY BLOCK-----\n",
			expectError: true,
			errorMsg:    "base64 decode",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := whichpgp.DetectFlavorFromArmor(tc.armor)

			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDetectFlavorFromArmor_CorruptedPackets(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		payload     []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "invalid packet header (no high bit set)",
			payload:     []byte{0x00, 0x01, 0x04}, // high bit not set
			expectError: true,
			errorMsg:    "not a packet header",
		},
		{
			name:        "truncated new-format header",
			payload:     []byte{0xC0 | 6}, // missing length octet
			expectError: true,
			errorMsg:    "need length octet",
		},
		{
			name:        "truncated old-format header",
			payload:     []byte{0x80 | (6 << 2)}, // missing length
			expectError: true,
			errorMsg:    "need 1-octet length",
		},
		{
			name:        "unsupported old-format length type (indeterminate)",
			payload:     []byte{0x80 | (6 << 2) | 3, 0x00}, // length type 3 (indeterminate)
			expectError: true,
			errorMsg:    "indeterminate old-format length not supported",
		},
		{
			name:        "packet version 0 (invalid)",
			payload:     []byte{0xC0 | 6, 0x01, 0x00}, // version 0
			expectError: true,
			errorMsg:    "invalid packet version 0",
		},
		{
			name:        "truncated packet body (new format)",
			payload:     []byte{0xC0 | 6, 0x05, 0x04}, // claims 5 bytes but only 1
			expectError: true,
			errorMsg:    "truncated packet",
		},
		{
			name:        "truncated packet body (old format)",
			payload:     []byte{0x98, 0x05, 0x04}, // claims 5 bytes but only 1
			expectError: true,
			errorMsg:    "truncated packet",
		},
		{
			name:        "invalid partial length octet",
			payload:     []byte{0xC0 | 6, 200, 0x00}, // invalid partial length
			expectError: true,
			errorMsg:    "truncated packet", // Actually truncated
		},
		{
			name:        "suspiciously large body length",
			payload:     []byte{0xC0 | 6, 255, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF}, // 2^31 bytes
			expectError: true,
			errorMsg:    "truncated packet", // Actually truncated due to size check
		},
		{
			name:        "non-tag6 packet only",
			payload:     []byte{0xC0 | 1, 0x01, 0x00}, // tag 1 (not 6 or 14)
			expectError: true,
			errorMsg:    "no tag 6/14 packet found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			armor := armor(tc.payload)
			_, _, err := whichpgp.DetectFlavorFromArmor(armor)

			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

//nolint:dupword // duplicate armor lines are intentional here
func TestDetectFlavorFromArmor_EdgeCaseValidArmor(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		armor    string
		expected string
	}{
		{
			name: "multiple headers",
			armor: `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: First comment
Version: Test
Comment: Second comment
Hash: SHA256

xgEE
=A4sP
-----END PGP PUBLIC KEY BLOCK-----
`,
			expected: "LibrePGP (v4)",
		},
		{
			name: "extra whitespace in base64",
			armor: `-----BEGIN PGP PUBLIC KEY BLOCK-----

x g E E
= A 4 s P
-----END PGP PUBLIC KEY BLOCK-----
`,
			expected: "LibrePGP (v4)",
		},
		{
			name:     "mixed EOL styles (CRLF and LF)",
			armor:    "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n\r\nxgEE\r\n=A4sP\r\n-----END PGP PUBLIC KEY BLOCK-----\n",
			expected: "LibrePGP (v4)",
		},
		{
			name: "multiple blank lines",
			armor: `-----BEGIN PGP PUBLIC KEY BLOCK-----



xgEE


=A4sP


-----END PGP PUBLIC KEY BLOCK-----
`,
			expected: "LibrePGP (v4)",
		},
		{
			name: "header with special characters",
			armor: `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: Test with spaces and symbols: !@#$%^&*()
Version: 1.0.0

xgEE
=A4sP
-----END PGP PUBLIC KEY BLOCK-----
`,
			expected: "LibrePGP (v4)",
		},
		{
			name: "minimal armor with CRC",
			armor: `-----BEGIN PGP PUBLIC KEY BLOCK-----

xgEE
=A4sP
-----END PGP PUBLIC KEY BLOCK-----`,
			expected: "LibrePGP (v4)",
		},
		{
			name: "armor with unicode in headers",
			armor: `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: Test with unicode: テスト 🚀
Version: 1.0

xgEE
=A4sP
-----END PGP PUBLIC KEY BLOCK-----
`,
			expected: "LibrePGP (v4)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			flavor, ver, err := whichpgp.DetectFlavorFromArmor(tc.armor)
			require.NoError(t, err)
			require.Equal(t, 4, ver)
			assert.Equal(t, tc.expected, flavor)
		})
	}
}

func TestDetectFlavorFromArmor_DoSPrevention(t *testing.T) {
	t.Parallel()

	t.Run("extremely large base64 payload", func(t *testing.T) {
		t.Parallel()

		// Create base64 that would decode to >8MiB (default max)
		// Each base64 char represents ~6 bits, so ~12MiB base64 -> ~9MiB decoded
		largeB64 := strings.Repeat("A", 12*1024*1024) // 12MiB of 'A's

		armor := fmt.Sprintf(`-----BEGIN PGP PUBLIC KEY BLOCK-----

%s
-----END PGP PUBLIC KEY BLOCK-----
`, largeB64)

		_, _, err := whichpgp.DetectFlavorFromArmor(armor)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too large")
	})

	t.Run("large base64 with custom max bytes", func(t *testing.T) {
		t.Parallel()

		// Test with custom max bytes limit
		largeB64 := strings.Repeat("A", 100*1024) // 100KiB

		armor := fmt.Sprintf(`-----BEGIN PGP PUBLIC KEY BLOCK-----

%s
-----END PGP PUBLIC KEY BLOCK-----
`, largeB64)

		// Should fail with small limit
		_, err := whichpgp.DetectFlavorFromBytes([]byte(armor), whichpgp.WithMaxBytes(50*1024))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too large")

		// Should pass with larger limit (but invalid packet)
		_, err = whichpgp.DetectFlavorFromBytes([]byte(armor), whichpgp.WithMaxBytes(200*1024))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a packet header") // Invalid packet structure
	})

	t.Run("pathological packet sequence", func(t *testing.T) {
		t.Parallel()

		// Create many small invalid packets to test scanning limits
		var payload []byte
		for range 1000 {
			// Invalid packet headers
			payload = append(payload, 0x00, 0x01, 0x02)
		}

		armor := armor(payload)

		_, _, err := whichpgp.DetectFlavorFromArmor(armor)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not a packet header") // First invalid packet causes error
	})

	t.Run("deep partial length nesting", func(t *testing.T) {
		t.Parallel()

		// Create deeply nested partial lengths (but within scan cap)
		payload := []byte{0xC0 | 6, 224} // partial length start
		for range 10 {
			payload = append(payload, 224) // nested partial
		}

		payload = append(payload, 1, 0x04) // final one-octet with version

		armor := armor(payload)

		require.NotPanics(t, func() {
			_, _, err := whichpgp.DetectFlavorFromArmor(armor)

			require.NoError(t, err)
		})
	})

	t.Run("scan cap exceeded", func(t *testing.T) {
		t.Parallel()

		// Create payload larger than default scan cap (4MiB)
		// Fill with non-tag6 packets to force scanning to continue
		payload := make([]byte, 5*1024*1024) // 5MiB
		for i := 0; i < len(payload); i += 3 {
			payload[i] = 0xC0 | 1 // tag 1 packet
			if i+1 < len(payload) {
				payload[i+1] = 0x01 // length
			}

			if i+2 < len(payload) {
				payload[i+2] = 0x00 // dummy data
			}
		}

		armor := armor(payload)

		_, _, err := whichpgp.DetectFlavorFromArmor(armor)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scan cap reached")
	})

	t.Run("custom scan cap", func(t *testing.T) {
		t.Parallel()

		// Test with custom scan cap
		payload := make([]byte, 10*1024) // 10KiB of non-tag6 packets
		for i := 0; i < len(payload); i += 3 {
			payload[i] = 0xC0 | 1
			if i+1 < len(payload) {
				payload[i+1] = 0x01
			}

			if i+2 < len(payload) {
				payload[i+2] = 0x00
			}
		}

		armor := armor(payload)

		// Should fail with small scan cap
		_, err := whichpgp.DetectFlavorFromBytes([]byte(armor), whichpgp.WithScanCap(1024))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "scan cap reached")

		// Should succeed with larger scan cap (but still invalid packet)
		_, err = whichpgp.DetectFlavorFromBytes([]byte(armor), whichpgp.WithScanCap(20*1024))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "need length octet") // Invalid packet structure
	})
}
