// Package whichpgp detects the PGP flavor (OpenPGP v6 vs LibrePGP v4/v5)
// from ASCII-armored public key blocks.
package whichpgp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"io"
	"math"
	"strings"

	"github.com/pkg/errors"
)

// Constants for magic numbers and limits.
const (
	// Armor markers (without trailing newline). Some inputs may use CRLF or have
	// trailing spaces; we locate markers without assuming exact EOL style.
	beginMarker = "-----BEGIN PGP PUBLIC KEY BLOCK-----"
	endMarker   = "-----END PGP PUBLIC KEY BLOCK-----"

	// Safety cap for scanning packet bytes to avoid pathological inputs.
	maxPacketScanBytes = 4 * 1024 * 1024

	// Packet/header constants.
	headerNewFormatMask  = 0x40
	newFormatTagMask     = 0x3F
	oldFormatTagMask     = 0x0F
	oldFormatLenTypeMask = 0x03

	// Length encoding thresholds.
	oneOctetThreshold = 192
	twoOctetMax       = 223
	partialMin        = 224
	partialMax        = 254
	fiveOctetMarker   = 255

	// Partial length mask and bounds.
	partialLenMask = 0x1F
	maxPartialExp  = 30

	// CRC-24 constants.
	crc24Init = 0xB704CE
	crc24Poly = 0x1864CFB
	crc24Msb  = 0x1000000
	crcBits   = 8

	// Bit shifts.
	shift2  = 2
	shift8  = 8
	shift16 = 16
	shift24 = 24

	// Packet tags.
	tagPublicKey    = 6
	tagPublicSubkey = 14

	// Old-format length type values.
	oldLen1Octet        = 0
	oldLen2Octet        = 1
	oldLen4Octet        = 2
	oldLenIndeterminate = 3

	// Key versions.
	versionV6 = 6
	versionV5 = 5
	versionV4 = 4
)

// ============================================================================
//  API/Public Functions
// ============================================================================

// DetectFlavorFromArmor detects the PGP flavor from ASCII-armored public key text.
//
// Armor handling:
//   - Armor headers are ignored until a blank/whitespace-only separator line.
//   - The base64 body tolerates embedded ASCII whitespace and optional CRC-24.
//   - If a CRC-24 line is present, it is validated strictly; if missing, it is
//     allowed; if present but invalid, an error is returned.
//
// References: RFC 4880 (ASCII Armor and Armor Checksum, e.g., Section 6.3) and
// RFC 9580.
func DetectFlavorFromArmor(armored string) (string, int, error) {
	raw, err := decodeArmored(armored)
	if err != nil {
		return "", 0, err
	}

	ver, err := firstPubkeyVersion(raw)
	if err != nil {
		return "", 0, err
	}

	switch ver {
	case versionV6:
		return "OpenPGP (v6 / RFC 9580)", versionV6, nil
	case versionV5:
		return "LibrePGP (v5)", versionV5, nil
	case versionV4:
		return "LibrePGP (v4)", versionV4, nil
	default:
		return "Unknown", ver, nil
	}
}

// ============================================================================
//  Private/Internal Functions (ABC order)
// ============================================================================

// checkCRC validates the optional CRC-24 line against the decoded payload.
// Behavior:
//   - If a CRC line ("=xxx") exists and decodes to 3 bytes, validate strictly and
//     return an error on mismatch.
//   - If the CRC line is absent, decoding proceeds without CRC verification.
//   - If the CRC line exists but is malformed (cannot be base64-decoded to 3 bytes),
//     the function silently ignores CRC verification for compatibility.
//
// This matches common OpenPGP armor processing practice. See RFC 4880 (Armor and
// Armor Checksum, e.g., Section 6.3) and RFC 9580 for details.
func checkCRC(payload []byte, crcLine string) error {
	if strings.HasPrefix(crcLine, "=") && len(crcLine) >= 5 {
		crcBytes, err := base64.StdEncoding.DecodeString(crcLine[1:])
		if err == nil && len(crcBytes) == 3 {
			if calc := crc24(payload); !bytes.Equal(calc, crcBytes) {
				return errors.New("armor CRC24 mismatch")
			}
		}
	}

	return nil
}

// compactB64 removes ASCII whitespace characters from a base64 string.
// This is tolerant to inputs that include spaces/tabs/newlines within lines.
func compactB64(input string) string {
	// Fast path: no spaces/tabs/CR/LF present.
	if !strings.ContainsAny(input, " \t\r\n") {
		return input
	}

	// Build a compacted version without allocations for each rune.
	out := make([]byte, 0, len(input))
	for i := range input { // Go 1.22+ integer range
		switch input[i] {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			out = append(out, input[i])
		}
	}

	return string(out)
}

// consumePartialBody advances over a partial-length body and returns total consumed
// bytes. If tag is 6 or 14, the version byte is the first byte of the body.
func consumePartialBody(data []byte, startIndex int, hdrLen int, tag int, lenFirst byte) (int, int, bool, error) {
	bodyStart := startIndex + hdrLen

	chunkLen, ok := partialLenToSize(lenFirst)
	if !ok {
		return 0, 0, false, errors.New("invalid partial length")
	}

	err := ensureRange(data, startIndex, hdrLen+chunkLen)
	if err != nil {
		return 0, 0, false, err
	}

	if tag == tagPublicKey || tag == tagPublicSubkey {
		return 0, int(data[bodyStart]), true, nil
	}

	pos := bodyStart + chunkLen
	totalConsumed := hdrLen + chunkLen

	for {
		if pos >= len(data) {
			return 0, 0, false, errors.New("EOF within partial-length packet")
		}

		lenByte := data[pos]
		// Advance one for the length-octet itself.
		pos++
		totalConsumed++

		var (
			done bool
			err  error
		)

		pos, totalConsumed, done, err = stepPartialChunk(data, startIndex, pos, totalConsumed, lenByte)
		if err != nil {
			return 0, 0, false, err
		}

		if done {
			return totalConsumed, 0, false, nil
		}
		// Otherwise continue looping (another partial chunk)
	}
}

// CRC-24 (OpenPGP), poly 0x1864CFB, init 0xB704CE.
func crc24(data []byte) []byte {
	crc := uint32(crc24Init)
	for _, b := range data {
		crc ^= uint32(b) << shift16
		for range crcBits { // Go 1.22+ integer range
			crc <<= 1
			if (crc & crc24Msb) != 0 {
				crc ^= crc24Poly
			}
		}
	}

	return []byte{byte(crc >> shift16), byte(crc >> shift8), byte(crc)}
}

// decodeArmored parses the ASCII-armored block and returns the raw payload.
func decodeArmored(armored string) ([]byte, error) {
	block, err := findArmorBlock(armored)
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(strings.NewReader(block))

	err = readArmorHeaders(reader)
	if err != nil {
		return nil, err
	}

	b64, crcLine, err := readB64AndCRC(reader)
	if err != nil {
		return nil, err
	}

	payload, err := decodeBase64Payload(b64)
	if err != nil {
		return nil, err
	}

	err = checkCRC(payload, crcLine)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// decodeBase64Payload decodes a concatenated base64 payload string.
func decodeBase64Payload(b64 string) ([]byte, error) {
	// Strip ASCII whitespace that may legally appear inside base64 bodies.
	b64 = compactB64(b64)

	// Pre-decode size guard to avoid large allocations/DoS.
	// Roughly, decoded size <= len(b64) * 3 / 4.
	const (
		b64DecodeNumerator   = 3
		b64DecodeDenominator = 4
		sizeGuardMultiplier  = 2
	)

	if est := (len(b64) * b64DecodeNumerator) / b64DecodeDenominator; est > maxPacketScanBytes*sizeGuardMultiplier {
		return nil, errors.Errorf("armored payload too large (>~%d bytes)", maxPacketScanBytes*sizeGuardMultiplier)
	}

	payload, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.Wrap(err, "base64 decode")
	}

	return payload, nil
}

// ensureRange verifies [start, start+need) fits within data and caps large requests.
// Used by packet parsers to prevent overreads and excessive processing.
func ensureRange(data []byte, start int, need int) error {
	if need < 0 || need > maxPacketScanBytes {
		return errors.Errorf("requested range too large (cap %d bytes)", maxPacketScanBytes)
	}

	if start+need > len(data) {
		return errors.New("truncated packet")
	}

	return nil
}

// findArmorBlock extracts the armored block content between BEGIN/END lines.
func findArmorBlock(src string) (string, error) {
	// Find the BEGIN marker without requiring a specific newline style.
	beginIdx := strings.Index(src, beginMarker)
	if beginIdx < 0 {
		return "", errors.New("BEGIN line not found")
	}

	// Advance to the beginning of the line following the BEGIN marker.
	after := src[beginIdx+len(beginMarker):]
	if len(after) == 0 {
		return "", errors.New("unexpected EOF after BEGIN marker")
	}

	// Skip the remainder of the BEGIN line (including any trailing spaces/tabs)
	// by consuming the next line ending. Prefer LF if present; otherwise CR.
	// This handles both "\n" and "\r\n" by cutting at the LF index.
	if i := strings.IndexByte(after, '\n'); i >= 0 {
		after = after[i+1:]
	} else if j := strings.IndexByte(after, '\r'); j >= 0 {
		after = after[j+1:]
	} else {
		return "", errors.New("no end-of-line after BEGIN marker")
	}

	// Find the END marker anywhere after the body. We do not assume it starts
	// at column 0 nor that it has a specific trailing newline.
	endIdx := strings.Index(after, endMarker)
	if endIdx < 0 {
		return "", errors.New("END line not found")
	}

	return after[:endIdx], nil
}

// firstPubkeyVersion scans the raw packet data for the first public key or subkey
// packet (tag 6 or 14) and returns its version byte.
//
//nolint:cyclop // The packet scanning loop needs several branch cases (new/old format, partial/finite lengths).
func firstPubkeyVersion(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, errors.New("empty data")
	}

	var idx int

	limit := minInt(len(data), maxPacketScanBytes)

	for idx < limit {
		// Ensure we do not read beyond the slice when accessing data[idx].
		if idx >= len(data) {
			return 0, errors.New("truncated before header")
		}

		oct := data[idx]

		// Bit 7 must be set for packet headers per spec; otherwise bail out.
		if oct&0x80 == 0 {
			return 0, errors.Wrapf(errors.New("not a packet header"), "at %d", idx)
		}

		// New-format vs old-format is indicated by 0x40.
		if (oct & headerNewFormatMask) != 0 { // new-format
			adv, ver, found, err := parseNewFormatPacket(data, idx, int(oct&newFormatTagMask))
			if err != nil {
				return 0, err
			}

			if found {
				return ver, nil
			}

			idx += adv

			continue
		}

		// Old-format header path
		adv, ver, found, err := parseOldFormatPacket(
			data,
			idx,
			int((oct>>shift2)&oldFormatTagMask),
			int(oct&oldFormatLenTypeMask),
		)
		if err != nil {
			return 0, errors.Wrap(err, "failed to parse old-format packet")
		}

		if found {
			return ver, nil
		}

		idx += adv
	}

	// If we stopped because of the scan cap and the input is larger than the cap,
	// surface a dedicated hint so callers know how to react.
	if len(data) > maxPacketScanBytes && limit == maxPacketScanBytes {
		return 0, errors.Errorf(
			"scan cap reached (%d bytes) before finding tag 6/14; "+
				"if input is valid, consider increasing scan cap",
			maxPacketScanBytes,
		)
	}

	return 0, errors.New("no tag 6/14 packet found")
}

// minInt returns the smaller of two ints.
func minInt(a, b int) int {
	if a < b {
		return a
	}

	return b
}

// newFmtCaseShort handles l0 < 192 (one-octet body length).
func newFmtCaseShort(data []byte, index int, tag int, lenFirst byte) (int, int, bool, error) {
	bodyLen := int(lenFirst)
	hdrLen := 2

	err := ensureRange(data, index, hdrLen+bodyLen)
	if err != nil {
		return 0, 0, false, err
	}

	if tag == tagPublicKey || tag == tagPublicSubkey {
		// Ensure there is at least 1 byte to read the version.
		if bodyLen < 1 {
			return 0, 0, false, errors.New("public key packet body too short for version (new fmt)")
		}

		return 0, int(data[index+hdrLen]), true, nil
	}

	return hdrLen + bodyLen, 0, false, nil
}

// newFmtCaseTwoOctet handles 192 <= l0 <= 223 (two-octet body length encoding).
func newFmtCaseTwoOctet(data []byte, index int, tag int, lenFirst byte) (int, int, bool, error) {
	if index+2 >= len(data) {
		return 0, 0, false, errors.New("need 2-octet length (new fmt)")
	}

	bodyLen := int(lenFirst-oneOctetThreshold)*(1<<shift8) + int(data[index+2]) + oneOctetThreshold
	hdrLen := 3

	err := ensureRange(data, index, hdrLen+bodyLen)
	if err != nil {
		return 0, 0, false, err
	}

	if tag == tagPublicKey || tag == tagPublicSubkey {
		if bodyLen < 1 {
			return 0, 0, false, errors.New("public key packet body too short for version (new fmt)")
		}

		return 0, int(data[index+hdrLen]), true, nil
	}

	return hdrLen + bodyLen, 0, false, nil
}

// newFmtCaseFiveOctet handles l0 == 255 (five-octet body length encoding).
//
//nolint:dupl // The structure mirrors oldFmtCase4Octet; duplication is intentional for clarity across formats.
func newFmtCaseFiveOctet(data []byte, index int, tag int) (int, int, bool, error) {
	if index+5 >= len(data) {
		return 0, 0, false, errors.New("need 5-octet length (new fmt)")
	}

	bodyLen := int(data[index+2])<<shift24 | int(data[index+3])<<shift16 | int(data[index+4])<<shift8 | int(data[index+5])
	hdrLen := 6

	if bodyLen < 0 || bodyLen > maxPacketScanBytes {
		return 0, 0, false, errors.Errorf("suspiciously large body length (new fmt, cap %d bytes)", maxPacketScanBytes)
	}

	err := ensureRange(data, index, hdrLen+bodyLen)
	if err != nil {
		return 0, 0, false, err
	}

	if tag == tagPublicKey || tag == tagPublicSubkey {
		if bodyLen < 1 {
			return 0, 0, false, errors.New("public key packet body too short for version (new fmt)")
		}

		return 0, int(data[index+hdrLen]), true, nil
	}

	return hdrLen + bodyLen, 0, false, nil
}

// newFmtCasePartial handles partial body lengths (224..254).
func newFmtCasePartial(data []byte, index int, tag int, lenFirst byte) (int, int, bool, error) {
	const newFormatHeaderLen = 2

	return consumePartialBody(data, index, newFormatHeaderLen, tag, lenFirst)
}

// oldFmtCase1Octet is an old format handler for 1-octet body length.
func oldFmtCase1Octet(data []byte, index int, tag int) (int, int, bool, error) {
	if index+1 >= len(data) {
		return 0, 0, false, errors.New("need 1-octet length (old fmt)")
	}

	bodyLen := int(data[index+1])
	hdrLen := 2

	err := ensureRange(data, index, hdrLen+bodyLen)
	if err != nil {
		return 0, 0, false, err
	}

	if tag == tagPublicKey || tag == tagPublicSubkey {
		if bodyLen < 1 {
			return 0, 0, false, errors.New("public key packet body too short for version (old fmt)")
		}

		return 0, int(data[index+hdrLen]), true, nil
	}

	return hdrLen + bodyLen, 0, false, nil
}

func oldFmtCase2Octet(data []byte, index int, tag int) (int, int, bool, error) {
	if index+2 >= len(data) {
		return 0, 0, false, errors.New("need 2-octet length (old fmt)")
	}

	bodyLen := int(data[index+1])<<shift8 | int(data[index+2])
	hdrLen := 3

	err := ensureRange(data, index, hdrLen+bodyLen)
	if err != nil {
		return 0, 0, false, err
	}

	if tag == tagPublicKey || tag == tagPublicSubkey {
		if bodyLen < 1 {
			return 0, 0, false, errors.New("public key packet body too short for version (old fmt)")
		}

		return 0, int(data[index+hdrLen]), true, nil
	}

	return hdrLen + bodyLen, 0, false, nil
}

//nolint:dupl // The structure mirrors newFmtCaseFiveOctet but keep parallel logic for readability.
func oldFmtCase4Octet(data []byte, index int, tag int) (int, int, bool, error) {
	if index+4 >= len(data) {
		return 0, 0, false, errors.New("need 4-octet length (old fmt)")
	}

	bodyLen := int(data[index+1])<<shift24 | int(data[index+2])<<shift16 | int(data[index+3])<<shift8 | int(data[index+4])
	hdrLen := 5

	if bodyLen < 0 || bodyLen > maxPacketScanBytes {
		return 0, 0, false, errors.Errorf("suspiciously large body length (old fmt, cap %d bytes)", maxPacketScanBytes)
	}

	err := ensureRange(data, index, hdrLen+bodyLen)
	if err != nil {
		return 0, 0, false, err
	}

	if tag == tagPublicKey || tag == tagPublicSubkey {
		if bodyLen < 1 {
			return 0, 0, false, errors.New("public key packet body too short for version (old fmt)")
		}

		return 0, int(data[index+hdrLen]), true, nil
	}

	return hdrLen + bodyLen, 0, false, nil
}

// parseNewFormatPacket parses a new-format header at position i.
// Returns bytes to advance, version if found, and found flag.
func parseNewFormatPacket(data []byte, index int, tag int) (int, int, bool, error) {
	if index+1 >= len(data) {
		return 0, 0, false, errors.New("need length octet (new fmt header)")
	}

	lenFirst := data[index+1]
	switch {
	case lenFirst < oneOctetThreshold:
		return newFmtCaseShort(data, index, tag, lenFirst)
	case lenFirst >= oneOctetThreshold && lenFirst <= twoOctetMax:
		return newFmtCaseTwoOctet(data, index, tag, lenFirst)
	case lenFirst == fiveOctetMarker:
		return newFmtCaseFiveOctet(data, index, tag)
	default:
		// Partial body lengths: 224..254
		return newFmtCasePartial(data, index, tag, lenFirst)
	}
}

// parseOldFormatPacket parses an old-format header at position i.
func parseOldFormatPacket(data []byte, index int, tag int, ltype int) (int, int, bool, error) {
	switch ltype {
	case oldLen1Octet:
		return oldFmtCase1Octet(data, index, tag)
	case oldLen2Octet:
		return oldFmtCase2Octet(data, index, tag)
	case oldLen4Octet:
		return oldFmtCase4Octet(data, index, tag)
	case oldLenIndeterminate:
		// Indeterminate length: not expected for transferable public keys
		return 0, 0, false, errors.New("indeterminate old-format length not supported")
	default:
		return 0, 0, false, errors.New("invalid old-format length type")
	}
}

// partialLenToSize converts a partial length octet (224..254) into a chunk size.
// Returns false when the octet is outside spec or unreasonably large.
func partialLenToSize(lenOctet byte) (int, bool) {
	// RFC4880 4.2.2.4: 224..254 => chunk sizes 2^n, n = b & 0x1F
	if lenOctet < partialMin || lenOctet > partialMax {
		return 0, false
	}

	p := int(lenOctet & partialLenMask)
	if p < 0 || p > maxPartialExp {
		return 0, false
	}

	sz := 1 << p
	if sz <= 0 || sz > math.MaxInt/2 {
		return 0, false
	}

	return sz, true
}

// readArmorHeaders consumes optional armor headers until a blank line.
// Tolerance policy:
// - Header lines are treated as opaque (e.g., "Key: value", including "Comment:").
// - A blank or whitespace-only line ends the header section.
// - Multiple blank lines are permitted; the subsequent reader tolerates them.
func readArmorHeaders(reader *bufio.Reader) error {
	for {
		line, err := reader.ReadString('\n')
		if errors.Is(err, io.EOF) {
			return errors.New("unexpected EOF in armor headers")
		}

		line = strings.TrimRight(line, "\r\n")
		// Consider whitespace-only as a header terminator to be lenient about trailing spaces.
		if strings.TrimSpace(line) == "" {
			return nil
		}
		// Header lines are "Key: value" — ignore content
	}
}

// readB64AndCRC reads base64 lines until CRC line (=xxxx) or EOF and returns both.
func readB64AndCRC(reader *bufio.Reader) (string, string, error) {
	var (
		b64buf  strings.Builder
		crcLine string
	)

	for {
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", "", errors.Wrap(err, "read armored body line")
		}

		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "=") && len(trimmed) >= 5 {
			crcLine = trimmed

			break
		}

		if trimmed != "" {
			b64buf.WriteString(trimmed)
		}

		if errors.Is(err, io.EOF) {
			break
		}
	}

	return b64buf.String(), crcLine, nil
}

// stepFinalFiveOctet processes a final chunk with five-octet length (lx == 255).
func stepFinalFiveOctet(data []byte, start int, pos int, totalConsumed int) (int, int, bool, error) {
	if pos+3 >= len(data) {
		return pos, totalConsumed, false, errors.New("need 5-octet length (partial)")
	}

	chunkLen := int(data[pos])<<shift24 | int(data[pos+1])<<shift16 | int(data[pos+2])<<shift8 | int(data[pos+3])
	pos += 4

	totalConsumed += 4
	if chunkLen < 0 || chunkLen > maxPacketScanBytes {
		return pos, totalConsumed, false,
			errors.Errorf("suspiciously large final length (partial, cap %d bytes)", maxPacketScanBytes)
	}

	err := ensureRange(data, start, totalConsumed+chunkLen)
	if err != nil {
		return pos, totalConsumed, false, err
	}

	totalConsumed += chunkLen

	return pos, totalConsumed, true, nil
}

// stepFinalOneOctet processes a final chunk with one-octet length (lx < 192).
func stepFinalOneOctet(data []byte, start int, pos int, totalConsumed int, lenByte byte) (int, int, bool, error) {
	chunkLen := int(lenByte)

	err := ensureRange(data, start, totalConsumed+chunkLen)
	if err != nil {
		return pos, totalConsumed, false, err
	}

	totalConsumed += chunkLen

	return pos, totalConsumed, true, nil
}

// stepFinalTwoOctet processes a final chunk with two-octet length (192..223 encoding).
func stepFinalTwoOctet(data []byte, start int, pos int, totalConsumed int, lenByte byte) (int, int, bool, error) {
	if pos >= len(data) {
		return pos, totalConsumed, false, errors.New("need 2-octet length (partial)")
	}

	chunkLen := int(lenByte-oneOctetThreshold)*(1<<shift8) + int(data[pos]) + oneOctetThreshold
	pos++
	totalConsumed++

	err := ensureRange(data, start, totalConsumed+chunkLen)
	if err != nil {
		return pos, totalConsumed, false, err
	}

	totalConsumed += chunkLen

	return pos, totalConsumed, true, nil
}

// stepIntermediatePartial processes a non-final partial chunk (224..254).
func stepIntermediatePartial(data []byte, start int, pos int, totalConsumed int, lenByte byte) (int, int, bool, error) {
	partialLen, ok := partialLenToSize(lenByte)
	if !ok {
		return pos, totalConsumed, false, errors.New("invalid partial length inside body")
	}

	err := ensureRange(data, start, totalConsumed+partialLen)
	if err != nil {
		return pos, totalConsumed, false, err
	}

	pos += partialLen
	totalConsumed += partialLen

	if totalConsumed > maxPacketScanBytes {
		return pos, totalConsumed, false, errors.Errorf("partial packet too large (cap %d bytes)", maxPacketScanBytes)
	}

	return pos, totalConsumed, false, nil
}

// stepPartialChunk processes a single partial-length step.
// Returns updated pos/totalConsumed and whether this was the final chunk (done).
func stepPartialChunk(data []byte, start int, pos int, totalConsumed int, lenByte byte) (int, int, bool, error) {
	switch {
	case lenByte < oneOctetThreshold:
		return stepFinalOneOctet(data, start, pos, totalConsumed, lenByte)
	case lenByte >= oneOctetThreshold && lenByte <= twoOctetMax:
		return stepFinalTwoOctet(data, start, pos, totalConsumed, lenByte)
	case lenByte == fiveOctetMarker:
		return stepFinalFiveOctet(data, start, pos, totalConsumed)
	default:
		return stepIntermediatePartial(data, start, pos, totalConsumed, lenByte)
	}
}
