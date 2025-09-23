// Package whichpgp detects the PGP flavor (OpenPGP v6 vs LibrePGP v4/v5)
// from ASCII-armored public key blocks.
package whichpgp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/pkg/errors"
)

// ============================================================================
//  Constants
// ============================================================================

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
//  Types
// ============================================================================

// Flavor represents the PGP implementation family.
type Flavor uint8

const (
	// FlavorUnknown indicates an unrecognized or unsupported PGP flavor.
	FlavorUnknown Flavor = iota
	// FlavorLibrePGP represents LibrePGP (packet versions 4 and 5).
	FlavorLibrePGP
	// FlavorOpenPGP represents OpenPGP v6 (RFC 9580).
	FlavorOpenPGP
)

// String returns the human-readable name of the PGP flavor.
func (f Flavor) String() string {
	switch f {
	case FlavorLibrePGP:
		return "LibrePGP"
	case FlavorOpenPGP:
		return "OpenPGP"
	case FlavorUnknown:
		return "Unknown"
	default:
		return "Unknown"
	}
}

// Result contains the detection results from PGP armor analysis.
type Result struct {
	// Flavor indicates the PGP implementation family.
	Flavor Flavor
	// PacketVersion is the public-key packet version (4, 5, or 6).
	PacketVersion uint8
}

// String returns a human-readable description of the detection result.
func (r Result) String() string {
	switch r.Flavor {
	case FlavorLibrePGP:
		return fmt.Sprintf("LibrePGP (v%d)", r.PacketVersion)
	case FlavorOpenPGP:
		return fmt.Sprintf("OpenPGP (v%d / RFC 9580)", r.PacketVersion)
	case FlavorUnknown:
		return fmt.Sprintf("Unknown (v%d)", r.PacketVersion)
	default:
		return fmt.Sprintf("Unknown (v%d)", r.PacketVersion)
	}
}

// ============================================================================
//  Options
// ============================================================================

// Option configures PGP detection behavior.
type Option func(*config)

// config holds internal configuration for detection functions.
type config struct {
	maxBytes   int
	strictCRC  bool
	scanCap    int
	bufferSize int
}

// defaultConfig returns the default configuration.
func defaultConfig() *config {
	const (
		defaultSizeMultiplier = 2
		defaultBufferSizeKB   = 64
		kibibyte              = 1024
	)

	return &config{
		maxBytes:   maxPacketScanBytes * defaultSizeMultiplier, // 8 MiB default
		strictCRC:  false,
		scanCap:    maxPacketScanBytes,             // 4 MiB default
		bufferSize: defaultBufferSizeKB * kibibyte, // 64 KiB buffer for streaming
	}
}

// WithMaxBytes sets the maximum size limit for processing data.
// This prevents DoS attacks from extremely large inputs.
func WithMaxBytes(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.maxBytes = n
		}
	}
}

// WithStrictCRC enables strict CRC-24 validation.
// When enabled, missing CRC lines will cause errors.
func WithStrictCRC(strict bool) Option {
	return func(c *config) {
		c.strictCRC = strict
	}
}

// WithScanCap sets the packet scanning limit.
// This controls how much data is scanned when looking for public key packets.
func WithScanCap(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.scanCap = n
		}
	}
}

// WithBufferSize sets the buffer size for streaming operations.
func WithBufferSize(n int) Option {
	return func(c *config) {
		if n > 0 {
			c.bufferSize = n
		}
	}
}

// ============================================================================
//  API/Public Functions
// ============================================================================

// DetectFlavorFromBytes detects the PGP flavor from byte data.
// This is the primary API that supports configuration options.
//
// The function analyzes ASCII-armored public key blocks and returns structured
// results with type-safe flavor identification and packet version information.
//
// Options can be used to customize behavior:
//   - WithMaxBytes(n): Set maximum processing size limit
//   - WithStrictCRC(true): Require CRC-24 validation
//   - WithScanCap(n): Set packet scanning limit
//
// Example:
//
//	result, err := whichpgp.DetectFlavorFromBytes(data, WithStrictCRC(true))
//	if err != nil {
//	    return err
//	}
//	fmt.Printf("Detected: %s\n", result.String())
func DetectFlavorFromBytes(data []byte, opts ...Option) (Result, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	if len(data) > cfg.maxBytes {
		return Result{}, errors.Errorf("input too large (%d bytes, limit %d)", len(data), cfg.maxBytes)
	}

	// Use the existing decode logic with configuration
	raw, err := decodeArmoredWithConfig(string(data), cfg)
	if err != nil {
		return Result{}, err
	}

	ver, err := firstPubkeyVersionWithConfig(raw, cfg)
	if err != nil {
		return Result{}, err
	}

	return makeResult(ver), nil
}

// DetectFlavorFromReader detects the PGP flavor from an io.Reader stream.
// This function supports processing large inputs without loading everything into memory.
//
// The reader is consumed until EOF or the maximum configured size is reached.
// A buffer is used internally for efficient streaming operations.
//
// Example:
//
//	file, err := os.Open("pubkey.asc")
//	if err != nil {
//	    return err
//	}
//	defer file.Close()
//
//	result, err := whichpgp.DetectFlavorFromReader(file, WithMaxBytes(1024*1024))
//	if err != nil {
//	    return err
//	}
//	fmt.Printf("Detected: %s\n", result.String())
func DetectFlavorFromReader(reader io.Reader, opts ...Option) (Result, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	// Read from the stream with size limit
	data := make([]byte, 0, cfg.bufferSize)
	buf := make([]byte, cfg.bufferSize)

	for {
		bytesRead, err := reader.Read(buf)
		if bytesRead > 0 {
			if len(data)+bytesRead > cfg.maxBytes {
				return Result{}, errors.Errorf("stream too large (limit %d bytes)", cfg.maxBytes)
			}

			data = append(data, buf[:bytesRead]...)
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			return Result{}, errors.Wrap(err, "read stream")
		}
	}

	return DetectFlavorFromBytes(data, opts...)
}

// DetectFlavorFromString is a convenience function for string inputs.
// This provides a consistent interface for string-based detection.
func DetectFlavorFromString(data string, opts ...Option) (Result, error) {
	return DetectFlavorFromBytes([]byte(data), opts...)
}

// ============================================================================
//  Compatibility Aliases
// ============================================================================

// DetectFlavorFromArmor detects the PGP flavor from ASCII-armored public key text.
// This function is maintained for backward compatibility.
//
// For new code, prefer DetectFlavorFromBytes() which provides structured results and
// configuration options.
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
	result, err := DetectFlavorFromBytes([]byte(armored))
	if err != nil {
		return "", 0, err
	}

	return result.String(), int(result.PacketVersion), nil
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

// checkCRCWithConfig validates CRC with configuration options.
func checkCRCWithConfig(payload []byte, crcLine string, cfg *config) error {
	if cfg.strictCRC && (crcLine == "" || !strings.HasPrefix(crcLine, "=")) {
		return errors.New("CRC-24 line required but missing")
	}

	return checkCRC(payload, crcLine)
}

// decodeArmoredWithConfig parses ASCII-armored block with configuration.
func decodeArmoredWithConfig(armored string, cfg *config) ([]byte, error) {
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

	payload, err := decodeBase64PayloadWithConfig(b64, cfg)
	if err != nil {
		return nil, err
	}

	err = checkCRCWithConfig(payload, crcLine, cfg)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

// decodeBase64PayloadWithConfig decodes base64 payload with size limits.
func decodeBase64PayloadWithConfig(b64 string, cfg *config) ([]byte, error) {
	// Strip ASCII whitespace that may legally appear inside base64 bodies.
	b64 = compactB64(b64)

	// Pre-decode size guard to avoid large allocations/DoS.
	// Roughly, decoded size <= len(b64) * 3 / 4.
	const (
		b64DecodeNumerator   = 3
		b64DecodeDenominator = 4
	)

	if est := (len(b64) * b64DecodeNumerator) / b64DecodeDenominator; est > cfg.maxBytes {
		return nil, errors.Errorf("armored payload too large (>~%d bytes)", cfg.maxBytes)
	}

	payload, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.Wrap(err, "base64 decode")
	}

	return payload, nil
}

// firstPubkeyVersionWithConfig scans for first public key with configuration.
func firstPubkeyVersionWithConfig(data []byte, cfg *config) (int, error) {
	if len(data) == 0 {
		return 0, errors.New("empty data")
	}

	limit := minInt(len(data), cfg.scanCap)

	for idx := 0; idx < limit; {
		ver, advance, err := processPacketAt(data, idx, 0, 0)
		if err != nil {
			return 0, err
		}

		if ver != 0 {
			return ver, nil
		}

		if advance <= 0 {
			return 0, errors.Errorf("packet parsing made no progress at index %d", idx)
		}

		idx += advance
	}

	// If we stopped because of the scan cap and the input is larger than the cap,
	// surface a dedicated hint so callers know how to react.
	if len(data) > cfg.scanCap && limit == cfg.scanCap {
		return 0, errors.Errorf(
			"scan cap reached (%d bytes) before finding tag 6/14; "+
				"if input is valid, consider increasing scan cap",
			cfg.scanCap,
		)
	}

	return 0, errors.New("no tag 6/14 packet found")
}

// processPacketAt processes a single packet at the given index and returns version, advance, error.
// Returns version=0 if not a target packet, advance>0 to skip to next packet.
func processPacketAt(data []byte, idx int, _ int, _ int) (int, int, error) {
	// Ensure we do not read beyond the slice when accessing data[idx].
	if idx >= len(data) {
		return 0, 0, errors.New("truncated before header")
	}

	oct := data[idx]

	// Bit 7 must be set for packet headers per spec; otherwise bail out.
	if oct&0x80 == 0 {
		return 0, 0, errors.Wrapf(errors.New("not a packet header"), "at %d", idx)
	}

	// New-format vs old-format is indicated by 0x40.
	if (oct & headerNewFormatMask) != 0 { // new-format
		adv, ver, found, parseErr := parseNewFormatPacket(data, idx, int(oct&newFormatTagMask))
		if parseErr != nil {
			return 0, 0, parseErr
		}

		if found {
			return ver, 0, nil
		}

		return 0, adv, nil
	}

	// Old-format header path
	adv, ver, found, parseErr := parseOldFormatPacket(
		data,
		idx,
		int((oct>>shift2)&oldFormatTagMask),
		int(oct&oldFormatLenTypeMask),
	)
	if parseErr != nil {
		return 0, 0, errors.Wrap(parseErr, "failed to parse old-format packet")
	}

	if found {
		return ver, 0, nil
	}

	return 0, adv, nil
}

// makeResult creates a Result from a packet version.
func makeResult(ver int) Result {
	const maxUint8 = 255

	switch ver {
	case versionV6:
		return Result{Flavor: FlavorOpenPGP, PacketVersion: uint8(ver)}
	case versionV5, versionV4:
		return Result{Flavor: FlavorLibrePGP, PacketVersion: uint8(ver)}
	default:
		// Handle potential overflow by capping at max uint8
		packetVer := ver
		if ver > maxUint8 {
			packetVer = maxUint8
		} else if ver < 0 {
			packetVer = 0
		}

		// #nosec G115 -- packetVer is already validated to be within uint8 range
		return Result{Flavor: FlavorUnknown, PacketVersion: uint8(packetVer)}
	}
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
		version := int(data[bodyStart])
		if version == 0 {
			return 0, 0, false, errors.New("invalid packet version 0 (new fmt, partial)")
		}

		return 0, version, true, nil
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

		version := int(data[index+hdrLen])
		if version == 0 {
			return 0, 0, false, errors.New("invalid packet version 0 (new fmt)")
		}

		return 0, version, true, nil
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

		version := int(data[index+hdrLen])
		if version == 0 {
			return 0, 0, false, errors.New("invalid packet version 0 (new fmt)")
		}

		return 0, version, true, nil
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

		version := int(data[index+hdrLen])
		if version == 0 {
			return 0, 0, false, errors.New("invalid packet version 0 (new fmt)")
		}

		return 0, version, true, nil
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

		version := int(data[index+hdrLen])
		if version == 0 {
			return 0, 0, false, errors.New("invalid packet version 0 (old fmt)")
		}

		return 0, version, true, nil
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

		version := int(data[index+hdrLen])
		if version == 0 {
			return 0, 0, false, errors.New("invalid packet version 0 (old fmt)")
		}

		return 0, version, true, nil
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

		version := int(data[index+hdrLen])
		if version == 0 {
			return 0, 0, false, errors.New("invalid packet version 0 (old fmt)")
		}

		return 0, version, true, nil
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
