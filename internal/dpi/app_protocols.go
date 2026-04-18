// Package dpi — Application layer protocol parsers
package dpi

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

// ═══════════════════════════════════════════════════════════════════════════
// DNS
// ═══════════════════════════════════════════════════════════════════════════

type DNSPacket struct {
	ID        uint16
	IsQuery   bool
	Opcode    uint8
	RCode     uint8
	QDCount   uint16
	ANCount   uint16
	Questions []DNSQuestion
	Answers   []DNSResource

	// Threat indicators
	Entropy       float64 // >4.0 suggests DGA/tunneling
	IsTunneling   bool    // heuristic
	LongestLabel  int
	HasTXT        bool
}

type DNSQuestion struct {
	Name  string
	Type  uint16 // 1=A, 28=AAAA, 15=MX, 16=TXT, etc.
	Class uint16
}

type DNSResource struct {
	Name string
	Type uint16
	Data string
}

func ParseDNS(data []byte) *DNSPacket {
	if len(data) < 12 {
		return nil
	}

	pkt := &DNSPacket{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		IsQuery: data[2]&0x80 == 0,
		Opcode:  (data[2] >> 3) & 0x0F,
		RCode:   data[3] & 0x0F,
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
	}

	offset := 12
	for i := uint16(0); i < pkt.QDCount && offset < len(data); i++ {
		name, n := readDNSName(data, offset)
		offset += n
		if offset+4 > len(data) {
			break
		}

		q := DNSQuestion{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
			Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		}
		pkt.Questions = append(pkt.Questions, q)
		offset += 4

		if q.Type == 16 {
			pkt.HasTXT = true
		}

		// Detect longest label
		for _, lbl := range strings.Split(name, ".") {
			if len(lbl) > pkt.LongestLabel {
				pkt.LongestLabel = len(lbl)
			}
		}

		// Shannon entropy for DGA detection
		pkt.Entropy = shannonEntropy(name)
		if pkt.Entropy > 4.0 || pkt.LongestLabel > 50 {
			pkt.IsTunneling = true
		}
	}

	return pkt
}

// readDNSName reads a DNS name starting at offset, handling compression.
func readDNSName(data []byte, offset int) (string, int) {
	var parts []string
	start := offset
	jumped := false
	bytesRead := 0

	for offset < len(data) {
		l := int(data[offset])
		if l == 0 {
			offset++
			bytesRead++
			break
		}
		if l&0xC0 == 0xC0 { // compression pointer
			if offset+1 >= len(data) {
				break
			}
			newOff := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if !jumped {
				bytesRead += 2
			}
			offset = newOff
			jumped = true
			continue
		}
		if offset+1+l > len(data) {
			break
		}
		parts = append(parts, string(data[offset+1:offset+1+l]))
		offset += 1 + l
		if !jumped {
			bytesRead += 1 + l
		}
	}

	_ = start
	return strings.Join(parts, "."), bytesRead
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	for _, c := range s {
		freq[c]++
	}
	h := 0.0
	n := float64(len(s))
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP
// ═══════════════════════════════════════════════════════════════════════════

type HTTPPacket struct {
	IsRequest  bool
	Method     string
	URI        string
	Version    string
	StatusCode int
	Headers    map[string]string

	// Threat indicators
	UserAgent    string
	Host         string
	HasSQLi      bool // simple heuristic
	HasXSS       bool
	SuspiciousUA bool
}

func ParseHTTP(data []byte) *HTTPPacket {
	if len(data) < 10 {
		return nil
	}

	// Find first line
	crlf := bytes.Index(data, []byte("\r\n"))
	if crlf < 0 {
		return nil
	}

	firstLine := string(data[:crlf])
	parts := strings.Fields(firstLine)
	if len(parts) < 3 {
		return nil
	}

	pkt := &HTTPPacket{
		Headers: make(map[string]string),
	}

	// Request or response?
	if strings.HasPrefix(parts[0], "HTTP/") {
		pkt.IsRequest = false
		pkt.Version = parts[0]
		fmt.Sscanf(parts[1], "%d", &pkt.StatusCode)
	} else {
		pkt.IsRequest = true
		pkt.Method = parts[0]
		pkt.URI = parts[1]
		pkt.Version = parts[2]

		// SQLi heuristic
		lowURI := strings.ToLower(pkt.URI)
		sqliPatterns := []string{"union select", "' or 1=1", "'--", "/*", "xp_", "waitfor delay"}
		for _, p := range sqliPatterns {
			if strings.Contains(lowURI, p) {
				pkt.HasSQLi = true
				break
			}
		}

		// XSS heuristic
		xssPatterns := []string{"<script", "javascript:", "onerror=", "onload="}
		for _, p := range xssPatterns {
			if strings.Contains(lowURI, p) {
				pkt.HasXSS = true
				break
			}
		}
	}

	// Parse headers
	rest := data[crlf+2:]
	lines := bytes.Split(rest, []byte("\r\n"))
	for _, line := range lines {
		if len(line) == 0 {
			break
		}
		colon := bytes.Index(line, []byte(":"))
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(string(line[:colon]))
		val := strings.TrimSpace(string(line[colon+1:]))
		pkt.Headers[strings.ToLower(key)] = val
	}

	pkt.UserAgent = pkt.Headers["user-agent"]
	pkt.Host = pkt.Headers["host"]

	// Suspicious UAs
	badUAs := []string{"sqlmap", "nikto", "nmap", "masscan", "metasploit", "burp", "hydra"}
	lowUA := strings.ToLower(pkt.UserAgent)
	for _, bad := range badUAs {
		if strings.Contains(lowUA, bad) {
			pkt.SuspiciousUA = true
			break
		}
	}

	return pkt
}

// ═══════════════════════════════════════════════════════════════════════════
// TLS/SSL — JA3 fingerprinting
// ═══════════════════════════════════════════════════════════════════════════

type TLSPacket struct {
	ContentType   uint8 // 22 = handshake
	Version       uint16
	HandshakeType uint8 // 1 = ClientHello, 2 = ServerHello

	// ClientHello fields
	SNI            string // Server Name Indication (domain)
	CipherSuites   []uint16
	Extensions     []uint16
	EllipticCurves []uint16
	ECPointFormats []uint8

	// JA3 fingerprint (md5 of ClientHello parameters)
	JA3       string
	JA3Hash   string
}

func ParseTLS(data []byte) *TLSPacket {
	if len(data) < 5 {
		return nil
	}

	pkt := &TLSPacket{
		ContentType: data[0],
		Version:     binary.BigEndian.Uint16(data[1:3]),
	}

	// Only handshake
	if pkt.ContentType != 0x16 {
		return pkt
	}

	recordLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recordLen {
		return pkt
	}

	hs := data[5 : 5+recordLen]
	if len(hs) < 4 {
		return pkt
	}

	pkt.HandshakeType = hs[0]

	// Only ClientHello has JA3
	if pkt.HandshakeType != 1 {
		return pkt
	}

	// Skip: type(1) + length(3) + version(2) + random(32) = 38 bytes
	if len(hs) < 38 {
		return pkt
	}

	clientVersion := binary.BigEndian.Uint16(hs[4:6])
	offset := 38

	// Session ID
	if offset >= len(hs) {
		return pkt
	}
	sessionLen := int(hs[offset])
	offset += 1 + sessionLen

	// Cipher Suites
	if offset+2 > len(hs) {
		return pkt
	}
	cipherLen := int(binary.BigEndian.Uint16(hs[offset : offset+2]))
	offset += 2
	if offset+cipherLen > len(hs) {
		return pkt
	}
	for i := 0; i < cipherLen; i += 2 {
		if offset+i+2 > len(hs) {
			break
		}
		cipher := binary.BigEndian.Uint16(hs[offset+i : offset+i+2])
		// Filter GREASE values
		if !isGREASE(cipher) {
			pkt.CipherSuites = append(pkt.CipherSuites, cipher)
		}
	}
	offset += cipherLen

	// Compression Methods
	if offset >= len(hs) {
		return pkt
	}
	compLen := int(hs[offset])
	offset += 1 + compLen

	// Extensions
	if offset+2 > len(hs) {
		return pkt
	}
	extLen := int(binary.BigEndian.Uint16(hs[offset : offset+2]))
	offset += 2

	extEnd := offset + extLen
	for offset+4 <= extEnd && offset+4 <= len(hs) {
		extType := binary.BigEndian.Uint16(hs[offset : offset+2])
		extDataLen := int(binary.BigEndian.Uint16(hs[offset+2 : offset+4]))
		offset += 4

		if !isGREASE(extType) {
			pkt.Extensions = append(pkt.Extensions, extType)
		}

		// SNI extension
		if extType == 0x0000 && extDataLen > 5 {
			if offset+5 <= len(hs) {
				sniLen := int(binary.BigEndian.Uint16(hs[offset+3 : offset+5]))
				if offset+5+sniLen <= len(hs) {
					pkt.SNI = string(hs[offset+5 : offset+5+sniLen])
				}
			}
		}

		// Elliptic Curves extension (10)
		if extType == 0x000a && extDataLen > 2 {
			if offset+2 <= len(hs) {
				ecLen := int(binary.BigEndian.Uint16(hs[offset : offset+2]))
				for i := 0; i < ecLen && offset+2+i+2 <= len(hs); i += 2 {
					c := binary.BigEndian.Uint16(hs[offset+2+i : offset+4+i])
					if !isGREASE(c) {
						pkt.EllipticCurves = append(pkt.EllipticCurves, c)
					}
				}
			}
		}

		// EC Point Formats extension (11)
		if extType == 0x000b && extDataLen > 1 {
			if offset+1 <= len(hs) {
				pfLen := int(hs[offset])
				for i := 0; i < pfLen && offset+1+i < len(hs); i++ {
					pkt.ECPointFormats = append(pkt.ECPointFormats, hs[offset+1+i])
				}
			}
		}

		offset += extDataLen
	}

	// Build JA3
	ja3 := buildJA3(clientVersion, pkt.CipherSuites, pkt.Extensions, pkt.EllipticCurves, pkt.ECPointFormats)
	pkt.JA3 = ja3
	h := md5.Sum([]byte(ja3))
	pkt.JA3Hash = hex.EncodeToString(h[:])

	return pkt
}

func buildJA3(version uint16, ciphers, exts, curves []uint16, points []uint8) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%d,", version))

	// Ciphers
	for i, c := range ciphers {
		if i > 0 {
			sb.WriteString("-")
		}
		sb.WriteString(fmt.Sprintf("%d", c))
	}
	sb.WriteString(",")

	// Extensions
	for i, e := range exts {
		if i > 0 {
			sb.WriteString("-")
		}
		sb.WriteString(fmt.Sprintf("%d", e))
	}
	sb.WriteString(",")

	// Curves
	for i, c := range curves {
		if i > 0 {
			sb.WriteString("-")
		}
		sb.WriteString(fmt.Sprintf("%d", c))
	}
	sb.WriteString(",")

	// Point formats
	for i, p := range points {
		if i > 0 {
			sb.WriteString("-")
		}
		sb.WriteString(fmt.Sprintf("%d", p))
	}

	return sb.String()
}

// GREASE values are used to prevent ossification; exclude from JA3.
var greaseValues = map[uint16]bool{
	0x0a0a: true, 0x1a1a: true, 0x2a2a: true, 0x3a3a: true,
	0x4a4a: true, 0x5a5a: true, 0x6a6a: true, 0x7a7a: true,
	0x8a8a: true, 0x9a9a: true, 0xaaaa: true, 0xbaba: true,
	0xcaca: true, 0xdada: true, 0xeaea: true, 0xfafa: true,
}

func isGREASE(v uint16) bool {
	return greaseValues[v]
}

// ═══════════════════════════════════════════════════════════════════════════
// SSH
// ═══════════════════════════════════════════════════════════════════════════

type SSHPacket struct {
	Version    string // "SSH-2.0"
	SoftwareID string // e.g., "OpenSSH_8.9"
}

func ParseSSH(data []byte) *SSHPacket {
	if len(data) < 4 || !bytes.HasPrefix(data, []byte("SSH-")) {
		return nil
	}
	end := bytes.Index(data, []byte("\r\n"))
	if end < 0 {
		end = len(data)
		if end > 255 {
			end = 255
		}
	}
	banner := string(data[:end])
	parts := strings.SplitN(banner, "-", 3)
	pkt := &SSHPacket{}
	if len(parts) >= 2 {
		pkt.Version = parts[0] + "-" + parts[1]
	}
	if len(parts) == 3 {
		pkt.SoftwareID = parts[2]
	}
	return pkt
}
