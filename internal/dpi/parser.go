// Package dpi implements Deep Packet Inspection for Sentinel-Pi.
// Parses all layers from Ethernet up through application protocols.
package dpi

import (
	"encoding/binary"
	"errors"
	"net"
)

// ═══════════════════════════════════════════════════════════════════════════
// ParsedPacket — Complete dissection of a network packet
// ═══════════════════════════════════════════════════════════════════════════

type ParsedPacket struct {
	// Layer 2
	L2 EthernetHeader

	// Layer 3
	L3Proto string // "IPv4", "IPv6", "ARP"
	IPv4    *IPv4Header
	IPv6    *IPv6Header
	ARP     *ARPHeader

	// Layer 4
	L4Proto string // "TCP", "UDP", "ICMP", "ICMPv6"
	TCP     *TCPHeader
	UDP     *UDPHeader
	ICMP    *ICMPHeader

	// Layer 7 (DPI)
	AppProto string      // "DNS", "HTTP", "TLS", etc.
	App      interface{} // specific protocol struct

	// Payload
	Payload []byte

	// 5-tuple for flow tracking
	FlowKey FlowKey
}

type FlowKey struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// ═══════════════════════════════════════════════════════════════════════════
// Layer 2 — Ethernet
// ═══════════════════════════════════════════════════════════════════════════

type EthernetHeader struct {
	DstMAC    net.HardwareAddr
	SrcMAC    net.HardwareAddr
	EtherType uint16
	VLAN      uint16 // 802.1Q tag if present
}

const (
	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86DD
	EtherTypeARP  = 0x0806
	EtherTypeVLAN = 0x8100
)

func parseEthernet(data []byte) (*EthernetHeader, int, error) {
	if len(data) < 14 {
		return nil, 0, errors.New("ethernet: too short")
	}

	eth := &EthernetHeader{
		DstMAC:    net.HardwareAddr(data[0:6]),
		SrcMAC:    net.HardwareAddr(data[6:12]),
		EtherType: binary.BigEndian.Uint16(data[12:14]),
	}

	offset := 14

	// Handle VLAN tag
	if eth.EtherType == EtherTypeVLAN {
		if len(data) < 18 {
			return nil, 0, errors.New("vlan: truncated")
		}
		eth.VLAN = binary.BigEndian.Uint16(data[14:16]) & 0x0FFF
		eth.EtherType = binary.BigEndian.Uint16(data[16:18])
		offset = 18
	}

	return eth, offset, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Layer 3 — IPv4
// ═══════════════════════════════════════════════════════════════════════════

type IPv4Header struct {
	Version     uint8
	IHL         uint8 // header length / 4
	TOS         uint8
	TotalLength uint16
	ID          uint16
	Flags       uint8
	FragOffset  uint16
	TTL         uint8
	Protocol    uint8
	Checksum    uint16
	SrcIP       net.IP
	DstIP       net.IP
	Options     []byte
}

const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

func parseIPv4(data []byte) (*IPv4Header, int, error) {
	if len(data) < 20 {
		return nil, 0, errors.New("ipv4: too short")
	}

	ihl := (data[0] & 0x0F) * 4
	if ihl < 20 || int(ihl) > len(data) {
		return nil, 0, errors.New("ipv4: invalid IHL")
	}

	ip := &IPv4Header{
		Version:     data[0] >> 4,
		IHL:         data[0] & 0x0F,
		TOS:         data[1],
		TotalLength: binary.BigEndian.Uint16(data[2:4]),
		ID:          binary.BigEndian.Uint16(data[4:6]),
		Flags:       data[6] >> 5,
		FragOffset:  binary.BigEndian.Uint16(data[6:8]) & 0x1FFF,
		TTL:         data[8],
		Protocol:    data[9],
		Checksum:    binary.BigEndian.Uint16(data[10:12]),
		SrcIP:       net.IP(data[12:16]),
		DstIP:       net.IP(data[16:20]),
	}

	if ihl > 20 {
		ip.Options = data[20:ihl]
	}

	return ip, int(ihl), nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Layer 3 — IPv6
// ═══════════════════════════════════════════════════════════════════════════

type IPv6Header struct {
	Version      uint8
	TrafficClass uint8
	FlowLabel    uint32
	PayloadLen   uint16
	NextHeader   uint8
	HopLimit     uint8
	SrcIP        net.IP
	DstIP        net.IP
}

func parseIPv6(data []byte) (*IPv6Header, int, error) {
	if len(data) < 40 {
		return nil, 0, errors.New("ipv6: too short")
	}

	ip := &IPv6Header{
		Version:      data[0] >> 4,
		TrafficClass: ((data[0] & 0x0F) << 4) | (data[1] >> 4),
		FlowLabel:    binary.BigEndian.Uint32(data[0:4]) & 0x000FFFFF,
		PayloadLen:   binary.BigEndian.Uint16(data[4:6]),
		NextHeader:   data[6],
		HopLimit:     data[7],
		SrcIP:        net.IP(data[8:24]),
		DstIP:        net.IP(data[24:40]),
	}

	return ip, 40, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Layer 3 — ARP
// ═══════════════════════════════════════════════════════════════════════════

type ARPHeader struct {
	HardwareType uint16
	ProtocolType uint16
	HWSize       uint8
	ProtoSize    uint8
	Opcode       uint16 // 1=request, 2=reply
	SenderMAC    net.HardwareAddr
	SenderIP     net.IP
	TargetMAC    net.HardwareAddr
	TargetIP     net.IP
}

func parseARP(data []byte) (*ARPHeader, error) {
	if len(data) < 28 {
		return nil, errors.New("arp: too short")
	}

	return &ARPHeader{
		HardwareType: binary.BigEndian.Uint16(data[0:2]),
		ProtocolType: binary.BigEndian.Uint16(data[2:4]),
		HWSize:       data[4],
		ProtoSize:    data[5],
		Opcode:       binary.BigEndian.Uint16(data[6:8]),
		SenderMAC:    net.HardwareAddr(data[8:14]),
		SenderIP:     net.IP(data[14:18]),
		TargetMAC:    net.HardwareAddr(data[18:24]),
		TargetIP:     net.IP(data[24:28]),
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Layer 4 — TCP
// ═══════════════════════════════════════════════════════════════════════════

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8 // in bytes
	Flags      TCPFlags
	Window     uint16
	Checksum   uint16
	UrgPtr     uint16
	Options    []byte
	MSS        uint16 // from options
	WScale     uint8  // from options
	SACKPerm   bool
}

type TCPFlags struct {
	FIN, SYN, RST, PSH, ACK, URG, ECE, CWR bool
}

func (f TCPFlags) String() string {
	s := ""
	if f.FIN {
		s += "F"
	}
	if f.SYN {
		s += "S"
	}
	if f.RST {
		s += "R"
	}
	if f.PSH {
		s += "P"
	}
	if f.ACK {
		s += "A"
	}
	if f.URG {
		s += "U"
	}
	return s
}

func parseTCP(data []byte) (*TCPHeader, error) {
	if len(data) < 20 {
		return nil, errors.New("tcp: too short")
	}

	dataOff := (data[12] >> 4) * 4
	if dataOff < 20 || int(dataOff) > len(data) {
		return nil, errors.New("tcp: invalid data offset")
	}

	flagsByte := data[13]
	tcp := &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		Seq:        binary.BigEndian.Uint32(data[4:8]),
		Ack:        binary.BigEndian.Uint32(data[8:12]),
		DataOffset: dataOff,
		Flags: TCPFlags{
			FIN: flagsByte&0x01 != 0,
			SYN: flagsByte&0x02 != 0,
			RST: flagsByte&0x04 != 0,
			PSH: flagsByte&0x08 != 0,
			ACK: flagsByte&0x10 != 0,
			URG: flagsByte&0x20 != 0,
			ECE: flagsByte&0x40 != 0,
			CWR: flagsByte&0x80 != 0,
		},
		Window:   binary.BigEndian.Uint16(data[14:16]),
		Checksum: binary.BigEndian.Uint16(data[16:18]),
		UrgPtr:   binary.BigEndian.Uint16(data[18:20]),
	}

	if dataOff > 20 {
		tcp.Options = data[20:dataOff]
		parseTCPOptions(tcp)
	}

	return tcp, nil
}

func parseTCPOptions(tcp *TCPHeader) {
	opts := tcp.Options
	i := 0
	for i < len(opts) {
		kind := opts[i]
		if kind == 0 { // EOL
			break
		}
		if kind == 1 { // NOP
			i++
			continue
		}
		if i+1 >= len(opts) {
			break
		}
		length := int(opts[i+1])
		if length < 2 || i+length > len(opts) {
			break
		}

		switch kind {
		case 2: // MSS
			if length == 4 {
				tcp.MSS = binary.BigEndian.Uint16(opts[i+2 : i+4])
			}
		case 3: // Window Scale
			if length == 3 {
				tcp.WScale = opts[i+2]
			}
		case 4: // SACK Permitted
			tcp.SACKPerm = true
		}
		i += length
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Layer 4 — UDP
// ═══════════════════════════════════════════════════════════════════════════

type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

func parseUDP(data []byte) (*UDPHeader, error) {
	if len(data) < 8 {
		return nil, errors.New("udp: too short")
	}
	return &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Layer 4 — ICMP
// ═══════════════════════════════════════════════════════════════════════════

type ICMPHeader struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Rest     uint32
}

func parseICMP(data []byte) (*ICMPHeader, error) {
	if len(data) < 8 {
		return nil, errors.New("icmp: too short")
	}
	return &ICMPHeader{
		Type:     data[0],
		Code:     data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
		Rest:     binary.BigEndian.Uint32(data[4:8]),
	}, nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Parse — Main entry point
// ═══════════════════════════════════════════════════════════════════════════

// Parse dissects a raw Ethernet frame.
func Parse(frame []byte) (*ParsedPacket, error) {
	if len(frame) < 14 {
		return nil, errors.New("frame too short")
	}

	pkt := &ParsedPacket{}

	// Layer 2
	eth, offset, err := parseEthernet(frame)
	if err != nil {
		return nil, err
	}
	pkt.L2 = *eth
	l3 := frame[offset:]

	// Layer 3
	switch eth.EtherType {
	case EtherTypeIPv4:
		ip, ipHdrLen, err := parseIPv4(l3)
		if err != nil {
			return pkt, err
		}
		pkt.L3Proto = "IPv4"
		pkt.IPv4 = ip
		pkt.FlowKey.SrcIP = ip.SrcIP
		pkt.FlowKey.DstIP = ip.DstIP
		pkt.FlowKey.Proto = ip.Protocol

		if len(l3) > ipHdrLen {
			parseL4(pkt, ip.Protocol, l3[ipHdrLen:])
		}

	case EtherTypeIPv6:
		ip, ipHdrLen, err := parseIPv6(l3)
		if err != nil {
			return pkt, err
		}
		pkt.L3Proto = "IPv6"
		pkt.IPv6 = ip
		pkt.FlowKey.SrcIP = ip.SrcIP
		pkt.FlowKey.DstIP = ip.DstIP
		pkt.FlowKey.Proto = ip.NextHeader

		if len(l3) > ipHdrLen {
			parseL4(pkt, ip.NextHeader, l3[ipHdrLen:])
		}

	case EtherTypeARP:
		arp, err := parseARP(l3)
		if err == nil {
			pkt.L3Proto = "ARP"
			pkt.ARP = arp
		}
	}

	return pkt, nil
}

func parseL4(pkt *ParsedPacket, proto uint8, data []byte) {
	switch proto {
	case ProtoTCP:
		tcp, err := parseTCP(data)
		if err != nil {
			return
		}
		pkt.L4Proto = "TCP"
		pkt.TCP = tcp
		pkt.FlowKey.SrcPort = tcp.SrcPort
		pkt.FlowKey.DstPort = tcp.DstPort
		if int(tcp.DataOffset) < len(data) {
			pkt.Payload = data[tcp.DataOffset:]
			// Layer 7 DPI
			identifyApp(pkt, tcp.SrcPort, tcp.DstPort, pkt.Payload)
		}

	case ProtoUDP:
		udp, err := parseUDP(data)
		if err != nil {
			return
		}
		pkt.L4Proto = "UDP"
		pkt.UDP = udp
		pkt.FlowKey.SrcPort = udp.SrcPort
		pkt.FlowKey.DstPort = udp.DstPort
		if len(data) > 8 {
			pkt.Payload = data[8:]
			identifyApp(pkt, udp.SrcPort, udp.DstPort, pkt.Payload)
		}

	case ProtoICMP:
		icmp, err := parseICMP(data)
		if err == nil {
			pkt.L4Proto = "ICMP"
			pkt.ICMP = icmp
		}

	case ProtoICMPv6:
		pkt.L4Proto = "ICMPv6"
	}
}

// identifyApp dispatches to application-layer parsers based on port/content.
func identifyApp(pkt *ParsedPacket, srcPort, dstPort uint16, payload []byte) {
	if len(payload) == 0 {
		return
	}

	// Port-based hints
	port := dstPort
	if port == 0 || port > 49151 {
		port = srcPort
	}

	switch {
	case port == 53:
		if dns := ParseDNS(payload); dns != nil {
			pkt.AppProto = "DNS"
			pkt.App = dns
		}
	case port == 80 || port == 8080 || port == 8000:
		if http := ParseHTTP(payload); http != nil {
			pkt.AppProto = "HTTP"
			pkt.App = http
		}
	case port == 443 || port == 8443:
		if tls := ParseTLS(payload); tls != nil {
			pkt.AppProto = "TLS"
			pkt.App = tls
		}
	case port == 22:
		if ssh := ParseSSH(payload); ssh != nil {
			pkt.AppProto = "SSH"
			pkt.App = ssh
		}
	case port == 21:
		pkt.AppProto = "FTP"
	case port == 25 || port == 587 || port == 465:
		pkt.AppProto = "SMTP"
	case port == 445 || port == 139:
		pkt.AppProto = "SMB"
	case port == 3389:
		pkt.AppProto = "RDP"
	case port == 1883 || port == 8883:
		pkt.AppProto = "MQTT"
	case port == 5683:
		pkt.AppProto = "CoAP"
	default:
		// Content-based detection
		identifyByContent(pkt, payload)
	}
}

func identifyByContent(pkt *ParsedPacket, payload []byte) {
	if len(payload) < 4 {
		return
	}

	// HTTP request methods
	httpMethods := []string{"GET ", "POST", "PUT ", "HEAD", "DEL", "OPTI", "PATC"}
	prefix := string(payload[:min(5, len(payload))])
	for _, m := range httpMethods {
		if len(prefix) >= len(m) && prefix[:len(m)] == m {
			if http := ParseHTTP(payload); http != nil {
				pkt.AppProto = "HTTP"
				pkt.App = http
				return
			}
		}
	}

	// HTTP response
	if len(payload) >= 5 && string(payload[:5]) == "HTTP/" {
		if http := ParseHTTP(payload); http != nil {
			pkt.AppProto = "HTTP"
			pkt.App = http
			return
		}
	}

	// TLS handshake marker
	if payload[0] == 0x16 && payload[1] == 0x03 {
		if tls := ParseTLS(payload); tls != nil {
			pkt.AppProto = "TLS"
			pkt.App = tls
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
