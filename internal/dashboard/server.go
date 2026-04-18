// Package dashboard — Embedded Wireshark-style live dashboard.
// HTTP server + Server-Sent Events for real-time packet streaming.
package dashboard

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dhergam/sentinel-deep/internal/dpi"
	"github.com/dhergam/sentinel-deep/internal/ml"
)

//go:embed index.html
var indexHTML []byte

// ═══════════════════════════════════════════════════════════════════════════
// PacketRecord — single row in the live packet table
// ═══════════════════════════════════════════════════════════════════════════

type PacketRecord struct {
	Num       uint64  `json:"num"`
	Timestamp float64 `json:"ts"` // seconds since start
	SrcIP     string  `json:"src"`
	DstIP     string  `json:"dst"`
	SrcPort   uint16  `json:"sport,omitempty"`
	DstPort   uint16  `json:"dport,omitempty"`
	Proto     string  `json:"proto"`
	AppProto  string  `json:"app,omitempty"`
	Length    uint32  `json:"len"`
	Info      string  `json:"info"`
	Flags     string  `json:"flags,omitempty"`

	// Threat indicators
	MLScore   float32 `json:"ml,omitempty"`
	Attack    string  `json:"attack,omitempty"`
	Intel     string  `json:"intel,omitempty"`
	Severity  string  `json:"sev,omitempty"` // info/warn/high/critical
}

// Alert — a full threat event
type Alert struct {
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	SrcIP     string    `json:"src"`
	DstIP     string    `json:"dst"`
	Type      string    `json:"type"`
	Score     float32   `json:"score"`
	Severity  string    `json:"sev"`
	Details   string    `json:"details"`
	Prediction *ml.Prediction `json:"prediction,omitempty"`
}

// ═══════════════════════════════════════════════════════════════════════════
// Server
// ═══════════════════════════════════════════════════════════════════════════

type Server struct {
	listenAddr string
	startTime  time.Time

	// Live packet ring buffer (last N packets)
	packets   []PacketRecord
	packetsMu sync.RWMutex
	packetCap int
	packetSeq uint64

	// Alerts
	alerts   []Alert
	alertsMu sync.RWMutex
	alertCap int

	// SSE subscribers
	subs   map[chan []byte]struct{}
	subsMu sync.RWMutex

	// Stats (set by main)
	statsProvider func() map[string]interface{}
}

func NewServer(listenAddr string, packetCap, alertCap int) *Server {
	return &Server{
		listenAddr: listenAddr,
		startTime:  time.Now(),
		packetCap:  packetCap,
		alertCap:   alertCap,
		subs:       make(map[chan []byte]struct{}),
	}
}

// SetStatsProvider registers a function that returns system stats
func (s *Server) SetStatsProvider(fn func() map[string]interface{}) {
	s.statsProvider = fn
}

// AddPacket records a packet and broadcasts to SSE subscribers
func (s *Server) AddPacket(pkt *dpi.ParsedPacket, ts time.Time, length uint32,
	pred *ml.Prediction, intelInfo string) {

	seq := atomic.AddUint64(&s.packetSeq, 1)
	rec := s.buildRecord(seq, pkt, ts, length, pred, intelInfo)

	// Add to ring buffer
	s.packetsMu.Lock()
	s.packets = append(s.packets, rec)
	if len(s.packets) > s.packetCap {
		s.packets = s.packets[len(s.packets)-s.packetCap:]
	}
	s.packetsMu.Unlock()

	// Broadcast via SSE
	data, _ := json.Marshal(map[string]interface{}{"type": "packet", "data": rec})
	s.broadcast(data)
}

func (s *Server) buildRecord(seq uint64, pkt *dpi.ParsedPacket, ts time.Time,
	length uint32, pred *ml.Prediction, intelInfo string) PacketRecord {

	rec := PacketRecord{
		Num:       seq,
		Timestamp: ts.Sub(s.startTime).Seconds(),
		Proto:     pkt.L4Proto,
		AppProto:  pkt.AppProto,
		Length:    length,
	}

	if pkt.IPv4 != nil {
		rec.SrcIP = pkt.IPv4.SrcIP.String()
		rec.DstIP = pkt.IPv4.DstIP.String()
	} else if pkt.IPv6 != nil {
		rec.SrcIP = pkt.IPv6.SrcIP.String()
		rec.DstIP = pkt.IPv6.DstIP.String()
	} else if pkt.ARP != nil {
		rec.Proto = "ARP"
		rec.SrcIP = net.IP(pkt.ARP.SenderIP).String()
		rec.DstIP = net.IP(pkt.ARP.TargetIP).String()
		if pkt.ARP.Opcode == 1 {
			rec.Info = fmt.Sprintf("Who has %s? Tell %s", rec.DstIP, rec.SrcIP)
		} else {
			rec.Info = fmt.Sprintf("%s is at %s", rec.SrcIP, pkt.ARP.SenderMAC)
		}
	}

	if pkt.TCP != nil {
		rec.SrcPort = pkt.TCP.SrcPort
		rec.DstPort = pkt.TCP.DstPort
		rec.Flags = pkt.TCP.Flags.String()
		rec.Info = fmt.Sprintf("[%s] Seq=%d Ack=%d Win=%d",
			rec.Flags, pkt.TCP.Seq, pkt.TCP.Ack, pkt.TCP.Window)
	} else if pkt.UDP != nil {
		rec.SrcPort = pkt.UDP.SrcPort
		rec.DstPort = pkt.UDP.DstPort
		rec.Info = fmt.Sprintf("Len=%d", pkt.UDP.Length)
	} else if pkt.ICMP != nil {
		rec.Info = fmt.Sprintf("Type=%d Code=%d", pkt.ICMP.Type, pkt.ICMP.Code)
	}

	// Application layer details
	switch app := pkt.App.(type) {
	case *dpi.DNSPacket:
		if len(app.Questions) > 0 {
			q := app.Questions[0]
			if app.IsQuery {
				rec.Info = fmt.Sprintf("DNS query %s (type %d)", q.Name, q.Type)
			} else {
				rec.Info = fmt.Sprintf("DNS response %s", q.Name)
			}
			if app.IsTunneling {
				rec.Info += " [TUNNELING?]"
				rec.Severity = "warn"
			}
		}
	case *dpi.HTTPPacket:
		if app.IsRequest {
			rec.Info = fmt.Sprintf("HTTP %s %s", app.Method, app.URI)
		} else {
			rec.Info = fmt.Sprintf("HTTP/%d", app.StatusCode)
		}
		if app.HasSQLi {
			rec.Info += " [SQLi?]"
			rec.Severity = "high"
		}
		if app.SuspiciousUA {
			rec.Info += fmt.Sprintf(" UA=%s", app.UserAgent)
			rec.Severity = "high"
		}
	case *dpi.TLSPacket:
		if app.SNI != "" {
			rec.Info = fmt.Sprintf("TLS SNI=%s JA3=%s", app.SNI, app.JA3Hash[:min(8, len(app.JA3Hash))])
		} else {
			rec.Info = "TLS Handshake"
		}
	case *dpi.SSHPacket:
		rec.Info = fmt.Sprintf("SSH %s %s", app.Version, app.SoftwareID)
	}

	// ML + intel overlays
	if pred != nil {
		rec.MLScore = pred.AttackProb
		if pred.IsAttack {
			rec.Attack = pred.AttackType
			rec.Severity = "critical"
		}
	}
	if intelInfo != "" {
		rec.Intel = intelInfo
		if rec.Severity == "" {
			rec.Severity = "high"
		}
	}

	return rec
}

// AddAlert records a threat alert
func (s *Server) AddAlert(a Alert) {
	s.alertsMu.Lock()
	s.alerts = append(s.alerts, a)
	if len(s.alerts) > s.alertCap {
		s.alerts = s.alerts[len(s.alerts)-s.alertCap:]
	}
	s.alertsMu.Unlock()

	data, _ := json.Marshal(map[string]interface{}{"type": "alert", "data": a})
	s.broadcast(data)
}

// ═══════════════════════════════════════════════════════════════════════════
// SSE broadcast
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) broadcast(data []byte) {
	s.subsMu.RLock()
	defer s.subsMu.RUnlock()
	for sub := range s.subs {
		select {
		case sub <- data:
		default: // drop if slow
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP handlers
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/packets", s.handlePackets)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/stream", s.handleStream)

	srv := &http.Server{
		Addr:    s.listenAddr,
		Handler: mux,
	}
	return srv.ListenAndServe()
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func (s *Server) handlePackets(w http.ResponseWriter, r *http.Request) {
	s.packetsMu.RLock()
	out := make([]PacketRecord, len(s.packets))
	copy(out, s.packets)
	s.packetsMu.RUnlock()
	json.NewEncoder(w).Encode(out)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	s.alertsMu.RLock()
	out := make([]Alert, len(s.alerts))
	copy(out, s.alerts)
	s.alertsMu.RUnlock()
	json.NewEncoder(w).Encode(out)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if s.statsProvider == nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "no stats"})
		return
	}
	json.NewEncoder(w).Encode(s.statsProvider())
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	ch := make(chan []byte, 100)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()

	defer func() {
		s.subsMu.Lock()
		delete(s.subs, ch)
		s.subsMu.Unlock()
		close(ch)
	}()

	// Heartbeat every 15s
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case data := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-heartbeat.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
