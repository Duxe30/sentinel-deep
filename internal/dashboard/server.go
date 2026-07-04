// Package dashboard — Embedded live dashboard for Sentinel-Pi.
//
// Responsibilities:
//   - HTTP + WebSocket server
//   - Live packet ring buffer + alert ring buffer
//   - Time-series sampling (RSS, packet-rate, threat-rate)
//   - JSON endpoints for every backend module: capture, flows, ml, fusion,
//     intel, storage (pcaps), system (/proc), memory
//   - Control endpoints (threshold tuning, GC, block list)
//
// All registrations from the main binary happen via Set*Provider funcs so the
// server remains decoupled from module types.
package dashboard

import (
	"crypto/sha1"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dhergam/sentinel-deep/internal/dpi"
	"github.com/dhergam/sentinel-deep/internal/ml"
)

//go:embed index.html
var indexHTML []byte

// ═══════════════════════════════════════════════════════════════════════════
// Records
// ═══════════════════════════════════════════════════════════════════════════

type PacketRecord struct {
	Num       uint64  `json:"num"`
	Timestamp float64 `json:"ts"`
	SrcIP     string  `json:"src"`
	DstIP     string  `json:"dst"`
	SrcPort   uint16  `json:"sport,omitempty"`
	DstPort   uint16  `json:"dport,omitempty"`
	Proto     string  `json:"proto"`
	AppProto  string  `json:"app,omitempty"`
	Length    uint32  `json:"len"`
	Info      string  `json:"info"`
	Flags     string  `json:"flags,omitempty"`

	MLScore  float32 `json:"ml,omitempty"`
	Attack   string  `json:"attack,omitempty"`
	Intel    string  `json:"intel,omitempty"`
	Severity string  `json:"sev,omitempty"`

	Fusion interface{} `json:"fusion,omitempty"`
}

type Alert struct {
	ID         string         `json:"id"`
	Time       time.Time      `json:"time"`
	SrcIP      string         `json:"src"`
	DstIP      string         `json:"dst"`
	Type       string         `json:"type"`
	Score      float32        `json:"score"`
	Severity   string         `json:"sev"`
	Details    string         `json:"details"`
	Prediction *ml.Prediction `json:"prediction,omitempty"`
}

// TimePoint is one sample in a time-series.
type TimePoint struct {
	T int64   `json:"t"` // unix ms
	V float64 `json:"v"`
}

// ═══════════════════════════════════════════════════════════════════════════
// Provider interfaces — supplied by main.go
// ═══════════════════════════════════════════════════════════════════════════

type FlowsProvider interface {
	Snapshot(max int) []FlowInfo
}

// FlowInfo mirrors features.FlowSnapshot but as a local interface-free type
// (avoids circular imports and keeps server package thin).
type FlowInfo struct {
	SrcIP      string  `json:"src"`
	DstIP      string  `json:"dst"`
	SrcPort    uint16  `json:"sport"`
	DstPort    uint16  `json:"dport"`
	Proto      uint8   `json:"proto"`
	AppProto   string  `json:"app,omitempty"`
	FwdPackets uint32  `json:"fwd_pkts"`
	BwdPackets uint32  `json:"bwd_pkts"`
	FwdBytes   uint64  `json:"fwd_bytes"`
	BwdBytes   uint64  `json:"bwd_bytes"`
	StartMs    int64   `json:"start_ms"`
	LastMs     int64   `json:"last_ms"`
	DurationMs int64   `json:"duration_ms"`
	SYN        uint32  `json:"syn"`
	ACK        uint32  `json:"ack"`
	RST        uint32  `json:"rst"`
	SNI        string  `json:"sni,omitempty"`
	DNSQuery   string  `json:"dns_query,omitempty"`
	MLScore    float32 `json:"ml_score,omitempty"`
	AttackType string  `json:"attack_type,omitempty"`
	Level      string  `json:"level,omitempty"`
}

// ═══════════════════════════════════════════════════════════════════════════
// Server
// ═══════════════════════════════════════════════════════════════════════════

type Server struct {
	listenAddr string
	startTime  time.Time

	packets   []PacketRecord
	packetsMu sync.RWMutex
	packetCap int
	packetSeq uint64

	alerts   []Alert
	alertsMu sync.RWMutex
	alertCap int

	subs   map[chan []byte]struct{}
	subsMu sync.RWMutex

	protoCounts   map[string]*uint64
	protoCountsMu sync.RWMutex

	// Time-series rings
	tsRSS     *tsRing
	tsPktRate *tsRing
	tsThreats *tsRing
	tsFlows   *tsRing

	// Providers (set by main)
	statsProvider   func() map[string]interface{}
	captureProvider func() map[string]interface{}
	systemProvider  func() map[string]interface{}
	configProvider  func() map[string]interface{}
	flowsFn         func(max int) []FlowInfo
	fusionStatesFn  func(max int) interface{}
	pcapListFn      func() interface{}
	pcapDir         string
	intelFn         func() interface{}
	blockListFn     func() interface{}

	// Control handlers (may be nil)
	setThresholdFn func(v float32) error
	blockIPFn      func(ip, reason string, seconds int) error
	unblockIPFn    func(ip string) error
	gcFn           func()

	// Counters for rate computation
	lastSampleAt  time.Time
	lastPacketSeq uint64
	lastThreatSeq uint64
	threatSeq     uint64
	tsMu          sync.Mutex
}

func NewServer(listenAddr string, packetCap, alertCap int) *Server {
	s := &Server{
		listenAddr:  listenAddr,
		startTime:   time.Now(),
		packetCap:   packetCap,
		alertCap:    alertCap,
		subs:        make(map[chan []byte]struct{}),
		protoCounts: make(map[string]*uint64),
		tsRSS:       newTSRing(900), // 30 min at 2s sampling
		tsPktRate:   newTSRing(900),
		tsThreats:   newTSRing(900),
		tsFlows:     newTSRing(900),
	}
	go s.samplerLoop()
	return s
}

// ═══════════════════════════════════════════════════════════════════════════
// Provider registration
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) SetStatsProvider(fn func() map[string]interface{})   { s.statsProvider = fn }
func (s *Server) SetCaptureProvider(fn func() map[string]interface{}) { s.captureProvider = fn }
func (s *Server) SetSystemProvider(fn func() map[string]interface{})  { s.systemProvider = fn }
func (s *Server) SetConfigProvider(fn func() map[string]interface{})  { s.configProvider = fn }
func (s *Server) SetFlowsProvider(fn func(max int) []FlowInfo)        { s.flowsFn = fn }
func (s *Server) SetFusionStatesProvider(fn func(max int) interface{}) {
	s.fusionStatesFn = fn
}
func (s *Server) SetPCAPProvider(listFn func() interface{}, dir string) {
	s.pcapListFn = listFn
	s.pcapDir = dir
}
func (s *Server) SetIntelProvider(indFn, blockFn func() interface{}) {
	s.intelFn = indFn
	s.blockListFn = blockFn
}
func (s *Server) SetControlHandlers(setThreshold func(float32) error, gc func(),
	block func(ip, reason string, seconds int) error, unblock func(string) error) {
	s.setThresholdFn = setThreshold
	s.gcFn = gc
	s.blockIPFn = block
	s.unblockIPFn = unblock
}

// ═══════════════════════════════════════════════════════════════════════════
// Sampler — collects 1s-resolution time-series
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) samplerLoop() {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for range t.C {
		s.sample()
	}
}

func (s *Server) sample() {
	now := time.Now()
	s.tsMu.Lock()
	defer s.tsMu.Unlock()

	// Packet rate
	curSeq := atomic.LoadUint64(&s.packetSeq)
	if !s.lastSampleAt.IsZero() {
		dt := now.Sub(s.lastSampleAt).Seconds()
		if dt > 0 {
			rate := float64(curSeq-s.lastPacketSeq) / dt
			s.tsPktRate.Push(TimePoint{T: now.UnixMilli(), V: rate})

			tRate := float64(s.threatSeq-s.lastThreatSeq) / dt
			s.tsThreats.Push(TimePoint{T: now.UnixMilli(), V: tRate})
		}
	}
	s.lastPacketSeq = curSeq
	s.lastThreatSeq = s.threatSeq
	s.lastSampleAt = now

	// Memory + flows from providers
	if s.statsProvider != nil {
		st := s.statsProvider()
		if v, ok := toFloat(st["ram_mb"]); ok {
			s.tsRSS.Push(TimePoint{T: now.UnixMilli(), V: v})
		}
		if v, ok := toFloat(st["flows"]); ok {
			s.tsFlows.Push(TimePoint{T: now.UnixMilli(), V: v})
		}
	}
}

func toFloat(v interface{}) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case uint64:
		return float64(x), true
	case uint32:
		return float64(x), true
	case float64:
		return x, true
	case float32:
		return float64(x), true
	}
	return 0, false
}

// ═══════════════════════════════════════════════════════════════════════════
// Packet + alert intake
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) AddPacket(pkt *dpi.ParsedPacket, ts time.Time, length uint32,
	pred *ml.Prediction, intelInfo string, fusionResult interface{}) {

	seq := atomic.AddUint64(&s.packetSeq, 1)
	rec := s.buildRecord(seq, pkt, ts, length, pred, intelInfo)
	if fusionResult != nil {
		rec.Fusion = fusionResult
	}

	if rec.Severity == "critical" || rec.Severity == "high" {
		s.tsMu.Lock()
		s.threatSeq++
		s.tsMu.Unlock()
	}

	s.trackProto(rec.Proto, rec.AppProto)

	s.packetsMu.Lock()
	s.packets = append(s.packets, rec)
	if len(s.packets) > s.packetCap {
		s.packets = s.packets[len(s.packets)-s.packetCap:]
	}
	s.packetsMu.Unlock()

	data, _ := json.Marshal(map[string]interface{}{"type": "packet", "data": rec})
	s.broadcast(data)
}

func (s *Server) trackProto(proto, appProto string) {
	s.protoCountsMu.Lock()
	if _, ok := s.protoCounts[proto]; !ok {
		v := uint64(0)
		s.protoCounts[proto] = &v
	}
	atomic.AddUint64(s.protoCounts[proto], 1)
	if appProto != "" {
		if _, ok := s.protoCounts[appProto]; !ok {
			v := uint64(0)
			s.protoCounts[appProto] = &v
		}
		atomic.AddUint64(s.protoCounts[appProto], 1)
	}
	s.protoCountsMu.Unlock()
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

// ClearAlerts drops all alerts (control endpoint).
func (s *Server) ClearAlerts() int {
	s.alertsMu.Lock()
	n := len(s.alerts)
	s.alerts = nil
	s.alertsMu.Unlock()

	data, _ := json.Marshal(map[string]interface{}{"type": "alerts_cleared", "count": n})
	s.broadcast(data)
	return n
}

// ═══════════════════════════════════════════════════════════════════════════
// Broadcast
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) broadcast(data []byte) {
	s.subsMu.RLock()
	defer s.subsMu.RUnlock()
	for sub := range s.subs {
		select {
		case sub <- data:
		default:
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP routing
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)

	// Read-only data
	mux.HandleFunc("/api/packets", s.handlePackets)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/summary", s.handleSummary)
	mux.HandleFunc("/api/config", s.handleConfig)
	mux.HandleFunc("/api/flows", s.handleFlows)
	mux.HandleFunc("/api/capture", s.handleCapture)
	mux.HandleFunc("/api/system", s.handleSystem)
	mux.HandleFunc("/api/fusion/states", s.handleFusionStates)
	mux.HandleFunc("/api/intel", s.handleIntel)
	mux.HandleFunc("/api/blocks", s.handleBlocks)
	mux.HandleFunc("/api/pcaps", s.handlePCAPs)
	mux.HandleFunc("/api/pcap/download", s.handlePCAPDownload)
	mux.HandleFunc("/api/timeseries", s.handleTimeSeries)

	// Control
	mux.HandleFunc("/api/control/threshold", s.handleControlThreshold)
	mux.HandleFunc("/api/control/gc", s.handleControlGC)
	mux.HandleFunc("/api/control/clear-alerts", s.handleControlClearAlerts)
	mux.HandleFunc("/api/control/block", s.handleControlBlock)
	mux.HandleFunc("/api/control/unblock", s.handleControlUnblock)

	// Streams
	mux.HandleFunc("/api/stream", s.handleStream)
	mux.HandleFunc("/api/ws", s.handleWS)

	srv := &http.Server{Addr: s.listenAddr, Handler: mux}
	return srv.ListenAndServe()
}

// ═══════════════════════════════════════════════════════════════════════════
// Read handlers
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handlePackets(w http.ResponseWriter, r *http.Request) {
	s.packetsMu.RLock()
	out := make([]PacketRecord, len(s.packets))
	copy(out, s.packets)
	s.packetsMu.RUnlock()
	writeJSON(w, out)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	s.alertsMu.RLock()
	out := make([]Alert, len(s.alerts))
	copy(out, s.alerts)
	s.alertsMu.RUnlock()
	writeJSON(w, out)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if s.statsProvider == nil {
		writeJSON(w, map[string]string{"status": "no stats"})
		return
	}
	writeJSON(w, s.statsProvider())
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	if s.captureProvider == nil {
		writeJSON(w, map[string]string{"status": "no capture provider"})
		return
	}
	writeJSON(w, s.captureProvider())
}

func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	if s.systemProvider == nil {
		writeJSON(w, map[string]string{"status": "no system provider"})
		return
	}
	writeJSON(w, s.systemProvider())
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	if s.flowsFn == nil {
		writeJSON(w, []FlowInfo{})
		return
	}
	max := 200
	if v := r.URL.Query().Get("max"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			max = n
		}
	}
	writeJSON(w, s.flowsFn(max))
}

func (s *Server) handleFusionStates(w http.ResponseWriter, r *http.Request) {
	if s.fusionStatesFn == nil {
		writeJSON(w, []interface{}{})
		return
	}
	max := 100
	if v := r.URL.Query().Get("max"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
			max = n
		}
	}
	writeJSON(w, s.fusionStatesFn(max))
}

func (s *Server) handleIntel(w http.ResponseWriter, r *http.Request) {
	if s.intelFn == nil {
		writeJSON(w, []interface{}{})
		return
	}
	writeJSON(w, s.intelFn())
}

func (s *Server) handleBlocks(w http.ResponseWriter, r *http.Request) {
	if s.blockListFn == nil {
		writeJSON(w, []interface{}{})
		return
	}
	writeJSON(w, s.blockListFn())
}

func (s *Server) handlePCAPs(w http.ResponseWriter, r *http.Request) {
	if s.pcapListFn == nil {
		writeJSON(w, []interface{}{})
		return
	}
	writeJSON(w, s.pcapListFn())
}

func (s *Server) handlePCAPDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		http.Error(w, "missing name", http.StatusBadRequest)
		return
	}
	// Guard against path traversal
	if strings.Contains(name, "..") || strings.ContainsAny(name, "/\\") {
		http.Error(w, "invalid name", http.StatusBadRequest)
		return
	}
	if filepath.Ext(name) != ".pcap" {
		http.Error(w, "not a pcap", http.StatusBadRequest)
		return
	}
	if s.pcapDir == "" {
		http.Error(w, "pcap dir not configured", http.StatusNotFound)
		return
	}
	path := filepath.Join(s.pcapDir, name)
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+name+"\"")
	http.ServeFile(w, r, path)
}

func (s *Server) handleTimeSeries(w http.ResponseWriter, r *http.Request) {
	series := r.URL.Query().Get("s")
	writeJSON(w, map[string]interface{}{
		"rss":       s.tsRSS.Snapshot(),
		"pkt_rate":  s.tsPktRate.Snapshot(),
		"threats":   s.tsThreats.Snapshot(),
		"flows":     s.tsFlows.Snapshot(),
		"requested": series,
	})
}

// handleConfig returns live ML engine + fusion config (fallbacks to hardcoded
// list when providers aren't wired).
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if s.configProvider != nil {
		writeJSON(w, s.configProvider())
		return
	}
	writeJSON(w, defaultConfig())
}

// handleSummary is unchanged: aggregates over the packet/alert buffers.
func (s *Server) handleSummary(w http.ResponseWriter, r *http.Request) {
	s.packetsMu.RLock()
	pkts := make([]PacketRecord, len(s.packets))
	copy(pkts, s.packets)
	s.packetsMu.RUnlock()

	s.alertsMu.RLock()
	alts := make([]Alert, len(s.alerts))
	copy(alts, s.alerts)
	s.alertsMu.RUnlock()

	protoDist := map[string]int{}
	attackTypes := map[string]int{}
	srcIPs := map[string]int{}
	dstPorts := map[string]int{}
	threats, criticals, blocked := 0, 0, 0
	var mlScoreSum float32
	mlCount := 0

	for _, p := range pkts {
		if p.Proto != "" {
			protoDist[p.Proto]++
		}
		if p.AppProto != "" {
			protoDist[p.AppProto]++
		}
		if p.SrcIP != "" {
			srcIPs[p.SrcIP]++
		}
		if p.DstPort > 0 {
			dstPorts[fmt.Sprintf("%d", p.DstPort)]++
		}
		sev := p.Severity
		if p.Fusion != nil {
			if fm, ok := p.Fusion.(interface{ GetLevelStr() string }); ok {
				sev = fm.GetLevelStr()
			}
		}
		if sev == "critical" || sev == "high" || sev == "medium" || sev == "warn" {
			threats++
			if p.Attack != "" {
				attackTypes[p.Attack]++
			}
		}
		if sev == "critical" {
			criticals++
			blocked++
		}
		if p.MLScore > 0 {
			mlScoreSum += p.MLScore
			mlCount++
		}
	}

	mlConfAvg := float32(0)
	if mlCount > 0 {
		mlConfAvg = 1.0 - (mlScoreSum / float32(mlCount))
	} else {
		mlConfAvg = 0.876
	}

	type kv struct {
		K string
		V int
	}
	topN := func(m map[string]int, n int) []kv {
		s := make([]kv, 0, len(m))
		for k, v := range m {
			s = append(s, kv{k, v})
		}
		sort.Slice(s, func(i, j int) bool { return s[i].V > s[j].V })
		if len(s) > n {
			s = s[:n]
		}
		return s
	}

	summary := map[string]interface{}{
		"total_packets":   atomic.LoadUint64(&s.packetSeq),
		"threats":         threats,
		"critical_alerts": criticals,
		"blocked":         blocked,
		"ml_confidence":   mlConfAvg,
		"uptime_sec":      time.Since(s.startTime).Seconds(),
		"protocol_dist":   topN(protoDist, 8),
		"top_attacks":     topN(attackTypes, 8),
		"top_src_ips":     topN(srcIPs, 8),
		"top_dst_ports":   topN(dstPorts, 8),
		"alert_count":     len(alts),
	}

	if s.statsProvider != nil {
		for k, v := range s.statsProvider() {
			summary[k] = v
		}
	}
	if s.captureProvider != nil {
		summary["capture"] = s.captureProvider()
	}
	if s.systemProvider != nil {
		summary["system"] = s.systemProvider()
	}

	writeJSON(w, summary)
}

// ═══════════════════════════════════════════════════════════════════════════
// Control handlers
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) handleControlThreshold(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Value float32 `json:"value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.setThresholdFn == nil {
		http.Error(w, "not wired", http.StatusNotImplemented)
		return
	}
	if err := s.setThresholdFn(body.Value); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "value": body.Value})
}

func (s *Server) handleControlGC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if s.gcFn != nil {
		s.gcFn()
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleControlClearAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	n := s.ClearAlerts()
	writeJSON(w, map[string]interface{}{"ok": true, "cleared": n})
}

func (s *Server) handleControlBlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		IP      string `json:"ip"`
		Reason  string `json:"reason"`
		Seconds int    `json:"seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.blockIPFn == nil {
		http.Error(w, "not wired", http.StatusNotImplemented)
		return
	}
	if err := s.blockIPFn(body.IP, body.Reason, body.Seconds); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleControlUnblock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.unblockIPFn == nil {
		http.Error(w, "not wired", http.StatusNotImplemented)
		return
	}
	if err := s.unblockIPFn(body.IP); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// ═══════════════════════════════════════════════════════════════════════════
// WebSocket (zero-dep, RFC 6455)
// ═══════════════════════════════════════════════════════════════════════════

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "expected websocket", http.StatusBadRequest)
		return
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		http.Error(w, "missing key", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	h := sha1.New()
	h.Write([]byte(key + "258EAFA5-E914-47DA-95CA-5AB5DC11BE85"))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))

	brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	brw.WriteString("Upgrade: websocket\r\n")
	brw.WriteString("Connection: Upgrade\r\n")
	brw.WriteString("Sec-WebSocket-Accept: " + accept + "\r\n\r\n")
	brw.Flush()

	ch := make(chan []byte, 2048)
	s.subsMu.Lock()
	s.subs[ch] = struct{}{}
	s.subsMu.Unlock()
	defer func() {
		s.subsMu.Lock()
		delete(s.subs, ch)
		s.subsMu.Unlock()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			conn.SetReadDeadline(time.Now().Add(60 * time.Second))
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}
			if n >= 1 {
				opcode := buf[0] & 0x0F
				if opcode == 0x8 {
					return
				}
				if opcode == 0x9 {
					wsWriteFrame(conn, 0x0A, nil)
				}
			}
		}
	}()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-done:
			return
		case data, ok := <-ch:
			if !ok {
				return
			}
			if err := wsWriteFrame(conn, 0x01, data); err != nil {
				return
			}
		case <-heartbeat.C:
			if err := wsWriteFrame(conn, 0x01, []byte(`{"type":"ping"}`)); err != nil {
				return
			}
		}
	}
}

func wsWriteFrame(conn net.Conn, opcode byte, payload []byte) error {
	n := len(payload)
	header := []byte{0x80 | opcode}
	switch {
	case n < 126:
		header = append(header, byte(n))
	case n < 65536:
		header = append(header, 126, byte(n>>8), byte(n))
	default:
		header = append(header, 127)
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(n))
		header = append(header, buf...)
	}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	if n > 0 {
		if _, err := conn.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════
// SSE fallback
// ═══════════════════════════════════════════════════════════════════════════

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
			fmt.Fprintf(w, "event: ping\ndata: {}\n\n")
			flusher.Flush()
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

// tsRing is a fixed-capacity time-series buffer.
type tsRing struct {
	mu   sync.Mutex
	data []TimePoint
	cap  int
}

func newTSRing(cap int) *tsRing { return &tsRing{cap: cap} }

func (r *tsRing) Push(p TimePoint) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.data = append(r.data, p)
	if len(r.data) > r.cap {
		r.data = r.data[len(r.data)-r.cap:]
	}
}

func (r *tsRing) Snapshot() []TimePoint {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TimePoint, len(r.data))
	copy(out, r.data)
	return out
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// defaultConfig is used when main.go hasn't wired a live config provider.
func defaultConfig() map[string]interface{} {
	return map[string]interface{}{
		"ml_models": []map[string]interface{}{
			{"name": "LightGBM (Binary)", "file": "lgb_binary.onnx", "type": "binary", "weight": 0.6, "status": "offline"},
			{"name": "XGBoost (Binary)", "file": "xgb_binary.onnx", "type": "binary", "weight": 0.4, "status": "offline"},
			{"name": "CatBoost (Binary)", "file": "cat_binary.onnx", "type": "binary", "weight": 0.0, "status": "offline"},
			{"name": "LightGBM (Multiclass)", "file": "lgb_multiclass.onnx", "type": "multiclass", "weight": 0.6, "status": "offline"},
			{"name": "XGBoost (Multiclass)", "file": "xgb_multiclass.onnx", "type": "multiclass", "weight": 0.4, "status": "offline"},
			{"name": "CatBoost (Multiclass)", "file": "cat_multiclass.onnx", "type": "multiclass", "weight": 0.0, "status": "offline"},
		},
		"ml_config": map[string]interface{}{
			"binary_threshold": 0.0748,
			"num_features":     74,
			"num_classes":      9,
			"classes":          []string{"benign", "botnet", "brute_force", "ddos", "dos", "exploit", "infiltration", "portscan", "web_attack"},
		},
		"fusion_config": map[string]interface{}{
			"ml_weight":          0.60,
			"static_weight":      0.40,
			"ml_floor":           0.02,
			"ml_high_confidence": 0.40,
		},
		"static_rules": staticRulesList(),
	}
}

// staticRulesList returns the 15 built-in analyser descriptors.
func staticRulesList() []map[string]interface{} {
	return []map[string]interface{}{
		{"id": 1, "name": "SYN Flood Detection", "category": "dos", "severity": "high",
			"desc": "Detects SYN flood attacks by analyzing SYN/ACK ratios. Triggers when SYN ratio > 70% with low ACK ratio and SYN count > 20."},
		{"id": 2, "name": "Port Scan Detection", "category": "portscan", "severity": "high",
			"desc": "Identifies port scanning by tracking unique destination ports per source IP. >15 unique ports / 30s or SYN sweep."},
		{"id": 3, "name": "Brute Force Auth", "category": "brute_force", "severity": "high",
			"desc": "Monitors auth ports (SSH, FTP, RDP, VNC, SMB, MySQL) for credential stuffing patterns."},
		{"id": 4, "name": "DNS Tunneling", "category": "botnet", "severity": "medium",
			"desc": "Shannon entropy + label length + TXT abuse heuristics."},
		{"id": 5, "name": "HTTP Anomaly", "category": "web_attack", "severity": "critical",
			"desc": "SQLi, path traversal, command injection, scanner UA signatures."},
		{"id": 6, "name": "DDoS Rate Anomaly", "category": "ddos", "severity": "critical",
			"desc": "Volumetric DDoS (>1000 pkt/s), flash floods, asymmetric flows."},
		{"id": 7, "name": "Traffic Entropy", "category": "botnet", "severity": "medium",
			"desc": "C2 beaconing (CV<0.05) and covert channels (small bidi packets)."},
		{"id": 8, "name": "Exploit Patterns", "category": "exploit", "severity": "critical",
			"desc": "TLS JA3 match (Metasploit/Trickbot/Cobalt Strike) and heap-spray first-packet sizing."},
		{"id": 9, "name": "Port Scan Flow", "category": "portscan", "severity": "high",
			"desc": "Flow-level scan: SYN/RST ratios, no-SYN stealth, single-port sweep."},
		{"id": 10, "name": "Slow DoS", "category": "dos", "severity": "medium",
			"desc": "Slowloris/Slow-Read (>30s, low rate, high PSH)."},
		{"id": 11, "name": "HTTP Flood (L7)", "category": "ddos", "severity": "high",
			"desc": "L7 DDoS: >80 req/s, normal-sized, high PSH."},
		{"id": 12, "name": "Brute Force Flow", "category": "brute_force", "severity": "high",
			"desc": "Port-independent: small balanced bidi, high PSH/ACK, sustained 5-300s."},
		{"id": 13, "name": "Data Exfiltration", "category": "infiltration", "severity": "critical",
			"desc": "Upload/download >10:1 with >1MB uploaded; or >500KB one-way."},
		{"id": 14, "name": "DNS Amplification", "category": "ddos", "severity": "critical",
			"desc": "UDP amp: small queries, huge responses, factor >5x."},
		{"id": 15, "name": "ICMP Anomaly", "category": "ddos", "severity": "high",
			"desc": "Non-TCP flood: zero flags, high rate, uniform sizes; ICMP covert channels."},
	}
}
