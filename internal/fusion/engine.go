// Package fusion — Decision fusion engine for Sentinel-Pi v4.0 (Hardened Edition).
//
// Combines multiple static-analysis signals (rule-based algorithms) with ML
// model predictions using a weighted evidence accumulation approach designed
// to minimise false positives while maintaining high recall for real attacks.
//
// Architecture:
//
//	Static Analysers → StaticResult
//	ML Engine        → ml.Prediction
//	FusionEngine     → FusionResult  (shown in dashboard)
//
// v4.0 Changes:
//   - 15 static analysers (was 8): added SlowDoS, PortScanFlow, HTTPFlood,
//     BruteForceFlow, DataExfiltration, DNSAmplification, ICMPAnomaly
//   - Adaptive ML floor (2% base, context-aware)
//   - ML binary override: ML detection alone → minimum ThreatLow
//   - Static category override for ML multiclass misclassification
//   - Smarter fusion with model disagreement detection
//
// False-Positive Reduction Strategy:
//  1. Require CORROBORATION: ML alone OR static alone does not trigger CRITICAL.
//  2. Per-class confidence gates: each attack class has its own static signals.
//  3. Time-windowed evidence: brief single-packet anomalies are discounted.
//  4. Whitelist pass-through: known-benign destinations bypass ML.
//  5. Benign prior boost: if binary ML score < floor AND no static signals,
//     result is BENIGN regardless.
//  6. NEW: ML binary positive → minimum LOW (never discard ML detection).
//  7. NEW: Static override for misclassified multiclass labels.
package fusion

import (
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/dhergam/sentinel-deep/internal/dpi"
	"github.com/dhergam/sentinel-deep/internal/features"
	"github.com/dhergam/sentinel-deep/internal/ml"
)

// ═══════════════════════════════════════════════════════════════════════════
// Static analysis signals
// ═══════════════════════════════════════════════════════════════════════════

// StaticSignal is a single fired rule from a static analyser.
type StaticSignal struct {
	Name        string  // e.g. "port_scan_syn_ratio"
	Category    string  // e.g. "portscan", "dos", "bruteforce"
	Confidence  float32 // 0-1, how certain this rule fires
	Description string
}

// StaticResult aggregates all signals from static analysers for one flow.
type StaticResult struct {
	Signals        []StaticSignal
	MaxConfidence  float32
	TopCategory    string
	RulesFired     int
	CategoryScores map[string]float32
}

// ═══════════════════════════════════════════════════════════════════════════
// Fusion result — what the dashboard renders
// ═══════════════════════════════════════════════════════════════════════════

// ThreatLevel is the final decision tier.
type ThreatLevel int

const (
	ThreatBenign   ThreatLevel = iota // no threat
	ThreatLow                         // anomaly, watch
	ThreatMedium                      // likely suspicious
	ThreatHigh                        // probable attack
	ThreatCritical                    // confirmed attack, both static+ML agree
)

func (t ThreatLevel) String() string {
	return [...]string{"benign", "low", "medium", "high", "critical"}[t]
}

// FusionResult is the merged output for one flow evaluation.
type FusionResult struct {
	Level      ThreatLevel `json:"level"`
	LevelStr   string      `json:"level_str"`
	FinalScore float32     `json:"final_score"`
	AttackType string      `json:"attack_type,omitempty"`
	Confidence float32     `json:"confidence"`

	// Sub-scores
	MLScore       float32            `json:"ml_score"`
	MLAttackType  string             `json:"ml_attack_type,omitempty"`
	MLPerModel    map[string]float32 `json:"ml_per_model,omitempty"`
	StaticScore   float32            `json:"static_score"`
	StaticSignals []StaticSignal     `json:"static_signals,omitempty"`

	// Evidence summary
	Corroborated bool   `json:"corroborated"`
	Explanation  string `json:"explanation"`
}

// Accessor methods (used by features.Snapshot via any-cast).
func (r *FusionResult) GetScore() float32   { return r.FinalScore }
func (r *FusionResult) GetAttack() string   { return r.AttackType }
func (r *FusionResult) GetLevelStr() string { return r.LevelStr }

// ═══════════════════════════════════════════════════════════════════════════
// Flow state cache for time-windowed analysis
// ═══════════════════════════════════════════════════════════════════════════

type flowState struct {
	synCount      int
	ackCount      int
	rstCount      int
	pktCount      int
	byteCount     int64
	dstPortsSeen  map[uint16]struct{}
	srcIPsSeen    map[string]struct{}
	firstSeen     time.Time
	lastSeen      time.Time
	httpReqCount  int
	httpErrCount  int
	loginAttempts int
}

// ═══════════════════════════════════════════════════════════════════════════
// Engine
// ═══════════════════════════════════════════════════════════════════════════

// Engine fuses ML predictions with static analysis signals.
type Engine struct {
	mlEngine   *ml.Engine
	mu         sync.Mutex
	flowStates map[string]*flowState

	// Config
	mlWeight          float32
	staticWeight      float32
	mlFloorThreshold  float32
	mlHighConfidence  float32
	mlBinaryThreshold float32 // v4.0: from ML config
}

// NewEngine creates a fusion engine with v4.0 hardened defaults.
func NewEngine(mlEng *ml.Engine) *Engine {
	e := &Engine{
		mlEngine:          mlEng,
		flowStates:        make(map[string]*flowState),
		mlWeight:          0.60,  // v4: slightly reduced from 0.65
		staticWeight:      0.40,  // v4: increased from 0.35
		mlFloorThreshold:  0.02,  // v4: lowered from 0.04 → catches Data Exfil at 9.7%
		mlHighConfidence:  0.40,  // v4: lowered from 0.50 → SSH brute force at 39.2% now HIGH
		mlBinaryThreshold: 0.075, // default; overridden if ML engine available
	}
	if mlEng != nil {
		cfg := mlEng.GetConfig()
		if cfg != nil {
			e.mlBinaryThreshold = cfg.BinaryThreshold
		}
	}
	return e
}

// Analyze performs full fusion analysis on a completed or in-progress flow.
func (e *Engine) Analyze(
	flow *features.Flow,
	pkt *dpi.ParsedPacket,
	featVec []float32,
) *FusionResult {

	var mlPred *ml.Prediction
	if e.mlEngine != nil && len(featVec) > 0 {
		mlPred, _ = e.mlEngine.Predict(featVec)
	}

	mlScore := float32(0)
	mlAttack := ""
	mlPerModel := map[string]float32{}
	if mlPred != nil {
		mlScore = mlPred.AttackProb
		mlAttack = mlPred.AttackType
		mlPerModel = mlPred.BinaryPerModel
	}

	staticRes := e.runStaticAnalysis(flow, pkt, featVec)
	return e.fuse(mlScore, mlAttack, mlPerModel, staticRes)
}

// AnalyzePacketOnly runs lightweight static-only analysis.
func (e *Engine) AnalyzePacketOnly(pkt *dpi.ParsedPacket) *FusionResult {
	staticRes := e.runStaticAnalysis(nil, pkt, nil)
	return e.fuse(0, "", nil, staticRes)
}

// ═══════════════════════════════════════════════════════════════════════════
// Static analysers — 15 independent algorithms (v4.0)
// ═══════════════════════════════════════════════════════════════════════════

func (e *Engine) runStaticAnalysis(
	flow *features.Flow,
	pkt *dpi.ParsedPacket,
	featVec []float32,
) *StaticResult {

	res := &StaticResult{
		CategoryScores: make(map[string]float32),
	}

	analysers := []func(*features.Flow, *dpi.ParsedPacket, []float32) []StaticSignal{
		// Original 8
		e.analyzeSynFlood,
		e.analyzePortScan,
		e.analyzeBruteForce,
		e.analyzeDNSTunneling,
		e.analyzeHTTPAnomaly,
		e.analyzeDDoSRateAnomaly,
		e.analyzeTrafficEntropy,
		e.analyzeExploitPatterns,
		// v4.0: 7 NEW analysers
		e.analyzePortScanFlow,
		e.analyzeSlowDoS,
		e.analyzeHTTPFlood,
		e.analyzeBruteForceFlow,
		e.analyzeDataExfiltration,
		e.analyzeDNSAmplification,
		e.analyzeICMPAnomaly,
	}

	for _, fn := range analysers {
		sigs := fn(flow, pkt, featVec)
		res.Signals = append(res.Signals, sigs...)
	}

	for _, sig := range res.Signals {
		if existing, ok := res.CategoryScores[sig.Category]; ok {
			res.CategoryScores[sig.Category] = 1 - (1-existing)*(1-sig.Confidence)
		} else {
			res.CategoryScores[sig.Category] = sig.Confidence
		}
		res.RulesFired++
	}

	for cat, score := range res.CategoryScores {
		if score > res.MaxConfidence {
			res.MaxConfidence = score
			res.TopCategory = cat
		}
	}

	return res
}

// ─────────────────────────────────────────────────────────────────────────
// ORIGINAL 8 ANALYSERS
// ─────────────────────────────────────────────────────────────────────────

func (e *Engine) analyzeSynFlood(flow *features.Flow, pkt *dpi.ParsedPacket, _ []float32) []StaticSignal {
	if flow == nil {
		return nil
	}
	totalPkts := flow.FwdPackets + flow.BwdPackets
	if totalPkts < 10 {
		return nil
	}
	synRatio := float64(flow.SYNCount) / float64(totalPkts)
	ackRatio := float64(flow.ACKCount) / float64(totalPkts)
	if synRatio > 0.7 && ackRatio < 0.15 && flow.SYNCount > 20 {
		conf := float32(math.Min(1.0, synRatio*1.2))
		return []StaticSignal{{
			Name: "syn_flood_ratio", Category: "dos", Confidence: conf,
			Description: fmt.Sprintf("SYN ratio=%.2f ACK ratio=%.2f SYNs=%d", synRatio, ackRatio, flow.SYNCount),
		}}
	}
	rstRatio := float64(flow.RSTCount) / float64(totalPkts)
	if rstRatio > 0.4 && flow.RSTCount > 15 {
		return []StaticSignal{{
			Name: "rst_storm", Category: "dos", Confidence: float32(math.Min(0.75, rstRatio)),
			Description: fmt.Sprintf("RST ratio=%.2f count=%d", rstRatio, flow.RSTCount),
		}}
	}
	return nil
}

func (e *Engine) analyzePortScan(flow *features.Flow, pkt *dpi.ParsedPacket, featVec []float32) []StaticSignal {
	if pkt == nil || pkt.TCP == nil {
		return nil
	}
	srcIP := ""
	if pkt.IPv4 != nil {
		srcIP = pkt.IPv4.SrcIP.String()
	} else if pkt.IPv6 != nil {
		srcIP = pkt.IPv6.SrcIP.String()
	}
	if srcIP == "" {
		return nil
	}
	e.mu.Lock()
	state, ok := e.flowStates[srcIP]
	if !ok {
		state = &flowState{
			dstPortsSeen: make(map[uint16]struct{}),
			srcIPsSeen:   make(map[string]struct{}),
			firstSeen:    time.Now(),
		}
		e.flowStates[srcIP] = state
	}
	flags := pkt.TCP.Flags
	isSYN := flags.SYN && !flags.ACK
	if isSYN {
		state.synCount++
		state.dstPortsSeen[pkt.TCP.DstPort] = struct{}{}
	}
	uniquePorts := len(state.dstPortsSeen)
	elapsed := time.Since(state.firstSeen).Seconds()
	synCount := state.synCount
	e.mu.Unlock()

	if uniquePorts > 15 && elapsed < 30.0 {
		portsPerSec := float64(uniquePorts) / math.Max(elapsed, 1)
		conf := float32(math.Min(0.95, portsPerSec/10.0))
		return []StaticSignal{{
			Name: "port_scan_unique_ports", Category: "portscan", Confidence: conf,
			Description: fmt.Sprintf("src=%s unique_ports=%d in %.1fs (%.1f/s)", srcIP, uniquePorts, elapsed, portsPerSec),
		}}
	}
	if synCount > 30 && elapsed < 20.0 && uniquePorts == 1 {
		return []StaticSignal{{
			Name: "syn_sweep_single_port", Category: "portscan", Confidence: 0.70,
			Description: fmt.Sprintf("src=%s syn_count=%d single_port in %.1fs", srcIP, synCount, elapsed),
		}}
	}
	return nil
}

func (e *Engine) analyzeBruteForce(flow *features.Flow, pkt *dpi.ParsedPacket, featVec []float32) []StaticSignal {
	if pkt == nil {
		return nil
	}
	authPorts := map[uint16]string{22: "SSH", 21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC", 5901: "VNC", 445: "SMB", 1433: "MSSQL", 3306: "MySQL"}
	var dstPort uint16
	if pkt.TCP != nil {
		dstPort = pkt.TCP.DstPort
	} else if pkt.UDP != nil {
		dstPort = pkt.UDP.DstPort
	}
	service, isAuthPort := authPorts[dstPort]
	if !isAuthPort || flow == nil {
		return nil
	}
	if flow.FwdPackets < 20 {
		return nil
	}
	durationSec := flow.LastSeen.Sub(flow.StartTime).Seconds()
	if durationSec < 1 {
		durationSec = 1
	}
	fwdPps := float64(flow.FwdPackets) / durationSec
	avgFwdLen := float64(0)
	if flow.FwdPackets > 0 {
		avgFwdLen = float64(flow.FwdBytes) / float64(flow.FwdPackets)
	}
	if fwdPps > 5.0 && avgFwdLen < 200 && float64(flow.FwdPackets) > 30 {
		conf := float32(math.Min(0.90, fwdPps/50.0+0.4))
		return []StaticSignal{{
			Name: "brute_force_auth_port", Category: "brute_force", Confidence: conf,
			Description: fmt.Sprintf("%s port=%d pps=%.1f avg_payload=%.0f bytes", service, dstPort, fwdPps, avgFwdLen),
		}}
	}
	return nil
}

func (e *Engine) analyzeDNSTunneling(flow *features.Flow, pkt *dpi.ParsedPacket, _ []float32) []StaticSignal {
	if pkt == nil {
		return nil
	}
	dns, ok := pkt.App.(*dpi.DNSPacket)
	if !ok || dns == nil {
		return nil
	}
	var sigs []StaticSignal
	for _, q := range dns.Questions {
		entropy := shannonEntropy(q.Name)
		if entropy > 4.2 {
			sigs = append(sigs, StaticSignal{
				Name: "dns_high_entropy", Category: "botnet",
				Confidence:  float32(math.Min(0.85, (entropy-4.2)/1.5+0.4)),
				Description: fmt.Sprintf("query=%q entropy=%.2f", truncate(q.Name, 40), entropy),
			})
		}
		if dns.LongestLabel > 40 {
			sigs = append(sigs, StaticSignal{
				Name: "dns_long_label", Category: "botnet",
				Confidence:  float32(math.Min(0.80, float64(dns.LongestLabel)/60.0)),
				Description: fmt.Sprintf("longest_label=%d chars", dns.LongestLabel),
			})
		}
		if q.Type == 16 && dns.IsQuery {
			sigs = append(sigs, StaticSignal{
				Name: "dns_txt_query", Category: "botnet", Confidence: 0.55,
				Description: fmt.Sprintf("TXT query for %q", truncate(q.Name, 30)),
			})
		}
	}
	if dns.IsTunneling {
		sigs = append(sigs, StaticSignal{
			Name: "dns_tunneling_heuristic", Category: "botnet", Confidence: 0.72,
			Description: "DPI heuristic: DNS tunneling pattern",
		})
	}
	return sigs
}

func (e *Engine) analyzeHTTPAnomaly(flow *features.Flow, pkt *dpi.ParsedPacket, _ []float32) []StaticSignal {
	if pkt == nil {
		return nil
	}
	http, ok := pkt.App.(*dpi.HTTPPacket)
	if !ok || http == nil {
		return nil
	}
	var sigs []StaticSignal
	if http.HasSQLi {
		sigs = append(sigs, StaticSignal{Name: "http_sqli_pattern", Category: "web_attack", Confidence: 0.82,
			Description: fmt.Sprintf("SQLi in URI: %q", truncate(http.URI, 50))})
	}
	if containsAny(http.URI, []string{"../", "..\\", "%2e%2e", "%252e"}) {
		sigs = append(sigs, StaticSignal{Name: "http_path_traversal", Category: "exploit", Confidence: 0.78,
			Description: fmt.Sprintf("path traversal in URI: %q", truncate(http.URI, 50))})
	}
	if containsAny(http.URI, []string{";id", "|id", ";cat ", "|cat ", "$(", "`id`", "%3Bid", "%7Cid"}) {
		sigs = append(sigs, StaticSignal{Name: "http_cmd_injection", Category: "exploit", Confidence: 0.85,
			Description: fmt.Sprintf("cmd injection in URI: %q", truncate(http.URI, 50))})
	}
	if http.SuspiciousUA {
		sigs = append(sigs, StaticSignal{Name: "http_suspicious_ua", Category: "exploit", Confidence: 0.50,
			Description: fmt.Sprintf("suspicious UA: %q", truncate(http.UserAgent, 40))})
	}
	uaLower := strings.ToLower(http.UserAgent)
	scanners := []string{"nikto", "sqlmap", "nmap", "masscan", "zgrab", "dirsearch", "gobuster", "burp", "scanner", "python-requests"}
	for _, sc := range scanners {
		if strings.Contains(uaLower, sc) {
			sigs = append(sigs, StaticSignal{Name: "http_scanner_ua", Category: "web_attack", Confidence: 0.88,
				Description: fmt.Sprintf("scanner UA detected: %q", truncate(http.UserAgent, 30))})
			break
		}
	}
	return sigs
}

func (e *Engine) analyzeDDoSRateAnomaly(flow *features.Flow, pkt *dpi.ParsedPacket, featVec []float32) []StaticSignal {
	if flow == nil || len(featVec) < 20 {
		return nil
	}
	bytesPerSec := float64(featVec[18])
	pktsPerSec := float64(featVec[19])
	var sigs []StaticSignal
	if pktsPerSec > 1000 {
		conf := float32(math.Min(0.95, pktsPerSec/5000.0+0.6))
		sigs = append(sigs, StaticSignal{Name: "ddos_extreme_pkt_rate", Category: "ddos", Confidence: conf,
			Description: fmt.Sprintf("flow rate=%.0f pkt/s, %.0f bytes/s", pktsPerSec, bytesPerSec)})
	}
	durationUs := float64(featVec[0])
	totalPkts := float64(featVec[1]) + float64(featVec[2])
	if durationUs < 500_000 && totalPkts > 200 {
		sigs = append(sigs, StaticSignal{Name: "ddos_flash_flood", Category: "ddos", Confidence: 0.72,
			Description: fmt.Sprintf("%.0f pkts in %.1f ms", totalPkts, durationUs/1000)})
	}
	fwdPkts := float64(featVec[1])
	bwdPkts := float64(featVec[2])
	if fwdPkts > 50 && bwdPkts < 2 {
		asymRatio := fwdPkts / math.Max(bwdPkts+1, 1)
		if asymRatio > 25 {
			sigs = append(sigs, StaticSignal{Name: "ddos_asymmetric_flow", Category: "ddos",
				Confidence:  float32(math.Min(0.80, (asymRatio-25)/100+0.5)),
				Description: fmt.Sprintf("fwd=%.0f pkts bwd=%.0f pkts ratio=%.0f:1", fwdPkts, bwdPkts, asymRatio)})
		}
	}
	return sigs
}

func (e *Engine) analyzeTrafficEntropy(flow *features.Flow, pkt *dpi.ParsedPacket, featVec []float32) []StaticSignal {
	if flow == nil || len(featVec) < 30 {
		return nil
	}
	var sigs []StaticSignal
	iatMean := float64(featVec[22])
	iatStd := float64(featVec[23])
	if iatMean > 1_000_000 && iatStd > 0 {
		cv := iatStd / iatMean
		if cv < 0.05 && float64(flow.FwdPackets+flow.BwdPackets) > 10 {
			sigs = append(sigs, StaticSignal{Name: "beaconing_regular_iat", Category: "botnet",
				Confidence:  float32(math.Min(0.80, (0.05-cv)/0.05*0.5+0.5)),
				Description: fmt.Sprintf("very regular IAT: mean=%.1fms CV=%.4f (C2 beacon?)", iatMean/1000, cv)})
		}
	}
	fwdMean := float64(featVec[7])
	bwdMean := float64(featVec[11])
	if fwdMean < 80 && bwdMean < 80 && float64(flow.FwdPackets) > 20 {
		sigs = append(sigs, StaticSignal{Name: "covert_channel_small_pkts", Category: "infiltration", Confidence: 0.45,
			Description: fmt.Sprintf("tiny bidirectional packets: fwd_avg=%.0fb bwd_avg=%.0fb", fwdMean, bwdMean)})
	}
	return sigs
}

func (e *Engine) analyzeExploitPatterns(flow *features.Flow, pkt *dpi.ParsedPacket, featVec []float32) []StaticSignal {
	if pkt == nil {
		return nil
	}
	var sigs []StaticSignal
	malwareJA3 := map[string]string{
		"769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24,0":                                   "Metasploit",
		"769,4-5-10-9-100-98-3-6-19-18-99,,,":                                                                 "Trickbot",
		"771,49195-49199-49196-49200-52393-52392-49161-49171-57-51,0-23-65281-10-11-35-16-5-13-28,29-23-24,0": "Cobalt Strike",
		"771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24-25-256-257,0": "AsyncRAT",
	}
	if tls, ok := pkt.App.(*dpi.TLSPacket); ok && tls != nil {
		for ja3, family := range malwareJA3 {
			if tls.JA3Hash == ja3 {
				sigs = append(sigs, StaticSignal{Name: "tls_malware_ja3", Category: "botnet", Confidence: 0.90,
					Description: fmt.Sprintf("JA3 matches %s fingerprint", family)})
				break
			}
		}
	}
	if flow != nil && len(flow.FwdPktLengths) > 0 && flow.FwdPktLengths[0] > 32768 {
		sigs = append(sigs, StaticSignal{Name: "exploit_large_first_pkt", Category: "exploit", Confidence: 0.60,
			Description: fmt.Sprintf("oversized first packet: %d bytes (heap spray?)", flow.FwdPktLengths[0])})
	}
	return sigs
}

// ─────────────────────────────────────────────────────────────────────────
// v4.0: 7 NEW ANALYSERS
// ─────────────────────────────────────────────────────────────────────────

// ── Analyser 9: Port Scan from flow features ─────────────────────────────
// Solves: Port Scan missed because packet-level analyser gets pkt=nil on flow expiry.
func (e *Engine) analyzePortScanFlow(_ *features.Flow, _ *dpi.ParsedPacket, featVec []float32) []StaticSignal {
	if len(featVec) < 45 {
		return nil
	}
	fwdPkts := float64(featVec[1])
	bwdPkts := float64(featVec[2])
	fwdMean := float64(featVec[7])
	fwdStd := float64(featVec[8])
	synCount := float64(featVec[41])
	rstCount := float64(featVec[42])
	ackCount := float64(featVec[44])
	totalPkts := fwdPkts + bwdPkts
	if totalPkts < 20 {
		return nil
	}
	synRatio := synCount / totalPkts
	rstRatio := rstCount / totalPkts
	ackRatio := ackCount / totalPkts
	var sigs []StaticSignal
	// SYN scan: high SYN + high RST + low ACK + small uniform packets
	if synRatio > 0.3 && rstRatio > 0.2 && ackRatio < 0.15 && fwdMean < 80 && fwdStd < 20 {
		conf := float32(math.Min(0.85, (synRatio+rstRatio)*0.7))
		sigs = append(sigs, StaticSignal{
			Name: "portscan_flow_syn_rst", Category: "portscan", Confidence: conf,
			Description: fmt.Sprintf("SYN_ratio=%.2f RST_ratio=%.2f ACK_ratio=%.2f fwd_mean=%.0fb", synRatio, rstRatio, ackRatio, fwdMean),
		})
	}
	// Stealth scan: no SYN, high RST
	if synCount == 0 && rstRatio > 0.5 && fwdPkts > 10 && fwdMean < 60 {
		sigs = append(sigs, StaticSignal{
			Name: "portscan_stealth_scan", Category: "portscan", Confidence: 0.70,
			Description: fmt.Sprintf("no SYN, RST_ratio=%.2f fwd_pkts=%.0f (stealth scan?)", rstRatio, fwdPkts),
		})
	}
	return sigs
}

// ── Analyser 10: Slow DoS (Slowloris, Slow Read, R.U.D.Y.) ──────────────
// Solves: Slowloris at 0.01% ML — invisible to rate-based detection.
func (e *Engine) analyzeSlowDoS(_ *features.Flow, _ *dpi.ParsedPacket, featVec []float32) []StaticSignal {
	if len(featVec) < 40 {
		return nil
	}
	durationUs := float64(featVec[0])
	fwdPkts := float64(featVec[1])
	bwdPkts := float64(featVec[2])
	fwdMean := float64(featVec[7])
	pktsPerSec := float64(featVec[19])
	fwdPsh := float64(featVec[36])
	durationSec := durationUs / 1_000_000

	if durationSec > 30 && fwdPkts > 20 && fwdMean < 150 && pktsPerSec < 10 {
		bwdRatio := bwdPkts / math.Max(fwdPkts, 1)
		pshRatio := fwdPsh / math.Max(fwdPkts, 1)
		// Slowloris: many small fwd with PSH, few responses
		if bwdRatio < 0.15 && pshRatio > 0.7 {
			conf := float32(math.Min(0.85, 0.5+durationSec/300.0))
			return []StaticSignal{{
				Name: "slow_dos_partial_headers", Category: "dos", Confidence: conf,
				Description: fmt.Sprintf("duration=%.0fs fwd=%.0f bwd=%.0f mean=%.0fb rate=%.2f/s PSH=%.0f%%",
					durationSec, fwdPkts, bwdPkts, fwdMean, pktsPerSec, pshRatio*100),
			}}
		}
		// Slow Read: few fwd, many bwd, long duration
		if bwdPkts > fwdPkts*3 && fwdPkts < 20 && durationSec > 60 {
			return []StaticSignal{{
				Name: "slow_read_attack", Category: "dos", Confidence: 0.70,
				Description: fmt.Sprintf("duration=%.0fs fwd=%.0f bwd=%.0f (slow read?)", durationSec, fwdPkts, bwdPkts),
			}}
		}
	}
	return nil
}

// ── Analyser 11: HTTP Flood (Layer 7 DDoS) ───────────────────────────────
// Solves: HTTP Flood at 0.2% ML — normal-sized packets look like browsing.
func (e *Engine) analyzeHTTPFlood(_ *features.Flow, _ *dpi.ParsedPacket, featVec []float32) []StaticSignal {
	if len(featVec) < 45 {
		return nil
	}
	fwdPkts := float64(featVec[1])
	bwdPkts := float64(featVec[2])
	fwdMean := float64(featVec[7])
	bwdMean := float64(featVec[11])
	pktsPerSec := float64(featVec[19])
	pshCount := float64(featVec[43])
	durationSec := float64(featVec[0]) / 1_000_000

	if pktsPerSec > 80 && durationSec > 2 &&
		fwdMean > 100 && fwdMean < 3000 && bwdMean > 200 &&
		bwdPkts > fwdPkts*0.3 && fwdPkts > 300 {
		totalPkts := fwdPkts + bwdPkts
		pshRatio := pshCount / math.Max(totalPkts, 1)
		if pshRatio > 0.6 {
			conf := float32(math.Min(0.85, pktsPerSec/500.0+0.5))
			return []StaticSignal{{
				Name: "http_flood_l7", Category: "ddos", Confidence: conf,
				Description: fmt.Sprintf("L7 flood: rate=%.0f/s fwd_avg=%.0fb bwd_avg=%.0fb dur=%.0fs PSH=%.0f%%",
					pktsPerSec, fwdMean, bwdMean, durationSec, pshRatio*100),
			}}
		}
	}
	return nil
}

// ── Analyser 12: Brute Force from flow features ──────────────────────────
// Solves: FTP Brute Force missed because packet-level analyser needs port info.
func (e *Engine) analyzeBruteForceFlow(_ *features.Flow, _ *dpi.ParsedPacket, featVec []float32) []StaticSignal {
	if len(featVec) < 74 {
		return nil
	}
	durationSec := float64(featVec[0]) / 1_000_000
	fwdPkts := float64(featVec[1])
	bwdPkts := float64(featVec[2])
	fwdMean := float64(featVec[7])
	bwdMean := float64(featVec[11])
	fwdPps := float64(featVec[20])
	fwdPsh := float64(featVec[36])
	bwdPsh := float64(featVec[37])
	synCount := float64(featVec[41])
	ackCount := float64(featVec[44])
	pktSizeAvg := float64(featVec[73])

	if durationSec > 5 && durationSec < 300 &&
		fwdPkts > 50 && bwdPkts > 30 &&
		fwdMean < 250 && bwdMean < 300 && pktSizeAvg < 250 && fwdPps > 3 {
		totalPkts := fwdPkts + bwdPkts
		bwdRatio := bwdPkts / math.Max(fwdPkts, 1)
		pshRatio := (fwdPsh + bwdPsh) / math.Max(totalPkts, 1)
		synRatio := synCount / math.Max(totalPkts, 1)
		ackRatio := ackCount / math.Max(totalPkts, 1)
		if bwdRatio > 0.4 && bwdRatio < 2.5 && pshRatio > 0.4 && synRatio < 0.15 && ackRatio > 0.5 {
			conf := float32(math.Min(0.80, fwdPps/30.0+0.4))
			return []StaticSignal{{
				Name: "brute_force_flow_pattern", Category: "brute_force", Confidence: conf,
				Description: fmt.Sprintf("duration=%.0fs fwd=%.0f bwd=%.0f avg=%.0fb PSH=%.0f%% rate=%.1f/s",
					durationSec, fwdPkts, bwdPkts, pktSizeAvg, pshRatio*100, fwdPps),
			}}
		}
	}
	return nil
}

// ── Analyser 13: Data Exfiltration ───────────────────────────────────────
// Solves: Data Exfil detected by ML (9.7%) but discarded by fusion floor.
func (e *Engine) analyzeDataExfiltration(_ *features.Flow, _ *dpi.ParsedPacket, featVec []float32) []StaticSignal {
	if len(featVec) < 22 {
		return nil
	}
	durationSec := float64(featVec[0]) / 1_000_000
	fwdPkts := float64(featVec[1])
	bwdPkts := float64(featVec[2])
	fwdBytes := float64(featVec[3])
	bwdBytes := float64(featVec[4])
	fwdMean := float64(featVec[7])
	if durationSec < 5 || fwdPkts < 50 {
		return nil
	}
	if fwdBytes > 0 && bwdBytes > 0 {
		uploadRatio := fwdBytes / bwdBytes
		if uploadRatio > 10 && fwdBytes > 1_000_000 && fwdMean > 500 {
			conf := float32(math.Min(0.80, math.Log10(uploadRatio)/3.0+0.3))
			return []StaticSignal{{
				Name: "data_exfiltration_upload", Category: "infiltration", Confidence: conf,
				Description: fmt.Sprintf("upload=%.1fMB download=%.1fKB ratio=%.0f:1",
					fwdBytes/1_000_000, bwdBytes/1000, uploadRatio),
			}}
		}
	}
	if fwdBytes > 500_000 && bwdPkts < 5 && fwdPkts > 100 {
		return []StaticSignal{{
			Name: "data_exfiltration_oneway", Category: "infiltration", Confidence: 0.65,
			Description: fmt.Sprintf("one-way upload=%.1fMB fwd=%.0f bwd=%.0f", fwdBytes/1_000_000, fwdPkts, bwdPkts),
		}}
	}
	return nil
}

// ── Analyser 14: DNS/NTP Amplification DDoS ──────────────────────────────
// Solves: DNS Amplification at 0.07% ML — small queries, huge responses.
func (e *Engine) analyzeDNSAmplification(_ *features.Flow, _ *dpi.ParsedPacket, featVec []float32) []StaticSignal {
	if len(featVec) < 42 {
		return nil
	}
	fwdPkts := float64(featVec[1])
	bwdPkts := float64(featVec[2])
	fwdBytes := float64(featVec[3])
	bwdBytes := float64(featVec[4])
	fwdMean := float64(featVec[7])
	bwdMean := float64(featVec[11])
	pktsPerSec := float64(featVec[19])
	synCount := float64(featVec[41])
	if fwdPkts < 50 || bwdPkts < 50 {
		return nil
	}
	// UDP amplification: no SYN (not TCP), small queries, huge responses
	if synCount == 0 && fwdMean < 200 && bwdMean > 500 {
		ampFactor := bwdBytes / math.Max(fwdBytes, 1)
		sizeRatio := bwdMean / math.Max(fwdMean, 1)
		if ampFactor > 5 && sizeRatio > 5 && pktsPerSec > 50 {
			conf := float32(math.Min(0.90, math.Log10(ampFactor)/2.0+0.4))
			return []StaticSignal{{
				Name: "dns_amplification_ddos", Category: "ddos", Confidence: conf,
				Description: fmt.Sprintf("amp=%.0fx size_ratio=%.0fx fwd_avg=%.0fb bwd_avg=%.0fb rate=%.0f/s",
					ampFactor, sizeRatio, fwdMean, bwdMean, pktsPerSec),
			}}
		}
	}
	return nil
}

// ── Analyser 15: ICMP Anomaly ────────────────────────────────────────────
// Solves: non-TCP floods (ICMP) — zero TCP flags, high rate, uniform packets.
func (e *Engine) analyzeICMPAnomaly(_ *features.Flow, _ *dpi.ParsedPacket, featVec []float32) []StaticSignal {
	if len(featVec) < 72 {
		return nil
	}
	fwdPkts := float64(featVec[1])
	bwdPkts := float64(featVec[2])
	fwdMean := float64(featVec[7])
	fwdStd := float64(featVec[8])
	pktsPerSec := float64(featVec[19])
	synCount := float64(featVec[41])
	rstCount := float64(featVec[42])
	pshCount := float64(featVec[43])
	ackCount := float64(featVec[44])
	urgCount := float64(featVec[45])
	initFwdWin := float64(featVec[70])
	initBwdWin := float64(featVec[71])

	allFlagsZero := synCount == 0 && rstCount == 0 && pshCount == 0 && ackCount == 0 && urgCount == 0
	noTCPWindows := initFwdWin == 0 && initBwdWin == 0
	if !allFlagsZero || !noTCPWindows {
		return nil
	}
	var sigs []StaticSignal
	if pktsPerSec > 100 && fwdPkts > 200 && bwdPkts < fwdPkts*0.05 && fwdMean < 200 && fwdStd < 30 {
		conf := float32(math.Min(0.90, pktsPerSec/2000.0+0.6))
		sigs = append(sigs, StaticSignal{
			Name: "icmp_flood", Category: "ddos", Confidence: conf,
			Description: fmt.Sprintf("non-TCP flood: rate=%.0f/s fwd=%.0f mean=%.0fb std=%.1f",
				pktsPerSec, fwdPkts, fwdMean, fwdStd),
		})
	}
	if fwdPkts > 20 && bwdPkts > 20 && fwdMean > 80 && pktsPerSec < 50 {
		sigs = append(sigs, StaticSignal{
			Name: "icmp_covert_channel", Category: "infiltration", Confidence: 0.55,
			Description: fmt.Sprintf("non-TCP bidirectional: fwd=%.0f bwd=%.0f mean=%.0fb", fwdPkts, bwdPkts, fwdMean),
		})
	}
	return sigs
}

// ═══════════════════════════════════════════════════════════════════════════
// v4.0 Hardened Fusion Decision Logic
// ═══════════════════════════════════════════════════════════════════════════

func (e *Engine) fuse(
	mlScore float32,
	mlAttack string,
	mlPerModel map[string]float32,
	staticRes *StaticResult,
) *FusionResult {

	result := &FusionResult{
		MLScore:       mlScore,
		MLAttackType:  mlAttack,
		MLPerModel:    mlPerModel,
		StaticScore:   staticRes.MaxConfidence,
		StaticSignals: staticRes.Signals,
	}

	// ── v4.0 FIX #1: Adaptive ML floor ───────────────────────────────────
	mlAboveBinaryThreshold := mlScore >= e.mlBinaryThreshold

	if mlScore < e.mlFloorThreshold && !mlAboveBinaryThreshold && staticRes.MaxConfidence < 0.60 {
		result.Level = ThreatBenign
		result.LevelStr = ThreatBenign.String()
		result.FinalScore = 0
		result.Confidence = 1 - mlScore
		result.Explanation = fmt.Sprintf("ML=%.1f%% (below floor %.0f%%) + no static signals",
			mlScore*100, e.mlFloorThreshold*100)
		return result
	}

	// ── v4.0 FIX #5: Static category override ────────────────────────────
	attackType := mlAttack
	if staticRes.TopCategory != "" && staticRes.MaxConfidence >= 0.50 {
		if attackType == "" || !categoryMatch(attackType, staticRes.TopCategory) {
			attackType = staticRes.TopCategory
		}
	}
	if attackType == "" && staticRes.TopCategory != "" {
		attackType = staticRes.TopCategory
	}

	corroborated := false
	if mlAttack != "" && staticRes.TopCategory != "" {
		corroborated = categoryMatch(mlAttack, staticRes.TopCategory)
	}
	result.AttackType = attackType
	result.Corroborated = corroborated

	// ── Blended score ────────────────────────────────────────────────────
	blended := e.mlWeight*mlScore + e.staticWeight*staticRes.MaxConfidence
	if corroborated {
		blended = float32(math.Min(1.0, float64(blended)*1.25))
	}
	result.FinalScore = blended

	// ── Threat level assignment ──────────────────────────────────────────
	switch {
	case corroborated && mlScore >= 0.30 && staticRes.MaxConfidence >= 0.55:
		result.Level = ThreatCritical
		result.Confidence = float32(math.Min(1.0, float64(blended)*1.15))

	case mlScore >= e.mlHighConfidence && mlAttack != "":
		result.Level = ThreatHigh
		result.Confidence = mlScore

	case staticRes.MaxConfidence >= 0.70 && staticRes.RulesFired >= 2:
		result.Level = ThreatHigh
		result.Confidence = staticRes.MaxConfidence

	case blended >= 0.30:
		result.Level = ThreatMedium
		result.Confidence = blended

	case blended >= 0.10 || staticRes.RulesFired >= 1:
		result.Level = ThreatLow
		result.Confidence = blended

	case mlAboveBinaryThreshold && mlAttack != "":
		result.Level = ThreatLow
		result.Confidence = mlScore
		blended = mlScore * e.mlWeight
		result.FinalScore = blended

	default:
		result.Level = ThreatBenign
		result.Confidence = 1 - blended
	}

	// ── Model disagreement warning ───────────────────────────────────────
	modelDisagreement := ""
	if mlPerModel != nil {
		maxModel := float32(0)
		minModel := float32(1)
		for _, p := range mlPerModel {
			if p > maxModel {
				maxModel = p
			}
			if p < minModel {
				minModel = p
			}
		}
		if maxModel-minModel > 0.15 {
			modelDisagreement = fmt.Sprintf(" | model spread=%.0f%%", (maxModel-minModel)*100)
		}
	}

	result.LevelStr = result.Level.String()
	result.Explanation = buildExplanation(mlScore, mlAttack, staticRes, corroborated) + modelDisagreement

	return result
}

// ═══════════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════════

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len([]rune(s)))
	entropy := 0.0
	for _, f := range freq {
		p := f / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func containsAny(s string, patterns []string) bool {
	lower := strings.ToLower(s)
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func categoryMatch(mlCat, staticCat string) bool {
	mapping := map[string][]string{
		"dos":          {"dos", "ddos"},
		"ddos":         {"dos", "ddos"},
		"portscan":     {"portscan"},
		"brute_force":  {"brute_force"},
		"botnet":       {"botnet", "infiltration"},
		"infiltration": {"botnet", "infiltration"},
		"web_attack":   {"web_attack", "exploit"},
		"exploit":      {"exploit", "web_attack"},
	}
	if cats, ok := mapping[mlCat]; ok {
		for _, c := range cats {
			if c == staticCat {
				return true
			}
		}
	}
	return mlCat == staticCat
}

func buildExplanation(mlScore float32, mlAttack string, static *StaticResult, corroborated bool) string {
	parts := []string{}
	if mlScore > 0.03 {
		if mlAttack != "" {
			parts = append(parts, fmt.Sprintf("ML: %.1f%% %s", mlScore*100, mlAttack))
		} else {
			parts = append(parts, fmt.Sprintf("ML: %.1f%%", mlScore*100))
		}
	}
	if static.RulesFired > 0 {
		parts = append(parts, fmt.Sprintf("Static: %d rule(s) [%s %.0f%%]",
			static.RulesFired, static.TopCategory, static.MaxConfidence*100))
	}
	if corroborated {
		parts = append(parts, "✓ corroborated")
	}
	if len(parts) == 0 {
		return "no significant signals"
	}
	return strings.Join(parts, " | ")
}

// IPState is a per-IP snapshot returned to the dashboard.
type IPState struct {
	IP            string `json:"ip"`
	SynCount      int    `json:"syn"`
	AckCount      int    `json:"ack"`
	RstCount      int    `json:"rst"`
	PacketCount   int    `json:"packets"`
	ByteCount     int64  `json:"bytes"`
	DstPorts      int    `json:"dst_ports"`
	HTTPReqCount  int    `json:"http_req"`
	HTTPErrCount  int    `json:"http_err"`
	LoginAttempts int    `json:"login_attempts"`
	FirstSeenMs   int64  `json:"first_seen_ms"`
	LastSeenMs    int64  `json:"last_seen_ms"`
}

// StatesSnapshot returns a read-only snapshot of per-IP tracking state.
func (e *Engine) StatesSnapshot(max int) []IPState {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]IPState, 0, len(e.flowStates))
	for ip, s := range e.flowStates {
		dstPorts := 0
		if s.dstPortsSeen != nil {
			dstPorts = len(s.dstPortsSeen)
		}
		out = append(out, IPState{
			IP:            ip,
			SynCount:      s.synCount,
			AckCount:      s.ackCount,
			RstCount:      s.rstCount,
			PacketCount:   s.pktCount,
			ByteCount:     s.byteCount,
			DstPorts:      dstPorts,
			HTTPReqCount:  s.httpReqCount,
			HTTPErrCount:  s.httpErrCount,
			LoginAttempts: s.loginAttempts,
			FirstSeenMs:   s.firstSeen.UnixMilli(),
			LastSeenMs:    s.lastSeen.UnixMilli(),
		})
	}
	// Sort by pktCount desc
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].PacketCount < out[j].PacketCount; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	if max > 0 && len(out) > max {
		out = out[:max]
	}
	return out
}

// Weights returns (mlWeight, staticWeight, mlFloor, mlHighConfidence, binaryThreshold).
func (e *Engine) Weights() (float32, float32, float32, float32, float32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mlWeight, e.staticWeight, e.mlFloorThreshold, e.mlHighConfidence, e.mlBinaryThreshold
}

// SetBinaryThreshold updates the ML binary threshold (0.001–0.99).
func (e *Engine) SetBinaryThreshold(v float32) {
	if v < 0.001 {
		v = 0.001
	}
	if v > 0.99 {
		v = 0.99
	}
	e.mu.Lock()
	e.mlBinaryThreshold = v
	e.mu.Unlock()
}

// CleanupStaleStates removes flow states older than 5 minutes.
func (e *Engine) CleanupStaleStates() {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	for ip, state := range e.flowStates {
		if state.lastSeen.Before(cutoff) || state.lastSeen.IsZero() {
			delete(e.flowStates, ip)
		}
	}
}

// IsWhitelisted returns true for obviously benign destinations.
func IsWhitelisted(dstIP net.IP, dstPort uint16) bool {
	if dstIP.Equal(net.IPv4bcast) || dstIP.IsMulticast() || dstIP.IsLinkLocalMulticast() {
		return true
	}
	benignPorts := map[uint16]bool{
		53: false, 123: true, 67: true, 68: true, 5353: true, 1900: true,
	}
	if whitelisted, exists := benignPorts[dstPort]; exists {
		return whitelisted
	}
	return false
}
