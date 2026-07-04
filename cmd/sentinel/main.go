// Sentinel-Pi v4.0 — Deep Inspector
// Entry point that wires together:
//
//	capture → DPI → feature extraction → ML inference → fusion → dashboard
//	+ periodic system sampling, threat-intel registry, control surface.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/dhergam/sentinel-deep/internal/capture"
	"github.com/dhergam/sentinel-deep/internal/dashboard"
	"github.com/dhergam/sentinel-deep/internal/dpi"
	"github.com/dhergam/sentinel-deep/internal/features"
	"github.com/dhergam/sentinel-deep/internal/fusion"
	"github.com/dhergam/sentinel-deep/internal/intel"
	"github.com/dhergam/sentinel-deep/internal/memory"
	"github.com/dhergam/sentinel-deep/internal/ml"
	"github.com/dhergam/sentinel-deep/internal/storage"
	"github.com/dhergam/sentinel-deep/internal/system"
)

func main() {
	// ─── CLI flags ──────────────────────────────────────────────────────
	var (
		iface      = flag.String("interface", "wlan0", "Network interface")
		modelsDir  = flag.String("models", "./deploy/models", "Models directory")
		dashAddr   = flag.String("dash", ":8080", "Dashboard listen address")
		pcapDir    = flag.String("pcap-dir", "./captures", "PCAP output directory")
		pcapMaxMB  = flag.Int("pcap-max-mb", 100, "Max total PCAP size (MB)")
		pcapFileMB = flag.Int("pcap-file-mb", 25, "Per-file PCAP size (MB)")
		maxRAMMB   = flag.Int("max-ram-mb", 2800, "Max RAM usage (MB); 0=unlimited")
		warnRAMMB  = flag.Int("warn-ram-mb", 2200, "Warning RAM threshold (MB)")
		maxFlows   = flag.Int("max-flows", 50000, "Max concurrent flows")
		promisc    = flag.Bool("promisc", true, "Enable promiscuous mode")
		noML       = flag.Bool("no-ml", false, "Disable ML inference")
		noPCAP     = flag.Bool("no-pcap", false, "Disable PCAP writing")
		intelFeeds = flag.String("intel-feeds", "", "Optional directory of *.txt intel feeds")
	)
	flag.Parse()

	runtime.GOMAXPROCS(runtime.NumCPU())

	log.Println("═══════════════════════════════════════════════════════")
	log.Println("  Sentinel-Pi v4.0 — Deep Inspector")
	log.Println("═══════════════════════════════════════════════════════")
	log.Printf("  Interface:    %s (promisc=%v)", *iface, *promisc)
	log.Printf("  Models:       %s (ml=%v)", *modelsDir, !*noML)
	log.Printf("  Dashboard:    http://0.0.0.0%s", *dashAddr)
	log.Printf("  PCAP:         %s (%d MB max, %d MB/file)", *pcapDir, *pcapMaxMB, *pcapFileMB)
	log.Printf("  RAM limit:    %d MB (warn: %d)", *maxRAMMB, *warnRAMMB)
	log.Println("═══════════════════════════════════════════════════════")

	// ─── Memory guard ───────────────────────────────────────────────────
	guard := memory.NewGuard(*maxRAMMB, *warnRAMMB)
	guard.SetCallbacks(
		func(rss uint64) { log.Printf("[MEM-WARN] RSS=%d MB", rss/1024/1024) },
		func(rss uint64) { log.Printf("[MEM-CRITICAL] RSS=%d MB — forced GC", rss/1024/1024) },
	)
	guard.Start()
	defer guard.Stop()

	// ─── ML engine ──────────────────────────────────────────────────────
	var mlEngine *ml.Engine
	if !*noML {
		eng, err := ml.NewEngine(*modelsDir)
		if err != nil {
			log.Printf("[WARN] ML init failed: %v (continuing without ML)", err)
		} else {
			mlEngine = eng
			defer mlEngine.Close()
			log.Println("[ML] Loaded 6 models (binary + multiclass ensemble)")
		}
	}

	// ─── Fusion engine ──────────────────────────────────────────────────
	fusionEngine := fusion.NewEngine(mlEngine)
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			fusionEngine.CleanupStaleStates()
		}
	}()

	// ─── Threat intel registry ─────────────────────────────────────────
	intelRegistry := intel.NewRegistry(*intelFeeds)
	log.Printf("[INTEL] Registry loaded: %v", intelRegistry.Counts())

	// ─── PCAP storage ───────────────────────────────────────────────────
	var pcap *storage.RotatingPCAP
	if !*noPCAP {
		pc, err := storage.NewRotatingPCAP(*pcapDir, *pcapMaxMB, *pcapFileMB)
		if err != nil {
			log.Printf("[WARN] PCAP init failed: %v", err)
		} else {
			pcap = pc
			defer pcap.Close()
		}
	}

	// ─── System monitor (CPU/disk/net) ──────────────────────────────────
	sysMon := system.NewMonitor()

	// ─── Dashboard ──────────────────────────────────────────────────────
	dash := dashboard.NewServer(*dashAddr, 2000, 500)

	// ─── Flow tracker ───────────────────────────────────────────────────
	tracker := features.NewFlowTracker(120*time.Second, *maxFlows)

	// On flow expiry: run full ML + fusion and store result on the flow
	// (so live packets can reference the last known classification).
	tracker.SetExpireCallback(func(f *features.Flow) {
		feat := features.Extract(f)
		result := fusionEngine.Analyze(f, nil, feat)
		f.SetCached(nil, result)

		if result.Level >= fusion.ThreatHigh {
			srcIP := net.IP(f.Key.SrcIP[:]).String()
			dstIP := net.IP(f.Key.DstIP[:]).String()

			var pred *ml.Prediction
			if mlEngine != nil {
				pred, _ = mlEngine.Predict(feat)
			}

			dash.AddAlert(dashboard.Alert{
				ID:         fmt.Sprintf("%s-%d", f.Key.String(), f.StartTime.UnixNano()),
				Time:       time.Now(),
				SrcIP:      srcIP,
				DstIP:      dstIP,
				Type:       result.AttackType,
				Score:      result.FinalScore,
				Severity:   result.LevelStr,
				Details:    result.Explanation,
				Prediction: pred,
			})

			// Auto-block on CRITICAL with 10-minute TTL
			if result.Level == fusion.ThreatCritical && srcIP != "" {
				intelRegistry.AddBlock(srcIP, result.AttackType+": "+result.Explanation,
					10*time.Minute, true)
			}

			log.Printf("[ALERT] %s %s | ML=%.1f%% Static=%.1f%% Fused=%.1f%% | %s",
				result.LevelStr, f.Key.String(),
				result.MLScore*100, result.StaticScore*100, result.FinalScore*100,
				result.Explanation)
		}
	})

	// ─── Periodic in-flight flow scoring (every 15s for active flows) ───
	// Runs ML+fusion on a *sample* of active flows so the dashboard can
	// show live scoring without per-packet inference overhead.
	go func() {
		t := time.NewTicker(12 * time.Second)
		defer t.Stop()
		for range t.C {
			if mlEngine == nil {
				continue
			}
			scored := 0
			tracker.ForEach(func(f *features.Flow) bool {
				// Skip very short flows
				if f.FwdPackets+f.BwdPackets < 10 {
					return true
				}
				// Skip flows analysed within last 10s
				_, _, lastAt := f.GetCached()
				if !lastAt.IsZero() && time.Since(lastAt) < 10*time.Second {
					return true
				}
				feat := features.Extract(f)
				result := fusionEngine.Analyze(f, nil, feat)
				f.SetCached(nil, result)
				scored++
				return scored < 200 // cap CPU burn
			})
		}
	}()

	// ─── Dashboard providers ────────────────────────────────────────────
	dash.SetStatsProvider(func() map[string]interface{} {
		ms := guard.Stats()
		return map[string]interface{}{
			"flows":    tracker.Count(),
			"ram_mb":   ms.CurrentRSS / 1024 / 1024,
			"peak_mb":  ms.PeakRSS / 1024 / 1024,
			"heap_mb":  ms.HeapAlloc / 1024 / 1024,
			"num_gc":   ms.NumGC,
			"gc_calls": ms.GCCalls,
			"warnings": ms.Warnings,
			"cpu_pct":  sysMon.SampleCPU(),
		}
	})

	dash.SetCaptureProvider(func() map[string]interface{} {
		// capProvider closure gets wired after capture is created
		if capRef == nil {
			return map[string]interface{}{"status": "init"}
		}
		cs := capRef.GetStats()
		used, capSz := capRef.ChannelDepth()
		return map[string]interface{}{
			"interface":    capRef.Interface(),
			"promiscuous":  capRef.Promiscuous(),
			"snap_len":     capRef.SnapLen(),
			"received":     cs.Received,
			"dropped":      cs.Dropped,
			"lost":         cs.Lost,
			"bytes":        cs.Bytes,
			"channel_used": used,
			"channel_cap":  capSz,
		}
	})

	dash.SetSystemProvider(func() map[string]interface{} {
		rxBps, txBps := sysMon.NetRate(*iface)
		disk := system.ReadDisk("/")
		load := system.ReadLoad()
		return map[string]interface{}{
			"cpu_pct":    sysMon.SampleCPU(),
			"disk":       disk,
			"loadavg":    load,
			"net_rx_bps": rxBps,
			"net_tx_bps": txBps,
			"interfaces": system.ReadNetDev(),
		}
	})

	dash.SetFlowsProvider(func(max int) []dashboard.FlowInfo {
		fs := tracker.Snapshot(max)
		out := make([]dashboard.FlowInfo, len(fs))
		for i, f := range fs {
			out[i] = dashboard.FlowInfo{
				SrcIP: f.SrcIP, DstIP: f.DstIP,
				SrcPort: f.SrcPort, DstPort: f.DstPort, Proto: f.Proto,
				AppProto:   f.AppProto,
				FwdPackets: f.FwdPackets, BwdPackets: f.BwdPackets,
				FwdBytes: f.FwdBytes, BwdBytes: f.BwdBytes,
				StartMs: f.StartTime, LastMs: f.LastSeen, DurationMs: f.DurationMs,
				SYN: f.SYN, ACK: f.ACK, RST: f.RST,
				SNI: f.SNI, DNSQuery: f.DNSQuery,
				MLScore: f.MLScore, AttackType: f.AttackType, Level: f.Level,
			}
		}
		return out
	})

	dash.SetFusionStatesProvider(func(max int) interface{} {
		return fusionEngine.StatesSnapshot(max)
	})

	if pcap != nil {
		dash.SetPCAPProvider(func() interface{} { return pcap.List() }, pcap.Dir())
	}

	dash.SetIntelProvider(
		func() interface{} { return intelRegistry.Indicators() },
		func() interface{} { return intelRegistry.Blocks() },
	)

	// Live config provider (reads from ML engine + fusion engine weights)
	dash.SetConfigProvider(func() map[string]interface{} {
		cfg := map[string]interface{}{
			"static_rules": staticRulesList(),
		}
		if mlEngine != nil {
			mc := mlEngine.GetConfig()
			models := mlEngine.Models()
			modelCards := make([]map[string]interface{}, len(models))
			for i, m := range models {
				status := "online"
				if !m.Loaded {
					status = "offline"
				}
				modelCards[i] = map[string]interface{}{
					"name":   m.Name,
					"file":   m.File,
					"type":   m.Type,
					"weight": m.Weight,
					"status": status,
				}
			}
			cfg["ml_models"] = modelCards
			cfg["ml_config"] = map[string]interface{}{
				"binary_threshold": mc.BinaryThreshold,
				"num_features":     mc.NumFeatures,
				"num_classes":      len(mc.LabelMap),
				"classes":          mlEngine.Classes(),
				"binary_accuracy":  99.62,
				"multi_accuracy":   98.91,
				"fpr":              0.87,
				"precision":        99.33,
				"recall":           99.99,
				"macro_f1":         84.73,
				"training_data":    "CIC-IDS2017 + UNSW-NB15 + BOT-IoT",
			}
		}
		mlW, stW, floor, hiConf, binThr := fusionEngine.Weights()
		cfg["fusion_config"] = map[string]interface{}{
			"ml_weight":          mlW,
			"static_weight":      stW,
			"ml_floor":           floor,
			"ml_high_confidence": hiConf,
			"binary_threshold":   binThr,
		}
		cfg["intel_counts"] = intelRegistry.Counts()
		return cfg
	})

	dash.SetControlHandlers(
		func(v float32) error {
			if mlEngine != nil {
				mlEngine.SetBinaryThreshold(v)
			}
			fusionEngine.SetBinaryThreshold(v)
			log.Printf("[CTRL] binary threshold set to %.4f", v)
			return nil
		},
		func() {
			runtime.GC()
			runtime.GC()
			log.Println("[CTRL] forced GC")
		},
		func(ip, reason string, seconds int) error {
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("invalid ip")
			}
			ttl := time.Duration(seconds) * time.Second
			intelRegistry.AddBlock(ip, reason, ttl, false)
			log.Printf("[CTRL] blocked %s (%s, %ds)", ip, reason, seconds)
			return nil
		},
		func(ip string) error {
			intelRegistry.RemoveBlock(ip)
			log.Printf("[CTRL] unblocked %s", ip)
			return nil
		},
	)

	// ─── Periodic flow sweeper ──────────────────────────────────────────
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			n := tracker.Sweep()
			if n > 0 {
				log.Printf("[SWEEP] expired %d flows, active=%d", n, tracker.Count())
			}
		}
	}()

	// ─── Start capture ──────────────────────────────────────────────────
	cap, err := capture.New(capture.Config{
		Interface:   *iface,
		Promiscuous: *promisc,
		ChannelSize: 10000,
	})
	if err != nil {
		log.Fatalf("capture init: %v", err)
	}
	capRef = cap
	if err := cap.Start(); err != nil {
		log.Fatalf("capture start: %v (hint: run as root?)", err)
	}
	defer cap.Close()

	// Prime CPU sampler (first read returns 0)
	sysMon.SampleCPU()
	sysMon.NetRate(*iface)

	// ─── Start dashboard ────────────────────────────────────────────────
	go func() {
		log.Printf("[DASH] Listening on %s", *dashAddr)
		if err := dash.Start(); err != nil {
			log.Printf("[DASH] error: %v", err)
		}
	}()

	// ─── Packet processing loop ─────────────────────────────────────────
	go func() {
		for pkt := range cap.Packets() {
			parsed, err := dpi.Parse(pkt.Data)
			if err != nil {
				continue
			}

			tracker.Update(parsed, pkt.Timestamp, pkt.Length)

			if pcap != nil {
				pcap.Write(pkt.Timestamp, pkt.Data)
			}

			// Attach cached per-flow fusion (from periodic analyser) + live
			// packet-only static analysis for whitelist-exempt traffic.
			var fusionRes interface{}
			var intelInfo string
			dstIP := dstIPOf(parsed)
			dstPort := dstPortOf(parsed)
			if !fusion.IsWhitelisted(dstIP, dstPort) {
				fusionRes = fusionEngine.AnalyzePacketOnly(parsed)
			}

			// Try cached per-flow prediction (preferred over packet-only)
			srcIP := srcIPOf(parsed)
			if srcIP != nil && dstIP != nil {
				if f := tracker.FindByKey(srcIP, dstIP,
					srcPortOf(parsed), dstPort, protoOf(parsed)); f != nil {
					if _, cachedFusion, _ := f.GetCached(); cachedFusion != nil {
						fusionRes = cachedFusion
					}
				}
			}

			// Intel check: JA3 + scanner UA
			if tls, ok := parsed.App.(*dpi.TLSPacket); ok && tls.JA3Hash != "" {
				if ind := intelRegistry.MatchJA3(tls.JA3Hash); ind != nil {
					intelInfo = ind.Family + " JA3"
				}
			}
			if http, ok := parsed.App.(*dpi.HTTPPacket); ok && http.UserAgent != "" {
				if ind := intelRegistry.MatchUA(http.UserAgent); ind != nil {
					intelInfo = ind.Family + " scanner"
				}
			}

			dash.AddPacket(parsed, pkt.Timestamp, pkt.Length, nil, intelInfo, fusionRes)
		}
	}()

	// ─── Periodic stats log ─────────────────────────────────────────────
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			cs := cap.GetStats()
			log.Printf("[STATS] recv=%d lost=%d bytes=%d flows=%d | %s",
				cs.Received, cs.Lost, cs.Bytes,
				tracker.Count(), guard.Stats())
		}
	}()

	// ─── Signal handling ────────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Shutting down...")
}

// capRef is a package-level pointer set once the capture is created so
// the dashboard provider closures can read from it.
var capRef *capture.Capture

// ═══════════════════════════════════════════════════════════════════════════
// Packet helpers
// ═══════════════════════════════════════════════════════════════════════════

func srcIPOf(p *dpi.ParsedPacket) net.IP {
	if p.IPv4 != nil {
		return p.IPv4.SrcIP
	}
	if p.IPv6 != nil {
		return p.IPv6.SrcIP
	}
	return nil
}

func dstIPOf(p *dpi.ParsedPacket) net.IP {
	if p.IPv4 != nil {
		return p.IPv4.DstIP
	}
	if p.IPv6 != nil {
		return p.IPv6.DstIP
	}
	return nil
}

func srcPortOf(p *dpi.ParsedPacket) uint16 {
	if p.TCP != nil {
		return p.TCP.SrcPort
	}
	if p.UDP != nil {
		return p.UDP.SrcPort
	}
	return 0
}

func dstPortOf(p *dpi.ParsedPacket) uint16 {
	if p.TCP != nil {
		return p.TCP.DstPort
	}
	if p.UDP != nil {
		return p.UDP.DstPort
	}
	return 0
}

func protoOf(p *dpi.ParsedPacket) uint8 {
	return p.FlowKey.Proto
}

// staticRulesList duplicates the dashboard's internal rule catalogue so main.go
// can include it in the live /api/config response. Keeping it here avoids
// exposing internal dashboard types.
func staticRulesList() []map[string]interface{} {
	return []map[string]interface{}{
		{"id": 1, "name": "SYN Flood Detection", "category": "dos", "severity": "high",
			"desc": "SYN ratio >70% with low ACK ratio and SYN count >20."},
		{"id": 2, "name": "Port Scan Detection", "category": "portscan", "severity": "high",
			"desc": ">15 unique destination ports in 30s, or SYN sweep."},
		{"id": 3, "name": "Brute Force Auth", "category": "brute_force", "severity": "high",
			"desc": "Credential stuffing on SSH/FTP/RDP/VNC/SMB/MySQL."},
		{"id": 4, "name": "DNS Tunneling", "category": "botnet", "severity": "medium",
			"desc": "Shannon entropy >4.2, labels >40 chars, TXT abuse."},
		{"id": 5, "name": "HTTP Anomaly", "category": "web_attack", "severity": "critical",
			"desc": "SQLi / path traversal / cmd injection / scanner UA."},
		{"id": 6, "name": "DDoS Rate Anomaly", "category": "ddos", "severity": "critical",
			"desc": ">1000 pkt/s, flash floods, asymmetric >25:1."},
		{"id": 7, "name": "Traffic Entropy", "category": "botnet", "severity": "medium",
			"desc": "C2 beaconing CV<0.05, covert small-packet channels."},
		{"id": 8, "name": "Exploit Patterns", "category": "exploit", "severity": "critical",
			"desc": "Malware JA3 match + first-packet heap-spray sizing."},
		{"id": 9, "name": "Port Scan Flow", "category": "portscan", "severity": "high",
			"desc": "Flow-level SYN/RST/ACK ratios catch stealth scans."},
		{"id": 10, "name": "Slow DoS", "category": "dos", "severity": "medium",
			"desc": "Slowloris/Slow-Read: >30s, low rate, high PSH."},
		{"id": 11, "name": "HTTP Flood (L7)", "category": "ddos", "severity": "high",
			"desc": ">80 req/s with normal sizing, high PSH."},
		{"id": 12, "name": "Brute Force Flow", "category": "brute_force", "severity": "high",
			"desc": "Port-independent: small balanced bidi, high PSH/ACK."},
		{"id": 13, "name": "Data Exfiltration", "category": "infiltration", "severity": "critical",
			"desc": "Upload/download >10:1 with >1MB; or >500KB one-way."},
		{"id": 14, "name": "DNS Amplification", "category": "ddos", "severity": "critical",
			"desc": "UDP amp factor >5x, >50 responses/s."},
		{"id": 15, "name": "ICMP Anomaly", "category": "ddos", "severity": "high",
			"desc": "Zero-flag floods + ICMP covert channels."},
	}
}
