// Sentinel-Pi v3.0 — Deep Inspector
// Entry point that wires together:
//   capture → DPI → feature extraction → ML inference → dashboard
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/dhergam/sentinel-deep/internal/capture"
	"github.com/dhergam/sentinel-deep/internal/dashboard"
	"github.com/dhergam/sentinel-deep/internal/dpi"
	"github.com/dhergam/sentinel-deep/internal/features"
	"github.com/dhergam/sentinel-deep/internal/memory"
	"github.com/dhergam/sentinel-deep/internal/ml"
	"github.com/dhergam/sentinel-deep/internal/storage"
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
	)
	flag.Parse()

	// Restrict GC to reduce memory fragmentation on Pi
	runtime.GOMAXPROCS(runtime.NumCPU())

	log.Println("═══════════════════════════════════════════════════════")
	log.Println("  Sentinel-Pi v3.0 — Deep Inspector")
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
		func(rss uint64) {
			log.Printf("[MEM-WARN] RSS=%d MB (threshold crossed)", rss/1024/1024)
		},
		func(rss uint64) {
			log.Printf("[MEM-CRITICAL] RSS=%d MB — forced GC", rss/1024/1024)
		},
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

	// ─── Dashboard ──────────────────────────────────────────────────────
	dash := dashboard.NewServer(*dashAddr, 2000, 500)

	// ─── Flow tracker ───────────────────────────────────────────────────
	tracker := features.NewFlowTracker(120*time.Second, *maxFlows)

	// ML inference on flow expiry
	tracker.SetExpireCallback(func(f *features.Flow) {
		if mlEngine == nil {
			return
		}
		feat := features.Extract(f)
		pred, err := mlEngine.Predict(feat)
		if err != nil {
			return
		}
		if pred.IsAttack {
			dash.AddAlert(dashboard.Alert{
				ID:       fmt.Sprintf("%s-%d", f.Key.String(), f.StartTime.UnixNano()),
				Time:     time.Now(),
				SrcIP:    f.Key.String(),
				DstIP:    "",
				Type:     pred.AttackType,
				Score:    pred.AttackProb,
				Severity: severityFromScore(pred.AttackProb),
				Details:  fmt.Sprintf("Flow %s score=%.3f", f.Key.String(), pred.AttackProb),
				Prediction: pred,
			})
			log.Printf("[ALERT] %s %s (%.3f)", pred.AttackType, f.Key.String(), pred.AttackProb)
		}
	})

	// Stats provider for dashboard
	dash.SetStatsProvider(func() map[string]interface{} {
		ms := guard.Stats()
		return map[string]interface{}{
			"flows":  tracker.Count(),
			"ram_mb": ms.CurrentRSS / 1024 / 1024,
			"cpu_pct": 0, // TODO: read /proc/stat
		}
	})

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
	if err := cap.Start(); err != nil {
		log.Fatalf("capture start: %v (hint: run as root?)", err)
	}
	defer cap.Close()

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

			// Feature + flow tracking
			tracker.Update(parsed, pkt.Timestamp, pkt.Length)

			// PCAP
			if pcap != nil {
				pcap.Write(pkt.Timestamp, pkt.Data)
			}

			// Dashboard (live stream, no ML yet — ML runs on flow expiry)
			dash.AddPacket(parsed, pkt.Timestamp, pkt.Length, nil, "")
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

func severityFromScore(s float32) string {
	switch {
	case s >= 0.95:
		return "critical"
	case s >= 0.75:
		return "high"
	case s >= 0.5:
		return "warn"
	default:
		return "info"
	}
}
