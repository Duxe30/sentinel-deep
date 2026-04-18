// Package memory — Monitors and enforces RAM limits on Raspberry Pi.
// Reads /proc/self/status to track actual RSS and triggers callbacks
// when thresholds are crossed.
package memory

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// Guard — RAM enforcement
// ═══════════════════════════════════════════════════════════════════════════

type Guard struct {
	MaxRSS       uint64 // bytes; 0 = no limit
	WarnRSS      uint64 // bytes; soft warning threshold
	CheckPeriod  time.Duration

	currentRSS   uint64 // atomic
	peakRSS      uint64 // atomic
	warnings     uint64 // atomic
	gcCalls      uint64 // atomic

	onWarn       func(rss uint64)
	onCritical   func(rss uint64)

	stop chan struct{}
	wg   sync.WaitGroup
}

// NewGuard creates a new memory guard.
//   maxMB   — hard ceiling (forces GC + callback); 0 = no limit
//   warnMB  — soft threshold for warnings
func NewGuard(maxMB, warnMB int) *Guard {
	return &Guard{
		MaxRSS:      uint64(maxMB) * 1024 * 1024,
		WarnRSS:     uint64(warnMB) * 1024 * 1024,
		CheckPeriod: 5 * time.Second,
		stop:        make(chan struct{}),
	}
}

// SetCallbacks registers handlers for threshold crossings
func (g *Guard) SetCallbacks(onWarn, onCritical func(rss uint64)) {
	g.onWarn = onWarn
	g.onCritical = onCritical
}

// Start begins periodic monitoring
func (g *Guard) Start() {
	g.wg.Add(1)
	go g.loop()
}

// Stop halts the monitor
func (g *Guard) Stop() {
	close(g.stop)
	g.wg.Wait()
}

func (g *Guard) loop() {
	defer g.wg.Done()
	tick := time.NewTicker(g.CheckPeriod)
	defer tick.Stop()

	for {
		select {
		case <-g.stop:
			return
		case <-tick.C:
			g.check()
		}
	}
}

func (g *Guard) check() {
	rss, err := readRSS()
	if err != nil {
		return
	}

	atomic.StoreUint64(&g.currentRSS, rss)
	for {
		peak := atomic.LoadUint64(&g.peakRSS)
		if rss <= peak {
			break
		}
		if atomic.CompareAndSwapUint64(&g.peakRSS, peak, rss) {
			break
		}
	}

	// Hard limit
	if g.MaxRSS > 0 && rss >= g.MaxRSS {
		atomic.AddUint64(&g.warnings, 1)
		runtime.GC()
		runtime.GC() // twice to collect finalizers
		atomic.AddUint64(&g.gcCalls, 2)

		if g.onCritical != nil {
			g.onCritical(rss)
		}
		return
	}

	// Soft warning
	if g.WarnRSS > 0 && rss >= g.WarnRSS {
		atomic.AddUint64(&g.warnings, 1)
		if g.onWarn != nil {
			g.onWarn(rss)
		}
	}
}

// ReadRSS returns the current RSS of this process in bytes
func ReadRSS() (uint64, error) { return readRSS() }

func readRSS() (uint64, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				kb, err := strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					return 0, err
				}
				return kb * 1024, nil
			}
		}
	}
	return 0, fmt.Errorf("VmRSS not found")
}

// Stats returns a snapshot of memory stats
func (g *Guard) Stats() Stats {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return Stats{
		CurrentRSS: atomic.LoadUint64(&g.currentRSS),
		PeakRSS:    atomic.LoadUint64(&g.peakRSS),
		HeapAlloc:  ms.HeapAlloc,
		HeapSys:    ms.HeapSys,
		NumGC:      ms.NumGC,
		Warnings:   atomic.LoadUint64(&g.warnings),
		GCCalls:    atomic.LoadUint64(&g.gcCalls),
	}
}

type Stats struct {
	CurrentRSS uint64
	PeakRSS    uint64
	HeapAlloc  uint64
	HeapSys    uint64
	NumGC      uint32
	Warnings   uint64
	GCCalls    uint64
}

func (s Stats) String() string {
	return fmt.Sprintf("RSS=%s Peak=%s Heap=%s GC=%d Warnings=%d",
		formatBytes(s.CurrentRSS), formatBytes(s.PeakRSS),
		formatBytes(s.HeapAlloc), s.NumGC, s.Warnings)
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
