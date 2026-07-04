// Package system — Reads /proc to provide CPU, disk, network, and load stats.
// Linux-only. Non-Linux builds return zero values (see procstats_fallback.go).
package system

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CPUStats is a normalized CPU snapshot.
type CPUStats struct {
	User       uint64
	Nice       uint64
	System     uint64
	Idle       uint64
	IOWait     uint64
	IRQ        uint64
	SoftIRQ    uint64
	Steal      uint64
	TotalTicks uint64
}

// NetStats is a per-interface byte/packet counter.
type NetStats struct {
	Interface string `json:"iface"`
	RxBytes   uint64 `json:"rx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	RxErrors  uint64 `json:"rx_errors"`
	RxDropped uint64 `json:"rx_dropped"`
	TxBytes   uint64 `json:"tx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	TxErrors  uint64 `json:"tx_errors"`
	TxDropped uint64 `json:"tx_dropped"`
}

// DiskStats reports filesystem usage for a mount point.
type DiskStats struct {
	Path       string  `json:"path"`
	TotalBytes uint64  `json:"total"`
	FreeBytes  uint64  `json:"free"`
	UsedBytes  uint64  `json:"used"`
	UsedPct    float64 `json:"used_pct"`
}

// LoadAvg mirrors /proc/loadavg.
type LoadAvg struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

// Monitor computes CPU% from two consecutive reads and caches net counters
// per interface for rate computation.
type Monitor struct {
	mu       sync.Mutex
	prevCPU  CPUStats
	prevNets map[string]NetStats
	prevTime time.Time
}

// NewMonitor returns a fresh monitor. First SampleCPU returns 0.
func NewMonitor() *Monitor {
	return &Monitor{prevNets: make(map[string]NetStats)}
}

// SampleCPU returns cpu-busy percent since the previous sample.
func (m *Monitor) SampleCPU() float64 {
	cur, err := readCPU()
	if err != nil {
		return 0
	}
	m.mu.Lock()
	prev := m.prevCPU
	m.prevCPU = cur
	m.mu.Unlock()

	if prev.TotalTicks == 0 {
		return 0
	}
	dt := float64(cur.TotalTicks - prev.TotalTicks)
	if dt <= 0 {
		return 0
	}
	idle := float64((cur.Idle - prev.Idle) + (cur.IOWait - prev.IOWait))
	busy := (dt - idle) / dt * 100.0
	if busy < 0 {
		busy = 0
	}
	if busy > 100 {
		busy = 100
	}
	return busy
}

// SampleNet returns per-interface counters. If iface is empty, returns all.
func (m *Monitor) SampleNet(iface string) []NetStats {
	all := readNetDev()
	if iface == "" {
		return all
	}
	for _, n := range all {
		if n.Interface == iface {
			return []NetStats{n}
		}
	}
	return nil
}

// NetRate returns (rxBps, txBps) for iface since last call.
func (m *Monitor) NetRate(iface string) (rxBps, txBps uint64) {
	cur := m.SampleNet(iface)
	if len(cur) == 0 {
		return 0, 0
	}
	now := time.Now()
	c := cur[0]

	m.mu.Lock()
	prev, had := m.prevNets[iface]
	prevTime := m.prevTime
	m.prevNets[iface] = c
	m.prevTime = now
	m.mu.Unlock()

	if !had || prevTime.IsZero() {
		return 0, 0
	}
	dt := now.Sub(prevTime).Seconds()
	if dt <= 0 {
		return 0, 0
	}
	if c.RxBytes >= prev.RxBytes {
		rxBps = uint64(float64(c.RxBytes-prev.RxBytes) / dt)
	}
	if c.TxBytes >= prev.TxBytes {
		txBps = uint64(float64(c.TxBytes-prev.TxBytes) / dt)
	}
	return
}

// ReadDisk returns usage for a mount point ("/" for root).
func ReadDisk(path string) DiskStats {
	return readDisk(path)
}

// ReadLoad returns /proc/loadavg.
func ReadLoad() LoadAvg { return readLoad() }

// ReadCPU returns current ticks.
func ReadCPU() (CPUStats, error) { return readCPU() }

// ReadNetDev returns per-interface counters.
func ReadNetDev() []NetStats { return readNetDev() }

// ═══════════════════════════════════════════════════════════════════════════
// Internal parsers
// ═══════════════════════════════════════════════════════════════════════════

func readCPU() (CPUStats, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return CPUStats{}, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 8 {
			break
		}
		get := func(i int) uint64 {
			if i >= len(fields) {
				return 0
			}
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			return v
		}
		c := CPUStats{
			User:    get(1),
			Nice:    get(2),
			System:  get(3),
			Idle:    get(4),
			IOWait:  get(5),
			IRQ:     get(6),
			SoftIRQ: get(7),
			Steal:   get(8),
		}
		c.TotalTicks = c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
		return c, nil
	}
	return CPUStats{}, nil
}

func readNetDev() []NetStats {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return nil
	}
	defer f.Close()

	out := make([]NetStats, 0, 4)
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue // skip headers
		}
		line := sc.Text()
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if name == "lo" {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 16 {
			continue
		}
		g := func(i int) uint64 {
			v, _ := strconv.ParseUint(fields[i], 10, 64)
			return v
		}
		out = append(out, NetStats{
			Interface: name,
			RxBytes:   g(0),
			RxPackets: g(1),
			RxErrors:  g(2),
			RxDropped: g(3),
			TxBytes:   g(8),
			TxPackets: g(9),
			TxErrors:  g(10),
			TxDropped: g(11),
		})
	}
	return out
}

func readLoad() LoadAvg {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return LoadAvg{}
	}
	fields := strings.Fields(string(b))
	parse := func(i int) float64 {
		if i >= len(fields) {
			return 0
		}
		v, _ := strconv.ParseFloat(fields[i], 64)
		return v
	}
	return LoadAvg{Load1: parse(0), Load5: parse(1), Load15: parse(2)}
}
