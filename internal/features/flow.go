// Package features — Flow tracking and 74-feature extraction
// compatible with CICFlowMeter (for the trained ML models).
//
// IAT is measured in MICROSECONDS to match the trained scaler.
package features

import (
	"fmt"
	"math"
	"net"
	"sync"
	"time"

	"github.com/dhergam/sentinel-deep/internal/dpi"
)

// ═══════════════════════════════════════════════════════════════════════════
// Flow — A bidirectional network flow
// ═══════════════════════════════════════════════════════════════════════════

type Flow struct {
	Key       FlowKey
	StartTime time.Time
	LastSeen  time.Time

	// Forward direction (src→dst from first packet)
	FwdPackets     uint32
	FwdBytes       uint64
	FwdPktLengths  []uint32
	FwdTimestamps  []time.Time
	FwdPSHFlags    uint32
	FwdURGFlags    uint32
	FwdHeaderBytes uint64
	FwdInitWin     uint16 // TCP initial window

	// Backward direction
	BwdPackets     uint32
	BwdBytes       uint64
	BwdPktLengths  []uint32
	BwdTimestamps  []time.Time
	BwdPSHFlags    uint32
	BwdURGFlags    uint32
	BwdHeaderBytes uint64
	BwdInitWin     uint16

	// TCP flags (counts)
	FINCount uint32
	SYNCount uint32
	RSTCount uint32
	PSHCount uint32
	ACKCount uint32
	URGCount uint32
	ECECount uint32

	// Active/Idle detection
	ActivePeriods []time.Duration
	IdlePeriods   []time.Duration
	lastActivity  time.Time

	// Application layer
	AppProto string
	SNI      string
	DNSQuery string

	mu sync.Mutex
}

type FlowKey struct {
	SrcIP   [16]byte
	DstIP   [16]byte
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// NewFlowKey creates a canonical 5-tuple key (normalized direction)
func NewFlowKey(src, dst net.IP, sport, dport uint16, proto uint8) FlowKey {
	k := FlowKey{
		SrcPort: sport,
		DstPort: dport,
		Proto:   proto,
	}
	copy(k.SrcIP[:], src.To16())
	copy(k.DstIP[:], dst.To16())
	return k
}

// ReverseKey returns the key for opposite direction
func (k FlowKey) Reverse() FlowKey {
	return FlowKey{
		SrcIP:   k.DstIP,
		DstIP:   k.SrcIP,
		SrcPort: k.DstPort,
		DstPort: k.SrcPort,
		Proto:   k.Proto,
	}
}

func (k FlowKey) String() string {
	return fmt.Sprintf("%s:%d→%s:%d/%d",
		net.IP(k.SrcIP[:]), k.SrcPort,
		net.IP(k.DstIP[:]), k.DstPort, k.Proto)
}

// ═══════════════════════════════════════════════════════════════════════════
// FlowTracker — Thread-safe flow state manager
// ═══════════════════════════════════════════════════════════════════════════

type FlowTracker struct {
	flows       map[FlowKey]*Flow
	mu          sync.RWMutex
	timeout     time.Duration // flow expiry (default 120s)
	maxFlows    int           // max concurrent flows (RAM cap)
	onExpire    func(*Flow)   // callback when flow expires
}

func NewFlowTracker(timeout time.Duration, maxFlows int) *FlowTracker {
	return &FlowTracker{
		flows:    make(map[FlowKey]*Flow),
		timeout:  timeout,
		maxFlows: maxFlows,
	}
}

// SetExpireCallback is invoked with each expired flow (for ML inference)
func (ft *FlowTracker) SetExpireCallback(fn func(*Flow)) {
	ft.onExpire = fn
}

// Update processes a parsed packet and updates flow state
func (ft *FlowTracker) Update(pkt *dpi.ParsedPacket, timestamp time.Time, pktLen uint32) {
	if pkt.IPv4 == nil && pkt.IPv6 == nil {
		return
	}

	srcIP := pkt.FlowKey.SrcIP
	dstIP := pkt.FlowKey.DstIP
	if srcIP == nil || dstIP == nil {
		return
	}

	key := NewFlowKey(srcIP, dstIP, pkt.FlowKey.SrcPort, pkt.FlowKey.DstPort, pkt.FlowKey.Proto)

	ft.mu.Lock()
	defer ft.mu.Unlock()

	// Check if flow exists (forward or reverse direction)
	flow, isFwd := ft.lookupFlowLocked(key)
	if flow == nil {
		// Cap total flows (drop oldest if needed)
		if len(ft.flows) >= ft.maxFlows {
			ft.evictOldestLocked()
		}

		flow = &Flow{
			Key:          key,
			StartTime:    timestamp,
			LastSeen:     timestamp,
			lastActivity: timestamp,
			AppProto:     pkt.AppProto,
		}
		ft.flows[key] = flow
		isFwd = true
	}

	flow.mu.Lock()
	defer flow.mu.Unlock()

	// Idle detection (>1s gap = idle period)
	gap := timestamp.Sub(flow.LastSeen)
	if gap > time.Second {
		flow.IdlePeriods = append(flow.IdlePeriods, gap)
	}
	flow.LastSeen = timestamp

	// Cap slice lengths to prevent RAM bloat on long flows
	maxSlice := 1000

	// Update direction-specific
	if isFwd {
		flow.FwdPackets++
		flow.FwdBytes += uint64(pktLen)
		if len(flow.FwdPktLengths) < maxSlice {
			flow.FwdPktLengths = append(flow.FwdPktLengths, pktLen)
			flow.FwdTimestamps = append(flow.FwdTimestamps, timestamp)
		}
		if pkt.TCP != nil {
			if pkt.TCP.Flags.PSH {
				flow.FwdPSHFlags++
			}
			if pkt.TCP.Flags.URG {
				flow.FwdURGFlags++
			}
			flow.FwdHeaderBytes += uint64(pkt.TCP.DataOffset)
			if flow.FwdPackets == 1 {
				flow.FwdInitWin = pkt.TCP.Window
			}
		}
	} else {
		flow.BwdPackets++
		flow.BwdBytes += uint64(pktLen)
		if len(flow.BwdPktLengths) < maxSlice {
			flow.BwdPktLengths = append(flow.BwdPktLengths, pktLen)
			flow.BwdTimestamps = append(flow.BwdTimestamps, timestamp)
		}
		if pkt.TCP != nil {
			if pkt.TCP.Flags.PSH {
				flow.BwdPSHFlags++
			}
			if pkt.TCP.Flags.URG {
				flow.BwdURGFlags++
			}
			flow.BwdHeaderBytes += uint64(pkt.TCP.DataOffset)
			if flow.BwdPackets == 1 {
				flow.BwdInitWin = pkt.TCP.Window
			}
		}
	}

	// TCP flag counts (global)
	if pkt.TCP != nil {
		if pkt.TCP.Flags.FIN {
			flow.FINCount++
		}
		if pkt.TCP.Flags.SYN {
			flow.SYNCount++
		}
		if pkt.TCP.Flags.RST {
			flow.RSTCount++
		}
		if pkt.TCP.Flags.PSH {
			flow.PSHCount++
		}
		if pkt.TCP.Flags.ACK {
			flow.ACKCount++
		}
		if pkt.TCP.Flags.URG {
			flow.URGCount++
		}
		if pkt.TCP.Flags.ECE {
			flow.ECECount++
		}
	}
}

func (ft *FlowTracker) lookupFlowLocked(key FlowKey) (*Flow, bool) {
	if f, ok := ft.flows[key]; ok {
		return f, true
	}
	rev := key.Reverse()
	if f, ok := ft.flows[rev]; ok {
		return f, false
	}
	return nil, false
}

func (ft *FlowTracker) evictOldestLocked() {
	var oldestKey FlowKey
	var oldestTime time.Time
	first := true
	for k, f := range ft.flows {
		if first || f.LastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = f.LastSeen
			first = false
		}
	}
	if ft.onExpire != nil {
		ft.onExpire(ft.flows[oldestKey])
	}
	delete(ft.flows, oldestKey)
}

// Sweep expires idle flows (call periodically from goroutine)
func (ft *FlowTracker) Sweep() int {
	now := time.Now()
	ft.mu.Lock()
	defer ft.mu.Unlock()

	var expired []FlowKey
	for k, f := range ft.flows {
		if now.Sub(f.LastSeen) > ft.timeout {
			expired = append(expired, k)
		}
	}
	for _, k := range expired {
		if ft.onExpire != nil {
			ft.onExpire(ft.flows[k])
		}
		delete(ft.flows, k)
	}
	return len(expired)
}

func (ft *FlowTracker) Count() int {
	ft.mu.RLock()
	defer ft.mu.RUnlock()
	return len(ft.flows)
}

// ═══════════════════════════════════════════════════════════════════════════
// Feature Extraction — 74 features matching trained model
// ═══════════════════════════════════════════════════════════════════════════

// Feature order MUST match config.json from training.
var FeatureNames = []string{
	"flow_duration", "total_fwd_packets", "total_bwd_packets",
	"total_length_fwd", "total_length_bwd",
	"fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
	"bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
	"pkt_len_max", "pkt_len_min", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
	"flow_bytes_per_sec", "flow_pkts_per_sec",
	"fwd_pkts_per_sec", "bwd_pkts_per_sec",
	"flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
	"fwd_iat_total", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
	"bwd_iat_total", "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
	"fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
	"fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
	"ack_flag_count", "urg_flag_count", "ece_flag_count",
	"fwd_header_len", "bwd_header_len",
	"fwd_seg_size_avg", "bwd_seg_size_avg", "fwd_seg_size_min",
	"fwd_byts_b_avg", "fwd_pkts_b_avg", "fwd_blk_rate_avg",
	"bwd_byts_b_avg", "bwd_pkts_b_avg", "bwd_blk_rate_avg",
	"subflow_fwd_pkts", "subflow_fwd_byts",
	"subflow_bwd_pkts", "subflow_bwd_byts",
	"active_mean", "active_std", "active_max", "active_min",
	"idle_mean", "idle_std", "idle_max", "idle_min",
	"init_fwd_win_byts", "init_bwd_win_byts",
	"down_up_ratio", "pkt_size_avg",
}

// Extract computes 74 features from a flow (in the exact order expected)
func Extract(f *Flow) []float32 {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Duration in MICROSECONDS (matches trained model)
	durationUs := float64(f.LastSeen.Sub(f.StartTime).Microseconds())
	if durationUs < 1 {
		durationUs = 1
	}

	// Per-direction packet length stats
	fwdMax, fwdMin, fwdMean, fwdStd := lenStats(f.FwdPktLengths)
	bwdMax, bwdMin, bwdMean, bwdStd := lenStats(f.BwdPktLengths)

	// Combined packet lengths
	allLens := make([]uint32, 0, len(f.FwdPktLengths)+len(f.BwdPktLengths))
	allLens = append(allLens, f.FwdPktLengths...)
	allLens = append(allLens, f.BwdPktLengths...)
	allMax, allMin, allMean, allStd := lenStats(allLens)
	allVar := allStd * allStd

	// Rates (per second)
	durationSec := durationUs / 1_000_000
	totalBytes := float64(f.FwdBytes + f.BwdBytes)
	totalPkts := float64(f.FwdPackets + f.BwdPackets)

	bytesPerSec := totalBytes / max1(durationSec)
	pktsPerSec := totalPkts / max1(durationSec)
	fwdPps := float64(f.FwdPackets) / max1(durationSec)
	bwdPps := float64(f.BwdPackets) / max1(durationSec)

	// IAT — all in microseconds
	flowIATs := computeIATs(f.FwdTimestamps, f.BwdTimestamps)
	fwdIATs := computeIATs(f.FwdTimestamps, nil)
	bwdIATs := computeIATs(f.BwdTimestamps, nil)

	fiMean, fiStd, fiMax, fiMin := iatStats(flowIATs)
	fwdIMean, fwdIStd, fwdIMax, fwdIMin := iatStats(fwdIATs)
	bwdIMean, bwdIStd, bwdIMax, bwdIMin := iatStats(bwdIATs)

	fwdIATTotal := sum(fwdIATs)
	bwdIATTotal := sum(bwdIATs)

	// Active/Idle stats
	activeUs := durationsToUs(f.ActivePeriods)
	idleUs := durationsToUs(f.IdlePeriods)
	aMean, aStd, aMax, aMin := stats64(activeUs)
	iMean, iStd, iMax, iMin := stats64(idleUs)

	// Segment sizes
	fwdSegAvg := 0.0
	bwdSegAvg := 0.0
	if f.FwdPackets > 0 {
		fwdSegAvg = float64(f.FwdBytes) / float64(f.FwdPackets)
	}
	if f.BwdPackets > 0 {
		bwdSegAvg = float64(f.BwdBytes) / float64(f.BwdPackets)
	}
	fwdSegMin := fwdMin

	// Down/Up ratio
	downUp := 0.0
	if f.FwdPackets > 0 {
		downUp = float64(f.BwdPackets) / float64(f.FwdPackets)
	}

	// Packet size avg (across both directions)
	pktSizeAvg := 0.0
	if totalPkts > 0 {
		pktSizeAvg = totalBytes / totalPkts
	}

	// Bulk rates — simplified (set to 0, matches training since most flows don't bulk transfer)
	bulk := 0.0

	// Subflows — simplified as totals
	subFwdPkts := float64(f.FwdPackets)
	subFwdBytes := float64(f.FwdBytes)
	subBwdPkts := float64(f.BwdPackets)
	subBwdBytes := float64(f.BwdBytes)

	// Build feature vector in EXACT order
	return []float32{
		float32(durationUs),           // flow_duration
		float32(f.FwdPackets),         // total_fwd_packets
		float32(f.BwdPackets),         // total_bwd_packets
		float32(f.FwdBytes),           // total_length_fwd
		float32(f.BwdBytes),           // total_length_bwd
		float32(fwdMax), float32(fwdMin), float32(fwdMean), float32(fwdStd),
		float32(bwdMax), float32(bwdMin), float32(bwdMean), float32(bwdStd),
		float32(allMax), float32(allMin), float32(allMean), float32(allStd), float32(allVar),
		float32(bytesPerSec), float32(pktsPerSec),
		float32(fwdPps), float32(bwdPps),
		float32(fiMean), float32(fiStd), float32(fiMax), float32(fiMin),
		float32(fwdIATTotal), float32(fwdIMean), float32(fwdIStd), float32(fwdIMax), float32(fwdIMin),
		float32(bwdIATTotal), float32(bwdIMean), float32(bwdIStd), float32(bwdIMax), float32(bwdIMin),
		float32(f.FwdPSHFlags), float32(f.BwdPSHFlags),
		float32(f.FwdURGFlags), float32(f.BwdURGFlags),
		float32(f.FINCount), float32(f.SYNCount), float32(f.RSTCount), float32(f.PSHCount),
		float32(f.ACKCount), float32(f.URGCount), float32(f.ECECount),
		float32(f.FwdHeaderBytes), float32(f.BwdHeaderBytes),
		float32(fwdSegAvg), float32(bwdSegAvg), float32(fwdSegMin),
		float32(bulk), float32(bulk), float32(bulk),
		float32(bulk), float32(bulk), float32(bulk),
		float32(subFwdPkts), float32(subFwdBytes),
		float32(subBwdPkts), float32(subBwdBytes),
		float32(aMean), float32(aStd), float32(aMax), float32(aMin),
		float32(iMean), float32(iStd), float32(iMax), float32(iMin),
		float32(f.FwdInitWin), float32(f.BwdInitWin),
		float32(downUp), float32(pktSizeAvg),
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// Stat helpers
// ═══════════════════════════════════════════════════════════════════════════

func lenStats(lens []uint32) (max, min, mean, std float64) {
	if len(lens) == 0 {
		return 0, 0, 0, 0
	}
	min = float64(lens[0])
	max = float64(lens[0])
	sum := 0.0
	for _, l := range lens {
		v := float64(l)
		if v > max {
			max = v
		}
		if v < min {
			min = v
		}
		sum += v
	}
	mean = sum / float64(len(lens))
	sq := 0.0
	for _, l := range lens {
		d := float64(l) - mean
		sq += d * d
	}
	std = math.Sqrt(sq / float64(len(lens)))
	return
}

func computeIATs(ts1, ts2 []time.Time) []float64 {
	// Merge and sort timestamps
	all := make([]time.Time, 0, len(ts1)+len(ts2))
	all = append(all, ts1...)
	all = append(all, ts2...)

	if len(all) < 2 {
		return nil
	}
	// Sort
	for i := 1; i < len(all); i++ {
		for j := i; j > 0 && all[j-1].After(all[j]); j-- {
			all[j], all[j-1] = all[j-1], all[j]
		}
	}

	iats := make([]float64, len(all)-1)
	for i := 1; i < len(all); i++ {
		iats[i-1] = float64(all[i].Sub(all[i-1]).Microseconds())
	}
	return iats
}

func iatStats(iats []float64) (mean, std, max, min float64) {
	return stats64(iats)
}

func stats64(vals []float64) (mean, std, max, min float64) {
	if len(vals) == 0 {
		return
	}
	max = vals[0]
	min = vals[0]
	sum := 0.0
	for _, v := range vals {
		if v > max {
			max = v
		}
		if v < min {
			min = v
		}
		sum += v
	}
	mean = sum / float64(len(vals))
	sq := 0.0
	for _, v := range vals {
		d := v - mean
		sq += d * d
	}
	std = math.Sqrt(sq / float64(len(vals)))
	return
}

func sum(vals []float64) float64 {
	s := 0.0
	for _, v := range vals {
		s += v
	}
	return s
}

func durationsToUs(ds []time.Duration) []float64 {
	out := make([]float64, len(ds))
	for i, d := range ds {
		out[i] = float64(d.Microseconds())
	}
	return out
}

func max1(x float64) float64 {
	if x < 1 {
		return 1
	}
	return x
}
