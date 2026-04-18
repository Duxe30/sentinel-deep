// Package capture implements high-performance packet capture using AF_PACKET
// with mmap ring buffer (zero-copy) for Raspberry Pi 4.
//
// Design:
//   - Uses TPACKET_V3 for block-based ring buffer
//   - Memory-capped at 500 MB (tunable)
//   - Goroutine-safe with channel output
//   - Drops packets gracefully when consumer is slow (no deadlock)
package capture

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ═══════════════════════════════════════════════════════════════════════════
// Packet — A captured packet with full metadata
// ═══════════════════════════════════════════════════════════════════════════

type Packet struct {
	Timestamp  time.Time
	Interface  string
	Length     uint32
	CapLen     uint32
	Data       []byte // raw Ethernet frame
	IngressIdx uint32
}

// ═══════════════════════════════════════════════════════════════════════════
// Stats — Atomic counters for monitoring
// ═══════════════════════════════════════════════════════════════════════════

type Stats struct {
	Received uint64 // packets captured
	Dropped  uint64 // kernel drops
	Lost     uint64 // consumer-side drops
	Bytes    uint64 // total bytes captured
}

// ═══════════════════════════════════════════════════════════════════════════
// Capture — Main capture engine
// ═══════════════════════════════════════════════════════════════════════════

type Config struct {
	Interface    string        // e.g., "wlan0", "eth0"
	BlockSize    int           // default: 1 MB
	BlockCount   int           // default: 64 (total = 64 MB)
	SnapLen      int           // max bytes per packet; default: 65535 (full)
	Timeout      time.Duration // block timeout; default: 100ms
	Promiscuous  bool          // default: true
	ChannelSize  int           // output channel buffer; default: 10000
}

type Capture struct {
	cfg      Config
	fd       int
	ring     []byte
	ringSize int
	stats    *Stats
	out      chan *Packet
	stop     chan struct{}
	wg       sync.WaitGroup
	started  atomic.Bool
}

// New creates a new capture instance. Call Start() to begin.
func New(cfg Config) (*Capture, error) {
	// Set sensible defaults
	if cfg.BlockSize == 0 {
		cfg.BlockSize = 1 << 20 // 1 MB
	}
	if cfg.BlockCount == 0 {
		cfg.BlockCount = 64 // Total = 64 MB (safe for 4GB Pi)
	}
	if cfg.SnapLen == 0 {
		cfg.SnapLen = 65535
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 100 * time.Millisecond
	}
	if cfg.ChannelSize == 0 {
		cfg.ChannelSize = 10000
	}

	return &Capture{
		cfg:   cfg,
		stats: &Stats{},
		out:   make(chan *Packet, cfg.ChannelSize),
		stop:  make(chan struct{}),
	}, nil
}

// Start initializes AF_PACKET socket and begins capture loop.
func (c *Capture) Start() error {
	if c.started.Load() {
		return fmt.Errorf("already started")
	}

	// ─── 1. Create AF_PACKET raw socket ─────────────────────────────────
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("create socket: %w", err)
	}
	c.fd = fd

	// ─── 2. Get interface index ─────────────────────────────────────────
	ifi, err := net.InterfaceByName(c.cfg.Interface)
	if err != nil {
		unix.Close(fd)
		return fmt.Errorf("interface %s: %w", c.cfg.Interface, err)
	}

	// ─── 3. Set TPACKET_V3 ──────────────────────────────────────────────
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V3); err != nil {
		unix.Close(fd)
		return fmt.Errorf("set TPACKET_V3: %w", err)
	}

	// ─── 4. Configure ring buffer ───────────────────────────────────────
	frameSize := 2048 // typical MTU + headers
	framesPerBlock := c.cfg.BlockSize / frameSize

	req := tpacketReq3{
		blockSize:      uint32(c.cfg.BlockSize),
		blockNr:        uint32(c.cfg.BlockCount),
		frameSize:      uint32(frameSize),
		frameNr:        uint32(framesPerBlock * c.cfg.BlockCount),
		retireBlkTov:   uint32(c.cfg.Timeout.Milliseconds()),
		sizeofPrivData: 0,
		featureReqWord: 0,
	}

	reqBytes := (*[unsafe.Sizeof(req)]byte)(unsafe.Pointer(&req))[:]
	if err := unix.SetsockoptString(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, string(reqBytes)); err != nil {
		unix.Close(fd)
		return fmt.Errorf("PACKET_RX_RING: %w", err)
	}

	// ─── 5. mmap the ring buffer (zero-copy) ────────────────────────────
	c.ringSize = c.cfg.BlockSize * c.cfg.BlockCount
	ring, err := unix.Mmap(fd, 0, c.ringSize,
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_LOCKED)
	if err != nil {
		unix.Close(fd)
		return fmt.Errorf("mmap: %w", err)
	}
	c.ring = ring

	// ─── 6. Bind to interface ───────────────────────────────────────────
	sll := unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := unix.Bind(fd, &sll); err != nil {
		unix.Munmap(ring)
		unix.Close(fd)
		return fmt.Errorf("bind: %w", err)
	}

	// ─── 7. Set promiscuous mode ────────────────────────────────────────
	if c.cfg.Promiscuous {
		mreq := unix.PacketMreq{
			Ifindex: int32(ifi.Index),
			Type:    unix.PACKET_MR_PROMISC,
		}
		if err := unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, &mreq); err != nil {
			// Warning only — capture still works
			fmt.Printf("[WARN] promiscuous mode failed: %v\n", err)
		}
	}

	c.started.Store(true)
	c.wg.Add(1)
	go c.captureLoop()

	return nil
}

// captureLoop walks through ring blocks and emits packets.
func (c *Capture) captureLoop() {
	defer c.wg.Done()

	var blockIdx int
	for {
		select {
		case <-c.stop:
			return
		default:
		}

		blockOffset := blockIdx * c.cfg.BlockSize
		block := c.ring[blockOffset : blockOffset+c.cfg.BlockSize]

		hdr := (*tpacketBlockDesc)(unsafe.Pointer(&block[0]))

		// Wait for block to be filled by kernel
		if hdr.hdr.blockStatus&unix.TP_STATUS_USER == 0 {
			// Use poll to wait for data
			pfd := []unix.PollFd{{Fd: int32(c.fd), Events: unix.POLLIN}}
			_, err := unix.Poll(pfd, int(c.cfg.Timeout.Milliseconds()))
			if err != nil && err != unix.EINTR {
				return
			}
			continue
		}

		// Walk packets in this block
		c.walkBlock(block, hdr)

		// Release block back to kernel
		hdr.hdr.blockStatus = unix.TP_STATUS_KERNEL

		blockIdx = (blockIdx + 1) % c.cfg.BlockCount
	}
}

// walkBlock iterates all packets in a block and emits them.
func (c *Capture) walkBlock(block []byte, hdr *tpacketBlockDesc) {
	numPkts := hdr.hdr.numPkts
	offset := hdr.hdr.offsetToFirstPkt

	for i := uint32(0); i < numPkts; i++ {
		pkt := (*tpacket3Hdr)(unsafe.Pointer(&block[offset]))

		data := block[offset+pkt.mac : offset+pkt.mac+pkt.snaplen]

		// Copy data because ring buffer gets reused
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)

		p := &Packet{
			Timestamp: time.Unix(int64(pkt.sec), int64(pkt.nsec)),
			Interface: c.cfg.Interface,
			Length:    pkt.len,
			CapLen:    pkt.snaplen,
			Data:      dataCopy,
		}

		atomic.AddUint64(&c.stats.Received, 1)
		atomic.AddUint64(&c.stats.Bytes, uint64(pkt.len))

		// Non-blocking send; drop if consumer is slow
		select {
		case c.out <- p:
		default:
			atomic.AddUint64(&c.stats.Lost, 1)
		}

		offset += pkt.nextOffset
		if pkt.nextOffset == 0 {
			break
		}
	}
}

// Packets returns the output channel.
func (c *Capture) Packets() <-chan *Packet {
	return c.out
}

// Stats returns current statistics snapshot.
func (c *Capture) GetStats() Stats {
	return Stats{
		Received: atomic.LoadUint64(&c.stats.Received),
		Dropped:  atomic.LoadUint64(&c.stats.Dropped),
		Lost:     atomic.LoadUint64(&c.stats.Lost),
		Bytes:    atomic.LoadUint64(&c.stats.Bytes),
	}
}

// Close stops capture and releases resources.
func (c *Capture) Close() error {
	close(c.stop)
	c.wg.Wait()

	if c.ring != nil {
		unix.Munmap(c.ring)
	}
	if c.fd > 0 {
		unix.Close(c.fd)
	}
	close(c.out)
	return nil
}

// ═══════════════════════════════════════════════════════════════════════════
// Internal: kernel structures (TPACKET_V3)
// ═══════════════════════════════════════════════════════════════════════════

type tpacketReq3 struct {
	blockSize      uint32
	blockNr        uint32
	frameSize      uint32
	frameNr        uint32
	retireBlkTov   uint32
	sizeofPrivData uint32
	featureReqWord uint32
}

type tpacketBlockDesc struct {
	version     uint32
	offsetToPriv uint32
	hdr         tpacketHdrV1
}

type tpacketHdrV1 struct {
	blockStatus       uint32
	numPkts           uint32
	offsetToFirstPkt  uint32
	blkLen            uint32
	seqNum            uint64
	tsFirstPkt        [2]uint32
	tsLastPkt         [2]uint32
}

type tpacket3Hdr struct {
	nextOffset uint32
	sec        uint32
	nsec       uint32
	snaplen    uint32
	len        uint32
	status     uint32
	mac        uint16
	net        uint16
	hvTci      uint16
	hvTpid     uint16
	pad        [8]byte
}

func htons(v uint16) uint16 {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return binary.LittleEndian.Uint16(buf)
}

// Ensure syscall is used
var _ = syscall.Errno(0)
