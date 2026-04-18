// Package storage — PCAP file writing with rotation.
// Keeps on-disk footprint bounded (e.g., 100 MB cap).
package storage

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════
// PCAP global header (libpcap 2.4 format)
// ═══════════════════════════════════════════════════════════════════════════

const (
	pcapMagic      uint32 = 0xA1B2C3D4
	pcapVerMajor   uint16 = 2
	pcapVerMinor   uint16 = 4
	pcapSnapLen    uint32 = 65535
	pcapLinkType   uint32 = 1 // LINKTYPE_ETHERNET
)

type pcapGlobalHeader struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	Thiszone     int32
	Sigfigs      uint32
	Snaplen      uint32
	Network      uint32
}

type pcapRecordHeader struct {
	TsSec   uint32
	TsUsec  uint32
	InclLen uint32
	OrigLen uint32
}

// ═══════════════════════════════════════════════════════════════════════════
// Rotating writer
// ═══════════════════════════════════════════════════════════════════════════

type RotatingPCAP struct {
	dir          string
	maxFileSize  int64  // per-file, default 25 MB
	maxTotalSize int64  // total dir, default 100 MB
	maxFiles     int    // max file count

	currentFile  *os.File
	currentSize  int64
	currentName  string

	mu sync.Mutex
}

// NewRotatingPCAP creates a PCAP writer that rotates files.
//   dir — output directory
//   maxTotalMB — total disk cap (e.g., 100 for 100 MB)
//   maxFileMB  — per-file size (e.g., 25 for 25 MB → 4 files max)
func NewRotatingPCAP(dir string, maxTotalMB, maxFileMB int) (*RotatingPCAP, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	r := &RotatingPCAP{
		dir:          dir,
		maxFileSize:  int64(maxFileMB) * 1024 * 1024,
		maxTotalSize: int64(maxTotalMB) * 1024 * 1024,
		maxFiles:     (maxTotalMB / maxFileMB) + 1,
	}

	if err := r.rotate(); err != nil {
		return nil, err
	}
	return r, nil
}

// rotate closes current file and opens a new one (caller holds mu)
func (r *RotatingPCAP) rotate() error {
	if r.currentFile != nil {
		r.currentFile.Close()
	}

	// Clean up old files if over limit
	r.cleanupOldFiles()

	// New file name with timestamp
	name := fmt.Sprintf("sentinel_%s.pcap", time.Now().Format("20060102_150405"))
	path := filepath.Join(r.dir, name)

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create pcap: %w", err)
	}

	// Write global header
	hdr := pcapGlobalHeader{
		MagicNumber:  pcapMagic,
		VersionMajor: pcapVerMajor,
		VersionMinor: pcapVerMinor,
		Snaplen:      pcapSnapLen,
		Network:      pcapLinkType,
	}
	if err := binary.Write(f, binary.LittleEndian, &hdr); err != nil {
		f.Close()
		return err
	}

	r.currentFile = f
	r.currentName = name
	r.currentSize = 24 // global header size

	return nil
}

// cleanupOldFiles deletes oldest PCAPs to stay under total cap
func (r *RotatingPCAP) cleanupOldFiles() {
	entries, err := os.ReadDir(r.dir)
	if err != nil {
		return
	}

	type fileInfo struct {
		name string
		mod  time.Time
		size int64
	}

	var files []fileInfo
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".pcap" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, fileInfo{e.Name(), info.ModTime(), info.Size()})
	}

	// Total size
	var total int64
	for _, f := range files {
		total += f.size
	}

	// Sort by mod time (oldest first)
	for i := 1; i < len(files); i++ {
		for j := i; j > 0 && files[j-1].mod.After(files[j].mod); j-- {
			files[j], files[j-1] = files[j-1], files[j]
		}
	}

	// Delete oldest until under limit
	for total > r.maxTotalSize && len(files) > 0 {
		oldest := files[0]
		os.Remove(filepath.Join(r.dir, oldest.name))
		total -= oldest.size
		files = files[1:]
	}
}

// Write appends a packet record
func (r *RotatingPCAP) Write(timestamp time.Time, data []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Rotate if current file full
	recordSize := int64(16 + len(data))
	if r.currentSize+recordSize > r.maxFileSize {
		if err := r.rotate(); err != nil {
			return err
		}
	}

	rec := pcapRecordHeader{
		TsSec:   uint32(timestamp.Unix()),
		TsUsec:  uint32(timestamp.Nanosecond() / 1000),
		InclLen: uint32(len(data)),
		OrigLen: uint32(len(data)),
	}

	if err := binary.Write(r.currentFile, binary.LittleEndian, &rec); err != nil {
		return err
	}
	if _, err := r.currentFile.Write(data); err != nil {
		return err
	}

	r.currentSize += recordSize
	return nil
}

// Close finalizes the current file
func (r *RotatingPCAP) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.currentFile != nil {
		return r.currentFile.Close()
	}
	return nil
}
