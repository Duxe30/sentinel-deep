//go:build linux

package system

import "golang.org/x/sys/unix"

func readDisk(path string) DiskStats {
	if path == "" {
		path = "/"
	}
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return DiskStats{Path: path}
	}
	total := uint64(st.Blocks) * uint64(st.Bsize)
	free := uint64(st.Bavail) * uint64(st.Bsize)
	used := total - free
	pct := 0.0
	if total > 0 {
		pct = float64(used) / float64(total) * 100.0
	}
	return DiskStats{Path: path, TotalBytes: total, FreeBytes: free, UsedBytes: used, UsedPct: pct}
}
