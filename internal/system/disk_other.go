//go:build !linux

package system

func readDisk(path string) DiskStats {
	return DiskStats{Path: path}
}
