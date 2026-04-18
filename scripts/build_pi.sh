#!/usr/bin/env bash
# Cross-compile Sentinel-Pi for Raspberry Pi 4 (ARM64)

set -euo pipefail

cd "$(dirname "$0")/.."

echo "═══════════════════════════════════════════════"
echo "  Building Sentinel-Pi for Raspberry Pi 4 (ARM64)"
echo "═══════════════════════════════════════════════"

# Tidy modules
go mod tidy

# Build for ARM64 Linux (Pi 4/5)
GOOS=linux GOARCH=arm64 CGO_ENABLED=1 \
  go build -ldflags "-s -w" -o bin/sentinel-pi ./cmd/sentinel

ls -lh bin/sentinel-pi

echo ""
echo "[OK] Binary built. Copy to Pi with:"
echo "    scp bin/sentinel-pi pi@<IP>:/home/pi/"
echo "    scp -r deploy/models pi@<IP>:/home/pi/sentinel-models/"
echo ""
echo "Then on Pi:"
echo "    sudo ./sentinel-pi --interface wlan0 --models /home/pi/sentinel-models/"
