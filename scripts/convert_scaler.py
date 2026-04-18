#!/usr/bin/env python3
"""
Convert sklearn RobustScaler from joblib to JSON for Go consumption.

Usage:
    python convert_scaler.py scaler.joblib scaler.json
"""
import json
import sys
import joblib


def main():
    if len(sys.argv) != 3:
        print("Usage: convert_scaler.py <input.joblib> <output.json>")
        sys.exit(1)

    scaler = joblib.load(sys.argv[1])
    out = {
        "center": scaler.center_.tolist(),
        "scale": scaler.scale_.tolist(),
    }
    with open(sys.argv[2], "w") as f:
        json.dump(out, f)

    print(f"[OK] Converted {len(out['center'])} features.")
    print(f"     {sys.argv[1]} -> {sys.argv[2]}")


if __name__ == "__main__":
    main()
