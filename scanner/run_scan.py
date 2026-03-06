#!/usr/bin/env python3
import sys
import os
from nikto_runner import run_nikto
from make_report import build_report

# Try to import GVM runner
try:
    from gvm_runner import run_gvm_scan
    gvm_available = True
except Exception as e:
    print(f"[!] Warning: gvm_runner not available: {e}")
    run_gvm_scan = None
    gvm_available = False

# Read SKIP_GVM environment variable; default to 0
SKIP_GVM = os.getenv("SKIP_GVM", "0")
if SKIP_GVM not in ("0", "1"):
    print(f"[!] Warning: SKIP_GVM={SKIP_GVM} is invalid; defaulting to 0")
    SKIP_GVM = "0"

def main(target_url):
    print(f"[*] Starting scan pipeline for: {target_url}")

    # 1️⃣ Nikto scan
    nikto_out = run_nikto(target_url)
    if not nikto_out:
        print(f"[!] Nikto produced no output for {target_url}; skipping report generation.")
    else:
        print("[*] Nikto scan completed")
        try:
            html, pdf = build_report(nikto_out, gvm_summary=None)
            print(f"[*] Report generated: {html} {pdf}")
        except Exception as e:
            print(f"[!] Error while building report: {e}")

    # 2️⃣ GVM scan (only if not skipped and module available)
    if SKIP_GVM == "1":
        print("[*] GVM scan skipped because SKIP_GVM=1")
        return

    if not gvm_available:
        print("[*] GVM scan skipped because gvm_runner module not available")
        return

    try:
        gvm_summary = run_gvm_scan(target_url)
        if gvm_summary:
            print(f"[*] GVM scan info: {gvm_summary}")
        else:
            print("[!] GVM scan did not return a summary (it may be running asynchronously).")
    except Exception as e:
        print(f"[!] Error in GVM scan: {e}")

if __name__ == "__main__":
    targets_file = os.path.join(os.path.dirname(__file__), "targets.txt")
    if not os.path.exists(targets_file):
        print(f"[!] targets.txt not found at {targets_file}")
        sys.exit(1)

    with open(targets_file, "r") as f:
        targets = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not targets:
        print("[!] No targets found in targets.txt")
        sys.exit(1)

    for t in targets:
        print("="*60)
        main(t)

