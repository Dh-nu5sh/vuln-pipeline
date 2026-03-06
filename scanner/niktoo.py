#!/usr/bin/env python3
import os
import socket
import subprocess
import re
import html as html_module
from datetime import datetime
from urllib.parse import urlparse

# Base directory (same folder as script)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Output directory for reports
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Input file with targets
TARGETS_FILE = os.path.join(BASE_DIR, "targets.txt")


def _safe_name(target: str) -> str:
    """Generate a filesystem-safe filename from the target."""
    s = target.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")
    return "".join(c for c in s if c.isalnum() or c in ("_", "-", ".")).strip("_")


def _extract_host_and_scheme(raw: str):
    """
    Return a tuple (original_target_for_nikto, host_part_for_resolution).
    - If the raw target contains a scheme (http/https), we keep it for the nikto invocation.
    - The host part returned is stripped of port so it can be resolved to an IP.
    """
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = parsed.hostname or parsed.path  # fallback if parsing weird input
    scheme = parsed.scheme or "http"
    # keep port if present in original raw, but for resolution we strip it (we use host variable)
    if "://" in raw:
        nikto_target = raw
    else:
        # If the user provided host:port, preserve port in nikto target by checking parsed.port
        if parsed.port:
            nikto_target = f"{scheme}://{host}:{parsed.port}"
        else:
            nikto_target = f"{scheme}://{host}"
    return nikto_target, host


def _resolve_ip(host: str) -> str | None:
    """Resolve a hostname to an IP (prefer IPv4). Return IP as string or None on failure."""
    try:
        infos = socket.getaddrinfo(host, None)
        if not infos:
            return None
        # Try to pick an IPv4 address first
        for fam, _, _, _, sockaddr in infos:
            if fam == socket.AF_INET:
                return sockaddr[0]
        # else return first available (could be IPv6)
        return infos[0][4][0]
    except Exception:
        return None


def _html_to_text(html_content: str) -> str:
    """
    Convert HTML content to plain text.
    This is a simple implementation: strips scripts/styles, removes tags,
    unescapes entities, and normalizes whitespace.
    """
    # Remove script and style blocks
    cleaned = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html_content)
    # Convert common block-level tags to newlines to keep reasonable structure
    cleaned = re.sub(r"(?i)<\s*(br|p|div|li|tr|h[1-6])\b[^>]*>", "\n", cleaned)
    # Remove all remaining tags
    cleaned = re.sub(r"(?s)<[^>]+>", " ", cleaned)
    # Unescape HTML entities
    cleaned = html_module.unescape(cleaned)
    # Collapse multiple whitespace/newlines to sensible amount
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\n\s*\n+", "\n\n", cleaned)  # keep up to one blank line
    cleaned = cleaned.strip()
    return cleaned


def run_nikto(target: str):
    """Run Nikto for a given target (single HTML output), then convert to TXT."""
    nikto_target = target
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = _safe_name(nikto_target)

    txt_path = os.path.join(OUTPUT_DIR, f"nikto-{safe}-{ts}.txt")
    html_path = os.path.join(OUTPUT_DIR, f"nikto-{safe}-{ts}.html")

    print(f"\n[+] Scanning: {nikto_target}")
    print(f"  -> Output (HTML): {html_path}")
    print(f"  -> Will also write TXT: {txt_path}")

    # Run Nikto once (HTML). -maxtime is kept as before.
    subprocess.run(["nikto", "-h", nikto_target, "-maxtime", "300s", "-output", html_path, "-Format", "html"], check=False)

    # If HTML was produced, convert it to TXT
    if os.path.exists(html_path) and os.path.getsize(html_path) > 0:
        try:
            with open(html_path, "r", encoding="utf-8", errors="ignore") as f:
                html_content = f.read()
            text_content = _html_to_text(html_content)
            # If conversion yields something, write TXT
            if text_content:
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write(text_content)
                print(f"[+] Conversion complete: {txt_path}")
            else:
                # Fallback: if conversion empty, save a small notice file
                with open(txt_path, "w", encoding="utf-8") as f:
                    f.write(f"[!] HTML conversion produced no content for {nikto_target} (check HTML at {html_path})\n")
                print(f"[!] Conversion produced no content; wrote placeholder to {txt_path}")
        except Exception as e:
            print(f"[!] Error converting HTML to TXT for {nikto_target}: {e}")
    else:
        print(f"[!] No HTML output generated for {nikto_target} (check nikto/permissions)")


def main():
    if not os.path.exists(TARGETS_FILE):
        print(f"[!] targets.txt not found in {BASE_DIR}")
        return

    # Read and clean raw lines (preserve order, remove blanks and comments)
    with open(TARGETS_FILE, "r", encoding="utf-8") as f:
        raw_lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

    if not raw_lines:
        print("[!] No valid targets found in targets.txt")
        return

    # Map resolved IP -> representative nikto target (first occurrence wins)
    ip_to_target = {}
    unresolved_targets = []

    for raw in raw_lines:
        nikto_target, host = _extract_host_and_scheme(raw)
        ip = _resolve_ip(host)
        if ip:
            if ip not in ip_to_target:
                ip_to_target[ip] = nikto_target
        else:
            unresolved_targets.append(nikto_target)

    # Dedupe unresolved targets preserving order
    seen = set()
    dedup_unresolved = []
    for t in unresolved_targets:
        if t not in seen:
            dedup_unresolved.append(t)
            seen.add(t)

    # Final list of unique targets
    targets_to_scan = list(ip_to_target.values()) + dedup_unresolved

    print(f"[*] Found {len(targets_to_scan)} unique IP/target(s) to scan:")
    for t in targets_to_scan:
        print("   -", t)

    # --- Single target logic ---
    if len(targets_to_scan) == 1:
        run_nikto(targets_to_scan[0])
        print(f"\n✅ Report saved at: {OUTPUT_DIR}")
        return

    # --- Multiple targets logic ---
    for t in targets_to_scan:
        run_nikto(t)

    print(f"\n✅ All reports saved at: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
