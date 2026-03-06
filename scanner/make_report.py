#!/usr/bin/env python3
import os, subprocess
from jinja2 import Environment, FileSystemLoader
from datetime import datetime

TEMPLATE_DIR = os.path.dirname(__file__)
env = Environment(loader=FileSystemLoader(TEMPLATE_DIR))
tmpl = env.get_template("report_template.html.j2")

def build_report(nikto_file, gvm_summary=None, out_dir="../reports"):
    os.makedirs(out_dir, exist_ok=True)
    with open(nikto_file, "r", encoding="utf-8", errors="ignore") as f:
        nikto_text = f.read()
    summary = {
        "generated_on": datetime.now().isoformat(),
        "nikto_lines": len(nikto_text.splitlines()),
        "nikto_excerpt": "\n".join(nikto_text.splitlines()[:200])
    }
    if gvm_summary:
        summary["gvm"] = gvm_summary
    html = tmpl.render(summary=summary)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_html = os.path.join(out_dir, f"report-{ts}.html")
    out_pdf = out_html.replace(".html", ".pdf")
    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html)
    chromium_bin = None
    for b in ("chromium","chromium-browser","google-chrome","google-chrome-stable"):
        if subprocess.call(["which", b], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            chromium_bin = b
            break
    if chromium_bin:
        cmd = [chromium_bin, "--headless", "--disable-gpu", "--no-sandbox", f"--print-to-pdf={out_pdf}", "file://" + os.path.abspath(out_html)]
        subprocess.run(cmd, check=True)
    else:
        print("Chromium not found; PDF not created.")
    return out_html, out_pdf if chromium_bin else None

