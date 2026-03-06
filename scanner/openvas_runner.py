#!/usr/bin/env python3
import os, re, sys, time, socket, ipaddress
from dotenv import load_dotenv
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import GMPv227
from gvm.transforms import EtreeTransform
from lxml import etree  # for debug printing


# ===== Load environment credentials =====
load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), "secrets.env"))
OPENVAS_USER = os.getenv("OPENVAS_USER", "admin")
OPENVAS_PASS = os.getenv("OPENVAS_PASS", "admin")
GVMD_SOCKET = os.getenv("GVMD_SOCKET", "/run/gvmd/gvmd.sock")

# ===== Default Config UUIDs =====
DEFAULT_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"        # “Full and fast”
DEFAULT_SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"       # OpenVAS Default Scanner
DEFAULT_PORT_LIST_ID = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"     # All IANA assigned TCP and UDP


def connect_gmp():
    """Authenticate and return a live GMPv227 session."""
    conn = UnixSocketConnection(path=GVMD_SOCKET)
    gmp = GMPv227(connection=conn, transform=EtreeTransform())
    gmp.authenticate(OPENVAS_USER, OPENVAS_PASS)
    return gmp


def run_openvas_scan(target_ip):
    """Run OpenVAS scan using GVM socket interface."""
    print("=" * 60)
    print(f"[*] Starting OpenVAS scan for {target_ip}\n")

    try:
        with connect_gmp() as gmp:
            print("[+] Authenticated successfully.")
            version = gmp.get_version().findtext("version")
            print(f"[+] Connected to GVM version: {version}")

            # === Get Scan Config ===
            config_id = None
            for cfg in gmp.get_scan_configs().xpath("config"):
                if "Full and fast" in (cfg.findtext("name") or ""):
                    config_id = cfg.get("id")
                    break
            if not config_id:
                config_id = DEFAULT_CONFIG_ID
                print(f"[!] Using default config ID: {config_id}")
            print(f"[+] Using scan config ID: {config_id}")

            # === Prepare host specs to try (don't change original input unless needed) ===
            original_host = target_ip
            base_ip = target_ip.split("/")[0]
            host_candidates = [
                original_host,
                base_ip,
                f"{base_ip}/32",
            ]

            # === Create Target ===
            safe_target_name = f"Target_{original_host}".replace("/", "_")
            target_id = None
            last_resp = None

            for host_spec in host_candidates:
                print(f"[DEBUG] Trying create_target with hosts='{host_spec}' and name='{safe_target_name}'")
                try:
                    target_resp = gmp.create_target(
                        name=safe_target_name,
                        hosts=[str(host_spec)],     # pass hosts as list (works across gvm versions)
                        port_list_id=DEFAULT_PORT_LIST_ID,
                        alive_test="Consider Alive",
                        reverse_lookup_only=False,
                        reverse_lookup_unify=False
                    )
                except Exception as e:
                    print(f"[DEBUG] create_target raised exception: {e}")
                    last_resp = None
                    continue

                last_resp = target_resp
                try:
                    print("[DEBUG] create_target response:")
                    print(etree.tostring(target_resp, pretty_print=True).decode())
                except Exception:
                    print("[DEBUG] (could not pretty print target_resp) repr:", repr(target_resp))

                status = target_resp.get("status")
                status_text = (target_resp.get("status_text") or "").strip()
                # Success path
                target_id = target_resp.get("id")
                if target_id:
                    print(f"[+] Target created successfully: {target_id}")
                    break

                # If server says target exists, try to find existing target and reuse its id
                if status == "400" and "target exists" in status_text.lower():
                    print("[DEBUG] Server reports target exists already; searching existing targets to reuse ID...")
                    try:
                        existing = gmp.get_targets().xpath("target")
                        for t in existing:
                            t_hosts = (t.findtext("hosts") or "").strip()
                            t_name = (t.findtext("name") or "").strip()
                            # match by host string or by sanitized name
                            if t_hosts == str(host_spec) or t_name == safe_target_name:
                                target_id = t.get("id")
                                print(f"[+] Reusing existing target: id={target_id} name={t_name} hosts={t_hosts}")
                                break
                    except Exception as e:
                        print(f"[DEBUG] Could not fetch existing targets: {e}")

                    if target_id:
                        break
                    else:
                        print("[DEBUG] Existing target not found by exact match; will try next candidate if any.")
                        # continue to next candidate

                else:
                    print(f"[DEBUG] create_target reported status {status}: {status_text}")
                    # continue to next candidate

            # If still no target_id, print helpful debug info and raise
            if not target_id:
                try:
                    plists = gmp.get_port_lists().xpath("port_list")
                    print("[DEBUG] Available port lists (id : name) -- showing first 10:")
                    for pl in plists[:10]:
                        print(f"  {pl.get('id')} : {pl.findtext('name')}")
                except Exception as e:
                    print(f"[DEBUG] Could not fetch port lists: {e}")

                try:
                    existing = gmp.get_targets().xpath("target")
                    print(f"[DEBUG] Number of existing targets: {len(existing)} -- showing first 5 ids:")
                    for t in existing[:5]:
                        print(f"  id={t.get('id')} name={t.findtext('name')} hosts={t.findtext('hosts')}")
                except Exception as e:
                    print(f"[DEBUG] Could not fetch existing targets: {e}")

                if last_resp is not None:
                    st = last_resp.get("status_text") or "No status_text provided"
                    st_code = last_resp.get("status") or "No status"
                    raise Exception(f"Target creation failed: {st} (status {st_code})")
                else:
                    raise Exception("Target creation failed: no response from create_target attempts")

            # === Get Scanner ===
            scanners = gmp.get_scanners().xpath("scanner")
            scanner_id = next(
                (s.get("id") for s in scanners if "OpenVAS" in (s.findtext("name") or "")),
                DEFAULT_SCANNER_ID,
            )
            print(f"[+] Using scanner ID: {scanner_id}")

            # === Create Task ===
            safe_task_name = f"Scan_{original_host}".replace("/", "_")
            task_resp = gmp.create_task(
                name=safe_task_name,
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id
            )
            task_id = task_resp.get("id")
            if not task_id:
                raise Exception(f"Task creation failed: {task_resp.get('status_text')}")
            print(f"[+] Task created successfully: {task_id}")

            # === Start Task ===
            time.sleep(2)
            try:
                report_resp = gmp.start_task(task_id)
                try:
                    print("[DEBUG] start_task response:")
                    print(etree.tostring(report_resp, pretty_print=True).decode())
                except Exception:
                    print("[DEBUG] (could not pretty print start_task response) repr:", repr(report_resp))

                report_id = report_resp.get("id")
                # If start_task didn't return a report id, poll the task for last_report (common with some GVM versions)
                if not report_id:
                    print("[DEBUG] start_task returned no report id; polling task for last_report...")
                    report_id = None
                    poll_tries = 20
                    for i in range(poll_tries):
                        try:
                            tasks = gmp.get_tasks().xpath("task")
                        except Exception as e:
                            print(f"[DEBUG] get_tasks failed: {e}")
                            tasks = []

                        for t in tasks:
                            if t.get("id") == task_id:
                                lr = t.find("last_report")
                                if lr is not None:
                                    report_id = lr.get("id") or (lr.text or "").strip() or None
                                if report_id is None:
                                    rr = t.find(".//report")
                                    if rr is not None:
                                        report_id = rr.get("id") or (rr.text or "").strip() or None
                                if report_id:
                                    break
                        if report_id:
                            print(f"[✓] Found report id after polling: {report_id}")
                            break
                        time.sleep(3)
                    if not report_id:
                        raise Exception("Missing report ID after start_task and polling.")
                print(f"[✓] Scan started successfully. Report ID: {report_id}")
            except (BrokenPipeError, socket.error) as err:
                print(f"[!] Socket dropped ({err}); retrying...")
                time.sleep(5)
                with connect_gmp() as retry:
                    retry_task = retry.start_task(task_id)
                    report_id = retry_task.get("id")
                    print(f"[✓] Retry successful. Report ID: {report_id}")

            return {"target_id": target_id, "task_id": task_id, "report_id": report_id}

    except Exception as err:
        print(f"[x] Scan failed: {err}")
        if "host specification" in str(err).lower() or "host" in str(err).lower():
            print("[!] Hint: GVMD rejected the host string. Try the following:")
            print("    - Make sure the target in targets.txt is a plain IP (e.g. 10.10.10.9) or valid hostname.")
            print("    - Remove any extra characters, spaces, or trailing slashes from the target entry.")
            print("    - If the problem persists, try manually creating a target in the GVM web UI to see an accepted format.")
        return None


def preprocess_targets(file_path):
    """Read and sanitize entries in targets.txt. Supports IPs and hostnames."""
    if not os.path.exists(file_path):
        print(f"[!] targets.txt not found at {file_path}")
        return []

    clean = []
    with open(file_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            line = re.sub(r"^https?://", "", line)
            # Take only the hostname/IP portion before any slash (path)
            line = line.split("/")[0].strip()

            # Try validating as IP (IPv4/IPv6)
            try:
                ipaddress.ip_address(line)
                clean.append(line)
                continue
            except ValueError:
                pass  # not an IP, check hostname next

            # Validate hostname or domain name
            if re.match(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$", line):
                clean.append(line)
            else:
                print(f"[!] Invalid target skipped: {line}")
    return clean


if __name__ == "__main__":
    targets_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "targets.txt")
    print(f"[DEBUG] Loading targets from: {targets_file}")

    targets = preprocess_targets(targets_file)
    if not targets:
        print("[!] No valid targets found.")
        sys.exit(1)

    for t in targets:
        result = run_openvas_scan(t)
        if result:
            print(f"[✔] Scan launched for {t} | Report ID: {result['report_id']}\n")
        else:
            print(f"[x] Scan failed for {t}. Review logs.\n")

