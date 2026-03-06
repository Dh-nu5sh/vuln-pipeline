#!/usr/bin/env python3
import os
from dotenv import load_dotenv
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp

# Load secrets
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '../secrets.env'))
GVM_USER = os.getenv("GVM_USER")
GVM_PASS = os.getenv("GVM_PASS")
GVM_SOCKET = os.getenv("GVM_SOCKET")

def get_id(response):
    """Safely extract ID from GVM response (int or XML element)."""
    if response is None:
        raise ValueError("Response is None, cannot extract ID")
    
    # If it's already an int or string, return as string
    if isinstance(response, (int, str)):
        return str(response)
    
    # Check for 'id' attribute first (common in GVM responses)
    if hasattr(response, 'attrib') and 'id' in response.attrib:
        return response.attrib['id']
    
    # If it has a find method (XML element), try to extract <id> child element
    if hasattr(response, 'find'):
        id_el = response.find('id')
        if id_el is not None and hasattr(id_el, 'text'):
            return str(id_el.text)
    
    # Fallback: if it's something else, just convert to string
    return str(response)

def get_version_string(response):
    """Extract version string from GVM response."""
    if hasattr(response, 'find'):
        version_el = response.find('version')
        if version_el is not None and hasattr(version_el, 'text'):
            return version_el.text
    return str(response)

def run_gvm_scan(target_url):
    """Run GVM scan and return a summary dictionary."""
    # Validate environment variables
    if not all([GVM_USER, GVM_PASS, GVM_SOCKET]):
        print("[!] Missing GVM credentials. Check secrets.env file")
        return None
    
    print(f"[*] Connecting to GVM socket at: {GVM_SOCKET}")
    conn = UnixSocketConnection(path=GVM_SOCKET)

try:
    with Gmp(connection=conn) as gmp:
        gmp.authenticate(username=GVM_USER, password=GVM_PASS)
except Exception as e:
    print(f"[!] Connection to GVM failed: {e}")
    print("[!] Try running the script as '_gvm' user:")
    print("    sudo runuser -u _gvm -- python3 gvm_runner.py")
    raise
        
            # Get version safely
            version_resp = gmp.get_version()
            version = get_version_string(version_resp)
            print(f"[+] Connected to GVM: {version}")
            
            # Get scan config (required for create_task)
            configs = gmp.get_scan_configs()
            config_id = get_id(configs.find('.//config'))
            print(f"[+] Using scan config ID: {config_id}")
            
            # Get scanner (may be required depending on GVM version)
            scanners = gmp.get_scanners()
            scanner_id = get_id(scanners.find('.//scanner'))
            print(f"[+] Using scanner ID: {scanner_id}")
            
            # Create target
            target = gmp.create_target(name=target_url, hosts=[target_url])
            target_id = get_id(target)
            print(f"[+] Created target with ID: {target_id}")
            
            # Create task with config_id and scanner_id
            task = gmp.create_task(
                name=f"Scan {target_url}", 
                target_id=target_id,
                config_id=config_id,
                scanner_id=scanner_id
            )
            task_id = get_id(task)
            print(f"[+] Created task with ID: {task_id}")
            
            # Start scan
            start_resp = gmp.start_task(task_id)
            report_id = get_id(start_resp)
            print(f"[+] Scan started, report ID: {report_id}")
            
            # Return summary
            gvm_summary = {
                "target_id": target_id, 
                "task_id": task_id, 
                "report_id": report_id
            }
            return gvm_summary
            
    except Exception as e:
        print("[!] Error in GVM scan:", e)
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    # Test the function
    result = run_gvm_scan("192.168.1.1")
    if result:
        print("[+] GVM scan summary:", result)
    else:
        print("[!] GVM scan failed")
