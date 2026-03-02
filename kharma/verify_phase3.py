import sys
import os
import time
import subprocess
import psutil

# Add parent dir to path to import kharma modules if needed
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from mitigation import QuarantineManager
    print("✅ QuarantineManager import successful.")
except ImportError:
    print("❌ Failed to import QuarantineManager.")
    sys.exit(1)

def verify_quarantine():
    print("--- Starting Phase 3 Verification ---")
    
    # 1. Spawn a dummy process
    proc = subprocess.Popen(["python", "-c", "import time; [time.sleep(1) for _ in range(60)]"])
    pid = proc.pid
    print(f"[*] Spawned test process (PID: {pid})")
    
    try:
        # 2. Check initial state
        p = psutil.Process(pid)
        print(f"[*] Initial Status: {p.status()}")
        
        # 3. Test Quarantine (Suspend)
        print("[*] Applying Quarantine...")
        if QuarantineManager.suspend_process(pid):
            time.sleep(1)
            status = p.status()
            print(f"[*] Post-Quarantine Status: {status}")
            if status in [psutil.STATUS_STOPPED, psutil.STATUS_PARKED]: # Stopped/Parked depending on OS
                print("✅ PROCESS SUCCESSFULLY FROZEN")
            else:
                print(f"⚠️ Unexpected status after quarantine: {status}")
        else:
            print("❌ Failed to apply quarantine.")
            
        # 4. Test Resume
        print("[*] Releasing from Quarantine...")
        if QuarantineManager.resume_process(pid):
            time.sleep(1)
            status = p.status()
            print(f"[*] Post-Release Status: {status}")
            if status == psutil.STATUS_RUNNING or status == psutil.STATUS_SLEEPING:
                print("✅ PROCESS SUCCESSFULLY RESUMED")
            else:
                print(f"⚠️ Unexpected status after release: {status}")
        else:
            print("❌ Failed to resume process.")
            
    finally:
        # Cleanup
        if psutil.pid_exists(pid):
            proc.terminate()
            print("[*] Test process terminated.")

if __name__ == "__main__":
    verify_quarantine()
