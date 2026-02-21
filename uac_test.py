import sys
import ctypes

if __name__ == "__main__":
    print(f"sys.executable: {sys.executable}")
    print(f"sys.argv[0]: {sys.argv[0]}")
    print("Testing UAC prompt directly...")
    
    # Try the raw python elevation approach
    script = sys.argv[0]
    
    # Pause to read output
    input("Press Enter to launch admin prompt test...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'-c "import time; print(\'Admin works!\'); time.sleep(5)"', None, 1)
