try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

class YaraScanner:
    """
    Kharma Sentinel YARA Scanner.
    Uses industrial-grade YARA rules to identify complex malware patterns
    within captured network payloads.
    """
    def __init__(self):
        self.rules = None
        self.available = YARA_AVAILABLE
        if self.available:
            self._compile_default_rules()

    def _compile_default_rules(self):
        """Compiles a robust set of YARA rules for both network and file detection."""
        try:
            source = """
            rule Kharma_WebShell_General {
                meta: description = "Detects generic web shell command injection patterns"
                strings:
                    $s1 = "system(" nocase
                    $s2 = "passthru(" nocase
                    $s3 = "exec(" nocase
                    $s4 = "eval(base64_decode" nocase
                    $s5 = "shell_exec(" nocase
                    $s6 = "python_eval(" nocase
                condition: any of them
            }
            rule Kharma_ReverseShell_Python {
                meta: description = "Detects python-based reverse shell patterns"
                strings:
                    $p1 = "socket.socket("
                    $p2 = "subprocess.call(["
                    $p3 = "os.dup2(s.fileno()"
                    $p4 = "/bin/sh"
                    $p5 = "/bin/bash"
                condition: 3 of them
            }
            rule Kharma_Ransomware_Strings {
                meta: description = "Common strings found in ransomware notes/logic"
                strings:
                    $r1 = "all your files have been encrypted" nocase
                    $r2 = "BitCoin" nocase
                    $r3 = ".locked" nocase
                    $r4 = ".encrypted" nocase
                    $r5 = "private key" nocase
                condition: 2 of them
            }
            rule Kharma_Suspicious_Network_Tooling {
                meta: description = "Detects strings related to offensive network tools"
                strings:
                    $t1 = "Metasploit" nocase
                    $t2 = "Cobalt Strike" nocase
                    $t3 = "Mimikatz" nocase
                    $t4 = "Empire" nocase
                    $t5 = "beacons" nocase
                condition: any of them
            }
            """
            self.rules = yara.compile(source=source)
        except Exception as e:
            print(f"[YARA] Rule compilation failed: {e}")
            self.available = False

    def scan_data(self, data):
        """Scans raw bytes (e.g., network payloads)."""
        if not self.available or not self.rules or not data:
            return []
        try:
            matches = self.rules.match(data=data)
            return [m.rule for m in matches]
        except Exception as e:
            print(f"[YARA] Data scan error: {e}")
            return []

    def scan_file(self, file_path):
        """Scans a binary file on disk (Endpoint Detection)."""
        if not self.available or not self.rules or not os.path.exists(file_path):
            return []
        try:
            # We use match(filepath=...) which is more memory efficient for large binaries
            matches = self.rules.match(filepath=file_path)
            return [m.rule for m in matches]
        except Exception as e:
            print(f"[YARA] File scan error: {e} ({file_path})")
            return []

if __name__ == "__main__":
    scanner = YaraScanner()
    if scanner.available:
        print(f"Matches: {scanner.scan_data(b'<?php system($_GET[\"cmd\"]); ?>')}")
    else:
        print("YARA not available.")
