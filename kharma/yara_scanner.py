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
        """Compiles a small set of default rules for web-based threats."""
        try:
            # Inline rules for demo/base protection
            source = """
            rule Kharma_WebShell_Pattern {
                meta:
                    description = "Detects common PHP/system command patterns"
                strings:
                    $a = "system("
                    $b = "passthru("
                    $c = "exec("
                    $d = "base64_decode("
                condition:
                    any of them
            }
            rule Kharma_SQLi_Strict {
                meta:
                    description = "Strict SQL Injection patterns"
                strings:
                    $s1 = "UNION SELECT" nocase
                    $s2 = "GROUP BY" nocase
                    $s3 = "ORDER BY" nocase
                condition:
                    any of them
            }
            """
            self.rules = yara.compile(source=source)
        except Exception as e:
            print(f"[YARA] Rule compilation failed: {e}")
            self.available = False

    def scan(self, data):
        """Scans raw bytes against compiled YARA rules."""
        if not self.available or not self.rules or not data:
            return []
        
        try:
            matches = self.rules.match(data=data)
            return [m.rule for m in matches]
        except Exception as e:
            print(f"[YARA] Scan error: {e}")
            return []

if __name__ == "__main__":
    scanner = YaraScanner()
    if scanner.available:
        print(f"Matches: {scanner.scan(b'<?php system($_GET[\"cmd\"]); ?>')}")
    else:
        print("YARA not available.")
