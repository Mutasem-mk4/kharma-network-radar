import sys
import os

# Add current directory to path
sys.path.append(os.getcwd())

from threat import ThreatIntelligence

ti = ThreatIntelligence()
test_ips = ['0.0.0.0', '127.0.0.1', '8.8.8.8']

for ip in test_ips:
    is_malicious = ti.check_ip(ip)
    print(f"IP: {ip} -> Malicious: {is_malicious}")
    if ip in ['0.0.0.0', '127.0.0.1'] and is_malicious:
        print(f"FAILED: {ip} should not be malicious.")
        sys.exit(1)

print("SUCCESS: Whitelist is working.")
sys.exit(0)
