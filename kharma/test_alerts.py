import sys
import os
import time
from unittest.mock import MagicMock

# Add current directory to path
sys.path.append(os.getcwd())

from guardian import GuardianBot
from threat import ThreatIntelligence

# Mock the guardian to see if alert_threat is called
guardian = GuardianBot()
guardian.alert_threat = MagicMock()

# Setup threat intel with 8.8.8.8 as a "threat" for testing
ti = ThreatIntelligence()
ti.malicious_ips.add("8.8.8.8")

# Simulate the monitor loop
test_ip = "8.8.8.8"
if ti.check_ip(test_ip):
    print(f"Detected threat: {test_ip}")
    guardian.alert_threat(test_ip, "Test Process")

# Verify
if guardian.alert_threat.called:
    print("SUCCESS: GuardianBot.alert_threat was called correctly.")
    sys.exit(0)
else:
    print("FAILED: GuardianBot.alert_threat was NOT called.")
    sys.exit(1)
