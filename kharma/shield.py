import subprocess  # nosec B404
import os
import platform

class ShieldManager:
    """
    Manages OS-level firewall rules to block/unblock malicious IP addresses.
    Supports Windows (netsh) and potentially Linux (iptables/nftables).
    """
    def __init__(self):
        self.os_type = platform.system()
        self.rule_prefix = "KHARMA_BLOCK_"
        self._whitelist = ["127.0.0.1", "localhost", "::1"]

    def block_ip(self, ip):
        """Creates a firewall rule to drop all traffic to/from the target IP or CIDR."""
        if not ip or ip in self._whitelist: return False
        
        # Sanitize rule name for CIDR blocks (e.g. 1.2.3.0/24 -> 1_2_3_0_24)
        safe_name = ip.replace('.', '_').replace('/', '_')
        rule_name = f"{self.rule_prefix}{safe_name}"
        
        if self.os_type == "Windows":
            # Command: netsh advfirewall firewall add rule name="KHARMA_BLOCK_1.1.1.1" dir=out action=block remoteip=1.1.1.1
            try:
                # Add OUTBOUND block
                subprocess.run([ # nosec
                    "netsh", "advfirewall", "firewall", "add", "rule", 
                    f"name={rule_name}_OUT", "dir=out", "action=block", f"remoteip={ip}"
                ], capture_output=True, check=True)
                
                # Add INBOUND block
                subprocess.run([ # nosec
                    "netsh", "advfirewall", "firewall", "add", "rule", 
                    f"name={rule_name}_IN", "dir=in", "action=block", f"remoteip={ip}"
                ], capture_output=True, check=True)
                return True
            except subprocess.CalledProcessError as e:
                print(f"Shield Error: Failed to block IP on Windows. Admin rights likely missing. {e}")
                return False
        elif self.os_type == "Linux":
            # Command: iptables -A INPUT -s 1.1.1.1 -j DROP
            try:
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True) # nosec
                subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True) # nosec
                return True
            except Exception as e:
                print(f"Shield Error: Failed to block IP on Linux: {e}")
                return False
        return False

    def unblock_ip(self, ip):
        """Removes the firewall rules associated with the target IP or CIDR."""
        if not ip: return False
        
        safe_name = ip.replace('.', '_').replace('/', '_')
        rule_name = f"{self.rule_prefix}{safe_name}"
        
        if self.os_type == "Windows":
            try:
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_OUT"], capture_output=True) # nosec
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}_IN"], capture_output=True) # nosec
                return True
            except Exception as e:
                print(f"Shield Error: Failed to unblock IP on Windows: {e}")
                return False
        elif self.os_type == "Linux":
            try:
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True) # nosec
                subprocess.run(["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"], check=True) # nosec
                return True
            except Exception as e:
                print(f"Shield Error: Failed to unblock IP on Linux: {e}")
                return False
        return False

    def list_blocked(self):
        """
        Lists all IPs currently blocked by Kharma rules.
        In this implementation, it parses the local rule set.
        """
        blocked_ips = []
        if self.os_type == "Windows":
            try:
                output = subprocess.check_output(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], text=True) # nosec
                for line in output.split('\n'):
                    if self.rule_prefix in line and "Rule Name:" in line:
                        # Extract IP from 'Rule Name: KHARMA_BLOCK_1.2.3.4_OUT'
                        ip_part = line.split(self.rule_prefix)[1].replace('_OUT', '').replace('_IN', '').strip()
                        if ip_part not in blocked_ips:
                            blocked_ips.append(ip_part)
            except Exception as e:
                print(f"Shield Error: Failed to list blocked IPs: {e}")
                pass
        return blocked_ips
