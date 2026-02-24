import socket
import threading
import time

class HoneypotDecoy:
    """
    Kharma Sentinel Honeypot Decoy.
    Creates ghost services (FTP, Telnet, HTTP) on common ports to trap attackers.
    Any connection to these ports is flagged as a high-severity threat.
    """
    def __init__(self):
        self.ports = [21, 23, 80, 445, 3389]
        self.active_listeners = []
        self.detected_ips = set()
        self.on_detect_callback = None

    def start(self, callback=None):
        """Starts listeners on multiple ports."""
        self.on_detect_callback = callback
        for port in self.ports:
            t = threading.Thread(target=self._listen, args=(port,), daemon=True)
            t.start()
            self.active_listeners.append(t)
        print(f"[SENTINEL] Honeypot Decoys active on ports: {self.ports}")

    def _listen(self, port):
        """Internal port listener."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('0.0.0.0', port))
                s.listen(5)
                while True:
                    conn, addr = s.accept()
                    with conn:
                        attacker_ip = addr[0]
                        print(f"[HONEYPOT] ATTACKER DEPLOYED ON PORT {port}: {attacker_ip}")
                        self.detected_ips.add(attacker_ip)
                        if self.on_detect_callback:
                            self.on_detect_callback(attacker_ip, port)
                        # Minimal response to keep them engaged or just log and drop
                        conn.sendall(b"KharmaSentinel-Auth: Access Denied.\n")
                        time.sleep(0.5) 
        except Exception as e:
            # Port might be in use, skip silently
            pass

    def get_trapped_ips(self):
        return list(self.detected_ips)

if __name__ == "__main__":
    hp = HoneypotDecoy()
    hp.start()
    while True:
        time.sleep(1)
