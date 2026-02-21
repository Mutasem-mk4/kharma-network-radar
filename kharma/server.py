import os
import sys
import psutil
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS

# Attempt to load Kharma internal modules depending on execution context
try:
    from kharma.scanner import NetworkScanner
    from kharma.geoip import GeoIPResolver
    from kharma.threat import ThreatIntelligence
    from kharma.vt_engine import VTEngine
    from kharma.community import CommunityIntel
except ImportError:
    from scanner import NetworkScanner
    from geoip import GeoIPResolver
    from threat import ThreatIntelligence
    from vt_engine import VTEngine
    from community import CommunityIntel

class KharmaWebServer:
    def __init__(self, host="127.0.0.1", port=8085):
        self.host = host
        self.port = port
        
        # Determine the correct templates folder path regardless of pip vs source install
        if getattr(sys, 'frozen', False):
            # PyInstaller context
            template_dir = os.path.join(sys._MEIPASS, 'templates')
        else:
            # Standard package context
            template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
            
        self.app = Flask(__name__, template_folder=template_dir, static_folder=template_dir)
        CORS(self.app)  # Allow frontend requests
        self._setup_engines()
        self._setup_routes()

    def _setup_engines(self):
        """Initialize all the core data gathering engines."""
        self.scanner = NetworkScanner()
        self.geoip = GeoIPResolver()
        self.intel = ThreatIntelligence()
        self.vt_engine = VTEngine()
        self.community = CommunityIntel()

    def _setup_routes(self):
        @self.app.route('/')
        def index():
            """Serve the main Kharma Dashboard UI."""
            return render_template('index.html')

        @self.app.route('/api/radar', methods=['GET'])
        def get_live_radar():
            """
            Fetches all active network connections and runs them through the 
            Threat Intel, GeoIP, and VirusTotal engines to build a complete JSON response.
            """
            try:
                self.scanner.scan()
                active_connections = self.scanner.get_active_connections()
                radar_data = []

                for conn in active_connections:
                    remote_ip = conn['remote_ip']
                    
                    # 1. GeoIP Lookup
                    location = "[LOCAL]"
                    country_code = "LOCAL"
                    lat, lon = None, None
                    if remote_ip and not remote_ip.startswith(('127.', '192.168.', '10.')):
                        lat_lon = self.geoip.resolve(remote_ip)
                        if lat_lon:
                            lat = lat_lon[0]
                            lon = lat_lon[1]
                            location = f"{lat_lon[2]}, {lat_lon[3]}"
                            country_code = lat_lon[3]
                        else:
                            location = "[UNKNOWN]"
                            country_code = "N/A"

                    # 2. Threat Intel (Malware Detection)
                    is_malware = False
                    status_text = conn['status']
                    if remote_ip and self.intel.check_ip(remote_ip):
                        is_malware = True
                        status_text = "BREACHED"

                    # 3. VirusTotal EDR Scoring
                    vt_malicious = -1
                    vt_total = -1
                    if self.vt_engine.api_key and conn.get('exe'):
                        file_hash = self.vt_engine.get_file_hash(conn['exe'])
                        if file_hash:
                            vt_m, vt_t = self.vt_engine.check_hash(file_hash)
                            if vt_m is not None:
                                vt_malicious = vt_m
                                vt_total = vt_t
                                if vt_malicious > 0:
                                    is_malware = True
                                    status_text = "BREACHED"

                    # 4. Community Reputation
                    is_community_flagged = self.community.is_flagged(remote_ip)
                    community_detail = self.community.get_details(remote_ip) if is_community_flagged else None
                    if is_community_flagged:
                        status_text = "SUSPICIOUS"

                    # Assemble JSON Row
                    radar_data.append({
                        "process_name": conn.get('name', 'Unknown'),
                        "pid": conn.get('pid', 'N/A'),
                        "exe": conn.get('exe', ''),
                        "local_address": f"{conn.get('local_ip')}:{conn.get('local_port')}",
                        "remote_address": f"{remote_ip}:{conn.get('remote_port')}",
                        "remote_ip": remote_ip, # Send raw IP for reporting
                        "location": location,
                        "country_code": country_code,
                        "lat": lat,
                        "lon": lon,
                        "status": status_text,
                        "is_malware": is_malware,
                        "is_community_flagged": is_community_flagged,
                        "community_reports": community_detail['reports'] if is_community_flagged else 0,
                        "vt_malicious": vt_malicious,
                        "vt_total": vt_total
                    })

                return jsonify({"status": "success", "data": radar_data}), 200

            except Exception as e:
                import traceback
                return jsonify({"status": "error", "message": str(e), "trace": traceback.format_exc()}), 500

        @self.app.route('/api/kill/<int:pid>', methods=['DELETE'])
        def kill_process(pid):
            """API Endpoint to instantly terminate a process via the Web UI."""
            try:
                p = psutil.Process(pid)
                p_name = p.name()
                p.terminate()
                p.wait(timeout=3)
                return jsonify({"status": "success", "message": f"Terminated {p_name} (PID: {pid})"}), 200
            except psutil.NoSuchProcess:
                return jsonify({"status": "error", "message": f"PID {pid} not found."}), 404
            except psutil.AccessDenied:
                return jsonify({"status": "error", "message": f"Access Denied. Run Kharma as Admin/Root to kill PID {pid}."}), 403
            except Exception as e:
                return jsonify({"status": "error", "message": f"Failed to kill process: {e}"}), 500

        @self.app.route('/api/report', methods=['POST'])
        def report_to_community():
            """API Endpoint to report a malicious IP to the decentralized Kharma community."""
            try:
                data = request.get_json()
                remote_ip = data.get('ip')
                reason = data.get('reason', 'Manual Flag')
                
                if not remote_ip:
                    return jsonify({"status": "error", "message": "Missing IP address."}), 400
                    
                success = self.community.report_ip(remote_ip, reason)
                if success:
                    return jsonify({"status": "success", "message": f"IP {remote_ip} has been reported to the community."}), 200
                else:
                    return jsonify({"status": "error", "message": "Failed to report IP."}), 500
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

    def start(self):
        """Start the Flask internal server. This is a blocking call."""
        # Disable Flask startup banner for stealth
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        
        self.app.run(host=self.host, port=self.port, debug=False)

if __name__ == '__main__':
    server = KharmaWebServer()
    server.start()
