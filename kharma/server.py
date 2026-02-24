import os
import sys
import psutil
import random
import secrets
import logging
import json
from flask import Flask, render_template, jsonify, request, make_response, session, redirect, url_for
from flask_cors import CORS
from flask_talisman import Talisman
from flask_socketio import SocketIO, emit

# Attempt to load Kharma internal modules depending on execution context
try:
    from kharma.scanner import NetworkScanner
    from kharma.geoip import GeoIPResolver
    from kharma.threat import ThreatIntelligence
    from kharma.vt_engine import VTEngine
    from kharma.community import CommunityIntel
    from kharma.dpi import DPIEngine
    from kharma.shield import ShieldManager
    from kharma.guardian import GuardianBot
    from kharma.forensics import ForensicsDB
    from kharma.hunter import HunterEngine
    from kharma.behavior import BehaviorEngine
    from kharma.swarm import SwarmEngine
    from kharma.honeypot import HoneypotDecoy
    from kharma.asn_blocker import ASNBlocker
    from kharma.report_generator import ReportGenerator
except ImportError:
    from scanner import NetworkScanner
    from geoip import GeoIPResolver
    from threat import ThreatIntelligence
    from vt_engine import VTEngine
    from community import CommunityIntel
    from dpi import DPIEngine
    from shield import ShieldManager
    from guardian import GuardianBot
    from forensics import ForensicsDB
    from hunter import HunterEngine
    from behavior import BehaviorEngine
    from swarm import SwarmEngine
    from report_generator import ReportGenerator

class KharmaWebServer:
    def __init__(self, host="127.0.0.1", port=8085):
        self.host = host
        self.port = port
        self.secret_token = self._generate_session_token()
        
        # Determine the correct templates folder path regardless of pip vs source install
        if getattr(sys, 'frozen', False):
            # PyInstaller context
            template_dir = os.path.join(sys._MEIPASS, 'templates')
        else:
            # Standard package context
            template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
            
        self.app = Flask(__name__, template_folder=template_dir, static_folder=template_dir)
        self.app.secret_key = self.secret_token # Use the same token for session signing
        
        # Security Hardening: Lockdown CORS to strict localhost
        CORS(self.app, resources={r"/api/*": {"origins": ["http://127.0.0.1:*", "http://localhost:*"]}})
        
        # Security Hardening: Content Security Policy (CSP) and Security Headers
        csp = {
            'default-src': '\'self\'',
            'script-src': [
                '\'self\'',
                '\'unsafe-inline\'',
                'https://cdn.tailwindcss.com',
                'https://unpkg.com',
                'https://cdn.jsdelivr.net'
            ],
            'style-src': [
                '\'self\'',
                '\'unsafe-inline\'',
                'https://unpkg.com',
                'https://cdn.jsdelivr.net',
                'https://fonts.googleapis.com'
            ],
            'font-src': [
                '\'self\'',
                'https://fonts.gstatic.com'
            ],
            'img-src': [
                '\'self\'',
                'data:',
                'https://*.tile.openstreetmap.org',
                'https://img.icons8.com'
            ]
        }
        Talisman(self.app, content_security_policy=csp, force_https=False)
        
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        self._setup_engines()
        self._setup_routes()

    def _generate_session_token(self):
        """Generates a random token to prevent CSRF and unauthorized API calls."""
        import secrets
        return secrets.token_hex(24)

    def _require_auth(self, f):
        """Security Decorator: Ensures the request carries the correct session token or session cookie."""
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Check for Session Cookie (Web UI)
            if session.get('authenticated'):
                return f(*args, **kwargs)
                
            # 2. Check for Token Header/Param (Internal/CLI)
            token = request.headers.get('X-Kharma-Token') or request.args.get('token')
            if not token or token != self.secret_token:
                return jsonify({"status": "error", "message": "Unauthorized. Secure Session Required."}), 403
            return f(*args, **kwargs)
        return decorated_function

    def _setup_engines(self):
        """Initialize all the core data gathering engines."""
        self.scanner = NetworkScanner()
        self.geoip = GeoIPResolver()
        self.intel = ThreatIntelligence()
        self.vt_engine = VTEngine()
        self.community = CommunityIntel()
        self.dpi = DPIEngine()
        self.dpi.start() # Start background sniffing
        self.shield = ShieldManager()
        self.guardian = GuardianBot()
        self.forensics = ForensicsDB()
        self.behavior = BehaviorEngine()
        self.hunter = HunterEngine()
        self.swarm = SwarmEngine(self.secret_token)
        self.report_gen = ReportGenerator(self.forensics)
        
        # Sentinel: Honeypot Auto-Defense
        self.honeypot = HoneypotDecoy()
        self.honeypot.start(callback=self._honeypot_callback)
        
        # Sentinel: ASN Mass-Blocking
        self.asn_blocker = ASNBlocker(self.shield)
        
        # Sentinel: WebSocket Handlers
        self._setup_sockets()

    def _setup_sockets(self):
        @self.socketio.on('connect')
        def handle_connect():
            print("[MOBILE] Companion App Linked via WebSocket.")
            emit('auth_status', {'status': 'linked', 'identity': 'Kharma-Sentinel-Core'})

        @self.socketio.on('get_telemetry')
        def handle_telemetry(data):
            # Check auth token from data
            token = data.get('token')
            if token == self.secret_token:
                # Send back summary data
                emit('telemetry_update', {
                    'connections': len(self.scanner.get_active_connections()),
                    'threats': len(self.forensics.get_events(event_type="THREAT")),
                    'blocked': len(self.shield.list_blocked())
                })

        @self.socketio.on('remote_kill')
        def handle_kill(data):
            token = data.get('token')
            pid = data.get('pid')
            if token == self.secret_token and pid:
                print(f"[SENTINEL] REMOTE COMMAND: KILL PID {pid}")
                # Logic from kill_process route
                import psutil
                try:
                    p = psutil.Process(pid)
                    p.terminate()
                    emit('command_result', {'status': 'success', 'message': f'Process {pid} terminated.'})
                except Exception as e:
                    emit('command_result', {'status': 'error', 'message': str(e)})

        @self.socketio.on('remote_shield')
        def handle_shield(data):
            token = data.get('token')
            ip = data.get('ip')
            if token == self.secret_token and ip:
                print(f"[SENTINEL] REMOTE COMMAND: SHIELD IP {ip}")
                if self.shield.block_ip(ip):
                    emit('command_result', {'status': 'success', 'message': f'IP {ip} isolated.'})
                else:
                    emit('command_result', {'status': 'error', 'message': 'Shield failed.'})

    def _honeypot_callback(self, ip, port):
        """Autonomous Response: Block any IP that hits a honeypot port and its entire ASN."""
        print(f"[SENTINEL] HONEYPOT TRIGGERED BY {ip} ON PORT {port}. ISOLATING ASN...")
        # Mass block the range for immediate suppression
        blocked_count = self.asn_blocker.mass_block_asn(ip)
        
        self.guardian.alert_blocked(ip, reason=f"Honeypot Decoy (Port {port}) + ASN MASS BLOCK ({blocked_count} ranges)")
        self.forensics.log(
            event_type="BLOCKED",
            ip=ip,
            process="Honeypot Ghost",
            location="[LOCAL TRAP]",
            detail=f"Honeypot Port {port} Triggered Mass-Block",
            severity="critical"
        )

    def _load_settings(self):
        import json, os
        config_path = os.path.expanduser("~/.kharma/daemon_config.json")
        if os.path.exists(config_path):
            with open(config_path, "r") as f:
                try: return json.load(f)
                except Exception as e:
                    print(f"[SERVER] Settings load error: {e}")
                    return {}
        return {}

    def _setup_routes(self):
        @self.app.route('/')
        def index():
            """Serve the main Kharma Dashboard UI."""
            resp = make_response(render_template('index.html', session_token=self.secret_token))
            # Force anti-cache for security and fresh data
            resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            resp.headers['Pragma'] = 'no-cache'
            return resp

        @self.app.route('/login', methods=['GET'])
        def login():
            """Serve the Kharma Sentinel Login page."""
            if session.get('authenticated'):
                return redirect(url_for('index'))
            return render_template('login.html')

        @self.app.route('/api/login', methods=['POST'])
        def api_login():
            """Authentication Endpoint."""
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            settings = self._load_settings()
            stored_password = settings.get('web_password', 'sentinel123') # Default password if not set
            
            if username == 'admin' and password == stored_password:
                session['authenticated'] = True
                return jsonify({"status": "success", "message": "Authenticated."}), 200
            
            return jsonify({"status": "error", "message": "Invalid credentials."}), 401

        @self.app.route('/logout')
        def logout():
            """Clear the secure session."""
            session.pop('authenticated', None)
            return redirect(url_for('login'))

        @self.app.route('/api/radar', methods=['GET'])
        def get_live_radar():
            """
            Fetches all active network connections and runs them through the 
            Threat Intel, GeoIP, and VirusTotal engines to build a complete JSON response.
            """
            try:
                self.scanner.scan()
                self.dpi.update_flow_map(self.scanner.flow_map)                
                active_connections = self.scanner.get_active_connections()
                bandwidth_stats = self.dpi.get_bandwidth_report()
                payload_samples = self.dpi.get_recent_payloads()
                
                settings = self._load_settings()
                blocked_countries = settings.get('blocked_countries', [])
                
                radar_data = []
                blocked_ips = self.shield.list_blocked()

                for conn in active_connections:
                    remote_ip = conn['remote_ip']
                    
                    # 1. GeoIP Lookup
                    location = "[LOCAL]"
                    country_code = "LOCAL"
                    lat, lon = None, None
                    if remote_ip and not remote_ip.startswith(('127.', '192.168.', '10.')):
                        lat_lon = self.geoip.resolve(remote_ip)
                        if isinstance(lat_lon, tuple):
                            if len(lat_lon) >= 3:
                                lat, lon, location_str = lat_lon[0], lat_lon[1], lat_lon[2]
                                location = location_str
                                country_code = location_str.split(',')[-1].strip() if ',' in location_str else "N/A"
                                
                                # --- Geo-Fencing Auto-Block ---
                                if country_code != "N/A" and country_code in blocked_countries and remote_ip not in blocked_ips:
                                    if self.shield.block_ip(remote_ip):
                                        blocked_ips.append(remote_ip)
                                        self.forensics.log("BLOCKED", remote_ip, conn['name'], location, f"Geo-Fence Policy: {country_code}", "high")
                            else:
                                location = "Tuple Error"
                                country_code = "N/A"
                        else:
                            location = str(lat_lon) if lat_lon else "[UNKNOWN]"
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

                    # 5. AI Behavioral Profiling
                    ai_results = self.behavior.analyze(
                        conn.get('name', 'Unknown'), 
                        bandwidth_stats.get(conn['pid'], {}).get('in_kbps', 0),
                        bandwidth_stats.get(conn['pid'], {}).get('out_kbps', 0),
                        country_code,
                        payload=payload_samples.get(conn['pid'])
                    )

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
                        "lat": lat if lat is not None else (float(secrets.randbelow(8000)) / 100 - 40 if country_code != 'LOCAL' else None),
                        "lon": lon if lon is not None else (float(secrets.randbelow(8000)) / 100 - 40 if country_code != 'LOCAL' else None),
                        "status": status_text,
                        "is_malware": is_malware,
                        "is_community_flagged": is_community_flagged,
                        "community_reports": community_detail['reports'] if is_community_flagged else 0,
                        "in_kbps": bandwidth_stats.get(conn['pid'], {}).get('in_kbps', 0),
                        "out_kbps": bandwidth_stats.get(conn['pid'], {}).get('out_kbps', 0),
                        "anomalies": ai_results['anomalies'],
                        "ai_score": ai_results['score'],
                        "ai_level": ai_results['level'],
                        "ai_msg": ai_results['message'],
                        "is_shielded": remote_ip in blocked_ips,
                        "vt_malicious": vt_malicious,
                        "vt_total": vt_total
                    })

                    # 6. Auto-Shielding + Guardian + Forensics
                    if remote_ip not in blocked_ips:
                        risk_score = 0
                        if is_community_flagged and community_detail['reports'] >= 3: risk_score += 10
                        if vt_malicious > 5: risk_score += 10
                        if is_malware: risk_score += 10
                        
                        # Apply AI-based risk additions
                        if ai_results['level'] == 'CRITICAL': risk_score += 15
                        if ai_results['level'] == 'SUSPICIOUS': risk_score += 5
                        
                        if risk_score >= 10:
                            print(f"[SHIELD] Sentinel AI Trigger: Blocking {remote_ip} (Score: {risk_score})")
                            self.shield.block_ip(remote_ip)
                            blocked_ips.append(remote_ip)
                            self.guardian.alert_blocked(remote_ip, reason=f"Sentinel AI Detection: {ai_results['message']}")
                            self.forensics.log(
                                event_type="BLOCKED",
                                ip=remote_ip,
                                process=conn.get('name', 'Unknown'),
                                location=location,
                                detail=f"Risk Score: {risk_score}",
                                severity="high"
                            )
                            
                            # --- Autonomous Geofencing / Mass Block ---
                            # If the threat is severe (Score >= 20) or from a blocked country, isolate the entire range
                            if risk_score >= 20 or (country_code in blocked_countries and risk_score >= 10):
                                print(f"[SENTINEL] TRIGGERING MASS BLOCK FOR: {remote_ip} ({country_code})")
                                self.asn_blocker.mass_block_asn(remote_ip)
                                self.forensics.log(
                                    event_type="BLOCKED",
                                    ip=remote_ip,
                                    process=conn.get('name', 'Unknown'),
                                    location=location,
                                    detail=f"Automated Geofencing: ASN Isolated",
                                    severity="critical"
                                )

                    # 6. Guardian + Forensics Threat Logging
                    if is_malware:
                        self.guardian.alert_threat(remote_ip, conn.get('name', 'Unknown'))
                        self.forensics.log(
                            event_type="THREAT",
                            ip=remote_ip,
                            process=conn.get('name', 'Unknown'),
                            location=location,
                            detail=f"VT:{vt_malicious}/{vt_total}" if vt_malicious >= 0 else "Threat Intel Match",
                            severity="critical"
                        )

                    # 7. Community Flag Logging
                    if is_community_flagged and community_detail['reports'] >= 3:
                        self.forensics.log(
                            event_type="COMMUNITY_FLAG",
                            ip=remote_ip,
                            process=conn.get('name', 'Unknown'),
                            location=location,
                            detail=f"{community_detail['reports']} community reports",
                            severity="medium"
                        )

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

        @self.app.route('/api/shield', methods=['GET', 'POST', 'DELETE'])
        def manage_shield():
            """API Endpoint for manual firewall shield management."""
            try:
                # Sensitive actions (POST/DELETE) require auth
                if request.method in ['POST', 'DELETE']:
                    token = request.headers.get('X-Kharma-Token') or request.args.get('token')
                    if not token or token != self.secret_token:
                        return jsonify({"status": "error", "message": "Unauthorized action."}), 403

                if request.method == 'GET':
                    blocked = self.shield.list_blocked()
                    return jsonify({"status": "success", "data": blocked}), 200
                
                data = request.get_json()
                ip = data.get('ip')
                if not ip: return jsonify({"status": "error", "message": "No IP specified"}), 400

                if request.method == 'POST':
                    success = self.shield.block_ip(ip)
                    message = f"IP {ip} is now SHIELDED." if success else "Failed to block IP. Check admin rights."
                    return jsonify({"status": "success" if success else "error", "message": message}), 200 if success else 500
                
                if request.method == 'DELETE':
                    success = self.shield.unblock_ip(ip)
                    message = f"IP {ip} has been UNBLOCK." if success else "Failed to unblock IP."
                    return jsonify({"status": "success" if success else "error", "message": message}), 200 if success else 500

            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

        @self.app.route('/api/packets', methods=['GET'])
        def get_packets():
            """API Endpoint for the Live Packet Telemetry stream."""
            try:
                packets = self.dpi.get_packets()
                return jsonify({"status": "success", "data": packets}), 200
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

        @self.app.route('/api/settings', methods=['GET', 'POST'])
        def manage_settings():
            """API Endpoint to get/update Guardian Bot configuration."""
            try:
                if request.method == 'GET':
                    config = self.guardian.get_config()
                    return jsonify({"status": "success", "data": config}), 200
                
                data = request.get_json()
                self.guardian.save_config(data)
                return jsonify({"status": "success", "message": "Settings saved. Guardian Bot activated."}), 200
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

        @self.app.route('/api/settings/test', methods=['POST'])
        def test_guardian():
            """Sends a test alert to verify Guardian Bot connectivity."""
            try:
                sent_to = self.guardian.send_test_alert()
                if sent_to:
                    return jsonify({"status": "success", "message": f"✅ Test alert sent to: {', '.join(sent_to)}"}), 200
                else:
                    return jsonify({"status": "error", "message": "No channels configured. Save your settings first."}), 400
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

        @self.app.route('/api/history', methods=['GET', 'DELETE'])
        def manage_history():
            """API Endpoint to retrieve or clear security event history."""
            try:
                if request.method == 'GET':
                    event_type = request.args.get('type', None)
                    events = self.forensics.get_events(limit=200, event_type=event_type)
                    stats = self.forensics.get_stats()
                    return jsonify({"status": "success", "data": events, "stats": stats}), 200
                if request.method == 'DELETE':
                    self.forensics.clear()
                    return jsonify({"status": "success", "message": "History cleared."}), 200
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

        @self.app.route('/api/hunt/<int:pid>', methods=['GET'])
        @self._require_auth
        def hunt_process(pid):
            """Forensic Endpoint: Deep analysis of a specific process."""
            result = self.hunter.get_process_details(pid)
            if result['status'] == 'success':
                return jsonify(result), 200
            else:
                return jsonify(result), 404

        @self.app.route('/api/swarm', methods=['GET', 'POST', 'DELETE'])
        @self._require_auth
        def manage_swarm():
            """Node Management API for Multi-Node Hive."""
            try:
                if request.method == 'GET':
                    self.swarm.sync_all() # Fresh sync for UI
                    return jsonify({"status": "success", "data": self.swarm.get_hive_summary()}), 200
                
                if request.method == 'POST':
                    data = request.get_json()
                    self.swarm.add_node(data.get('url'), data.get('token'), data.get('name'))
                    return jsonify({"status": "success", "message": "Node joined the hive."}), 200
                
                if request.method == 'DELETE':
                    url = request.args.get('url')
                    self.swarm.remove_node(url)
                    return jsonify({"status": "success", "message": "Node removed from hive."}), 200
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

        @self.app.route('/api/history/export', methods=['GET'])
        def export_history():
            """Exports the full history as CSV or JSON."""
            from flask import Response
            fmt = request.args.get('format', 'json')
            try:
                if fmt == 'csv':
                    data = self.forensics.export_csv()
                    return Response(data, mimetype='text/csv',
                                    headers={"Content-Disposition": "attachment;filename=kharma_history.csv"})
                else:
                    data = self.forensics.export_json()
                    return Response(data, mimetype='application/json',
                                    headers={"Content-Disposition": "attachment;filename=kharma_history.json"})
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

            return jsonify({"status": "success", "message": f"✅ Added {len(demo_events)} demo events to history."}), 200

        @self.app.route('/api/report/export', methods=['GET'])
        def export_security_report():
            """Generates and serves a premium security report."""
            from flask import Response
            try:
                html_content = self.report_gen.generate_html_report()
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                return Response(
                    html_content,
                    mimetype='text/html',
                    headers={"Content-Disposition": f"attachment;filename=sentinel_report_{timestamp}.html"}
                )
            except Exception as e:
                return jsonify({"status": "error", "message": str(e)}), 500

    def start(self):
        """Start the Flask internal server. This is a blocking call."""
        # Disable Flask startup banner for stealth
        import logging
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
        
        self.socketio.run(self.app, host=self.host, port=self.port, debug=False)

if __name__ == '__main__':
    import platform, sys, os
    if platform.system() == "Windows":
        import ctypes
        if ctypes.windll.shell32.IsUserAnAdmin() == 0:
            script = os.path.abspath(sys.argv[0])
            params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
            if getattr(sys, 'frozen', False):
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
            else:
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
            sys.exit(0)

    # Auto-open browser in 1 second
    import threading, webbrowser, time
    def open_browser():
        time.sleep(1.5)
        webbrowser.open("http://127.0.0.1:8085")
    
    threading.Thread(target=open_browser, daemon=True).start()

    server = KharmaWebServer()
    server.start()
