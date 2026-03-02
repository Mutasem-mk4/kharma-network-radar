import os
import sys
import psutil
import random
import secrets
import logging
import json
import jwt
import time
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, make_response, session, redirect, url_for
from flask_compress import Compress
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
    from kharma.mitigation import QuarantineManager
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
    from mitigation import QuarantineManager

class KharmaWebServer:
    def __init__(self, host="127.0.0.1", port=8085):
        self.host = host
        self.port = port
        self._radar_cache = []
        self._radar_last_refreshed = 0
        self.secret_token = self._generate_session_token()
        
        # Determine the correct templates and static folder paths
        if getattr(sys, 'frozen', False):
            # PyInstaller context
            template_dir = os.path.join(sys._MEIPASS, 'templates')
            static_dir = os.path.join(sys._MEIPASS, 'static')
        else:
            # Standard package context
            base_dir = os.path.dirname(os.path.abspath(__file__))
            template_dir = os.path.join(base_dir, 'templates')
            static_dir = os.path.join(base_dir, 'static')
            
        self.app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
        Compress(self.app)  # Enable gzip/brotli compression for responses
        self.app.secret_key = self.secret_token # Use the same token for session signing
        
        # Security Hardening: Lockdown CORS to strict localhost
        CORS(self.app, resources={r"/api/*": {"origins": ["http://127.0.0.1:*", "http://localhost:*"]}})

        @self.app.after_request
        def add_cache_headers(response):
            # Apply long-term caching for static assets
            if request.path.startswith('/static/'):
                response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
            return response
        
        # Security Hardening: Content Security Policy (CSP) and Security Headers
        csp = {
            'default-src': '\'self\'',
            'script-src': [
                '\'self\'',
                '\'unsafe-inline\'',
                'https://cdn.tailwindcss.com',
                'https://unpkg.com',
                'https://cdn.jsdelivr.net',
                'https://cdnjs.cloudflare.com'
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
                'https://*.basemaps.cartocdn.com',
                'https://img.icons8.com',
                'https://unpkg.com'
            ]
        }
        Talisman(self.app, content_security_policy=csp, force_https=False)
        
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        
        self.start_time = time.time()
        self.rate_limits = {} # IP -> [timestamps]

        self._setup_engines()
        
        # Persistent State: Load Pro License
        self.is_pro = self.forensics.get_setting("is_pro") == "True"
        
        self._setup_routes()

    def _kill_process_and_children(self, pid):
        """Forcefully kills a process and its entire child hierarchy (Phase 18 Hardening)."""
        try:
            parent = psutil.Process(pid)
            critical_procs = {'system idle process', 'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe', 'winlogon.exe'}
            if parent.name().lower() in critical_procs:
                return False
            children = parent.children(recursive=True)
            for child in children:
                try:
                    if child.name().lower() not in critical_procs:
                        child.kill() # Force SIGKILL
                except:
                    pass
            parent.kill() # Force SIGKILL
            return True
        except psutil.NoSuchProcess:
            return False
        except Exception as e:
            print(f"[SENTINEL] Enforcement Error (PID {pid}): {e}")
            return False

    def _quarantine_process(self, pid):
        """Suspends a process (Phase 3: Proactive Mitigation) using QuarantineManager."""
        return QuarantineManager.suspend_process(pid)

    def _resume_process(self, pid):
        """Resumes a suspended process using QuarantineManager."""
        return QuarantineManager.resume_process(pid)

    def _load_settings(self):
        """Unified settings loader: Combines Guardian config and DB settings."""
        # Start with Guardian's JSON-based config
        config = self.guardian.get_config()
        
        # Overlay DB-based settings (like language)
        lang = self.forensics.get_setting("language", "EN")
        config['language'] = lang

        # Overlay Encrypted Settings (Enterprise Security)
        for key in ['telegram_bot_token', 'telegram_chat_id', 'discord_webhook_url']:
            val = self.forensics.get_encrypted_setting(key, "")
            if val:
                config[key] = val
        
        # Track First Run (Phase 8)
        config['first_run'] = self.forensics.get_setting("first_run_completed") != "True"
        
        return config

    def _generate_session_token(self):
        """Generates a random token to prevent CSRF and unauthorized API calls."""
        import secrets
        return secrets.token_hex(24)

    def _rate_limit(self, limit=5, window=60):
        """Simple in-memory rate limiter for sensitive endpoints."""
        from functools import wraps
        from flask import request, jsonify
        import time
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                ip = request.remote_addr
                now = time.time()
                if ip not in self.rate_limits:
                    self.rate_limits[ip] = []
                # Clean old requests
                self.rate_limits[ip] = [t for t in self.rate_limits[ip] if now - t < window]
                if len(self.rate_limits[ip]) >= limit:
                    return jsonify({"status": "error", "message": "Too many requests. Please wait."}), 429
                self.rate_limits[ip].append(now)
                return f(*args, **kwargs)
            return decorated_function
        return decorator

    def _require_auth(self, f):
        """Security Decorator: Ensures the request carries a valid JWT or session cookie."""
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 1. Check for Session Cookie (Web UI)
            if session.get('authenticated'):
                return f(*args, **kwargs)
                
            # 2. Check for JWT Header
            auth_header = request.headers.get('Authorization')
            token = None
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
            
            # Fallback for old clients (legacy support for migration phase)
            if not token:
                token = request.headers.get('X-Kharma-Token') or request.args.get('token')

            if not token:
                return jsonify({"status": "error", "message": "Authentication token missing."}), 401
            
            # Validate JWT
            try:
                # If it's the raw secret_token (legacy), allow it
                if token == self.secret_token:
                    return f(*args, **kwargs)
                
                # Otherwise, treat as JWT
                decoded = jwt.decode(token, self.secret_token, algorithms=["HS256"])
                return f(*args, **kwargs)
            except jwt.ExpiredSignatureError:
                return jsonify({"status": "error", "message": "Session expired. Please login again."}), 401
            except jwt.InvalidTokenError:
                return jsonify({"status": "error", "message": "Invalid security token."}), 401
            
        return decorated_function

    def _require_signature(self, f):
        """Security Decorator: Validates HMAC-SHA256 signature for Swarm requests."""
        from functools import wraps
        import hmac
        import hashlib
        import time
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('X-Kharma-Token')
            timestamp = request.headers.get('X-Kharma-Timestamp')
            signature = request.headers.get('X-Kharma-Signature')
            
            if not token or token != self.secret_token:
                return jsonify({"status": "error", "message": "Invalid Swarm Token"}), 403
            if not timestamp or not signature:
                return jsonify({"status": "error", "message": "Missing Signature Headers"}), 403
            
            # Anti-Replay: Check if timestamp is within 30 seconds
            if abs(time.time() - int(timestamp)) > 30:
                return jsonify({"status": "error", "message": "Signature Expired (Clock drift or Replay)"}), 403
            
            # Validate Signature
            endpoint = request.path
            data_str = request.get_data(as_text=True) if request.method == 'POST' else ""
            message = f"{endpoint}|{timestamp}|{data_str}".encode()
            expected = hmac.new(self.secret_token.encode(), message, hashlib.sha256).hexdigest()
            
            if not hmac.compare_digest(signature, expected):
                return jsonify({"status": "error", "message": "Invalid Cryptographic Signature"}), 403
                
            return f(*args, **kwargs)
        return decorated_function

    def _setup_engines(self):
        """Initialize all the core data gathering engines."""
        self.scanner = NetworkScanner()
        self.scanner.start_background_scan(interval=0.5) # Phase 25: Real-time background scanning
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
        
        # Guardian: Sentinel Alert Monitor
        self._start_alert_monitor()

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
                self.shield.block_ip(ip)
                emit('command_result', {'status': 'success', 'message': f'IP {ip} shielded.'})

        @self.socketio.on('remote_quarantine')
        def handle_quarantine(data):
            token = data.get('token')
            pid = data.get('pid')
            if token == self.secret_token and pid:
                if self._quarantine_process(pid):
                    emit('command_result', {'status': 'success', 'message': f'Process {pid} suspended.'})
                else:
                    emit('command_result', {'status': 'error', 'message': f'Failed to suspend {pid}.'})

        @self.socketio.on('remote_resume')
        def handle_resume(data):
            token = data.get('token')
            pid = data.get('pid')
            if token == self.secret_token and pid:
                if self._resume_process(pid):
                    emit('command_result', {'status': 'success', 'message': f'Process {pid} resumed.'})
                else:
                    emit('command_result', {'status': 'error', 'message': f'Failed to resume {pid}.'})

    def _start_alert_monitor(self):
        """Ghost v3: Spawns a background thread to bridge detections with Guardian alerts."""
        def alert_loop():
            # Keep track of last seen threat IPs and DPI packet times to avoid flooding
            # although GuardianBot has internal throttling/sets.
            last_packet_time = ""
            
            while True:
                try:
                    # 1. Monitor Network Scanner for Malicious IPs
                    active_conns = self.scanner.get_active_connections()
                    for conn in active_conns:
                        remote_ip = conn.get('remote_ip')
                        if remote_ip and self.intel.check_ip(remote_ip):
                            # Guardian handles internal throttling and set-based deduplication
                            self.guardian.alert_threat(remote_ip, conn.get('name', 'Unknown'))

                    # 2. Monitor DPI Engine for Payload Alerts
                    packets = self.dpi.get_packets()
                    if packets:
                        latest = packets[-1] # Check newest first
                        if latest.get('severity') == 'danger' and latest.get('alert'):
                            # Only alert if it's a new timestamped packet
                            p_time = latest.get('time', '')
                            if p_time != last_packet_time:
                                self.guardian.alert_dpi(
                                    latest.get('src', 'Unknown'), 
                                    latest.get('dst', 'Unknown'), 
                                    latest.get('alert', 'Suspicious Payload')
                                )
                                last_packet_time = p_time
                    
                    time.sleep(1.0) # Poll interval
                except Exception as e:
                    # Silent failure with backup logging for background thread
                    import sys
                    print(f"[SENTINEL] Alert Monitor Error: {e}", file=sys.stderr)
                    time.sleep(5)

        import threading
        thread = threading.Thread(target=alert_loop, daemon=True)
        thread.start()

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


    def _setup_routes(self):
        @self.app.route('/api/license', methods=['POST'])
        @self._require_auth
        @self._rate_limit(limit=3, window=60)
        def manage_license():
            data = request.json
            key = data.get("key", "")
            if key == "KHARMA-PRO-2026":
                self.is_pro = True
                self.forensics.set_setting("is_pro", "True")
                return jsonify({"status": "success", "message": "KHARMA PRO ACTIVATED", "is_pro": True}), 200
            return jsonify({"status": "error", "message": "INVALID LICENSE KEY"}), 403

        @self.app.route('/api/status', methods=['GET'])
        def get_status():
            # Get requester's IP for local map centering
            ip = request.remote_addr
            if ip in ('127.0.0.1', '::1'):
                # Try to get public IP if local
                try:
                    import requests
                    ip = requests.get('https://api.ipify.org', timeout=1).text
                except:
                    pass
            
            lat, lon, _ = self.geoip.resolve(ip)
            
            return jsonify({
                "status": "online",
                "is_pro": self.is_pro,
                "version": "11.0.1",
                "lat": lat,
                "lon": lon
            })

        @self.app.route('/api/health')
        def health_check():
            """Enterprise Health Monitoring."""
            import time
            return jsonify({
                "status": "success",
                "service": "Kharma Sentinel",
                "uptime": int(time.time() - self.start_time),
                "healthy": True
            })

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
        @self._rate_limit(limit=5, window=60)
        def api_login():
            """Authentication Endpoint issuing JWT."""
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            settings = self._load_settings()
            stored_password = settings.get('web_password', 'sentinel123') 
            
            if username == 'admin' and password == stored_password:
                session['authenticated'] = True
                
                # Issue JWT
                payload = {
                    'exp': datetime.utcnow() + timedelta(hours=24),
                    'iat': datetime.utcnow(),
                    'user': username,
                    'tier': 'pro' if self.is_pro else 'lite'
                }
                token = jwt.encode(payload, self.secret_token, algorithm="HS256")
                
                return jsonify({
                    "status": "success", 
                    "token": token,
                    "is_pro": self.is_pro
                }), 200
            
            return jsonify({"status": "error", "message": "Invalid credentials"}), 401

        @self.app.route('/logout')
        def logout():
            """Clear the secure session."""
            session.pop('authenticated', None)
            return redirect(url_for('login'))

        @self.app.route('/api/radar', methods=['GET'])
        def get_live_radar():
            """
            Fetches all active network connections.
            Cached for 1s to prevent overhead from high-frequency frontend polling.
            """
            # Pagination parameters (applied after data collection)
            limit = int(request.args.get('limit', 200))
            offset = int(request.args.get('offset', 0))

            now = time.time()
            if hasattr(self, '_radar_cache') and (now - self._radar_last_refreshed < 1.0):
                return jsonify({"status": "success", "data": self._radar_cache}), 200

            try:
                # Update DPI stats
                # Sync flow map for attribution
                self.dpi.update_flow_map(self.scanner.get_flow_map())
                bw_report = self.dpi.get_bandwidth_report()
                active_connections = self.scanner.get_active_connections()

                radar_data = []
                blocked_ips = self.shield.list_blocked()

                for conn in active_connections:
                    pid = conn['pid']
                    remote_ip = conn['remote_ip']

                    # 1. GeoIP Lookup (Local MMDB, very fast)
                    lat, lon, location = self.geoip.resolve(remote_ip)

                    # 2. Bandwidth stats (DPI with I/O Fallback)
                    bw = bw_report.get(pid, {"in_kbps": 0.0, "out_kbps": 0.0})

                    # Fallback to direct I/O if DPI is silent
                    if bw['in_kbps'] <= 0.0 or bw['out_kbps'] <= 0.0:
                        io = conn.get('io_counters')
                        if io:
                            io_report = self.behavior.get_io_kbps(pid, io)
                            if io_report:
                                bw['in_kbps'] = max(bw['in_kbps'], io_report['in_kbps'])
                                bw['out_kbps'] = max(bw['out_kbps'], io_report['out_kbps'])

                    # 3. Threat Intelligence (O(1) Set lookup)
                    is_malware = self.intel.check_ip(remote_ip)

                    # 4. Behavioral Analysis (Local heuristics)
                    ai_results = self.behavior.analyze(
                        conn.get('name', 'Unknown'),
                        bw['in_kbps'], bw['out_kbps'],
                        remote_ip, location.split(',')[-1].strip()
                    )

                    # 5. Community Flags
                    is_flagged = self.community.is_flagged(remote_ip)

                    # Assemble row
                    radar_data.append({
                        "process_name": conn.get('name', 'Unknown'),
                        "pid": pid,
                        "exe": conn.get('exe', ''),
                        "local_address": f"{conn.get('local_ip')}:{conn.get('local_port')}",
                        "remote_address": f"{remote_ip}:{conn.get('remote_port')}",
                        "remote_ip": remote_ip,
                        "location": location,
                        "lat": lat,
                        "lon": lon,
                        "status": conn.get('status', 'ACTIVE'),
                        "is_malware": is_malware,
                        "is_flagged": is_flagged,
                        "ai_score": ai_results['score'],
                        "ai_level": ai_results['level'],
                        "ai_msg": ai_results['message'],
                        "anomalies": ai_results['anomalies'],
                        "in_kbps": bw['in_kbps'],
                        "out_kbps": bw['out_kbps'],
                        "is_shielded": remote_ip in blocked_ips
                    })

                # Apply pagination before caching and response
                paginated = radar_data[offset:offset+limit]
                self._radar_cache = paginated
                self._radar_last_refreshed = now
                return jsonify({"status": "success", "data": paginated, "total": len(radar_data)}), 200

            except Exception as e:
                import traceback
                traceback.print_exc()
                return jsonify({"status": "error", "message": str(e)}), 500


        @self.app.route('/api/kill/<int:pid>', methods=['DELETE'])
        @self._require_auth
        def kill_process(pid):
            """API Endpoint to instantly terminate a process via the Web UI."""
            try:
                p = psutil.Process(pid)
                p_name = p.name()
                critical_procs = {'system idle process', 'system', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'svchost.exe', 'explorer.exe', 'winlogon.exe'}
                if p_name.lower() in critical_procs:
                    return jsonify({"status": "error", "message": f"Cannot kill critical OS process: {p_name}"}), 403
                p.terminate()
                p.wait(timeout=3)
                return jsonify({"status": "success", "message": f"Terminated {p_name} (PID: {pid})"}), 200
            except psutil.NoSuchProcess:
                return jsonify({"status": "error", "message": f"PID {pid} not found."}), 404
            except psutil.AccessDenied:
                return jsonify({"status": "error", "message": f"Access Denied. Run Kharma as Admin/Root to kill PID {pid}."}), 403
            except Exception as e:
                return jsonify({"status": "error", "message": f"Failed to kill process: {e}"}), 500

        @self.app.route('/api/quarantine/<int:pid>', methods=['DELETE'])
        @self._require_auth
        def quarantine_process(pid):
            """API Endpoint to suspend a process."""
            if self._quarantine_process(pid):
                return jsonify({"status": "success", "message": f"Process {pid} suspended (Quarantined)."}), 200
            return jsonify({"status": "error", "message": f"Failed to suspend PID {pid}."}), 500

        @self.app.route('/api/resume/<int:pid>', methods=['POST'])
        @self._require_auth
        def resume_process(pid):
            """API Endpoint to resume a suspended process."""
            if self._resume_process(pid):
                return jsonify({"status": "success", "message": f"Process {pid} resumed."}), 200
            return jsonify({"status": "error", "message": f"Failed to resume PID {pid}."}), 500

        @self.app.route('/api/mitigate/stats', methods=['GET'])
        def get_mitigation_stats():
            """API Endpoint to get current mitigation statistics."""
            quarantined = QuarantineManager.get_quarantined_pids()
            return jsonify({
                "status": "success",
                "quarantined_count": len(quarantined),
                "quarantined_pids": quarantined
            }), 200

        @self.app.route('/api/report', methods=['POST', 'DELETE'])
        @self._require_auth
        def report_to_community():
            """API Endpoint to report/un-report a malicious IP to the decentralized Kharma community."""
            try:
                if request.method == 'DELETE':
                    ip = request.args.get('ip')
                    if not ip: return jsonify({"status": "error", "message": "Missing IP."}), 400
                    success = self.community.unreport_ip(ip)
                    return jsonify({"status": "success" if success else "error", "message": f"IP {ip} un-reported." if success else "Failed to remove flag."}), 200 if success else 500

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
        @self._require_auth
        def manage_shield():
            """API Endpoint for manual firewall shield management."""
            try:
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
            """API Endpoint to get/update system configuration and localization."""
            try:
                if request.method == 'GET':
                    config = self._load_settings()
                    return jsonify({"status": "success", "data": config}), 200
                
                data = request.get_json()
                
                # 1. Update Credential Encryption (Sensitive)
                sensitive_keys = ['telegram_bot_token', 'telegram_chat_id', 'discord_webhook_url']
                for key in sensitive_keys:
                    if key in data:
                        self.forensics.set_encrypted_setting(key, data[key])
                        # Update live instance
                        self.guardian.config[key] = data[key]
                
                # 2. Update Guardian Bot non-sensitive config
                non_sensitive_keys = ['alert_on_threat', 'alert_on_block', 'alert_on_dpi']
                if any(k in data for k in non_sensitive_keys):
                    self.guardian.save_config(data)
                
                # 3. Update Persisted DB Settings
                if 'language' in data:
                    self.forensics.set_setting("language", data['language'])
                
                if 'first_run_completed' in data:
                    self.forensics.set_setting("first_run_completed", "True")

                return jsonify({"status": "success", "message": "Settings updated successfully."}), 200
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

        @self.app.route('/api/swarm/block', methods=['POST'])
        @self._require_signature
        def sync_block():
            """Inbound Federated Block request from another node."""
            data = request.json
            ip = data.get('ip')
            if ip:
                if self.shield.block_ip(ip):
                    from kharma.forensics import ForensicsDB
                    self.forensics.log("BLOCKED", ip, "Swarm/Federated", "Hive Broadcast", "Federated Block via Signed Request", "high")
                    return jsonify({"status": "success", "message": f"Federated block applied for {ip}"}), 200
            return jsonify({"status": "error", "message": "Invalid Request"}), 400

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
    # if platform.system() == "Windows":
    #     import ctypes
    #     if ctypes.windll.shell32.IsUserAnAdmin() == 0:
    #         script = os.path.abspath(sys.argv[0])
    #         params = ' '.join([f'"{arg}"' for arg in sys.argv[1:]])
    #         if getattr(sys, 'frozen', False):
    #             ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    #         else:
    #             ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
    #         sys.exit(0)

    # Auto-open browser in 1 second
    import threading, webbrowser, time
    def open_browser():
        time.sleep(1.5)
        webbrowser.open("http://127.0.0.1:8085")
    
    threading.Thread(target=open_browser, daemon=True).start()

    server = KharmaWebServer()
    server.start()
