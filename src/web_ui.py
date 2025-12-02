"""
Web UI for Finsecure Toolkit

Flask-based web interface for the cybersecurity toolkit.
Provides a user-friendly GUI for all toolkit modules.
"""

import os
import sys
import json
import threading
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, session, redirect, url_for
from werkzeug.utils import secure_filename

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from identity_checker import IdentityChecker
from logger import Logger
from config import Config
from port_scanner import PortScanner
from password_tester import PasswordTester
from stress_tester import StressTester
from web_discovery import WebDiscovery
from packet_capture import PacketCapture
from report_generator import ReportGenerator

# Get project root directory (parent of src/)
project_root = Path(__file__).parent.parent

app = Flask(__name__, 
            template_folder=str(project_root / 'templates'),
            static_folder=str(project_root / 'static'))
app.secret_key = os.urandom(24)  # For session management
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize core components
config = Config()
logger = Logger(config.get_log_dir())
identity_checker = IdentityChecker()

# Ensure upload directory exists
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)


@app.route('/')
def index():
    """Default route - redirect to primary module after login."""
    if 'user' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('port_scanner_page'))


def _get_identity_context():
    """Shared helper for identity/consent context."""
    identity_valid = identity_checker.verify_identity()
    consent_valid = identity_checker.verify_consent() if identity_valid else False

    team_info = {}
    if identity_valid:
        try:
            team_info = identity_checker.get_team_info()
        except Exception:
            team_info = {}

    return {
        'identity_valid': identity_valid,
        'consent_valid': consent_valid,
        'team_info': team_info,
    }


def _get_member_credentials():
    """
    Extract member credentials (full name + registration number) from identity.txt.
    
    Returns:
        List of dicts: [{'name': 'Full Name', 'reg': 'REG123'}, ...]
    """
    members_list = []
    if not identity_checker.verify_identity():
        return members_list

    try:
        team_info = identity_checker.get_team_info()
    except Exception:
        return members_list

    for member in team_info.get('members', []):
        if '(' in member and ')' in member:
            name = member[:member.index('(')].strip()
            reg = member[member.index('(') + 1:member.index(')')].strip()
            if name and reg:
                members_list.append({'name': name, 'reg': reg})
    return members_list


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login/authentication page using identity.txt credentials."""
    identity_valid = identity_checker.verify_identity()
    error = None

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not identity_valid:
            error = "identity.txt is missing or invalid. Please fix it before logging in."
        else:
            matched_user = None
            for m in _get_member_credentials():
                if m['name'].lower() == username.lower() and m['reg'] == password:
                    matched_user = m
                    break

            if matched_user:
                session['user'] = {
                    'name': matched_user['name'],
                    'reg': matched_user['reg']
                }
                return redirect(url_for('index'))
            else:
                error = "Invalid username or password."

    return render_template(
        'login.html',
        identity_valid=identity_valid,
        error=error
    )


@app.route('/logout')
def logout():
    """Log out the current user."""
    session.pop('user', None)
    return redirect(url_for('login'))


def _require_login():
    """Simple helper to enforce authentication in page routes."""
    return 'user' in session


@app.route('/port-scanner')
def port_scanner_page():
    if not _require_login():
        return redirect(url_for('login'))
    ctx = _get_identity_context()
    return render_template('port_scanner.html', **ctx)


@app.route('/password-assessment')
def password_assessment_page():
    if not _require_login():
        return redirect(url_for('login'))
    ctx = _get_identity_context()
    return render_template('password_assessment.html', **ctx)


@app.route('/load-testing')
def load_testing_page():
    if not _require_login():
        return redirect(url_for('login'))
    ctx = _get_identity_context()
    return render_template('load_testing.html', **ctx)


@app.route('/web-discovery')
def web_discovery_page():
    if not _require_login():
        return redirect(url_for('login'))
    ctx = _get_identity_context()
    return render_template('web_discovery.html', **ctx)


@app.route('/packet-capture')
def packet_capture_page():
    if not _require_login():
        return redirect(url_for('login'))
    ctx = _get_identity_context()
    return render_template('packet_capture.html', **ctx)


@app.route('/report-generator')
def report_generator_page():
    if not _require_login():
        return redirect(url_for('login'))
    ctx = _get_identity_context()
    return render_template('report_generator.html', **ctx)


@app.route('/api/verify-identity', methods=['POST'])
def api_verify_identity():
    """API endpoint to verify identity."""
    try:
        if 'user' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        if identity_checker.verify_identity() and identity_checker.verify_consent():
            team_info = identity_checker.get_team_info()
            return jsonify({
                'success': True,
                'team_info': team_info
            })
        return jsonify({'success': False, 'message': 'Identity or consent validation failed'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for port scanning."""
    try:
        data = request.json

        if 'user' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        target = data.get('target')
        ports = data.get('ports', '1-1000')
        threads = int(data.get('threads', 50))
        
        if not target:
            return jsonify({'success': False, 'message': 'Target is required'}), 400
        
        # Verify identity and consent
        if not identity_checker.verify_identity() or not identity_checker.verify_consent():
            return jsonify({'success': False, 'message': 'Identity or consent validation failed'}), 403
        
        # Check if target is approved
        if not identity_checker.is_target_approved(target):
            return jsonify({'success': False, 'message': f'Target {target} is not in approved list'}), 403
        
        # Run scan in background thread
        def run_scan():
            scanner = PortScanner(logger, config)
            scanner.scan(target, ports, threads, str(config.get_output_dir()))
        
        thread = threading.Thread(target=run_scan)
        thread.daemon = True
        thread.start()
        
        return jsonify({'success': True, 'message': 'Scan started'})
    except Exception as e:
        logger.error(f"Scan API error: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/password-test', methods=['POST'])
def api_password_test():
    """API endpoint for password testing."""
    try:
        if 'user' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        # Verify identity
        if not identity_checker.verify_identity():
            return jsonify({'success': False, 'message': 'Identity validation failed'}), 403
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = Path(app.config['UPLOAD_FOLDER']) / filename
        file.save(str(filepath))
        
        # Run password test
        def run_test():
            tester = PasswordTester(logger, config)
            tester.test_passwords(str(filepath), simulate=True, 
                                output_dir=str(config.get_output_dir()))
        
        thread = threading.Thread(target=run_test)
        thread.daemon = True
        thread.start()
        
        return jsonify({'success': True, 'message': 'Password test started'})
    except Exception as e:
        logger.error(f"Password test API error: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/stress-test', methods=['POST'])
def api_stress_test():
    """API endpoint for stress testing."""
    try:
        data = request.json

        if 'user' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        target = data.get('target')
        clients = int(data.get('clients', 50))
        duration = int(data.get('duration', 60))
        
        if not target:
            return jsonify({'success': False, 'message': 'Target is required'}), 400
        
        # Verify identity and consent
        if not identity_checker.verify_identity() or not identity_checker.verify_consent():
            return jsonify({'success': False, 'message': 'Identity or consent validation failed'}), 403
        
        # Check if target is approved
        if not identity_checker.is_target_approved(target):
            return jsonify({'success': False, 'message': f'Target {target} is not in approved list'}), 403
        
        # Run stress test
        def run_test():
            tester = StressTester(logger, config)
            tester.run_stress_test(target, clients, duration, 
                                  str(config.get_output_dir()))
        
        thread = threading.Thread(target=run_test)
        thread.daemon = True
        thread.start()
        
        return jsonify({'success': True, 'message': 'Stress test started'})
    except Exception as e:
        logger.error(f"Stress test API error: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/footprint', methods=['POST'])
def api_footprint():
    """API endpoint for web discovery."""
    try:
        data = request.json

        if 'user' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        target = data.get('target')
        threads = int(data.get('threads', 10))
        
        if not target:
            return jsonify({'success': False, 'message': 'Target is required'}), 400
        
        # Verify identity and consent
        if not identity_checker.verify_identity() or not identity_checker.verify_consent():
            return jsonify({'success': False, 'message': 'Identity or consent validation failed'}), 403
        
        # Check if target is approved
        if not identity_checker.is_target_approved(target):
            return jsonify({'success': False, 'message': f'Target {target} is not in approved list'}), 403
        
        # Run discovery
        def run_discovery():
            discovery = WebDiscovery(logger, config)
            discovery.discover(target, None, threads, str(config.get_output_dir()))
        
        thread = threading.Thread(target=run_discovery)
        thread.daemon = True
        thread.start()
        
        return jsonify({'success': True, 'message': 'Web discovery started'})
    except Exception as e:
        logger.error(f"Footprint API error: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/pcap', methods=['POST'])
def api_pcap():
    """API endpoint for packet capture."""
    try:
        data = request.json

        if 'user' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        interface = data.get('interface')
        count = int(data.get('count', 100))
        filter_expr = data.get('filter')
        
        # Verify identity
        if not identity_checker.verify_identity():
            return jsonify({'success': False, 'message': 'Identity validation failed'}), 403
        
        # Run packet capture
        def run_capture():
            capture = PacketCapture(logger, config)
            capture.capture(interface, count, filter_expr, str(config.get_output_dir()))
        
        thread = threading.Thread(target=run_capture)
        thread.daemon = True
        thread.start()
        
        return jsonify({'success': True, 'message': 'Packet capture started'})
    except Exception as e:
        logger.error(f"Packet capture API error: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/generate-report', methods=['POST'])
def api_generate_report():
    """API endpoint for report generation."""
    try:
        data = request.json

        if 'user' not in session:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401

        input_dir = data.get('input_dir', str(config.get_output_dir()))
        format_type = data.get('format', 'both')
        
        # Verify identity
        if not identity_checker.verify_identity():
            return jsonify({'success': False, 'message': 'Identity validation failed'}), 403
        
        # Generate report
        generator = ReportGenerator(logger, config, identity_checker)
        result = generator.generate_report(input_dir, None, format_type)
        
        if result == 0:
            return jsonify({'success': True, 'message': 'Report generated successfully'})
        else:
            return jsonify({'success': False, 'message': 'Report generation failed'}), 500
    except Exception as e:
        logger.error(f"Report generation API error: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/results', methods=['GET'])
def api_get_results():
    """API endpoint to get scan results."""
    try:
        output_dir = Path(config.get_output_dir())
        results = []
        
        if output_dir.exists():
            for json_file in output_dir.glob('*.json'):
                try:
                    # Check file size first to avoid loading huge files
                    file_size = json_file.stat().st_size
                    if file_size > 10 * 1024 * 1024:  # Skip files larger than 10MB
                        logger.warning(f"Skipping large file: {json_file.name} ({file_size} bytes)")
                        results.append({
                            'filename': json_file.name,
                            'timestamp': '',
                            'type': _detect_result_type(json_file.name),
                            'data': {'error': 'File too large to load', 'size': file_size},
                            'size': file_size
                        })
                        continue
                    
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # Truncate large data structures
                    truncated_data = _truncate_result_data(data, json_file.name)
                    
                    results.append({
                        'filename': json_file.name,
                        'timestamp': data.get('timestamp', ''),
                        'type': _detect_result_type(json_file.name),
                        'data': truncated_data,
                        'size': file_size
                    })
                except json.JSONDecodeError as e:
                    logger.error(f"JSON decode error for {json_file.name}: {e}")
                    results.append({
                        'filename': json_file.name,
                        'timestamp': '',
                        'type': _detect_result_type(json_file.name),
                        'data': {'error': 'Invalid JSON file'},
                        'size': 0
                    })
                except Exception as e:
                    logger.error(f"Error loading {json_file.name}: {e}")
                    pass
        
        return jsonify({'success': True, 'results': results})
    except Exception as e:
        logger.error(f"Results API error: {e}", exc_info=True)
        return jsonify({'success': False, 'message': str(e)}), 500


def _truncate_result_data(data, filename):
    """Truncate large data structures to prevent browser crashes."""
    # Create a copy to avoid modifying original
    result = {}
    
    # For stress tests with large metrics arrays
    if 'metrics' in data and isinstance(data['metrics'], list):
        if len(data['metrics']) > 1000:
            result['metrics'] = data['metrics'][:1000]  # Keep first 1000
            result['metrics_truncated'] = True
            result['total_metrics'] = len(data['metrics'])
        else:
            result['metrics'] = data['metrics']
    
    # For other large arrays
    if 'packets' in data and isinstance(data['packets'], list):
        if len(data['packets']) > 500:
            result['packets'] = data['packets'][:500]
            result['packets_truncated'] = True
            result['total_packets'] = len(data['packets'])
        else:
            result['packets'] = data['packets']
    
    # Copy all other fields
    for key, value in data.items():
        if key not in ['metrics', 'packets']:
            if isinstance(value, (dict, list)):
                # Limit nested structures
                if isinstance(value, list) and len(value) > 100:
                    result[key] = value[:100]
                    result[f'{key}_truncated'] = True
                else:
                    result[key] = value
            else:
                result[key] = value
    
    return result


def _detect_result_type(filename: str) -> str:
    """Detect result type from filename."""
    filename_lower = filename.lower()
    if 'scan_' in filename_lower:
        return 'port_scan'
    elif 'auth_test' in filename_lower:
        return 'password_test'
    elif 'stress_' in filename_lower:
        return 'stress_test'
    elif 'footprint_' in filename_lower:
        return 'web_discovery'
    elif 'pcap_' in filename_lower:
        return 'packet_capture'
    return 'unknown'


@app.route('/results')
def results_page():
    """Results viewing page."""
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('results.html')


if __name__ == '__main__':
    # Verify identity before starting
    if not identity_checker.verify_identity():
        print("ERROR: identity.txt not found or invalid!")
        print("   Please create identity.txt before starting the web UI")
        sys.exit(1)
    
    if not identity_checker.verify_consent():
        print("ERROR: consent.txt not found or invalid!")
        print("   Please create consent.txt before starting the web UI")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("Finsecure Web UI Starting...")
    print("="*60)
    print("Access the UI at: http://127.0.0.1:5000")
    print("Press Ctrl+C to stop the server")
    print("="*60 + "\n")
    
    app.run(debug=True, host='127.0.0.1', port=5000)

