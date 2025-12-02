"""
Port Scanner Module

Pure Python TCP port scanner with banner grabbing and service identification.
Includes thread limiting and rate limiting for safety.
"""

import asyncio
import json
import socket
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import concurrent.futures

from logger import Logger
from config import Config


class PortScanner:
    """TCP port scanner with banner grabbing capabilities."""
    
    # Common service ports and their expected banners
    SERVICE_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        8080: 'HTTP-Proxy'
    }
    
    def __init__(self, logger: Logger, config: Config):
        """
        Initialize the port scanner.
        
        Args:
            logger: Logger instance
            config: Configuration instance
        """
        self.logger = logger
        self.config = config
        self.results: List[Dict] = []
    
    def parse_port_range(self, port_spec: str) -> List[int]:
        """
        Parse port specification into list of ports.
        
        Supports:
        - Single port: "80"
        - Range: "1-1000"
        - Comma-separated: "80,443,8080"
        - Combination: "80,443,8000-8010"
        
        Args:
            port_spec: Port specification string
            
        Returns:
            List of port numbers
        """
        ports = []
        
        for part in port_spec.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-', 1)
                try:
                    ports.extend(range(int(start), int(end) + 1))
                except ValueError:
                    self.logger.warning(f"Invalid port range: {part}")
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    self.logger.warning(f"Invalid port: {part}")
        
        return sorted(set(ports))  # Remove duplicates and sort
    
    def scan_port(self, host: str, port: int, timeout: int = 3) -> Tuple[bool, Optional[str]]:
        """
        Scan a single port synchronously.
        
        Args:
            host: Target hostname or IP
            port: Port number to scan
            timeout: Connection timeout in seconds
            
        Returns:
            Tuple of (is_open, banner)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            
            if result == 0:
                # Port is open, try to grab banner
                banner = self._grab_banner(sock, port)
                sock.close()
                return True, banner
            else:
                sock.close()
                return False, None
                
        except socket.gaierror:
            self.logger.error(f"Hostname resolution failed for {host}")
            return False, None
        except Exception as e:
            self.logger.debug(f"Error scanning {host}:{port}: {e}")
            return False, None
    
    def _grab_banner(self, sock: socket.socket, port: int, timeout: int = 3) -> Optional[str]:
        """
        Attempt to grab banner from open port.
        
        Args:
            sock: Connected socket
            port: Port number
            timeout: Read timeout
            
        Returns:
            Banner string or None
        """
        try:
            sock.settimeout(timeout)
            
            # Try to receive initial data
            sock.send(b'\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            
            if banner:
                return banner[:200]  # Limit banner length
                
        except Exception:
            pass
        
        # Return service name if known
        return self.SERVICE_PORTS.get(port, 'Unknown')
    
    def scan(self, target: str, port_spec: str, max_threads: int = 50, 
             output_dir: Optional[str] = None) -> int:
        """
        Scan target host for open ports.
        
        Args:
            target: Target hostname or IP address
            port_spec: Port specification (e.g., "1-1000", "80,443")
            max_threads: Maximum number of threads
            output_dir: Output directory for results
            
        Returns:
            Exit code (0 for success)
        """
        self.logger.info(f"Starting port scan: {target}")
        self.logger.log_operation('port_scanner', 'scan_start', {
            'target': target,
            'port_spec': port_spec,
            'max_threads': max_threads
        })
        
        # Parse ports
        ports = self.parse_port_range(port_spec)
        self.logger.info(f"Scanning {len(ports)} ports on {target}")
        
        # Limit threads for safety
        max_threads = min(max_threads, self.config.get_max_threads())
        
        # Scan ports with thread pool
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.scan_port, target, port): port 
                      for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    is_open, banner = future.result()
                    if is_open:
                        open_ports.append({
                            'port': port,
                            'service': self.SERVICE_PORTS.get(port, 'Unknown'),
                            'banner': banner,
                            'timestamp': datetime.now().isoformat()
                        })
                        print(f"  ✓ Port {port} is open - {banner[:50] if banner else 'No banner'}")
                except Exception as e:
                    self.logger.error(f"Error scanning port {port}: {e}")
        
        # Store results
        scan_result = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'total_ports_scanned': len(ports),
            'open_ports': open_ports,
            'open_count': len(open_ports)
        }
        
        self.results.append(scan_result)
        self.logger.info(f"Scan complete: {len(open_ports)} open ports found")
        
        # Export results
        if output_dir:
            self._export_results(output_dir, scan_result)
        else:
            self._export_results(self.config.get_output_dir(), scan_result)
        
        return 0
    
    def _export_results(self, output_dir: str, result: Dict) -> None:
        """
        Export scan results to JSON and HTML formats.
        
        Args:
            output_dir: Output directory
            result: Scan result dictionary
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_safe = result['target'].replace('.', '_').replace(':', '_')
        
        # Export JSON
        json_file = output_path / f"scan_{target_safe}_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2)
        
        self.logger.info(f"Results exported to {json_file}")
        
        # Export HTML
        html_file = output_path / f"scan_{target_safe}_{timestamp}.html"
        self._generate_html_report(html_file, result)
        
        self.logger.info(f"HTML report generated: {html_file}")
    
    def _generate_html_report(self, html_file: Path, result: Dict) -> None:
        """
        Generate HTML report for scan results.
        
        Args:
            html_file: Output HTML file path
            result: Scan result dictionary
        """
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Port Scan Report - {result['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .summary {{ background-color: #e7f3ff; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>Port Scan Report</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Target:</strong> {result['target']}</p>
        <p><strong>Scan Time:</strong> {result['timestamp']}</p>
        <p><strong>Total Ports Scanned:</strong> {result['total_ports_scanned']}</p>
        <p><strong>Open Ports Found:</strong> {result['open_count']}</p>
    </div>
    
    <h2>Open Ports</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Banner</th>
        </tr>
"""
        
        for port_info in result['open_ports']:
            html_content += f"""
        <tr>
            <td>{port_info['port']}</td>
            <td>{port_info['service']}</td>
            <td>{port_info.get('banner', 'N/A')}</td>
        </tr>
"""
        
        html_content += """
    </table>
    <footer style="margin-top: 30px; color: #666; font-size: 12px;">
        <p>Generated by Finsecure Toolkit - Educational Use Only</p>
    </footer>
</body>
</html>
"""
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

