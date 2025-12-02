"""
Load/DoS Testing Module

Safe, controlled load testing with client limits and auto-throttling.
Maximum 200 clients enforced for safety.
"""

import asyncio
import json
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import aiohttp
import matplotlib.pyplot as plt

from logger import Logger
from config import Config


class StressTester:
    """Controlled load testing tool with safety limits."""
    
    def __init__(self, logger: Logger, config: Config):
        """
        Initialize the stress tester.
        
        Args:
            logger: Logger instance
            config: Configuration instance
        """
        self.logger = logger
        self.config = config
        self.metrics: List[Dict] = []
    
    def run_stress_test(self, target: str, num_clients: int, duration: int,
                       output_dir: Optional[str] = None) -> int:
        """
        Run controlled load test against target.
        
        Args:
            target: Target URL or IP address
            num_clients: Number of concurrent clients (max 200)
            duration: Test duration in seconds
            output_dir: Output directory for results
            
        Returns:
            Exit code (0 for success)
        """
        # Safety check: enforce maximum clients
        max_clients = self.config.get_max_clients()
        if num_clients > max_clients:
            print(f"⚠️  WARNING: Client count limited to {max_clients} for safety")
            num_clients = max_clients
        
        print("\n" + "="*60)
        print("⚠️  LOAD TESTING MODULE - AUTHORIZED USE ONLY")
        print("="*60)
        print(f"Target: {target}")
        print(f"Clients: {num_clients}")
        print(f"Duration: {duration} seconds")
        print("="*60 + "\n")
        
        self.logger.warning(f"Load test initiated: {target} with {num_clients} clients")
        self.logger.log_operation('stress_tester', 'test_start', {
            'target': target,
            'clients': num_clients,
            'duration': duration
        })
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"http://{target}"
        
        try:
            # Run async load test
            asyncio.run(self._async_load_test(target, num_clients, duration))
            
            # Generate summary
            summary = self._generate_summary(target, duration)
            
            # Display results
            print(f"\n📊 Load Test Results:")
            print(f"   Total Requests: {summary['total_requests']}")
            print(f"   Successful: {summary['successful_requests']}")
            print(f"   Failed: {summary['failed_requests']}")
            print(f"   Average Response Time: {summary['avg_response_time']:.2f}ms")
            print(f"   Min Response Time: {summary['min_response_time']:.2f}ms")
            print(f"   Max Response Time: {summary['max_response_time']:.2f}ms")
            print(f"   Requests/Second: {summary['requests_per_second']:.2f}")
            
            # Export results
            if output_dir:
                self._export_results(output_dir, summary)
            else:
                self._export_results(self.config.get_output_dir(), summary)
            
            return 0
            
        except Exception as e:
            print(f"❌ ERROR: Load test failed: {str(e)}")
            self.logger.error(f"Load test failed: {str(e)}", exc_info=True)
            return 1
    
    async def _async_load_test(self, target: str, num_clients: int, duration: int) -> None:
        """
        Run asynchronous load test.
        
        Args:
            target: Target URL
            num_clients: Number of concurrent clients
            duration: Test duration in seconds
        """
        start_time = time.time()
        end_time = start_time + duration
        
        async def make_request(session: aiohttp.ClientSession, client_id: int):
            """Make a single request and record metrics."""
            request_count = 0
            while time.time() < end_time:
                try:
                    request_start = time.time()
                    async with session.get(target, timeout=aiohttp.ClientTimeout(total=10)) as response:
                        await response.read()
                        request_time = (time.time() - request_start) * 1000  # Convert to ms
                        
                        self.metrics.append({
                            'timestamp': time.time(),
                            'client_id': client_id,
                            'status_code': response.status,
                            'response_time': request_time,
                            'success': 200 <= response.status < 400
                        })
                        request_count += 1
                        
                        # Rate limiting: small delay between requests
                        await asyncio.sleep(self.config.get_rate_limit_delay())
                        
                except asyncio.TimeoutError:
                    self.metrics.append({
                        'timestamp': time.time(),
                        'client_id': client_id,
                        'status_code': 0,
                        'response_time': 10000,  # 10 second timeout
                        'success': False
                    })
                except Exception as e:
                    self.logger.debug(f"Request error: {e}")
                    self.metrics.append({
                        'timestamp': time.time(),
                        'client_id': client_id,
                        'status_code': 0,
                        'response_time': 0,
                        'success': False
                    })
        
        # Create session with connection limits
        connector = aiohttp.TCPConnector(limit=num_clients, limit_per_host=num_clients)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Create client tasks
            tasks = [make_request(session, i) for i in range(num_clients)]
            await asyncio.gather(*tasks)
    
    def _generate_summary(self, target: str, duration: int) -> Dict:
        """
        Generate summary statistics from metrics.
        
        Args:
            target: Target URL
            duration: Test duration
            
        Returns:
            Summary dictionary
        """
        if not self.metrics:
            return {
                'target': target,
                'timestamp': datetime.now().isoformat(),
                'duration': duration,
                'total_requests': 0,
                'successful_requests': 0,
                'failed_requests': 0,
                'avg_response_time': 0,
                'min_response_time': 0,
                'max_response_time': 0,
                'requests_per_second': 0
            }
        
        successful = [m for m in self.metrics if m['success']]
        failed = [m for m in self.metrics if not m['success']]
        
        response_times = [m['response_time'] for m in successful if m['response_time'] > 0]
        
        summary = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'duration': duration,
            'total_requests': len(self.metrics),
            'successful_requests': len(successful),
            'failed_requests': len(failed),
            'avg_response_time': sum(response_times) / len(response_times) if response_times else 0,
            'min_response_time': min(response_times) if response_times else 0,
            'max_response_time': max(response_times) if response_times else 0,
            'requests_per_second': len(self.metrics) / duration if duration > 0 else 0,
            'metrics': self.metrics
        }
        
        return summary
    
    def _export_results(self, output_dir: str, summary: Dict) -> None:
        """
        Export test results to JSON and generate performance plots.
        
        Args:
            output_dir: Output directory
            summary: Test summary dictionary
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_safe = summary['target'].replace('://', '_').replace('/', '_').replace('.', '_')
        
        # Export JSON
        json_file = output_path / f"stress_{target_safe}_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        
        self.logger.info(f"Results exported to {json_file}")
        
        # Generate performance plots
        if self.metrics:
            self._generate_plots(output_path, target_safe, timestamp)
    
    def _generate_plots(self, output_path: Path, target_safe: str, timestamp: str) -> None:
        """
        Generate performance visualization plots.
        
        Args:
            output_path: Output directory path
            target_safe: Sanitized target name
            timestamp: Timestamp string
        """
        try:
            # Response time over time
            successful_metrics = [m for m in self.metrics if m['success'] and m['response_time'] > 0]
            if successful_metrics:
                timestamps = [m['timestamp'] - min(m['timestamp'] for m in successful_metrics) 
                            for m in successful_metrics]
                response_times = [m['response_time'] for m in successful_metrics]
                
                plt.figure(figsize=(12, 6))
                plt.plot(timestamps, response_times, alpha=0.6)
                plt.xlabel('Time (seconds)')
                plt.ylabel('Response Time (ms)')
                plt.title('Response Time Over Time')
                plt.grid(True, alpha=0.3)
                
                plot_file = output_path / f"stress_{target_safe}_{timestamp}_response_time.png"
                plt.savefig(plot_file, dpi=150, bbox_inches='tight')
                plt.close()
                
                self.logger.info(f"Performance plot generated: {plot_file}")
            
            # Status code distribution
            status_codes = {}
            for m in self.metrics:
                code = m['status_code']
                status_codes[code] = status_codes.get(code, 0) + 1
            
            if status_codes:
                plt.figure(figsize=(10, 6))
                codes = list(status_codes.keys())
                counts = list(status_codes.values())
                plt.bar(codes, counts)
                plt.xlabel('HTTP Status Code')
                plt.ylabel('Count')
                plt.title('Status Code Distribution')
                plt.grid(True, alpha=0.3, axis='y')
                
                plot_file = output_path / f"stress_{target_safe}_{timestamp}_status_codes.png"
                plt.savefig(plot_file, dpi=150, bbox_inches='tight')
                plt.close()
                
                self.logger.info(f"Status code plot generated: {plot_file}")
                
        except Exception as e:
            self.logger.warning(f"Failed to generate plots: {e}")

