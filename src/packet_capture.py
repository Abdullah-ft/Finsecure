"""
Packet Capture Module

Local network traffic capture and analysis using scapy.
Captures local lab traffic only with safety limits.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import sys

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  WARNING: scapy not available. Install with: pip install scapy")

from logger import Logger
from config import Config


class PacketCapture:
    """Packet capture and analysis tool."""
    
    def __init__(self, logger: Logger, config: Config):
        """
        Initialize the packet capture tool.
        
        Args:
            logger: Logger instance
            config: Configuration instance
        """
        self.logger = logger
        self.config = config
        self.packets: List[Dict] = []
        
        if not SCAPY_AVAILABLE:
            self.logger.warning("scapy not available - packet capture disabled")
    
    def capture(self, interface: Optional[str] = None, count: int = 100,
               filter_expr: Optional[str] = None, output_dir: Optional[str] = None) -> int:
        """
        Capture network packets.
        
        Args:
            interface: Network interface name (None for default)
            count: Number of packets to capture
            filter_expr: BPF filter expression
            output_dir: Output directory for results
            
        Returns:
            Exit code (0 for success)
        """
        if not SCAPY_AVAILABLE:
            print("❌ ERROR: scapy is required for packet capture")
            print("   Install with: pip install scapy")
            return 1
        
        # Safety limit on packet count
        max_count = self.config.get('packet_count_limit', 1000)
        count = min(count, max_count)
        
        print("\n" + "="*60)
        print("⚠️  PACKET CAPTURE MODULE - LOCAL TRAFFIC ONLY")
        print("="*60)
        print(f"Interface: {interface or 'Default'}")
        print(f"Packets: {count}")
        print(f"Filter: {filter_expr or 'None'}")
        print("="*60 + "\n")
        
        self.logger.warning(f"Packet capture initiated: {count} packets")
        self.logger.log_operation('packet_capture', 'capture_start', {
            'interface': interface,
            'count': count,
            'filter': filter_expr
        })
        
        try:
            print(f"📡 Capturing {count} packets... (Press Ctrl+C to stop early)")
            
            # Capture packets
            packets = sniff(
                iface=interface,
                count=count,
                filter=filter_expr,
                prn=self._process_packet,
                stop_filter=lambda x: len(self.packets) >= count
            )
            
            print(f"\n✅ Captured {len(self.packets)} packets")
            
            # Generate summary
            summary = self._generate_summary()
            
            # Display summary
            print(f"\n📊 Packet Capture Summary:")
            print(f"   Total Packets: {summary['total_packets']}")
            print(f"   TCP: {summary['tcp_count']}")
            print(f"   UDP: {summary['udp_count']}")
            print(f"   ICMP: {summary['icmp_count']}")
            print(f"   Other: {summary['other_count']}")
            print(f"   Unique Source IPs: {summary['unique_src_ips']}")
            print(f"   Unique Dest IPs: {summary['unique_dest_ips']}")
            
            # Export results
            if output_dir:
                self._export_results(output_dir, summary)
            else:
                self._export_results(self.config.get_output_dir(), summary)
            
            return 0
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Capture interrupted by user")
            self.logger.warning("Packet capture interrupted")
            return 130
        except Exception as e:
            print(f"❌ ERROR: Packet capture failed: {str(e)}")
            self.logger.error(f"Packet capture failed: {str(e)}", exc_info=True)
            return 1
    
    def _process_packet(self, packet) -> None:
        """
        Process a captured packet and extract information.
        
        Args:
            packet: Scapy packet object
        """
        try:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'protocol': 'Unknown',
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'length': len(packet),
                'summary': packet.summary()
            }
            
            # Extract IP layer
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_info['src_ip'] = ip_layer.src
                packet_info['dst_ip'] = ip_layer.dst
                packet_info['protocol'] = 'IP'
            
            # Extract TCP layer
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = tcp_layer.sport
                packet_info['dst_port'] = tcp_layer.dport
                packet_info['flags'] = str(tcp_layer.flags)
            
            # Extract UDP layer
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = udp_layer.sport
                packet_info['dst_port'] = udp_layer.dport
            
            # Extract ICMP layer
            elif packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
            
            self.packets.append(packet_info)
            
            # Print packet info
            if packet_info['protocol'] in ['TCP', 'UDP']:
                print(f"  {packet_info['protocol']}: {packet_info['src_ip']}:{packet_info['src_port']} -> "
                      f"{packet_info['dst_ip']}:{packet_info['dst_port']}")
            
        except Exception as e:
            self.logger.debug(f"Error processing packet: {e}")
    
    def _generate_summary(self) -> Dict:
        """
        Generate summary statistics from captured packets.
        
        Returns:
            Summary dictionary
        """
        if not self.packets:
            return {
                'timestamp': datetime.now().isoformat(),
                'total_packets': 0,
                'tcp_count': 0,
                'udp_count': 0,
                'icmp_count': 0,
                'other_count': 0,
                'unique_src_ips': 0,
                'unique_dest_ips': 0
            }
        
        protocols = {}
        src_ips = set()
        dest_ips = set()
        
        for packet in self.packets:
            protocol = packet.get('protocol', 'Unknown')
            protocols[protocol] = protocols.get(protocol, 0) + 1
            
            if packet.get('src_ip'):
                src_ips.add(packet['src_ip'])
            if packet.get('dst_ip'):
                dest_ips.add(packet['dst_ip'])
        
        summary = {
            'timestamp': datetime.now().isoformat(),
            'total_packets': len(self.packets),
            'tcp_count': protocols.get('TCP', 0),
            'udp_count': protocols.get('UDP', 0),
            'icmp_count': protocols.get('ICMP', 0),
            'other_count': sum(v for k, v in protocols.items() if k not in ['TCP', 'UDP', 'ICMP']),
            'unique_src_ips': len(src_ips),
            'unique_dest_ips': len(dest_ips),
            'src_ips': list(src_ips),
            'dest_ips': list(dest_ips),
            'packets': self.packets
        }
        
        return summary
    
    def _export_results(self, output_dir: str, summary: Dict) -> None:
        """
        Export capture results to JSON and save as .pcap summary.
        
        Args:
            output_dir: Output directory
            summary: Capture summary dictionary
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Export JSON
        json_file = output_path / f"pcap_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)
        
        self.logger.info(f"Results exported to {json_file}")
        
        # Generate human-readable summary
        summary_file = output_path / f"pcap_{timestamp}_summary.txt"
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("Packet Capture Summary\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Timestamp: {summary['timestamp']}\n")
            f.write(f"Total Packets: {summary['total_packets']}\n\n")
            f.write("Protocol Distribution:\n")
            f.write(f"  TCP: {summary['tcp_count']}\n")
            f.write(f"  UDP: {summary['udp_count']}\n")
            f.write(f"  ICMP: {summary['icmp_count']}\n")
            f.write(f"  Other: {summary['other_count']}\n\n")
            f.write(f"Unique Source IPs: {summary['unique_src_ips']}\n")
            f.write(f"Unique Destination IPs: {summary['unique_dest_ips']}\n\n")
            f.write("Source IPs:\n")
            for ip in summary.get('src_ips', [])[:20]:  # First 20
                f.write(f"  - {ip}\n")
            if len(summary.get('src_ips', [])) > 20:
                f.write(f"  ... and {len(summary['src_ips']) - 20} more\n")
            f.write("\nDestination IPs:\n")
            for ip in summary.get('dest_ips', [])[:20]:  # First 20
                f.write(f"  - {ip}\n")
            if len(summary.get('dest_ips', [])) > 20:
                f.write(f"  ... and {len(summary['dest_ips']) - 20} more\n")
        
        self.logger.info(f"Summary exported to {summary_file}")

