#!/usr/bin/env python3
"""
Finsecure - Cybersecurity Toolkit for Educational Use
CY4053 Final Project - PayBuddy Security Assessment

AUTHORIZED EDUCATIONAL PROJECT ONLY
For testing security in controlled lab environments only.
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from identity_checker import IdentityChecker
from logger import Logger
from config import Config


def print_banner():
    """Display the toolkit banner with safety warnings."""
    banner = """
    ╔══════════════════════════════════════════════════════════════════╗
    ║                    FINSECURE TOOLKIT v1.0                        ║
    ║              CY4053 Final Project - PayBuddy Assessment          ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║  ⚠️  AUTHORIZED EDUCATIONAL USE ONLY                             ║
    ║  ⚠️  For controlled lab environments only                        ║
    ║  ⚠️  Requires identity.txt and consent.txt validation            ║
    ╚══════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    """Main entry point for the Finsecure toolkit."""
    parser = argparse.ArgumentParser(
        description="Finsecure - Cybersecurity Toolkit for Educational Use",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
⚠️  WARNING: This toolkit is for AUTHORIZED EDUCATIONAL USE ONLY.
    All operations require valid identity.txt and consent.txt files.
    Unauthorized use is strictly prohibited.
        """
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Test configuration without executing operations'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Port Scanner
    scan_parser = subparsers.add_parser('scan', help='Port scanning module')
    scan_parser.add_argument('target', help='Target host or IP address')
    scan_parser.add_argument('-p', '--ports', default='1-1000', 
                            help='Port range (e.g., 1-1000, 80,443,8080)')
    scan_parser.add_argument('-t', '--threads', type=int, default=50,
                            help='Maximum threads (default: 50)')
    scan_parser.add_argument('-o', '--output', help='Output directory')
    
    # Password Assessment
    auth_parser = subparsers.add_parser('auth_test', help='Password assessment module')
    auth_parser.add_argument('password_file', help='File containing passwords to test')
    auth_parser.add_argument('--simulate', action='store_true',
                            help='Simulation mode (offline testing only)')
    auth_parser.add_argument('-o', '--output', help='Output directory')
    
    # Load/DoS Testing
    stress_parser = subparsers.add_parser('stress', help='Load testing module')
    stress_parser.add_argument('target', help='Target URL or IP address')
    stress_parser.add_argument('-c', '--clients', type=int, default=50,
                              help='Number of concurrent clients (max: 200)')
    stress_parser.add_argument('-d', '--duration', type=int, default=60,
                              help='Test duration in seconds')
    stress_parser.add_argument('-o', '--output', help='Output directory')
    
    # Web Discovery
    footprint_parser = subparsers.add_parser('footprint', help='Web discovery module')
    footprint_parser.add_argument('target', help='Target domain or URL')
    footprint_parser.add_argument('-w', '--wordlist', help='Custom wordlist file')
    footprint_parser.add_argument('-t', '--threads', type=int, default=10,
                                 help='Number of threads (default: 10)')
    footprint_parser.add_argument('-o', '--output', help='Output directory')
    
    # Packet Capture
    pcap_parser = subparsers.add_parser('pcap', help='Packet capture module')
    pcap_parser.add_argument('-i', '--interface', help='Network interface')
    pcap_parser.add_argument('-c', '--count', type=int, default=100,
                            help='Number of packets to capture')
    pcap_parser.add_argument('-f', '--filter', help='BPF filter expression')
    pcap_parser.add_argument('-o', '--output', help='Output directory')
    
    # Report Generation
    report_parser = subparsers.add_parser('report', help='Generate consolidated report')
    report_parser.add_argument('-i', '--input', required=True,
                              help='Directory containing scan results')
    report_parser.add_argument('-o', '--output', help='Output file path')
    report_parser.add_argument('-f', '--format', choices=['docx', 'pdf', 'both'],
                              default='both', help='Report format')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Display banner
    print_banner()
    
    # Initialize configuration
    config = Config()
    
    # Initialize logger
    logger = Logger(config.get_log_dir())
    
    # CRITICAL: Verify identity and consent before ANY operation
    identity_checker = IdentityChecker()
    
    try:
        if not identity_checker.verify_identity():
            print("❌ ERROR: identity.txt validation failed!")
            logger.error("Identity verification failed")
            return 1
        
        if not identity_checker.verify_consent():
            print("❌ ERROR: consent.txt validation failed!")
            logger.error("Consent verification failed")
            return 1
        
        # Display team information
        team_info = identity_checker.get_team_info()
        print(f"\n✅ Identity verified: {team_info['team_name']}")
        print(f"   Team Members: {', '.join(team_info['members'])}")
        print(f"   Approved Targets: {', '.join(team_info['approved_targets'])}")
        print()
        
        logger.info(f"Toolkit started by {team_info['team_name']}")
        logger.info(f"Command: {args.command}")
        
        if args.dry_run:
            print("🔍 DRY-RUN MODE: Configuration check only, no operations executed")
            logger.info("Dry-run mode enabled")
            return 0
        
        # Route to appropriate module
        if args.command == 'scan':
            from port_scanner import PortScanner
            scanner = PortScanner(logger, config)
            return scanner.scan(args.target, args.ports, args.threads, args.output)
        
        elif args.command == 'auth_test':
            from password_tester import PasswordTester
            tester = PasswordTester(logger, config)
            return tester.test_passwords(args.password_file, args.simulate, args.output)
        
        elif args.command == 'stress':
            from stress_tester import StressTester
            tester = StressTester(logger, config)
            return tester.run_stress_test(args.target, args.clients, args.duration, args.output)
        
        elif args.command == 'footprint':
            from web_discovery import WebDiscovery
            discovery = WebDiscovery(logger, config)
            return discovery.discover(args.target, args.wordlist, args.threads, args.output)
        
        elif args.command == 'pcap':
            from packet_capture import PacketCapture
            capture = PacketCapture(logger, config)
            return capture.capture(args.interface, args.count, args.filter, args.output)
        
        elif args.command == 'report':
            from report_generator import ReportGenerator
            generator = ReportGenerator(logger, config, identity_checker)
            return generator.generate_report(args.input, args.output, args.format)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user")
        logger.warning("Operation cancelled by user")
        return 130
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())

