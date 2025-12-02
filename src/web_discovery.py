"""
Web Discovery Module

Directory enumeration and subdomain probing with rate limiting.
Safe, controlled discovery for authorized targets only.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Set
import aiohttp
from urllib.parse import urljoin, urlparse

from logger import Logger
from config import Config


class WebDiscovery:
    """Web discovery tool for directory enumeration and subdomain probing."""
    
    # Common directory wordlist
    DEFAULT_DIRECTORIES = [
        'admin', 'administrator', 'api', 'assets', 'backup', 'config',
        'database', 'db', 'docs', 'download', 'files', 'images', 'img',
        'includes', 'js', 'login', 'logs', 'old', 'private', 'public',
        'secure', 'static', 'test', 'tmp', 'uploads', 'www', 'wwwroot',
        'css', 'scripts', 'vendor', 'lib', 'src', 'dist', 'build'
    ]
    
    # Common subdomain prefixes
    DEFAULT_SUBDOMAINS = [
        'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'dev', 'test',
        'staging', 'secure', 'vpn', 'portal', 'webmail', 'cpanel',
        'ns1', 'ns2', 'dns', 'mx', 'smtp', 'pop', 'imap'
    ]
    
    def __init__(self, logger: Logger, config: Config):
        """
        Initialize the web discovery tool.
        
        Args:
            logger: Logger instance
            config: Configuration instance
        """
        self.logger = logger
        self.config = config
        self.found_paths: List[Dict] = []
        self.found_subdomains: List[Dict] = []
    
    def discover(self, target: str, wordlist_file: Optional[str] = None,
                num_threads: int = 10, output_dir: Optional[str] = None) -> int:
        """
        Perform web discovery (directory enumeration and subdomain probing).
        
        Args:
            target: Target domain or URL
            wordlist_file: Optional custom wordlist file
            num_threads: Number of concurrent threads
            output_dir: Output directory for results
            
        Returns:
            Exit code (0 for success)
        """
        self.logger.info(f"Starting web discovery: {target}")
        self.logger.log_operation('web_discovery', 'discover_start', {
            'target': target,
            'wordlist_file': wordlist_file,
            'threads': num_threads
        })
        
        # Ensure target has protocol
        if not target.startswith(('http://', 'https://')):
            target = f"https://{target}"
        
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        domain = parsed.netloc.split(':')[0]  # Remove port if present
        
        print(f"\n🔍 Web Discovery: {target}")
        print(f"   Base URL: {base_url}")
        print(f"   Domain: {domain}\n")
        
        # Load wordlist
        if wordlist_file:
            directories = self._load_wordlist(wordlist_file)
        else:
            directories = self.DEFAULT_DIRECTORIES
        
        # Limit threads for safety
        num_threads = min(num_threads, self.config.get_max_threads())
        
        try:
            # Directory enumeration
            print("📁 Enumerating directories...")
            asyncio.run(self._enumerate_directories(base_url, directories, num_threads))
            
            # Subdomain probing
            print("\n🌐 Probing subdomains...")
            asyncio.run(self._probe_subdomains(domain, num_threads))
            
            # Display results
            print(f"\n📊 Discovery Results:")
            print(f"   Directories Found: {len(self.found_paths)}")
            print(f"   Subdomains Found: {len(self.found_subdomains)}")
            
            if self.found_paths:
                print("\n   Found Directories:")
                for path in self.found_paths[:10]:  # Show first 10
                    print(f"      ✓ {path['url']} ({path['status_code']})")
                if len(self.found_paths) > 10:
                    print(f"      ... and {len(self.found_paths) - 10} more")
            
            if self.found_subdomains:
                print("\n   Found Subdomains:")
                for subdomain in self.found_subdomains:
                    print(f"      ✓ {subdomain['subdomain']} ({subdomain['status_code']})")
            
            # Export results
            if output_dir:
                self._export_results(output_dir, target, base_url, domain)
            else:
                self._export_results(self.config.get_output_dir(), target, base_url, domain)
            
            return 0
            
        except Exception as e:
            print(f"❌ ERROR: Web discovery failed: {str(e)}")
            self.logger.error(f"Web discovery failed: {str(e)}", exc_info=True)
            return 1
    
    def _load_wordlist(self, wordlist_file: str) -> List[str]:
        """
        Load wordlist from file.
        
        Args:
            wordlist_file: Path to wordlist file
            
        Returns:
            List of directory names
        """
        wordlist_path = Path(wordlist_file)
        if not wordlist_path.exists():
            self.logger.warning(f"Wordlist file not found: {wordlist_file}, using default")
            return self.DEFAULT_DIRECTORIES
        
        directories = []
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                directory = line.strip()
                if directory and not directory.startswith('#'):
                    directories.append(directory)
        
        return directories if directories else self.DEFAULT_DIRECTORIES
    
    async def _enumerate_directories(self, base_url: str, directories: List[str],
                                   num_threads: int) -> None:
        """
        Enumerate directories asynchronously.
        
        Args:
            base_url: Base URL to test
            directories: List of directory names to test
            num_threads: Number of concurrent requests
        """
        semaphore = asyncio.Semaphore(num_threads)
        
        async def check_directory(directory: str):
            """Check if a directory exists."""
            async with semaphore:
                url = urljoin(base_url, f"/{directory}/")
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as session:
                        async with session.get(url, allow_redirects=False) as response:
                            if response.status < 500:  # Accept 2xx, 3xx, 4xx
                                self.found_paths.append({
                                    'url': url,
                                    'status_code': response.status,
                                    'directory': directory,
                                    'timestamp': datetime.now().isoformat()
                                })
                                print(f"  ✓ Found: {url} ({response.status})")
                
                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    self.logger.debug(f"Error checking {url}: {e}")
                
                # Rate limiting
                await asyncio.sleep(self.config.get_rate_limit_delay())
        
        tasks = [check_directory(d) for d in directories]
        await asyncio.gather(*tasks)
    
    async def _probe_subdomains(self, domain: str, num_threads: int) -> None:
        """
        Probe for subdomains.
        
        Args:
            domain: Base domain name
            num_threads: Number of concurrent requests
        """
        semaphore = asyncio.Semaphore(num_threads)
        
        async def check_subdomain(subdomain: str):
            """Check if a subdomain exists."""
            async with semaphore:
                subdomain_url = f"https://{subdomain}.{domain}"
                try:
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as session:
                        async with session.get(subdomain_url, allow_redirects=False) as response:
                            if response.status < 500:
                                self.found_subdomains.append({
                                    'subdomain': f"{subdomain}.{domain}",
                                    'url': subdomain_url,
                                    'status_code': response.status,
                                    'timestamp': datetime.now().isoformat()
                                })
                                print(f"  ✓ Found: {subdomain_url} ({response.status})")
                
                except asyncio.TimeoutError:
                    pass
                except Exception as e:
                    self.logger.debug(f"Error checking {subdomain_url}: {e}")
                
                # Rate limiting
                await asyncio.sleep(self.config.get_rate_limit_delay())
        
        tasks = [check_subdomain(s) for s in self.DEFAULT_SUBDOMAINS]
        await asyncio.gather(*tasks)
    
    def _export_results(self, output_dir: str, target: str, base_url: str, domain: str) -> None:
        """
        Export discovery results to JSON.
        
        Args:
            output_dir: Output directory
            target: Original target
            base_url: Base URL
            domain: Domain name
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        target_safe = domain.replace('.', '_')
        
        results = {
            'target': target,
            'base_url': base_url,
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'directories_found': len(self.found_paths),
            'subdomains_found': len(self.found_subdomains),
            'directories': self.found_paths,
            'subdomains': self.found_subdomains
        }
        
        json_file = output_path / f"footprint_{target_safe}_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)
        
        self.logger.info(f"Results exported to {json_file}")

