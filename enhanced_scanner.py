#!/usr/bin/env python3
"""
Enhanced RedhoodEye Scanner - Async I/O and Advanced Service Detection
Author: RedHood
Version: 2.0 - Enhanced with Async I/O and Advanced Service Detection
"""

import asyncio
import aiohttp
import socket
import ssl
import ftplib
import smtplib
import telnetlib
import subprocess
import hashlib
import binascii
import struct
import json
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging

@dataclass
class ServiceInfo:
    """Enhanced service information"""
    port: int
    protocol: str
    service_name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    fingerprint: Optional[str] = None
    ssl_info: Optional[Dict] = None
    response_time: Optional[float] = None
    additional_info: Optional[Dict] = None

class AdvancedServiceDetector:
    """Enhanced service detection with protocol-specific probes"""
    
    def __init__(self):
        self.service_signatures = {
            # HTTP/HTTPS
            'http': {
                'ports': [80, 8080, 8000, 8888, 9000],
                'probes': [
                    b'GET / HTTP/1.1\r\nHost: {host}\r\n\r\n',
                    b'HEAD / HTTP/1.1\r\nHost: {host}\r\n\r\n'
                ]
            },
            'https': {
                'ports': [443, 8443, 9443],
                'probes': [
                    b'GET / HTTP/1.1\r\nHost: {host}\r\n\r\n'
                ]
            },
            # SSH
            'ssh': {
                'ports': [22],
                'probes': [
                    b'SSH-2.0-OpenSSH_8.2p1\r\n'
                ]
            },
            # FTP
            'ftp': {
                'ports': [21],
                'probes': [
                    b'USER anonymous\r\n',
                    b'PASS anonymous@example.com\r\n'
                ]
            },
            # SMTP
            'smtp': {
                'ports': [25, 587, 465],
                'probes': [
                    b'EHLO example.com\r\n',
                    b'HELO example.com\r\n'
                ]
            },
            # DNS
            'dns': {
                'ports': [53],
                'probes': [
                    # Standard DNS query for google.com
                    b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01'
                ]
            },
            # MySQL
            'mysql': {
                'ports': [3306],
                'probes': [
                    b'\x0a\x00\x00\x01\x85\xa6\x03\x00\x00\x00\x00\x01\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                ]
            },
            # PostgreSQL
            'postgresql': {
                'ports': [5432],
                'probes': [
                    b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
                ]
            },
            # Redis
            'redis': {
                'ports': [6379],
                'probes': [
                    b'*1\r\n$4\r\nPING\r\n'
                ]
            },
            # MongoDB
            'mongodb': {
                'ports': [27017],
                'probes': [
                    b'\x3a\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00'
                ]
            }
        }
        
        self.version_patterns = {
            'apache': r'Apache/([\d.]+)',
            'nginx': r'nginx/([\d.]+)',
            'openssh': r'OpenSSH_([\d.]+)',
            'mysql': r'([\d.]+)-MariaDB',
            'postgresql': r'PostgreSQL ([\d.]+)',
            'redis': r'redis_version:([\d.]+)',
            'mongodb': r'([\d.]+)',
            'iis': r'Microsoft-IIS/([\d.]+)',
            'tomcat': r'Apache-Coyote/([\d.]+)',
            'jetty': r'Jetty\(([\d.]+)\)'
        }

    async def detect_service_async(self, host: str, port: int, protocol: str = 'TCP') -> ServiceInfo:
        """Async service detection with enhanced probes"""
        start_time = datetime.now()
        
        try:
            if protocol.upper() == 'TCP':
                return await self._detect_tcp_service_async(host, port)
            else:
                return await self._detect_udp_service_async(host, port)
        except Exception as e:
            logging.error(f"Service detection error for {host}:{port}: {e}")
            return ServiceInfo(
                port=port,
                protocol=protocol,
                service_name='unknown',
                banner=f"Detection error: {str(e)}"
            )
        finally:
            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds()

    async def _detect_tcp_service_async(self, host: str, port: int) -> ServiceInfo:
        """Enhanced TCP service detection"""
        try:
            # Create connection with timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0
            )
            
            # Get initial banner
            banner = await self._get_banner_async(reader, writer, host, port)
            
            # Try protocol-specific detection
            service_info = await self._probe_protocol_specific(host, port, banner)
            
            # SSL/TLS detection
            ssl_info = await self._detect_ssl_info(host, port)
            
            writer.close()
            await writer.wait_closed()
            
            return ServiceInfo(
                port=port,
                protocol='TCP',
                service_name=service_info.get('service_name', 'unknown'),
                version=service_info.get('version'),
                banner=banner,
                fingerprint=service_info.get('fingerprint'),
                ssl_info=ssl_info,
                additional_info=service_info.get('additional_info', {})
            )
            
        except asyncio.TimeoutError:
            return ServiceInfo(port=port, protocol='TCP', service_name='timeout')
        except Exception as e:
            return ServiceInfo(port=port, protocol='TCP', service_name='error', banner=str(e))

    async def _detect_udp_service_async(self, host: str, port: int) -> ServiceInfo:
        """Enhanced UDP service detection"""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            
            # Try different UDP probes
            for service_name, config in self.service_signatures.items():
                if port in config.get('ports', []):
                    for probe in config.get('probes', []):
                        try:
                            sock.sendto(probe, (host, port))
                            data, addr = sock.recvfrom(1024)
                            
                            if data:
                                return ServiceInfo(
                                    port=port,
                                    protocol='UDP',
                                    service_name=service_name,
                                    banner=data.decode('utf-8', errors='ignore')[:200],
                                    fingerprint=self._generate_fingerprint(data)
                                )
                        except socket.timeout:
                            continue
                        except Exception:
                            continue
            
            sock.close()
            return ServiceInfo(port=port, protocol='UDP', service_name='unknown')
            
        except Exception as e:
            return ServiceInfo(port=port, protocol='UDP', service_name='error', banner=str(e))

    async def _get_banner_async(self, reader, writer, host: str, port: int) -> str:
        """Get service banner asynchronously"""
        try:
            # Send initial probe
            probe = b'\r\n'
            writer.write(probe)
            await writer.drain()
            
            # Read response with timeout
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return "No banner"

    async def _probe_protocol_specific(self, host: str, port: int, banner: str) -> Dict[str, Any]:
        """Protocol-specific service detection"""
        service_info = {'service_name': 'unknown', 'version': None, 'fingerprint': None}
        
        # HTTP/HTTPS detection
        if port in [80, 443, 8080, 8443, 8000, 8888, 9000]:
            http_info = await self._detect_http_service(host, port)
            service_info.update(http_info)
        
        # SSH detection
        elif port == 22:
            ssh_info = await self._detect_ssh_service(host, port)
            service_info.update(ssh_info)
        
        # Database detection
        elif port in [3306, 5432, 6379, 27017]:
            db_info = await self._detect_database_service(host, port)
            service_info.update(db_info)
        
        # Extract version from banner
        if banner and banner != "No banner":
            version = self._extract_version_from_banner(banner)
            if version:
                service_info['version'] = version
        
        return service_info

    async def _detect_http_service(self, host: str, port: int) -> Dict[str, Any]:
        """Enhanced HTTP/HTTPS service detection"""
        try:
            protocol = 'https' if port in [443, 8443, 9443] else 'http'
            url = f"{protocol}://{host}:{port}"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5.0) as response:
                    headers = dict(response.headers)
                    
                    server = headers.get('Server', '')
                    powered_by = headers.get('X-Powered-By', '')
                    
                    # Extract version information
                    version = None
                    if server:
                        version = self._extract_version_from_banner(server)
                    
                    return {
                        'service_name': 'http' if protocol == 'http' else 'https',
                        'version': version,
                        'fingerprint': f"Server: {server}, Powered-By: {powered_by}",
                        'additional_info': {
                            'server': server,
                            'powered_by': powered_by,
                            'status_code': response.status,
                            'content_type': headers.get('Content-Type', '')
                        }
                    }
        except Exception as e:
            return {'service_name': 'http' if port != 443 else 'https', 'error': str(e)}

    async def _detect_ssh_service(self, host: str, port: int) -> Dict[str, Any]:
        """Enhanced SSH service detection"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=5.0
            )
            
            # Read SSH banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            banner_str = banner.decode('utf-8', errors='ignore').strip()
            
            writer.close()
            await writer.wait_closed()
            
            # Extract SSH version
            version = self._extract_version_from_banner(banner_str)
            
            return {
                'service_name': 'ssh',
                'version': version,
                'fingerprint': banner_str,
                'additional_info': {
                    'ssh_banner': banner_str
                }
            }
        except Exception as e:
            return {'service_name': 'ssh', 'error': str(e)}

    async def _detect_database_service(self, host: str, port: int) -> Dict[str, Any]:
        """Enhanced database service detection"""
        service_map = {
            3306: 'mysql',
            5432: 'postgresql', 
            6379: 'redis',
            27017: 'mongodb'
        }
        
        service_name = service_map.get(port, 'unknown')
        
        try:
            # Try to connect and get version info
            if service_name == 'mysql':
                return await self._detect_mysql_service(host, port)
            elif service_name == 'postgresql':
                return await self._detect_postgresql_service(host, port)
            elif service_name == 'redis':
                return await self._detect_redis_service(host, port)
            elif service_name == 'mongodb':
                return await self._detect_mongodb_service(host, port)
        except Exception as e:
            return {'service_name': service_name, 'error': str(e)}
        
        return {'service_name': service_name}

    async def _detect_ssl_info(self, host: str, port: int) -> Optional[Dict]:
        """Detect SSL/TLS information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context),
                timeout=5.0
            )
            
            cert = writer.get_extra_info('ssl_object').getpeercert()
            cipher = writer.get_extra_info('ssl_object').cipher()
            
            writer.close()
            await writer.wait_closed()
            
            return {
                'certificate': {
                    'subject': dict(x[0] for x in cert['subject']),
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'version': cert['version'],
                    'serial_number': cert['serialNumber'],
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter']
                },
                'cipher': {
                    'name': cipher[0],
                    'version': cipher[1],
                    'bits': cipher[2]
                }
            }
        except:
            return None

    def _extract_version_from_banner(self, banner: str) -> Optional[str]:
        """Extract version information from service banner"""
        for pattern_name, pattern in self.version_patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _generate_fingerprint(self, data: bytes) -> str:
        """Generate fingerprint from service response"""
        return hashlib.md5(data).hexdigest()[:16]

class AsyncPortScanner:
    """Enhanced async port scanner with advanced service detection"""
    
    def __init__(self, target: str, ports: List[int], max_concurrent: int = 100, 
                 timeout: float = 5.0, use_advanced_detection: bool = True):
        self.target = target
        self.ports = ports
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.use_advanced_detection = use_advanced_detection
        self.service_detector = AdvancedServiceDetector() if use_advanced_detection else None
        self.results: List[ServiceInfo] = []
        self.semaphore = Semaphore(max_concurrent)
        
    async def scan(self) -> List[ServiceInfo]:
        """Main async scanning method"""
        tasks = []
        
        for port in self.ports:
            task = create_task(self._scan_port(port))
            tasks.append(task)
        
        # Wait for all tasks to complete
        results = await gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and collect valid results
        for result in results:
            if isinstance(result, ServiceInfo):
                self.results.append(result)
        
        return self.results

    async def _scan_port(self, port: int) -> ServiceInfo:
        """Scan a single port asynchronously"""
        async with self.semaphore:
            try:
                if self.use_advanced_detection:
                    return await self.service_detector.detect_service_async(self.target, port)
                else:
                    return await self._basic_port_check(port)
            except Exception as e:
                return ServiceInfo(
                    port=port,
                    protocol='TCP',
                    service_name='error',
                    banner=str(e)
                )

    async def _basic_port_check(self, port: int) -> ServiceInfo:
        """Basic port connectivity check"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target, port),
                timeout=self.timeout
            )
            
            writer.close()
            await writer.wait_closed()
            
            return ServiceInfo(
                port=port,
                protocol='TCP',
                service_name='open'
            )
        except asyncio.TimeoutError:
            return ServiceInfo(port=port, protocol='TCP', service_name='timeout')
        except Exception as e:
            return ServiceInfo(port=port, protocol='TCP', service_name='closed')

# Example usage
async def main():
    """Example usage of the enhanced scanner"""
    target = "example.com"
    ports = [22, 80, 443, 3306, 5432, 6379, 27017]
    
    scanner = AsyncPortScanner(
        target=target,
        ports=ports,
        max_concurrent=50,
        timeout=5.0,
        use_advanced_detection=True
    )
    
    print(f"Scanning {target} for ports: {ports}")
    results = await scanner.scan()
    
    print("\nScan Results:")
    print("=" * 60)
    for result in results:
        if result.service_name not in ['closed', 'timeout', 'error']:
            print(f"Port {result.port}/{result.protocol}: {result.service_name}")
            if result.version:
                print(f"  Version: {result.version}")
            if result.banner:
                print(f"  Banner: {result.banner[:100]}...")
            if result.ssl_info:
                print(f"  SSL: {result.ssl_info['cipher']['name']}")
            print()

if __name__ == "__main__":
    asyncio.run(main()) 