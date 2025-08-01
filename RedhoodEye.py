#!/usr/bin/env python3
"""
RedhoodEye - Advanced Network Scanner
Author: RedHood
Version: 1.1 - Enhanced with Async I/O and Advanced Service Detection
"""

import socket
import threading
import argparse
import sys
import time
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import dns.resolver
import json
from datetime import datetime
import csv
from pathlib import Path
import logging
from typing import Optional, Dict, Any, List
import requests
from bs4 import BeautifulSoup
import re
import struct
import urllib.parse
import base64
from dataclasses import dataclass
import hashlib

# Async I/O imports for enhanced performance
import asyncio
import aiohttp
import async_timeout
from asyncio import Semaphore, Queue, create_task, gather

# Enhanced service detection imports
import ssl
import ftplib
import smtplib
import subprocess
import hashlib
import binascii

# Try to import psutil for better cross-platform network info
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Try to import scheduling libraries
try:
    import schedule
    HAS_SCHEDULE = True
except ImportError:
    HAS_SCHEDULE = False

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    HAS_APSCHEDULER = True
except ImportError:
    HAS_APSCHEDULER = False

# Enhanced async imports
try:
    import asyncio
    import aiohttp
    import async_timeout
    from asyncio import Semaphore, Queue, create_task, gather
    HAS_ASYNC = True
except ImportError:
    HAS_ASYNC = False

# ANSI color codes for terminal output
class Colors:
    """ANSI color codes for terminal output"""
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colored output"""
    
    COLORS = {
        'DEBUG': Colors.BRIGHT_BLACK,
        'INFO': Colors.BRIGHT_GREEN,
        'WARNING': Colors.BRIGHT_YELLOW,
        'ERROR': Colors.BRIGHT_RED,
        'CRITICAL': Colors.BRIGHT_RED + Colors.BOLD,
        'SUCCESS': Colors.BRIGHT_GREEN + Colors.BOLD,
        'PROGRESS': Colors.BRIGHT_CYAN,
        'BANNER': Colors.BRIGHT_MAGENTA,
        'STATS': Colors.BRIGHT_BLUE,
        'HEADER': Colors.BRIGHT_WHITE + Colors.BOLD,
        'SEPARATOR': Colors.BRIGHT_BLACK + Colors.DIM
    }
    
    def __init__(self, fmt=None, datefmt=None, use_colors=True):
        if fmt is None:
            fmt = '%(asctime)s [%(levelname)s] %(message)s'
        if datefmt is None:
            datefmt = '%H:%M:%S'
        super().__init__(fmt, datefmt)
        self.use_colors = use_colors and self._supports_color()
    
    def _supports_color(self):
        """Check if terminal supports colors"""
        if not hasattr(sys.stdout, 'isatty') or not sys.stdout.isatty():
            return False
        if os.name == 'nt':
            try:
                import colorama
                colorama.init()
                return True
            except ImportError:
                return False
        return True
    
    def format(self, record):
        """Format log record with colors"""
        if hasattr(record, 'color'):
            color = record.color
        else:
            color = self.COLORS.get(record.levelname, Colors.RESET)
        
        formatted = super().format(record)
        
        if self.use_colors and color != Colors.RESET:
            formatted = f"{color}{formatted}{Colors.RESET}"
        
        return formatted

class PortScannerLogger:
    """Advanced logger for port scanner with colored output and file logging"""
    
    def __init__(self, name: str = "PortScanner", log_file: Optional[str] = None, 
                 log_level: str = "INFO", use_colors: bool = True, 
                 max_file_size: int = 10 * 1024 * 1024, backup_count: int = 5):
        
        self.name = name
        self.log_file = log_file
        self.use_colors = use_colors
        self.max_file_size = max_file_size
        self.backup_count = backup_count
        
        # Create logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Create formatters
        self._create_formatters()
        
        # Create handlers
        self._create_handlers()
        
        # Thread safety
        self._lock = threading.Lock()
        
        # Progress tracking for single-line display
        self._in_progress = False
        self._progress_line_length = 0
    
    def _create_formatters(self):
        """Create formatters for different output types"""
        self.console_formatter = ColoredFormatter(
            fmt='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S',
            use_colors=self.use_colors
        )
        
        self.file_formatter = logging.Formatter(
            fmt='%(asctime)s [%(levelname)s] [%(threadName)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    def _create_handlers(self):
        """Create and configure handlers"""
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(self.console_formatter)
        self.logger.addHandler(console_handler)
        
        if self.log_file:
            self._create_file_handler()
    
    def _create_file_handler(self):
        """Create file handler with rotation"""
        try:
            log_path = Path(self.log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            from logging.handlers import RotatingFileHandler
            file_handler = RotatingFileHandler(
                self.log_file,
                maxBytes=self.max_file_size,
                backupCount=self.backup_count,
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(self.file_formatter)
            self.logger.addHandler(file_handler)
            
        except Exception as e:
            try:
                file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(self.file_formatter)
                self.logger.addHandler(file_handler)
            except Exception as e2:
                self.warning(f"Could not create file handler: {e2}")
    
    def _log_with_color(self, level: str, message: str, color: str = None, **kwargs):
        """Log message with custom color"""
        with self._lock:
            # If we're in progress mode, clear the line first for any non-progress message
            if self._in_progress:
                # Clear the current line and move to next line
                print(f"\r{' ' * self._progress_line_length}\r", end='', flush=True)
                self._in_progress = False
                self._progress_line_length = 0
            
            record = self.logger.makeRecord(
                self.name, getattr(logging, level.upper()), 
                "", 0, message, (), None
            )
            
            if color:
                record.color = color
            
            for key, value in kwargs.items():
                setattr(record, key, value)
            
            self.logger.handle(record)
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(message, extra=kwargs)
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(message, extra=kwargs)
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.logger.warning(message, extra=kwargs)
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self.logger.error(message, extra=kwargs)
    
    def success(self, message: str, **kwargs):
        """Log success message with green color"""
        self._log_with_color("INFO", message, Colors.BRIGHT_GREEN + Colors.BOLD, **kwargs)
    
    def progress(self, message: str, **kwargs):
        """Log progress message with cyan color"""
        self._log_with_color("INFO", message, Colors.BRIGHT_CYAN, **kwargs)
    
    def banner(self, message: str, **kwargs):
        """Log banner message with magenta color"""
        self._log_with_color("INFO", message, Colors.BRIGHT_MAGENTA, **kwargs)
    
    def stats(self, message: str, **kwargs):
        """Log statistics message with blue color"""
        self._log_with_color("INFO", message, Colors.BRIGHT_BLUE, **kwargs)
    
    def header(self, message: str, **kwargs):
        """Log header message with white bold color"""
        self._log_with_color("INFO", message, Colors.BRIGHT_WHITE + Colors.BOLD, **kwargs)
    
    def separator(self, char: str = "=", length: int = 60, **kwargs):
        """Log separator line"""
        separator_line = char * length
        self._log_with_color("INFO", separator_line, Colors.BRIGHT_BLACK + Colors.DIM, **kwargs)
    
    def scan_start(self, target: str, ports: str, threads: int, timeout: int, **kwargs):
        """Log scan start information"""
        self.header("STARTING PORT SCAN", **kwargs)
        self.info(f"Target: {target}")
        self.info(f"Ports: {ports}")
        self.info(f"Threads: {threads}")
        self.info(f"Timeout: {timeout}s")
        self.separator()
    
    def scan_progress(self, current: int, total: int, percentage: float, **kwargs):
        """Log scan progress on single line"""
        progress_msg = f"Progress: {percentage:.1f}% ({current}/{total})"
        
        with self._lock:
            # Track progress state
            self._in_progress = True
            self._progress_line_length = len(progress_msg)
            
            # Use direct print for single-line updates
            if self.use_colors:
                print(f"\r{Colors.BRIGHT_CYAN}{progress_msg}{Colors.RESET}", end='', flush=True)
            else:
                print(f"\r{progress_msg}", end='', flush=True)
            

        
        # Also log to file if logging is enabled
        if hasattr(self, 'log_file') and self.log_file:
            self.progress(progress_msg, **kwargs)
    
    def port_found(self, port: int, service: str, banner: str = None, **kwargs):
        """Log when a port is found open"""
        if banner:
            self.banner(f"Port {port} ({service}): {banner}", **kwargs)
        else:
            self.banner(f"Port {port} ({service})", **kwargs)
    
    def scan_complete(self, duration: float, open_count: int, total_count: int, **kwargs):
        """Log scan completion"""
        self.separator()
        self.success(f"Scan completed in {duration:.2f} seconds", **kwargs)
        self.stats(f"Found {open_count} open ports out of {total_count} scanned", **kwargs)
        self.separator()
    
    def network_error(self, error: str, port: int = None, **kwargs):
        """Log network errors"""
        if port:
            self.error(f"Network error on port {port}: {error}", **kwargs)
        else:
            self.error(f"Network error: {error}", **kwargs)
    
    def timeout_error(self, port: int, **kwargs):
        """Log timeout errors"""
        self.warning(f"Timeout on port {port}", **kwargs)
    
    def connection_refused(self, port: int, **kwargs):
        """Log connection refused errors"""
        self.debug(f"Connection refused on port {port}", **kwargs)
    
    def cleanup_info(self, message: str, **kwargs):
        """Log cleanup operations"""
        self.debug(f"Cleanup: {message}", **kwargs)
    
    def configuration_info(self, config: Dict[str, Any], **kwargs):
        """Log configuration information"""
        self.info("CONFIGURATION", **kwargs)
        for key, value in config.items():
            self.info(f"   {key}: {value}", **kwargs)
    
    def performance_metrics(self, metrics: Dict[str, Any], **kwargs):
        """Log performance metrics"""
        self.stats("PERFORMANCE METRICS", **kwargs)
        for key, value in metrics.items():
            if isinstance(value, float):
                self.stats(f"   {key}: {value:.2f}", **kwargs)
            else:
                self.stats(f"   {key}: {value}", **kwargs)
    
    def file_saved(self, filename: str, format_type: str, **kwargs):
        """Log when a file is successfully saved"""
        self.success(f"Results saved to {filename} ({format_type} format)", **kwargs)

# Common services and their default ports
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
    1433: "MSSQL", 1521: "Oracle", 2181: "ZooKeeper", 5672: "RabbitMQ",
    9200: "Elasticsearch", 11211: "Memcached", 27018: "MongoDB-Shard",
    50070: "Hadoop-NameNode", 50075: "Hadoop-DataNode", 60010: "HBase-Master"
}

# Predefined port sets for common scan types
PORT_SETS = {
    'web': [80, 443, 8080, 8443, 3000, 5000, 8000, 9000],
    'database': [3306, 5432, 6379, 27017, 1433, 1521, 2181],
    'remote': [22, 23, 3389, 5900, 5901, 5902, 5903],
    'email': [25, 110, 143, 465, 587, 993, 995],
    'file': [21, 22, 445, 139],
    'common': [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017],
    'all': list(range(1, 65536))
}

class ProxyManager:
    """Manage HTTP/HTTPS and SOCKS proxy connections"""
    
    def __init__(self, proxy_url=None, proxy_auth=None):
        self.proxy_url = proxy_url
        self.proxy_auth = proxy_auth
        self.proxy_type = None
        self.proxy_host = None
        self.proxy_port = None
        self.proxy_username = None
        self.proxy_password = None
        
        if proxy_url:
            self._parse_proxy_url()
    
    def _parse_proxy_url(self):
        """Parse proxy URL to extract components"""
        try:
            parsed = urllib.parse.urlparse(self.proxy_url)
            self.proxy_type = parsed.scheme.lower()
            self.proxy_host = parsed.hostname
            self.proxy_port = parsed.port or self._get_default_port()
            
            if parsed.username:
                self.proxy_username = urllib.parse.unquote(parsed.username)
            if parsed.password:
                self.proxy_password = urllib.parse.unquote(parsed.password)
                
        except Exception as e:
            raise ValueError(f"Invalid proxy URL: {e}")
    
    def _get_default_port(self):
        """Get default port for proxy type"""
        defaults = {
            'http': 8080,
            'https': 8443,
            'socks4': 1080,
            'socks5': 1080
        }
        return defaults.get(self.proxy_type, 8080)
    
    def create_proxy_socket(self, target_host, target_port, timeout=10):
        """Create socket through proxy"""
        if not self.proxy_url:
            return None
            
        if self.proxy_type in ['http', 'https']:
            return self._create_http_proxy_socket(target_host, target_port, timeout)
        elif self.proxy_type in ['socks4', 'socks5']:
            return self._create_socks_proxy_socket(target_host, target_port, timeout)
        else:
            raise ValueError(f"Unsupported proxy type: {self.proxy_type}")
    
    def _create_http_proxy_socket(self, target_host, target_port, timeout):
        """Create socket through HTTP/HTTPS proxy"""
        try:
            # Create connection to proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.proxy_host, self.proxy_port))
            
            # Build CONNECT request
            connect_request = f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
            connect_request += f"Host: {target_host}:{target_port}\r\n"
            
            if self.proxy_username and self.proxy_password:
                auth = base64.b64encode(f"{self.proxy_username}:{self.proxy_password}".encode()).decode()
                connect_request += f"Proxy-Authorization: Basic {auth}\r\n"
            
            connect_request += "Connection: keep-alive\r\n\r\n"
            
            # Send CONNECT request
            sock.send(connect_request.encode())
            
            # Read response
            response = sock.recv(4096).decode()
            
            if not response.startswith("HTTP/1.1 200"):
                sock.close()
                raise Exception(f"Proxy connection failed: {response.split()[0]}")
            
            return sock
            
        except Exception as e:
            if 'sock' in locals():
                sock.close()
            raise Exception(f"HTTP proxy connection failed: {e}")
    
    def _create_socks_proxy_socket(self, target_host, target_port, timeout):
        """Create socket through SOCKS proxy"""
        try:
            # Create connection to proxy
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.proxy_host, self.proxy_port))
            
            if self.proxy_type == 'socks5':
                # SOCKS5 handshake
                # Version 5, 1 authentication method (no auth)
                sock.send(b'\x05\x01\x00')
                response = sock.recv(2)
                
                if response[0] != 5 or response[1] != 0:
                    sock.close()
                    raise Exception("SOCKS5 authentication failed")
                
                # Connect command
                # Version 5, connect command, reserved, IPv4, address, port
                addr_bytes = socket.inet_aton(target_host)
                port_bytes = struct.pack('>H', target_port)
                
                request = b'\x05\x01\x00\x01' + addr_bytes + port_bytes
                sock.send(request)
                
                response = sock.recv(10)
                if response[1] != 0:
                    sock.close()
                    raise Exception(f"SOCKS5 connection failed: {response[1]}")
                
                return sock
                
            elif self.proxy_type == 'socks4':
                # SOCKS4 handshake
                addr_bytes = socket.inet_aton(target_host)
                port_bytes = struct.pack('>H', target_port)
                
                request = b'\x04\x01' + port_bytes + addr_bytes + b'\x00'
                sock.send(request)
                
                response = sock.recv(8)
                if response[1] != 90:
                    sock.close()
                    raise Exception(f"SOCKS4 connection failed: {response[1]}")
                
                return sock
                
        except Exception as e:
            if 'sock' in locals():
                sock.close()
            raise Exception(f"SOCKS proxy connection failed: {e}")
    
    def get_proxy_info(self):
        """Get proxy configuration info"""
        if not self.proxy_url:
            return "No proxy configured"
        
        info = f"Proxy: {self.proxy_type.upper()} {self.proxy_host}:{self.proxy_port}"
        if self.proxy_username:
            info += f" (Auth: {self.proxy_username})"
        return info


class ScheduledScanner:
    """Manage scheduled port scans"""
    
    def __init__(self, scheduler_type='apscheduler'):
        self.scheduler_type = scheduler_type
        self.scheduler = None
        self.jobs = {}
        
        if scheduler_type == 'apscheduler' and HAS_APSCHEDULER:
            self.scheduler = BackgroundScheduler()
            self.scheduler.start()
        elif scheduler_type == 'schedule' and HAS_SCHEDULE:
            self.scheduler = schedule
        else:
            raise ImportError("No scheduling library available. Install 'apscheduler' or 'schedule'")
    
    def add_scan_job(self, job_id, target, ports, schedule_time, **kwargs):
        """Add a scheduled scan job"""
        if self.scheduler_type == 'apscheduler':
            return self._add_apscheduler_job(job_id, target, ports, schedule_time, **kwargs)
        elif self.scheduler_type == 'schedule':
            return self._add_schedule_job(job_id, target, ports, schedule_time, **kwargs)
    
    def _add_apscheduler_job(self, job_id, target, ports, schedule_time, **kwargs):
        """Add job using APScheduler"""
        try:
            # Parse schedule time (cron format: "0 2 * * *" for daily at 2 AM)
            if isinstance(schedule_time, str):
                cron_parts = schedule_time.split()
                if len(cron_parts) == 5:
                    trigger = CronTrigger(
                        minute=cron_parts[0],
                        hour=cron_parts[1],
                        day=cron_parts[2],
                        month=cron_parts[3],
                        day_of_week=cron_parts[4]
                    )
                else:
                    raise ValueError("Invalid cron format. Use: minute hour day month day_of_week")
            else:
                trigger = schedule_time
            
            # Create scanner function
            def scan_job():
                try:
                    scanner = PortScanner(target, **kwargs)
                    scanner.start_port = parse_ports(ports)
                    results = scanner.scan()
                    
                    # Save results with timestamp
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    output_file = f"scheduled_scan_{job_id}_{timestamp}.json"
                    
                    with open(output_file, 'w') as f:
                        json.dump({
                            'job_id': job_id,
                            'target': target,
                            'timestamp': timestamp,
                            'results': results
                        }, f, indent=2)
                    
                    print(f"Scheduled scan {job_id} completed. Results saved to {output_file}")
                    
                except Exception as e:
                    print(f"Scheduled scan {job_id} failed: {e}")
            
            # Add job to scheduler
            job = self.scheduler.add_job(scan_job, trigger=trigger, id=job_id)
            self.jobs[job_id] = job
            
            return True
            
        except Exception as e:
            print(f"Failed to add scheduled job: {e}")
            return False
    
    def _add_schedule_job(self, job_id, target, ports, schedule_time, **kwargs):
        """Add job using schedule library"""
        try:
            # Parse schedule time (simple format: "daily", "hourly", etc.)
            if schedule_time == "daily":
                job = self.scheduler.every().day.at("02:00").do(
                    self._run_schedule_scan, job_id, target, ports, **kwargs
                )
            elif schedule_time == "hourly":
                job = self.scheduler.every().hour.do(
                    self._run_schedule_scan, job_id, target, ports, **kwargs
                )
            elif schedule_time == "weekly":
                job = self.scheduler.every().monday.at("02:00").do(
                    self._run_schedule_scan, job_id, target, ports, **kwargs
                )
            else:
                raise ValueError("Invalid schedule format. Use: daily, hourly, weekly")
            
            self.jobs[job_id] = job
            return True
            
        except Exception as e:
            print(f"Failed to add scheduled job: {e}")
            return False
    
    def _run_schedule_scan(self, job_id, target, ports, **kwargs):
        """Run scheduled scan (for schedule library)"""
        try:
            scanner = PortScanner(target, **kwargs)
            scanner.start_port = parse_ports(ports)
            results = scanner.scan()
            
            # Save results with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"scheduled_scan_{job_id}_{timestamp}.json"
            
            with open(output_file, 'w') as f:
                json.dump({
                    'job_id': job_id,
                    'target': target,
                    'timestamp': timestamp,
                    'results': results
                }, f, indent=2)
            
            print(f"Scheduled scan {job_id} completed. Results saved to {output_file}")
            
        except Exception as e:
            print(f"Scheduled scan {job_id} failed: {e}")
    
    def remove_job(self, job_id):
        """Remove a scheduled job"""
        if job_id in self.jobs:
            if self.scheduler_type == 'apscheduler':
                self.scheduler.remove_job(job_id)
            else:
                self.scheduler.clear(job_id)
            del self.jobs[job_id]
            return True
        return False
    
    def list_jobs(self):
        """List all scheduled jobs"""
        if self.scheduler_type == 'apscheduler':
            jobs = self.scheduler.get_jobs()
            return [{'id': job.id, 'next_run': job.next_run_time} for job in jobs]
        else:
            return list(self.jobs.keys())
    
    def start_scheduler(self):
        """Start the scheduler (for schedule library)"""
        if self.scheduler_type == 'schedule':
            import time
            while True:
                self.scheduler.run_pending()
                time.sleep(60)  # Check every minute
    
    def stop_scheduler(self):
        """Stop the scheduler"""
        if self.scheduler_type == 'apscheduler':
            self.scheduler.shutdown()
        else:
            self.scheduler.clear()


class ServiceDetector:
    """Advanced service detection with protocol analysis"""
    
    def __init__(self):
        self.service_patterns = {
            'SSH': [
                (b'SSH-', 'SSH'),
                (b'SSH_', 'SSH'),
            ],
            'HTTP': [
                (b'HTTP/', 'HTTP Server'),
                (b'Server:', 'HTTP Server'),
                (b'nginx', 'Nginx'),
                (b'Apache', 'Apache'),
                (b'IIS', 'IIS'),
            ],
            'FTP': [
                (b'FTP', 'FTP Server'),
                (b'vsFTPd', 'vsFTPd'),
                (b'ProFTPD', 'ProFTPD'),
            ],
            'SMTP': [
                (b'SMTP', 'SMTP Server'),
                (b'Postfix', 'Postfix'),
                (b'Exchange', 'Exchange'),
            ],
            'MySQL': [
                (b'MySQL', 'MySQL'),
                (b'mysql', 'MySQL'),
            ],
            'PostgreSQL': [
                (b'PostgreSQL', 'PostgreSQL'),
                (b'postgres', 'PostgreSQL'),
            ],
            'Redis': [
                (b'Redis', 'Redis'),
                (b'redis', 'Redis'),
            ],
            'DNS': [
                (b'DNS', 'DNS Server'),
                (b'BIND', 'BIND DNS'),
            ]
        }
    
    def detect_service(self, port, banner, protocol='TCP'):
        """Advanced service detection with version analysis"""
        if not banner or banner == "No banner":
            return self._detect_by_port(port)
        
        banner_lower = banner.lower()
        banner_upper = banner.upper()
        
        # Try pattern matching
        for service_name, patterns in self.service_patterns.items():
            for pattern, service_type in patterns:
                if pattern in banner:
                    version = self._extract_version(banner)
                    return f"{service_type} {version}".strip()
        
        # Protocol-specific detection
        if protocol == 'UDP':
            return self._detect_udp_service(port, banner)
        
        # Fallback to port-based detection
        return self._detect_by_port(port)
    
    def _detect_by_port(self, port):
        """Detect service by port number"""
        return COMMON_SERVICES.get(port, "Unknown")
    
    def _extract_version(self, banner):
        """Extract version information from banner"""
        # Common version patterns
        version_patterns = [
            r'(\d+\.\d+\.\d+)',  # x.x.x
            r'(\d+\.\d+)',       # x.x
            r'version[:\s]+([^\s]+)',  # version: x.x.x
            r'v([\d.]+)',        # vx.x.x
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return ""
    
    def _detect_udp_service(self, port, banner):
        """Detect UDP-specific services"""
        udp_services = {
            53: 'DNS',
            67: 'DHCP Server',
            68: 'DHCP Client',
            69: 'TFTP',
            123: 'NTP',
            137: 'NetBIOS Name Service',
            138: 'NetBIOS Datagram',
            161: 'SNMP',
            162: 'SNMP Trap',
            514: 'Syslog',
            520: 'RIP',
            1194: 'OpenVPN',
            5353: 'mDNS',
        }
        
        if port in udp_services:
            return udp_services[port]
        
        return "Unknown UDP Service"

# Enhanced Async Classes
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
                    b'\x0a\x00\x00\x01\x85\xa6\x03\x00\x00\x00\x00\x01\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
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

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1000, threads=100, timeout=3, banner_timeout=1, 
                 verbose=False, output_file=None, output_format='json', scan_type='tcp', fast_scan=False,
                 log_file=None, log_level="INFO", use_colors=True, rate_limit=None, randomize=False,
                 proxy_url=None, proxy_auth=None):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.threads = threads
        self.timeout = timeout
        self.banner_timeout = banner_timeout
        self.verbose = verbose
        self.output_file = output_file
        self.output_format = output_format
        self.scan_type = scan_type
        self.fast_scan = fast_scan
        self.rate_limit = rate_limit
        self.randomize = randomize
        self.open_ports = []
        self.closed_ports = []
        self.error_ports = []
        self.lock = threading.Lock()
        self.scan_start_time = None
        self.scan_end_time = None
        self.target_family = None  # IPv4 or IPv6
        
        # Setup proxy manager
        self.proxy_manager = ProxyManager(proxy_url, proxy_auth)
        
        # Setup logging
        self.logger = PortScannerLogger(
            log_file=log_file,
            log_level=log_level,
            use_colors=use_colors
        )
        
        # Setup service detector
        self.service_detector = ServiceDetector()
        
        # Log configuration
        config = {
            'target': target,
            'port_range': f"{start_port}-{end_port}",
            'threads': threads,
            'timeout': timeout,
            'banner_timeout': banner_timeout,
            'verbose': verbose,
            'fast_scan': fast_scan,
            'output_format': output_format,
            'proxy': self.proxy_manager.get_proxy_info()
        }
        self.logger.configuration_info(config)
        
    def resolve_hostname(self, hostname):
        """Resolve hostname to IP address with IPv6 support"""
        try:
            # Try to get address info (supports both IPv4 and IPv6)
            addrinfo = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            
            # Prefer IPv4 addresses
            for info in addrinfo:
                if info[0] == socket.AF_INET:  # IPv4
                    self.target_family = socket.AF_INET
                    ip = info[4][0]
                    self.logger.info(f"Resolved {hostname} to IPv4: {ip}")
                    return ip
            
            # If no IPv4, use the first available address (IPv6)
            if addrinfo:
                self.target_family = addrinfo[0][0]
                ip = addrinfo[0][4][0]
                self.logger.info(f"Resolved {hostname} to IPv6: {ip}")
                return ip
            
        except socket.gaierror:
            # Fallback to gethostbyname for backward compatibility
            try:
                ip = socket.gethostbyname(hostname)
                self.target_family = socket.AF_INET
                self.logger.info(f"Resolved {hostname} to IPv4 (fallback): {ip}")
                return ip
            except socket.gaierror:
                self.logger.error(f"Could not resolve hostname '{hostname}'")
                sys.exit(1)
        
        self.logger.error(f"Could not resolve hostname '{hostname}'")
        sys.exit(1)
    
    def is_valid_ip(self, ip):
        """Check if the given string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def parse_targets(self, target_input):
        """Parse target input which can be IP, hostname, CIDR, or file"""
        targets = []
        
        # Check if it's a file
        if os.path.isfile(target_input):
            try:
                with open(target_input, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            targets.extend(self.parse_targets(line))
                return targets
            except Exception as e:
                self.logger.error(f"Error reading target file: {e}")
                return []
        
        # Check if it's CIDR notation
        if '/' in target_input:
            try:
                network = ipaddress.ip_network(target_input, strict=False)
                targets = [str(ip) for ip in network.hosts()]
                self.logger.info(f"Parsed CIDR {target_input} -> {len(targets)} targets")
                return targets
            except ValueError as e:
                self.logger.error(f"Invalid CIDR notation: {e}")
                return []
        
        # Single target
        return [target_input]
    
    def scan_port(self, port):
        """Scan a single port and return result"""
        sock = None
        try:
            # Determine socket family based on target
            if self.target_family is None:
                # Auto-detect based on target format
                family = socket.AF_INET6 if ':' in self.target else socket.AF_INET
            else:
                family = self.target_family
            
            # Create socket based on scan type
            if self.scan_type.lower() == 'udp':
                sock = socket.socket(family, socket.SOCK_DGRAM)
                sock.settimeout(self.timeout)
                
                # Enhanced UDP scanning with ICMP error detection
                try:
                    # Send probe packet
                    probe_data = self._get_udp_probe(port)
                    sock.sendto(probe_data, (self.target, port))
                    
                    try:
                        # Wait for response
                        data, addr = sock.recvfrom(1024)
                        # If we get a response, port is open
                        return {
                            'port': port,
                            'status': 'open',
                            'service': self.get_service_name(port, data.decode('utf-8', errors='ignore')[:200], 'UDP'),
                            'banner': data.decode('utf-8', errors='ignore')[:200],
                            'protocol': 'UDP'
                        }
                    except socket.timeout:
                        # No response - try to detect ICMP errors
                        return self._check_udp_icmp_errors(port)
                        
                except Exception as e:
                    return {
                        'port': port,
                        'status': 'error',
                        'service': self.get_service_name(port, None, 'UDP'),
                        'banner': f"UDP Error: {str(e)}",
                        'protocol': 'UDP'
                    }
            else:
                # TCP scanning with proxy support
                if self.proxy_manager.proxy_url:
                    # Use proxy connection
                    sock = self.proxy_manager.create_proxy_socket(self.target, port, self.timeout)
                    if sock is None:
                        return {
                            'port': port,
                            'status': 'error',
                            'service': self.get_service_name(port),
                            'banner': 'Proxy connection failed',
                            'protocol': 'TCP'
                        }
                else:
                    # Direct connection
                    sock = socket.socket(family, socket.SOCK_STREAM)
                    sock.settimeout(self.timeout)
                    result = sock.connect_ex((self.target, port))
                    
                    if result != 0:
                        with self.lock:
                            self.closed_ports.append(port)
                        self.logger.connection_refused(port)
                        return {'port': port, 'status': 'closed', 'banner': None, 'service': None}
            
            # Port is open (either through proxy or direct connection), try to get banner
            banner = self.get_banner(sock, port)
            service = self.get_service_name(port)
            
            port_info = {
                'port': port,
                'service': service,
                'banner': banner,
                'protocol': 'tcp'
            }
            
            with self.lock:
                self.open_ports.append(port_info)
            
            # Log the open port
            self.logger.port_found(port, service, banner)
            
            if self.verbose:
                self.logger.banner(f"Port {port}/tcp open - {service}")
                if banner and banner != "No banner":
                    self.logger.debug(f"    Banner: {banner}")
            
            return {
                'port': port,
                'status': 'open',
                'service': service,
                'banner': banner
            }
            
        except socket.timeout:
            with self.lock:
                self.error_ports.append({'port': port, 'error': 'timeout'})
            self.logger.timeout_error(port)
            return {'port': port, 'status': 'error', 'error': 'timeout', 'banner': None, 'service': None}
        except Exception as e:
            with self.lock:
                self.error_ports.append({'port': port, 'error': str(e)})
            self.logger.network_error(str(e), port)
            return {'port': port, 'status': 'error', 'error': str(e), 'banner': None, 'service': None}
        finally:
            # Always close the socket
            if sock:
                try:
                    sock.close()
                    self.logger.cleanup_info(f"Socket closed for port {port}")
                except:
                    pass
    
    def get_banner(self, sock, port):
        """Attempt to get banner from open port with port-specific probes"""
        try:
            # First, try to receive banner without sending anything (some services send banner on connect)
            if not self.fast_scan:
                try:
                    sock.settimeout(self.banner_timeout)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        return banner[:200]  # Limit banner length
                except socket.timeout:
                    pass
                except:
                    pass
            
            # Reset timeout for sending probes
            sock.settimeout(self.banner_timeout)
            
            # Port-specific probes
            if port == 80 or port == 443 or port in [8080, 8443, 3000, 5000, 8000, 9000]:
                # HTTP/HTTPS probes
                probes = [
                    b'GET / HTTP/1.0\r\n\r\n',
                    b'HEAD / HTTP/1.0\r\n\r\n',
                    b'OPTIONS / HTTP/1.0\r\n\r\n'
                ]
            elif port == 22:
                # SSH probe
                probes = [b'SSH-2.0-OpenSSH_8.2p1\r\n']
            elif port == 21:
                # FTP probe
                probes = [b'USER anonymous\r\n', b'HELP\r\n']
            elif port == 25 or port in [110, 143, 465, 587, 993, 995]:
                # Email service probes
                probes = [b'EHLO test\r\n', b'HELP\r\n', b'QUIT\r\n']
            elif port in [3306, 5432, 1433, 1521]:
                # Database probes
                probes = [b'\x00\x00\x00\x85', b'SELECT 1\r\n', b'VERSION\r\n']
            else:
                # Generic probes for other ports
                probes = [
                    b'\r\n',
                    b'HELP\r\n',
                    b'VERSION\r\n',
                    b'INFO\r\n',
                    b'STATUS\r\n'
                ]
            
            for probe in probes:
                try:
                    sock.send(probe)
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        return banner[:200]  # Limit banner length
                except:
                    continue
                    
        except Exception:
            pass
        
        return "No banner"
    
    def _get_udp_probe(self, port):
        """Get appropriate UDP probe for specific ports"""
        if port == 53:  # DNS
            return b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'
        elif port == 123:  # NTP
            return b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        elif port == 161:  # SNMP
            return b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'
        else:
            return b'\x00' * 8  # Generic null probe
    
    def _check_udp_icmp_errors(self, port):
        """Check for ICMP error messages to determine UDP port status"""
        # This is a simplified version - in a real implementation,
        # you would need raw sockets to capture ICMP messages
        return {
            'port': port,
            'status': 'open|filtered',  # Can't determine without ICMP analysis
            'service': self.get_service_name(port, None, 'UDP'),
            'banner': None,
            'protocol': 'UDP'
        }
    
    def get_service_name(self, port, banner=None, protocol='TCP'):
        """Get service name for a port with advanced detection"""
        if banner and banner != "No banner":
            return self.service_detector.detect_service(port, banner, protocol)
        return COMMON_SERVICES.get(port, "Unknown")
    
    def scan(self):
        """Main scanning method"""
        self.scan_start_time = datetime.now()
        
        # Parse ports to get the actual list
        if isinstance(self.start_port, list):
            # New list mode
            ports_to_scan = self.start_port
        elif isinstance(self.start_port, int) and isinstance(self.end_port, int):
            # Legacy range mode
            ports_to_scan = list(range(self.start_port, self.end_port + 1))
        else:
            # Fallback
            ports_to_scan = [self.start_port] if isinstance(self.start_port, int) else []
        
        # Randomize port order if requested
        if self.randomize:
            import random
            random.shuffle(ports_to_scan)
            self.logger.info("Port order randomized for stealth scanning")
        
        # Limit threads for large scans to prevent system overload
        if len(ports_to_scan) > 10000 and self.threads > 200:
            self.threads = 200
            self.logger.warning(f"Thread count limited to {self.threads} for large scan")
        
        # Log scan start
        self.logger.scan_start(
            target=self.target,
            ports=f"{len(ports_to_scan)} ports",
            threads=self.threads,
            timeout=self.timeout
        )
        
        # Create thread pool
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all port scanning tasks
            future_to_port = {
                executor.submit(self.scan_port, port): port 
                for port in ports_to_scan
            }
            
            # Process completed tasks
            completed = 0
            total_ports = len(ports_to_scan)
            
            # Rate limiting
            if self.rate_limit:
                delay = 1.0 / self.rate_limit  # seconds between requests
                self.logger.info(f"Rate limiting: {self.rate_limit} requests/second")
            
            for future in as_completed(future_to_port):
                completed += 1
                result = future.result()
                
                # Apply rate limiting
                if self.rate_limit and completed % 10 == 0:  # Every 10 requests
                    time.sleep(delay)
                
                # Show progress
                progress = (completed / total_ports) * 100
                self.logger.scan_progress(completed, total_ports, progress)
                
                # Add small delay for visibility in small scans
                if total_ports <= 10:
                    time.sleep(0.1)
        
        # Clear progress state and print newline after progress is complete
        with self.logger._lock:
            if self.logger._in_progress:
                print(f"\r{' ' * self.logger._progress_line_length}\r", end='', flush=True)
                self.logger._in_progress = False
                self.logger._progress_line_length = 0
        print()
        
        self.scan_end_time = datetime.now()
        scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        # Log scan completion
        self.logger.scan_complete(
            duration=scan_duration,
            open_count=len(self.open_ports),
            total_count=total_ports
        )
        
        # Log performance metrics
        metrics = {
            'ports_per_second': total_ports / scan_duration if scan_duration > 0 else 0,
            'open_percentage': (len(self.open_ports) / total_ports * 100) if total_ports > 0 else 0,
            'error_percentage': (len(self.error_ports) / total_ports * 100) if total_ports > 0 else 0
        }
        self.logger.performance_metrics(metrics)
        
        # Save results to file if specified
        if self.output_file:
            self.save_results()
        
        return self.open_ports
    
    def save_results(self):
        """Save scan results to file in various formats"""
        try:
            # Calculate total ports scanned
            if isinstance(self.start_port, list):
                total_ports_scanned = len(self.start_port)
            else:
                total_ports_scanned = self.end_port - self.start_port + 1
            
            # Ensure scan times are set
            if self.scan_start_time is None:
                self.scan_start_time = datetime.now()
            if self.scan_end_time is None:
                self.scan_end_time = datetime.now()
            
            results = {
                'target': self.target,
                'scan_time': self.scan_start_time.isoformat(),
                'scan_duration': (self.scan_end_time - self.scan_start_time).total_seconds(),
                'total_ports_scanned': total_ports_scanned,
                'open_ports': len(self.open_ports),
                'closed_ports': len(self.closed_ports),
                'error_ports': len(self.error_ports),
                'scan_type': self.scan_type,
                'results': {
                    'open_ports': self.open_ports,
                    'closed_ports': self.closed_ports,
                    'error_ports': self.error_ports
                }
            }
            
            if self.output_format.lower() == 'json':
                with open(self.output_file, 'w') as f:
                    json.dump(results, f, indent=2)
            
            elif self.output_format.lower() == 'csv':
                with open(self.output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Port', 'Service', 'Status', 'Banner', 'Protocol'])
                    
                    for port_info in sorted(self.open_ports, key=lambda x: x['port']):
                        writer.writerow([
                            port_info['port'],
                            port_info['service'],
                            'open',
                            port_info['banner'],
                            port_info['protocol']
                        ])
            
            elif self.output_format.lower() == 'html':
                html_content = self.generate_html_report(results)
                with open(self.output_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            
            self.logger.file_saved(self.output_file, self.output_format.upper())
            
        except Exception as e:
            self.logger.error(f"Error saving results: {e}")
    
    def generate_html_report(self, results):
        """Generate HTML report"""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Port Scan Results - {results['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-box {{ background-color: #e8f4f8; padding: 10px; border-radius: 5px; flex: 1; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .open {{ background-color: #d4edda; }}
        .closed {{ background-color: #f8d7da; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Port Scan Results</h1>
        <p><strong>Target:</strong> {results['target']}</p>
        <p><strong>Scan Time:</strong> {results['scan_time']}</p>
        <p><strong>Duration:</strong> {results['scan_duration']:.2f} seconds</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <h3>Total Ports</h3>
            <p>{results['total_ports_scanned']}</p>
        </div>
        <div class="stat-box">
            <h3>Open Ports</h3>
            <p>{results['open_ports']}</p>
        </div>
        <div class="stat-box">
            <h3>Closed Ports</h3>
            <p>{results['closed_ports']}</p>
        </div>
        <div class="stat-box">
            <h3>Errors</h3>
            <p>{results['error_ports']}</p>
        </div>
    </div>
    
    <h2>Open Ports</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Protocol</th>
            <th>Banner</th>
        </tr>
"""
        
        for port_info in sorted(results['results']['open_ports'], key=lambda x: x['port']):
            html += f"""
        <tr class="open">
            <td>{port_info['port']}</td>
            <td>{port_info['service']}</td>
            <td>{port_info['protocol']}</td>
            <td>{port_info['banner']}</td>
        </tr>
"""
        
        html += """
    </table>
</body>
</html>
"""
        return html
    
    def get_scan_stats(self):
        """Get scan statistics"""
        if self.scan_start_time and self.scan_end_time:
            duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        else:
            duration = 0
        
        total_ports = len(self.open_ports) + len(self.closed_ports) + len(self.error_ports)
        
        return {
            'target': self.target,
            'scan_duration': duration,
            'total_ports': total_ports,
            'open_ports': len(self.open_ports),
            'closed_ports': len(self.closed_ports),
            'error_ports': len(self.error_ports),
            'open_percentage': (len(self.open_ports) / total_ports * 100) if total_ports > 0 else 0,
            'ports_per_second': total_ports / duration if duration > 0 else 0
        }
    
    def check_target_info(self):
        """Check detailed information about target system"""
        self.logger.header("Target System Information")
        self.logger.separator()
        
        # Basic target info
        self.logger.info(f"Target: {self.target}")
        
        # DNS Resolution
        try:
            if not self.is_valid_ip(self.target):
                resolved_ip = self.resolve_hostname(self.target)
                self.logger.success(f"DNS Resolution: {self.target} -> {resolved_ip}")
                # Try reverse DNS lookup
                try:
                    reverse_dns = socket.gethostbyaddr(resolved_ip)[0]
                    self.logger.info(f"Reverse DNS: {resolved_ip} -> {reverse_dns}")
                except:
                    self.logger.info("Reverse DNS: Not available")
            else:
                self.logger.info(f"Target is IP address: {self.target}")
                # Try reverse DNS lookup for IP
                try:
                    reverse_dns = socket.gethostbyaddr(self.target)[0]
                    self.logger.info(f"Reverse DNS: {self.target} -> {reverse_dns}")
                except:
                    self.logger.info("Reverse DNS: Not available")
        except Exception as e:
            self.logger.error(f"DNS Resolution failed: {e}")
        
        # Ping test with cross-platform support
        try:
            import subprocess
            import platform
            import re
            
            # Cross-platform ping command
            if platform.system().lower() == 'windows':
                ping_cmd = ['ping', '-n', '4', '-w', '1000']
            elif platform.system().lower() == 'darwin':  # macOS
                ping_cmd = ['ping', '-c', '4', '-W', '1']
            else:  # Linux and others
                ping_cmd = ['ping', '-c', '4', '-W', '1']
            
            ping_cmd.append(self.target)
            
            result = subprocess.run(ping_cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.logger.success("Ping test: SUCCESS")
                # Extract ping statistics with cross-platform regex
                lines = result.stdout.split('\n')
                for line in lines:
                    # Cross-platform time extraction
                    if 'time=' in line or 'time<' in line:
                        # Windows: time=89ms, Linux/macOS: time=89.123 ms
                        time_match = re.search(r'time[=<](\d+(?:\.\d+)?)\s*ms', line)
                        if time_match:
                            ping_time = time_match.group(1)
                            self.logger.info(f"Ping time: {ping_time}ms")
                    elif 'Packets:' in line or 'packets transmitted' in line:
                        self.logger.info(f"Ping stats: {line.strip()}")
                    elif 'TTL=' in line:
                        ttl_match = re.search(r'TTL=(\d+)', line)
                        if ttl_match:
                            ttl = ttl_match.group(1)
                            self.logger.info(f"TTL: {ttl}")
            else:
                self.logger.warning("Ping test: FAILED (host may be blocking ICMP)")
        except Exception as e:
            self.logger.warning(f"Ping test failed: {e}")
        
        # Quick port availability check for --how-is
        open_ports = []
        common_ports = [80, 443, 22, 21, 25, 53]
        
        # Check if user wants to skip port check
        if hasattr(self, 'no_port_check') and self.no_port_check:
            self.logger.info("Port availability check: Skipped (--no-port-check)")
        else:
            self.logger.info("Quick port availability check:")
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((self.target, port))
                    
                    if result == 0:
                        self.logger.success(f"  Port {port} (TCP): OPEN - {self.get_service_name(port)}")
                        open_ports.append(port)
                    else:
                        self.logger.info(f"  Port {port} (TCP): CLOSED - {self.get_service_name(port)}")
                except Exception as e:
                    self.logger.warning(f"  Port {port} (TCP): ERROR - {e}")
                finally:
                    try:
                        sock.close()
                    except:
                        pass
        
        # Network interface info
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            self.logger.info(f"Local system: {hostname} ({local_ip})")
            
            # Get additional network info with cross-platform support
            try:
                if HAS_PSUTIL:
                    # Use psutil for cross-platform network info
                    interfaces = psutil.net_if_addrs()
                    interface_count = len(interfaces)
                    self.logger.info(f"Network interfaces: {interface_count} interfaces found")
                    
                    # Show primary interface info
                    for name, addrs in interfaces.items():
                        for addr in addrs:
                            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                                self.logger.info(f"Primary interface: {name} ({addr.address})")
                                break
                else:
                    # Fallback to command-line tools
                    import platform
                    if platform.system().lower() == 'windows':
                        ipconfig_cmd = ['ipconfig']
                    elif platform.system().lower() == 'darwin':  # macOS
                        ipconfig_cmd = ['ifconfig']
                    else:  # Linux and others
                        ipconfig_cmd = ['ip', 'addr']  # Modern Linux
                    
                    result = subprocess.run(ipconfig_cmd, capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        self.logger.info("Network interfaces: Available")
                    else:
                        # Fallback for older systems
                        if platform.system().lower() != 'windows':
                            fallback_cmd = ['ifconfig']
                            subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=5)
                            self.logger.info("Network interfaces: Available (fallback)")
            except:
                pass
        except Exception as e:
            self.logger.warning(f"Could not get local system info: {e}")
        
        # Route information with cross-platform support
        try:
            import subprocess
            import platform
            
            if platform.system().lower() == 'windows':
                route_cmd = ['route', 'print']
            elif platform.system().lower() == 'darwin':  # macOS
                route_cmd = ['netstat', '-rn']
            else:  # Linux and others
                route_cmd = ['ip', 'route']  # Modern Linux
            
            result = subprocess.run(route_cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                self.logger.info("Network routing information available")
                # Try to extract default gateway
                lines = result.stdout.split('\n')
                for line in lines:
                    if '0.0.0.0' in line or 'default' in line.lower():
                        self.logger.info(f"Default gateway info: {line.strip()[:80]}...")
                        break
            else:
                # Fallback for older systems
                if platform.system().lower() not in ['windows', 'darwin']:
                    fallback_cmd = ['netstat', '-rn']
                    subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=10)
                    self.logger.info("Network routing information available (fallback)")
                else:
                    self.logger.warning("Could not get routing information")
        except Exception as e:
            self.logger.warning(f"Route check failed: {e}")
        
        # Summary
        self.logger.separator()
        self.logger.info("Summary:")
        self.logger.info(f"  - Port scanning: Disabled (use --ports to enable)")
        self.logger.info(f"  - Network connectivity: Available")
        self.logger.info(f"  - WHOIS information: Retrieved")
        
        # WHOIS Information
        self.logger.info("WHOIS Information:")
        whois_info = self.get_whois_info(self.target)
        if whois_info:
            for key, value in whois_info.items():
                if key == 'Raw WHOIS Record (from <pre> tag)' and value:
                    self.logger.info("WHOIS Record:")
                    # Show complete WHOIS record
                    lines = value.split('\n')
                    for line in lines:
                        if line.strip():
                            self.logger.info(f"  {line.strip()}")
                elif len(value) < 200:
                    self.logger.info(f"{key}: {value}")
                else:
                    self.logger.info(f"{key}: {value}")
        else:
            self.logger.warning("WHOIS information not available")
        
        self.logger.separator()
        self.logger.success("Target system information check completed")
    
    def get_whois_info(self, query):
        """
        Fetches WHOIS HTML from whois.com and parses it to extract information.
        
        Args:
            query (str): The domain or IP address for WHOIS lookup
            
        Returns:
            dict: A dictionary containing extracted WHOIS information, or None if an error occurs.
        """
        base_url = "https://www.whois.com/whois/"
        url = f"{base_url}{query}"
        
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            html_content = response.text
            
        except requests.exceptions.RequestException as e:
            self.logger.warning(f"WHOIS request failed: {e}")
            return None
        
        soup = BeautifulSoup(html_content, 'html.parser')
        extracted_data = {}
        
        # Extract Page Title
        title_tag = soup.find('title')
        if title_tag:
            extracted_data['Page Title'] = title_tag.get_text(strip=True)
        
        # Extract Canonical URL
        canonical_link = soup.find('link', rel='canonical')
        if canonical_link and 'href' in canonical_link.attrs:
            extracted_data['Canonical URL'] = canonical_link['href']
        
        # Extract Meta Description
        meta_description = soup.find('meta', attrs={'name': 'description'})
        if meta_description and 'content' in meta_description.attrs:
            extracted_data['Meta Description'] = meta_description['content']
        
        # Extract Open Graph Title
        og_title = soup.find('meta', property='og:title')
        if og_title and 'content' in og_title.attrs:
            extracted_data['OG Title'] = og_title['content']
        
        # Attempt to find the main WHOIS record text
        pre_tag = soup.find('pre')
        if pre_tag:
            extracted_data['Raw WHOIS Record (from <pre> tag)'] = pre_tag.get_text(strip=True)
        else:
            # Fallback if no <pre> tag is found, try other common WHOIS data containers
            whois_results_div = soup.find('div', class_='query-results')
            if whois_results_div:
                extracted_data['WHOIS Data (from .query-results div)'] = whois_results_div.get_text(separator='\n', strip=True)
            else:
                card_body = soup.find('div', class_='card-body')
                if card_body:
                    extracted_data['WHOIS Data (from first .card-body)'] = card_body.get_text(separator='\n', strip=True)
                else:
                    extracted_data['WHOIS Data'] = 'Could not locate specific WHOIS data block.'
        
        return extracted_data

def print_results(open_ports, stats=None):
    """Print scan results in a formatted way"""
    if not open_ports:
        print("No open ports found.")
        return
    
    print("\n" + "=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    print(f"{'Port':<8} {'Service':<15} {'Status':<10} {'Banner'}")
    print("-" * 60)
    
    # Group ports by service category
    service_categories = {
        'WEB SERVICES': [],
        'REMOTE SERVICES': [],
        'DATABASE SERVICES': [],
        'EMAIL SERVICES': [],
        'FILE SERVICES': [],
        'OTHER SERVICES': []
    }
    
    for port_info in sorted(open_ports, key=lambda x: x['port']):
        service = port_info['service']
        if service in ['HTTP', 'HTTPS', 'HTTP-Proxy', 'HTTPS-Alt']:
            service_categories['WEB SERVICES'].append(port_info)
        elif service in ['SSH', 'Telnet', 'RDP', 'VNC']:
            service_categories['REMOTE SERVICES'].append(port_info)
        elif service in ['MySQL', 'PostgreSQL', 'Redis', 'MongoDB', 'MSSQL', 'Oracle']:
            service_categories['DATABASE SERVICES'].append(port_info)
        elif service in ['SMTP', 'POP3', 'IMAP', 'IMAPS', 'POP3S']:
            service_categories['EMAIL SERVICES'].append(port_info)
        elif service in ['FTP']:
            service_categories['FILE SERVICES'].append(port_info)
        else:
            service_categories['OTHER SERVICES'].append(port_info)
    
    # Print each category
    for category, ports in service_categories.items():
        if ports:
            print(f"\n{category}:")
            print("-" * 40)
            for port_info in ports:
                banner = port_info['banner'][:50] + "..." if len(port_info['banner']) > 50 else port_info['banner']
                print(f"{port_info['port']:<8} {port_info['service']:<15} {'BANNER':<10} {banner}")
    
    if stats:
        print("\n" + "=" * 60)
        print("SCAN STATISTICS")
        print("=" * 60)
        print(f"Target: {stats['target']}")
        print(f"Total ports scanned: {stats['total_ports']}")
        print(f"Open ports: {stats['open_ports']}")
        print(f"Closed ports: {stats['closed_ports']}")
        print(f"Error ports: {stats['error_ports']}")
        print(f"Open percentage: {stats['open_percentage']:.2f}%")

def parse_ports(ports_str):
    """Parse ports string (e.g., '1-1000', '80,443,8080', or 'web', 'database')"""
    # Check if it's a predefined port set
    if ports_str.lower() in PORT_SETS:
        ports = PORT_SETS[ports_str.lower()]
        # Return the actual port list for complete scanning
        return ports
    
    ports = []
    
    if ',' in ports_str:
        # Comma-separated ports
        for port_str in ports_str.split(','):
            port_str = port_str.strip()
            if '-' in port_str:
                start, end = map(int, port_str.split('-'))
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError(f"Port range {start}-{end} is invalid")
                ports.extend(range(start, end + 1))
            else:
                port = int(port_str)
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port {port} is invalid")
                ports.append(port)
        return ports
    elif '-' in ports_str:
        # Range of ports
        start, end = map(int, ports_str.split('-'))
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise ValueError(f"Port range {start}-{end} is invalid")
        return list(range(start, end + 1))
    else:
        # Single port
        try:
            port = int(ports_str)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} is invalid")
            return [port]
        except ValueError:
            raise ValueError(f"Invalid port specification: {ports_str}")

def print_help_examples():
    """Print detailed help examples"""
    print("""
EXAMPLES:
  Basic Usage:
    python RedhoodEye.py --target 192.168.1.1
    python RedhoodEye.py --target example.com --ports 80,443,8080
    python RedhoodEye.py --target 10.0.0.1 --ports 1-1000 --threads 100

  System Information (WHOIS + Network Info):
    python RedhoodEye.py --target google.com --how-is
    python RedhoodEye.py --target 192.168.1.1 --how-is
    python RedhoodEye.py --target example.com --how-is --ports 80-443
    python RedhoodEye.py --target google.com --how-is --no-port-check

  Predefined Port Sets:
    python RedhoodEye.py --target 192.168.1.1 --ports web
    python RedhoodEye.py --target 192.168.1.1 --ports database
    python RedhoodEye.py --target 192.168.1.1 --ports remote
    python RedhoodEye.py --target 192.168.1.1 --ports email
    python RedhoodEye.py --target 192.168.1.1 --ports file
    python RedhoodEye.py --target 192.168.1.1 --ports common

  Advanced Usage:
    python RedhoodEye.py --target 192.168.1.1 --ports all --threads 200
    python RedhoodEye.py --target example.com --timeout 5 --verbose
    python RedhoodEye.py --target 192.168.1.1 --output results.json --format json
    python RedhoodEye.py --target 192.168.1.1 --output results.csv --format csv
    python RedhoodEye.py --target 192.168.1.1 --output report.html --format html

  Stealth Scanning:
    python RedhoodEye.py --target 192.168.1.1 --rate-limit 10 --randomize
    python RedhoodEye.py --target 192.168.1.1 --scan-type udp --ports 53,123,161
    python RedhoodEye.py --target 192.168.1.1 --show-closed --verbose

  Multiple Targets:
    python RedhoodEye.py --cidr 192.168.1.0/24 --ports 80,443
    python RedhoodEye.py --target-file targets.txt --ports web
    python RedhoodEye.py --target-file hosts.txt --scan-type udp --ports 53,123,161

  Display Options:
    python RedhoodEye.py --target 192.168.1.1 --no-banner
    python RedhoodEye.py --target 192.168.1.1 --no-colors

  Fast Scan Mode:
    python RedhoodEye.py --target 192.168.1.1 --fast-scan
    python RedhoodEye.py --target 192.168.1.1 --banner-timeout 0.5

  Logging Features:
    python RedhoodEye.py --target 192.168.1.1 --log-file scan.log --log-level DEBUG
    python RedhoodEye.py --target 192.168.1.1 --no-colors

  Proxy Scanning:
    python RedhoodEye.py --target 192.168.1.1 --proxy http://proxy:8080
    python RedhoodEye.py --target 192.168.1.1 --proxy socks5://proxy:1080
    python RedhoodEye.py --target 192.168.1.1 --proxy http://proxy:8080 --proxy-auth user:pass

  Scheduled Scanning:
    python RedhoodEye.py --target 192.168.1.1 --schedule "0 2 * * *" --job-id daily_scan
    python RedhoodEye.py --target 192.168.1.1 --schedule daily --job-id daily_scan
    python RedhoodEye.py --target 192.168.1.1 --schedule hourly --job-id hourly_scan
    python RedhoodEye.py --list-jobs
    python RedhoodEye.py --remove-job daily_scan

PORT SETS:
  web        - Web services (80, 443, 8080, 8443, 3000, 5000, 8000, 9000)
  database   - Database services (3306, 5432, 6379, 27017, 1433, 1521, 2181)
  remote     - Remote access (22, 23, 3389, 5900, 5901, 5902, 5903)
  email      - Email services (25, 110, 143, 465, 587, 993, 995)
  file       - File services (21, 22, 445, 139)
  common     - Common services (21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017)
  all        - All ports (1-65535) - WARNING: Large scan, may trigger thread limitation

OUTPUT FORMATS:
  json       - JSON format (default)
  csv        - CSV format for spreadsheet import
  html       - HTML report with styling

SAFETY FEATURES:
  - Thread limitation: Large scans (>10k ports) with high threads (>200) are limited to 200 threads
  - Resource management: Proper socket cleanup and thread pool shutdown
  - Error handling: Comprehensive network error reporting and recovery
  - Memory efficient: Optimized data structures for large scans

PERFORMANCE TIPS:
  - Use more threads for faster scanning: --threads 200
  - Lower timeout for speed: --timeout 1
  - Higher timeout for reliability: --timeout 10
  - Use --fast-scan for quick banner grabbing
  - Adjust banner-timeout for different network conditions
  - Use specific ports instead of ranges for faster results
  - Use predefined port sets for common scenarios
  - System automatically limits threads for large scans (>10k ports)
  - Use --how-is to check target system connectivity, DNS, and WHOIS info
  - Use --how-is --ports to include quick port scanning with system info
  - Use --rate-limit for stealth scanning to avoid detection
  - Use --randomize to randomize port order for stealth
  - Use --scan-type udp for UDP service detection
  - Use --show-closed to see closed ports in verbose mode
  - Monitor system resources during large scans
  - Use appropriate thread counts based on your system capabilities

WARNING MESSAGES:
  - "Thread count limited to 200 for large scan" - Appears when scanning large port ranges (>10k ports) with high thread counts (>200)
  - This is a safety feature to prevent system overload
  - The warning indicates the system is protecting your resources
""")

def print_banner():
    """Print RedHood banner"""
    try:
        # Check if colors are supported
        try:
            import colorama
            colorama.init()
        except ImportError:
            pass
        
        # Check terminal size for appropriate banner
        try:
            import shutil
            terminal_width = shutil.get_terminal_size().columns
        except:
            terminal_width = 80  # Default width
        
        if terminal_width >= 80:
            # Full banner
            banner = """
\033[91m
██████╗ ███████╗██████╗ ██╗  ██╗ ██████╗ ██████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██║  ██║██╔═══██╗██╔═══██╗██╔══██╗
██████╔╝█████╗  ██║  ██║███████║██║   ██║██║   ██║██║  ██║
██╔══██╗██╔══╝  ██║  ██║██╔══██║██║   ██║██║   ██║██║  ██║
██║  ██║███████╗██████╔╝██║  ██║╚██████╔╝╚██████╔╝██████╔╝
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═════╝
\033[0m
\033[93m╔══════════════════════════════════════════════════════════════════════════════╗
║                              RedhoodEye - Advanced Network Scanner                ║
║                              Advanced Service Detection & UDP Scanning             ║
║                              WHOIS Lookup & Cross-Platform Support               ║
║                              GitHub: https://github.com/0xRedHood                ║
╚══════════════════════════════════════════════════════════════════════════════╝\033[0m
"""
        else:
            # Compact banner for smaller terminals
            banner = """
\033[91m
██████╗ ███████╗██████╗ ██╗  ██╗ ██████╗ ██████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██║  ██║██╔═══██╗██╔═══██╗██╔══██╗
██████╔╝█████╗  ██║  ██║███████║██║   ██║██║   ██║██║  ██║
██╔══██╗██╔══╝  ██║  ██║██╔══██║██║   ██║██║   ██║██║  ██║
██║  ██║███████╗██████╔╝██║  ██║╚██████╔╝╚██████╔╝██████╔╝
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═════╝
\033[0m
\033[93m╔══════════════════════════════════════════════════════════════════════════════╗
║                              RedhoodEye - Advanced Network Scanner                ║
║                              Advanced Service Detection & UDP Scanning             ║
║                              WHOIS Lookup & Cross-Platform Support               ║
║                              GitHub: https://github.com/0xRedHood                ║
╚══════════════════════════════════════════════════════════════════════════════╝\033[0m
"""
        print(banner)
    except:
        # Fallback banner without colors
        banner = """
██████╗ ███████╗██████╗ ██╗  ██╗ ██████╗ ██████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██║  ██║██╔═══██╗██╔═══██╗██╔══██╗
██████╔╝█████╗  ██║  ██║███████║██║   ██║██║   ██║██║  ██║
██╔══██╗██╔══╝  ██║  ██║██╔══██║██║   ██║██║   ██║██║  ██║
██║  ██║███████╗██████╔╝██║  ██║╚██████╔╝╚██████╔╝██████╔╝
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═════╝

╔══════════════════════════════════════════════════════════════════════════════╗
║                              RedhoodEye - Advanced Network Scanner                ║
║                              Advanced Service Detection & UDP Scanning             ║
║                              WHOIS Lookup & Cross-Platform Support               ║
║                              GitHub: https://github.com/0xRedHood                ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
        print(banner)

def main():
    parser = argparse.ArgumentParser(
        description="RedhoodEye - Advanced Network Scanner with Banner Grabbing, Service Detection, and Async Mode",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python RedhoodEye.py --target 192.168.1.1 --ports 1-1000 --threads 100
  python RedhoodEye.py --target example.com --ports web
  python RedhoodEye.py --target 10.0.0.1 --ports database --verbose
  
  # 🚀 Enhanced Async Scan (much faster, advanced detection):
  python RedhoodEye.py --target example.com --ports 1-1000 --Ec
  python RedhoodEye.py --target 192.168.1.1 --ports 80,443,8080 --Ec
  
  # For more info, use --help-examples
        """
    )
    
    parser.add_argument('--target', '-t', required=True,
                       help='Target IP address or hostname')
    parser.add_argument('--ports', '-p', default='1-1000',
                       help='Port range (1-1000), specific ports (80,443,8080), or predefined sets (web,database,remote,email,common,all)')
    parser.add_argument('--threads', default=100, type=int,
                       help='Number of threads (default: 100)')
    parser.add_argument('--timeout', default=3, type=int,
                       help='Connection timeout in seconds (default: 3)')
    parser.add_argument('--banner-timeout', default=1, type=float,
                       help='Banner grabbing timeout in seconds (default: 1)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output - show open ports immediately')
    parser.add_argument('--output', '-o', 
                       help='Save results to file')
    parser.add_argument('--format', choices=['json', 'csv', 'html'], default='json',
                       help='Output format (default: json)')
    parser.add_argument('--fast-scan', action='store_true',
                       help='Fast scan mode - skip initial banner wait')
    parser.add_argument('--help-examples', action='store_true',
                       help='Show detailed examples and port sets')
    parser.add_argument('--log-file',
                       help='Log file path for detailed logging')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO',
                       help='Log level (default: INFO)')
    parser.add_argument('--no-colors', action='store_true',
                       help='Disable colored output')
    parser.add_argument('--how-is', action='store_true',
                       help='Show detailed information about target system (DNS, WHOIS, network connectivity)')
    parser.add_argument('--scan-type', choices=['tcp', 'udp'], default='tcp',
                       help='Scan type: tcp or udp (default: tcp)')
    parser.add_argument('--rate-limit', type=int,
                       help='Rate limit in requests per second (for stealth scanning)')
    parser.add_argument('--randomize', action='store_true',
                       help='Randomize port order for stealth scanning')
    parser.add_argument('--show-closed', action='store_true',
                       help='Show closed ports in verbose output')
    parser.add_argument('--no-port-check', action='store_true',
                       help='Skip port availability check in --how-is mode')
    parser.add_argument('--target-file', 
                       help='File containing list of targets (one per line)')
    parser.add_argument('--cidr', 
                       help='Scan CIDR range (e.g., 192.168.1.0/24)')
    parser.add_argument('--no-banner', action='store_true',
                       help='Disable banner display')
    
    # Proxy options
    parser.add_argument('--proxy', 
                       help='Proxy URL (http://proxy:port, https://proxy:port, socks5://proxy:port)')
    parser.add_argument('--proxy-auth', 
                       help='Proxy authentication (username:password)')
    
    # Scheduling options
    parser.add_argument('--schedule', 
                       help='Schedule scan (cron format: "0 2 * * *" for daily at 2 AM, or "daily", "hourly", "weekly")')
    parser.add_argument('--job-id', 
                       help='Job ID for scheduled scans')
    parser.add_argument('--list-jobs', action='store_true',
                       help='List all scheduled jobs')
    parser.add_argument('--remove-job', 
                       help='Remove scheduled job by ID')
    parser.add_argument('--scheduler-type', choices=['apscheduler', 'schedule'], default='apscheduler',
                       help='Scheduler type (default: apscheduler)')
    
    parser.add_argument('--Ec', action='store_true', help='Use enhanced async scanner')
    
    # Check for help-examples before parsing other arguments
    if '--help-examples' in sys.argv:
        print_help_examples()
        sys.exit(0)
    
    args = parser.parse_args()
    
    # Print banner first (unless disabled)
    if not args.no_banner:
        print_banner()
    
    # Determine target(s)
    if args.target_file:
        target_input = args.target_file
    elif args.cidr:
        target_input = args.cidr
    else:
        target_input = args.target
    
    # Handle scheduling operations
    if args.list_jobs:
        try:
            scheduler = ScheduledScanner(args.scheduler_type)
            jobs = scheduler.list_jobs()
            print("Scheduled jobs:")
            for job in jobs:
                if isinstance(job, dict):
                    print(f"  ID: {job['id']}, Next run: {job['next_run']}")
                else:
                    print(f"  ID: {job}")
        except Exception as e:
            print(f"Error listing jobs: {e}")
        sys.exit(0)
    
    if args.remove_job:
        try:
            scheduler = ScheduledScanner(args.scheduler_type)
            if scheduler.remove_job(args.remove_job):
                print(f"Job {args.remove_job} removed successfully")
            else:
                print(f"Job {args.remove_job} not found")
        except Exception as e:
            print(f"Error removing job: {e}")
        sys.exit(0)
    
    # Handle scheduled scanning
    if args.schedule:
        if not args.job_id:
            print("Error: --job-id is required for scheduled scans")
            sys.exit(1)
        
        try:
            scheduler = ScheduledScanner(args.scheduler_type)
            scanner_kwargs = {
                'timeout': args.timeout,
                'banner_timeout': args.banner_timeout,
                'threads': args.threads,
                'verbose': args.verbose,
                'output_file': args.output,
                'output_format': args.format,
                'fast_scan': args.fast_scan,
                'log_file': args.log_file,
                'log_level': args.log_level,
                'use_colors': not args.no_colors,
                'scan_type': args.scan_type,
                'rate_limit': args.rate_limit,
                'randomize': args.randomize,
                'proxy_url': args.proxy,
                'proxy_auth': args.proxy_auth
            }
            
            if scheduler.add_scan_job(args.job_id, args.target, args.ports, args.schedule, **scanner_kwargs):
                print(f"Scheduled scan job '{args.job_id}' added successfully")
                if args.scheduler_type == 'schedule':
                    print("Starting scheduler (press Ctrl+C to stop)...")
                    scheduler.start_scheduler()
            else:
                print("Failed to add scheduled scan job")
                sys.exit(1)
        except Exception as e:
            print(f"Error setting up scheduled scan: {e}")
            sys.exit(1)
    
    # Create scanner with first target for initialization
    scanner = PortScanner(
        args.target, 
        start_port=1,  # Will be overridden after parsing ports
        end_port=1000,  # Will be overridden after parsing ports
        timeout=args.timeout, 
        banner_timeout=args.banner_timeout,
        threads=args.threads,
        verbose=args.verbose,
        output_file=args.output,
        output_format=args.format,
        fast_scan=args.fast_scan,
        log_file=args.log_file,
        log_level=args.log_level,
        use_colors=not args.no_colors,
        scan_type=args.scan_type,
        rate_limit=args.rate_limit,
        randomize=args.randomize,
        proxy_url=args.proxy,
        proxy_auth=args.proxy_auth
    )
    
    # Store additional arguments for --how-is
    scanner.no_port_check = args.no_port_check
    
    # Parse targets
    targets = scanner.parse_targets(target_input)
    if not targets:
        scanner.logger.error("No valid targets found")
        sys.exit(1)
    
    # For now, use the first target for initialization
    # In a full implementation, you'd want to scan multiple targets
    primary_target = targets[0]
    
    # Resolve hostname if needed
    if not scanner.is_valid_ip(primary_target):
        resolved_ip = scanner.resolve_hostname(primary_target)
        scanner.target = resolved_ip
    else:
        scanner.target = primary_target
    
    # Handle --how-is option
    if args.how_is:
        scanner.check_target_info()
        sys.exit(0)
    
    # Parse ports
    try:
        ports_list = parse_ports(args.ports)
        scanner.start_port = ports_list
        scanner.end_port = None  # Not used in new mode
    except ValueError as e:
        scanner.logger.error(f"Error parsing ports: {e}")
        sys.exit(1)
    
    # Validate ports
    for port in ports_list:
        if not (1 <= port <= 65535):
            scanner.logger.error(f"Port {port} must be between 1 and 65535")
            sys.exit(1)
    
    # Start scanning
    try:
        open_ports = scanner.scan()
        stats = scanner.get_scan_stats()
        print_results(open_ports, stats)
        
        # Summary
        scanner.logger.success(f"Summary: {len(open_ports)} open ports found")
        
    except KeyboardInterrupt:
        scanner.logger.warning("Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        scanner.logger.error(f"Error during scan: {e}")
        sys.exit(1)

def parse_ports_for_async(ports_str):
    if '-' in ports_str:
        start, end = map(int, ports_str.split('-'))
        return list(range(start, end + 1))
    else:
        return [int(p) for p in ports_str.split(',') if p.strip().isdigit()]

async def run_enhanced_scan(args):
    ports = parse_ports_for_async(args.ports)
    scanner = AsyncPortScanner(
        target=args.target,
        ports=ports,
        max_concurrent=args.threads if hasattr(args, 'threads') else 100,
        timeout=args.timeout if hasattr(args, 'timeout') else 5.0,
        use_advanced_detection=True
    )
    print(f"🔍 Enhanced Async Scan: {args.target} Ports: {ports[0]}-{ports[-1]}")
    results = await scanner.scan()
    for result in results:
        if result.service_name not in ['closed', 'timeout', 'error']:
            print(f"Port {result.port}/{result.protocol}: {result.service_name} {result.version or ''}")
            if result.banner:
                print(f"  Banner: {result.banner[:100]}")
            if result.ssl_info:
                print(f"  SSL: {result.ssl_info['cipher']['name']}")

if __name__ == "__main__":
    main() 