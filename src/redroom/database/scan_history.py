"""Scan history database management for The Red Room."""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path
import structlog

logger = structlog.get_logger()


class ScanHistoryDB:
    """Manages scan history in SQLite database."""
    
    def __init__(self, db_path: str = "redroom_scans.db"):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self._init_database()
        logger.info("scan_history_db_initialized", db_path=db_path)
    
    def _init_database(self):
        """Create database tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_url TEXT NOT NULL,
                    scan_date TIMESTAMP NOT NULL,
                    duration_seconds REAL,
                    endpoints_found INTEGER,
                    vulnerabilities_found INTEGER,
                    critical_count INTEGER,
                    high_count INTEGER,
                    medium_count INTEGER,
                    low_count INTEGER,
                    status TEXT,
                    report_text TEXT
                )
            """)
            
            # Vulnerabilities table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    vuln_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    endpoint TEXT,
                    method TEXT,
                    payload TEXT,
                    evidence TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)
            
            # Endpoints table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS endpoints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    method TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id)
                )
            """)
            
            # Create indexes for better query performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_target 
                ON scans(target_url)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_date 
                ON scans(scan_date DESC)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_vulns_scan 
                ON vulnerabilities(scan_id)
            """)
            
            conn.commit()
            logger.info("database_tables_initialized")
    
    def save_scan(self, scan_results: Dict[str, Any], report: str, 
                  duration: float = 0) -> int:
        """
        Save scan results to database.
        
        Args:
            scan_results: Scan results dictionary
            report: Full text report
            duration: Scan duration in seconds
            
        Returns:
            Scan ID
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Count vulnerabilities by severity
            vulnerabilities = scan_results.get('vulnerabilities', [])
            severity_counts = {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
            
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'LOW')
                if severity in severity_counts:
                    severity_counts[severity] += 1
            
            # Insert scan record
            cursor.execute("""
                INSERT INTO scans (
                    target_url, scan_date, duration_seconds,
                    endpoints_found, vulnerabilities_found,
                    critical_count, high_count, medium_count, low_count,
                    status, report_text
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_results.get('base_url'),
                datetime.now(),
                duration,
                scan_results.get('endpoints_found', 0),
                scan_results.get('vulnerabilities_found', 0),
                severity_counts['CRITICAL'],
                severity_counts['HIGH'],
                severity_counts['MEDIUM'],
                severity_counts['LOW'],
                'completed',
                report
            ))
            
            scan_id = cursor.lastrowid
            
            # Insert vulnerabilities
            for vuln in vulnerabilities:
                cursor.execute("""
                    INSERT INTO vulnerabilities (
                        scan_id, vuln_type, severity, endpoint,
                        method, payload, evidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    vuln.get('type'),
                    vuln.get('severity'),
                    vuln.get('endpoint'),
                    vuln.get('method'),
                    vuln.get('payload'),
                    vuln.get('evidence')
                ))
            
            # Insert endpoints
            for endpoint in scan_results.get('endpoints', []):
                cursor.execute("""
                    INSERT INTO endpoints (scan_id, path, method)
                    VALUES (?, ?, ?)
                """, (
                    scan_id,
                    endpoint.get('path'),
                    endpoint.get('method')
                ))
            
            conn.commit()
            logger.info("scan_saved", scan_id=scan_id, 
                       vulnerabilities=len(vulnerabilities))
            
            return scan_id
    
    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Get scan by ID.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Scan data or None
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get scan record
            cursor.execute("""
                SELECT * FROM scans WHERE id = ?
            """, (scan_id,))
            
            scan_row = cursor.fetchone()
            if not scan_row:
                return None
            
            scan = dict(scan_row)
            
            # Get vulnerabilities
            cursor.execute("""
                SELECT * FROM vulnerabilities WHERE scan_id = ?
            """, (scan_id,))
            
            scan['vulnerabilities'] = [dict(row) for row in cursor.fetchall()]
            
            # Get endpoints
            cursor.execute("""
                SELECT * FROM endpoints WHERE scan_id = ?
            """, (scan_id,))
            
            scan['endpoints'] = [dict(row) for row in cursor.fetchall()]
            
            return scan
    
    def get_all_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get all scans ordered by date (newest first).
        
        Args:
            limit: Maximum number of scans to return
            
        Returns:
            List of scan summaries
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    id, target_url, scan_date, duration_seconds,
                    endpoints_found, vulnerabilities_found,
                    critical_count, high_count, medium_count, low_count,
                    status
                FROM scans
                ORDER BY scan_date DESC
                LIMIT ?
            """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_scans_by_target(self, target_url: str) -> List[Dict[str, Any]]:
        """
        Get all scans for a specific target.
        
        Args:
            target_url: Target URL
            
        Returns:
            List of scans for the target
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 
                    id, target_url, scan_date, duration_seconds,
                    endpoints_found, vulnerabilities_found,
                    critical_count, high_count, medium_count, low_count,
                    status
                FROM scans
                WHERE target_url = ?
                ORDER BY scan_date DESC
            """, (target_url,))
            
            return [dict(row) for row in cursor.fetchall()]
    
    def compare_scans(self, scan_id1: int, scan_id2: int) -> Dict[str, Any]:
        """
        Compare two scans.
        
        Args:
            scan_id1: First scan ID
            scan_id2: Second scan ID
            
        Returns:
            Comparison data
        """
        scan1 = self.get_scan(scan_id1)
        scan2 = self.get_scan(scan_id2)
        
        if not scan1 or not scan2:
            return {}
        
        # Calculate differences
        comparison = {
            'scan1': {
                'id': scan_id1,
                'date': scan1['scan_date'],
                'vulnerabilities': scan1['vulnerabilities_found'],
                'critical': scan1['critical_count'],
                'high': scan1['high_count'],
                'medium': scan1['medium_count'],
                'low': scan1['low_count']
            },
            'scan2': {
                'id': scan_id2,
                'date': scan2['scan_date'],
                'vulnerabilities': scan2['vulnerabilities_found'],
                'critical': scan2['critical_count'],
                'high': scan2['high_count'],
                'medium': scan2['medium_count'],
                'low': scan2['low_count']
            },
            'changes': {
                'vulnerabilities': scan2['vulnerabilities_found'] - scan1['vulnerabilities_found'],
                'critical': scan2['critical_count'] - scan1['critical_count'],
                'high': scan2['high_count'] - scan1['high_count'],
                'medium': scan2['medium_count'] - scan1['medium_count'],
                'low': scan2['low_count'] - scan1['low_count']
            }
        }
        
        # Determine if security improved
        total_change = comparison['changes']['vulnerabilities']
        comparison['improved'] = total_change < 0
        comparison['worsened'] = total_change > 0
        comparison['unchanged'] = total_change == 0
        
        return comparison
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get overall statistics.
        
        Returns:
            Statistics dictionary
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Total scans
            cursor.execute("SELECT COUNT(*) FROM scans")
            total_scans = cursor.fetchone()[0]
            
            # Total vulnerabilities
            cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
            total_vulnerabilities = cursor.fetchone()[0]
            
            # Vulnerabilities by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities
                GROUP BY severity
            """)
            severity_counts = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Most scanned targets
            cursor.execute("""
                SELECT target_url, COUNT(*) as scan_count
                FROM scans
                GROUP BY target_url
                ORDER BY scan_count DESC
                LIMIT 5
            """)
            top_targets = [
                {'url': row[0], 'count': row[1]} 
                for row in cursor.fetchall()
            ]
            
            # Most common vulnerabilities
            cursor.execute("""
                SELECT vuln_type, COUNT(*) as count
                FROM vulnerabilities
                GROUP BY vuln_type
                ORDER BY count DESC
                LIMIT 10
            """)
            top_vulnerabilities = [
                {'type': row[0], 'count': row[1]} 
                for row in cursor.fetchall()
            ]
            
            return {
                'total_scans': total_scans,
                'total_vulnerabilities': total_vulnerabilities,
                'severity_counts': severity_counts,
                'top_targets': top_targets,
                'top_vulnerabilities': top_vulnerabilities
            }
    
    def delete_scan(self, scan_id: int) -> bool:
        """
        Delete a scan and all related data.
        
        Args:
            scan_id: Scan ID to delete
            
        Returns:
            True if deleted, False otherwise
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Delete vulnerabilities
            cursor.execute("DELETE FROM vulnerabilities WHERE scan_id = ?", (scan_id,))
            
            # Delete endpoints
            cursor.execute("DELETE FROM endpoints WHERE scan_id = ?", (scan_id,))
            
            # Delete scan
            cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
            
            conn.commit()
            
            deleted = cursor.rowcount > 0
            if deleted:
                logger.info("scan_deleted", scan_id=scan_id)
            
            return deleted
