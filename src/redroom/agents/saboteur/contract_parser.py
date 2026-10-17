"""Parser for OpenAPI specs and security contracts."""

import yaml
import json
from typing import Dict, List, Any, Optional
import structlog

logger = structlog.get_logger()


class ContractParser:
    """Parses OpenAPI specifications and security contracts."""
    
    def __init__(self):
        """Initialize contract parser."""
        logger.info("contract_parser_initialized")
    
    def parse_openapi_spec(self, spec: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse OpenAPI specification.
        
        Args:
            spec: OpenAPI specification dictionary
            
        Returns:
            Parsed specification with endpoints and schemas
        """
        parsed = {
            "endpoints": [],
            "schemas": {},
            "security_schemes": []
        }
        
        # Extract endpoints
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method in ["get", "post", "put", "delete", "patch"]:
                    endpoint = {
                        "path": path,
                        "method": method.upper(),
                        "summary": details.get("summary", ""),
                        "description": details.get("description", ""),
                        "parameters": details.get("parameters", []),
                        "request_body": details.get("requestBody", {}),
                        "responses": details.get("responses", {})
                    }
                    parsed["endpoints"].append(endpoint)
        
        # Extract schemas
        components = spec.get("components", {})
        parsed["schemas"] = components.get("schemas", {})
        parsed["security_schemes"] = components.get("securitySchemes", {})
        
        logger.info(
            "openapi_parsed",
            endpoints=len(parsed["endpoints"]),
            schemas=len(parsed["schemas"])
        )
        
        return parsed
    
    def parse_security_contracts(self, contracts: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Parse security contracts.
        
        Args:
            contracts: Security contracts dictionary
            
        Returns:
            List of parsed contracts
        """
        parsed_contracts = []
        
        for contract in contracts.get("security_contracts", []):
            parsed = {
                "endpoint": contract.get("endpoint"),
                "method": contract.get("method"),
                "invariants": []
            }
            
            for invariant in contract.get("invariants", []):
                parsed["invariants"].append({
                    "name": invariant.get("name"),
                    "description": invariant.get("description"),
                    "rule": invariant.get("rule"),
                    "severity": invariant.get("severity", "medium")
                })
            
            parsed_contracts.append(parsed)
        
        logger.info("security_contracts_parsed", count=len(parsed_contracts))
        return parsed_contracts
    
    def match_endpoint_to_contract(
        self,
        endpoint: str,
        method: str,
        contracts: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Match an endpoint to its security contract.
        
        Args:
            endpoint: API endpoint path
            method: HTTP method
            contracts: List of security contracts
            
        Returns:
            Matching contract or None
        """
        for contract in contracts:
            if contract["endpoint"] == endpoint and contract["method"] == method:
                return contract
        
        return None
    
    def extract_invariants(self, contract: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Extract invariants from a contract.
        
        Args:
            contract: Security contract
            
        Returns:
            List of invariants
        """
        return contract.get("invariants", [])
    
    def validate_against_contract(
        self,
        code: str,
        contract: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Validate code against security contract.
        
        Args:
            code: Source code to validate
            contract: Security contract
            
        Returns:
            List of violations
        """
        violations = []
        
        for invariant in contract.get("invariants", []):
            rule = invariant.get("rule", "")
            
            # Check for atomic operations
            if "atomic" in rule.lower():
                if "asyncio.sleep" in code or "time.sleep" in code:
                    violations.append({
                        "invariant": invariant["name"],
                        "severity": invariant["severity"],
                        "description": f"Violation: {invariant['description']}",
                        "rule": rule
                    })
            
            # Check for balance constraints
            if "balance" in rule.lower() and ">= 0" in rule:
                if "balance -" in code and "if balance >=" not in code:
                    violations.append({
                        "invariant": invariant["name"],
                        "severity": invariant["severity"],
                        "description": f"Violation: {invariant['description']}",
                        "rule": rule
                    })
            
            # Check for idempotency
            if "idempotent" in rule.lower():
                if "POST" in code or "PUT" in code:
                    violations.append({
                        "invariant": invariant["name"],
                        "severity": invariant["severity"],
                        "description": f"Potential violation: {invariant['description']}",
                        "rule": rule
                    })
        
        logger.info("contract_validation_complete", violations=len(violations))
        return violations
    
    def generate_test_cases(self, contract: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate test cases from security contract.
        
        Args:
            contract: Security contract
            
        Returns:
            List of test cases
        """
        test_cases = []
        
        for invariant in contract.get("invariants", []):
            test_case = {
                "name": f"test_{invariant['name']}",
                "description": f"Verify {invariant['description']}",
                "endpoint": contract["endpoint"],
                "method": contract["method"],
                "expected_behavior": invariant["rule"],
                "severity": invariant["severity"]
            }
            test_cases.append(test_case)
        
        return test_cases
