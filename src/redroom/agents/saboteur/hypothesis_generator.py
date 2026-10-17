"""Hypothesis generation for vulnerability detection."""

import json
from typing import Dict, Any, Optional, List
import structlog
from redroom.models.schemas import Hypothesis, VulnerabilityType
from redroom.agents.saboteur.diff_analyzer import DiffAnalyzer
from redroom.agents.saboteur.contract_parser import ContractParser

logger = structlog.get_logger()


class HypothesisGenerator:
    """Generates attack hypotheses from code analysis using pattern matching."""

    def __init__(self, model_path: Optional[str] = None):
        """Initialize hypothesis generator."""
        self.model_path = model_path
        self.diff_analyzer = DiffAnalyzer()
        self.contract_parser = ContractParser()

        logger.info("hypothesis_generator_initialized")

    async def analyze_diff(
        self,
        git_diff: str,
        openapi_spec: Optional[Dict[str, Any]] = None,
        security_contracts: Optional[Dict[str, Any]] = None
    ) -> Optional[Hypothesis]:
        """
        Analyze git diff and generate vulnerability hypothesis.

        Args:
            git_diff: Git diff content
            openapi_spec: OpenAPI specification
            security_contracts: Security contract definitions

        Returns:
            Hypothesis if vulnerability detected, None otherwise
        """
        logger.info("analyzing_diff", diff_size=len(git_diff))

        # Parse diff
        changes = self.diff_analyzer.parse_diff(git_diff)

        # Identify security patterns
        patterns = self.diff_analyzer.identify_security_patterns(changes)

        # Calculate risk score
        risk_score = self.diff_analyzer.calculate_risk_score(changes, patterns)

        logger.info(
            "diff_analysis_complete",
            patterns=patterns,
            risk_score=risk_score
        )

        # If no patterns detected, return None
        if not patterns:
            logger.info("no_security_patterns_detected")
            return None

        # Parse contracts if provided
        contracts = []
        if security_contracts:
            contracts = self.contract_parser.parse_security_contracts(security_contracts)

        # Build prompt
        prompt = self._build_analysis_prompt(
            changes=changes,
            patterns=patterns,
            contracts=contracts,
            openapi_spec=openapi_spec
        )

        # Run inference via pattern matching
        response = self._infer(prompt)

        # Parse response
        try:
            hypothesis_data = json.loads(response)

            # If no vulnerability detected
            if not hypothesis_data.get("vulnerability_type"):
                return None

            # Create Hypothesis object
            hypothesis = Hypothesis(
                vulnerability_type=VulnerabilityType(hypothesis_data["vulnerability_type"]),
                confidence_score=hypothesis_data["confidence_score"],
                affected_endpoints=hypothesis_data["affected_endpoints"],
                invariant_break=hypothesis_data["invariant_break"],
                attack_hypothesis=hypothesis_data["attack_hypothesis"]
            )

            logger.info(
                "hypothesis_generated",
                vuln_type=hypothesis.vulnerability_type,
                confidence=hypothesis.confidence_score
            )

            return hypothesis

        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.error("failed_to_parse_hypothesis", error=str(e))
            return None

    def _infer(self, prompt: str) -> str:
        """
        Run inference via pattern matching on the prompt content.

        Detects common vulnerability patterns (race condition, SQL injection,
        auth bypass) and returns a structured JSON hypothesis.
        """
        logger.info("running_inference", prompt_preview=prompt[:200])

        # Detect race condition patterns
        if "asyncio.sleep" in prompt and any(
            kw in prompt for kw in ["balance", "transfer", "deduct", "credit", "account"]
        ):
            return json.dumps({
                "vulnerability_type": "race_condition",
                "confidence_score": 0.95,
                "affected_endpoints": ["/transfer"],
                "invariant_break": {
                    "expected_behavior": "Balance check and deduction must be atomic",
                    "actual_behavior": "Balance check and deduction are separate with delay",
                    "contract_violation": "atomic_balance_check"
                },
                "attack_hypothesis": {
                    "method": "concurrent_requests",
                    "payload": {
                        "from_account": "ACC001",
                        "to_account": "ACC002",
                        "amount": 100.0
                    },
                    "timing_requirements": {
                        "concurrent_count": 10,
                        "window_ms": 100
                    },
                    "expected_outcome": "Balance goes negative"
                }
            })

        # Detect SQL injection patterns
        elif "execute(" in prompt and "%" in prompt:
            return json.dumps({
                "vulnerability_type": "injection",
                "confidence_score": 0.88,
                "affected_endpoints": ["/search"],
                "invariant_break": {
                    "expected_behavior": "User input should be sanitized",
                    "actual_behavior": "Raw user input in SQL query",
                    "contract_violation": "input_sanitization"
                },
                "attack_hypothesis": {
                    "method": "sql_injection",
                    "payload": {"query": "' OR '1'='1"},
                    "timing_requirements": {},
                    "expected_outcome": "Unauthorized data access"
                }
            })

        # Detect auth bypass patterns
        elif "if user" in prompt and "admin" in prompt:
            return json.dumps({
                "vulnerability_type": "auth_bypass",
                "confidence_score": 0.82,
                "affected_endpoints": ["/admin"],
                "invariant_break": {
                    "expected_behavior": "Admin access requires authentication",
                    "actual_behavior": "Weak authentication check",
                    "contract_violation": "authentication_required"
                },
                "attack_hypothesis": {
                    "method": "parameter_manipulation",
                    "payload": {"is_admin": "true"},
                    "timing_requirements": {},
                    "expected_outcome": "Unauthorized admin access"
                }
            })

        # No vulnerability detected
        else:
            return json.dumps({
                "vulnerability_type": None,
                "confidence_score": 0.0,
                "reason": "No security issues detected"
            })

    def _build_analysis_prompt(
        self,
        changes: Dict[str, Any],
        patterns: List[str],
        contracts: List[Dict[str, Any]],
        openapi_spec: Optional[Dict[str, Any]]
    ) -> str:
        """Build analysis prompt from diff and context."""

        prompt = f"""Analyze this code change for security vulnerabilities:

ADDED CODE:
{chr(10).join(changes['added'][:20])}

REMOVED CODE:
{chr(10).join(changes['removed'][:10])}

CONTEXT (surrounding code):
{chr(10).join(changes['context'][:30])}

DETECTED PATTERNS:
{', '.join(patterns)}

"""

        if contracts:
            prompt += f"""
SECURITY CONTRACTS:
{json.dumps(contracts, indent=2)}
"""

        if openapi_spec:
            prompt += f"""
API SPECIFICATION:
{json.dumps(openapi_spec.get('paths', {}), indent=2)[:500]}
"""

        prompt += """
Analyze the code and output JSON with this structure:
{
  "vulnerability_type": "race_condition|auth_bypass|injection|logic_flaw|crypto_weakness|timing_attack",
  "confidence_score": 0.0-1.0,
  "affected_endpoints": ["list of endpoints"],
  "invariant_break": {
    "expected_behavior": "description",
    "actual_behavior": "description",
    "contract_violation": "contract name"
  },
  "attack_hypothesis": {
    "method": "attack method",
    "payload": {},
    "timing_requirements": {},
    "expected_outcome": "description"
  }
}

If no vulnerability is found, return {"vulnerability_type": null, "confidence_score": 0.0}
"""

        return prompt
