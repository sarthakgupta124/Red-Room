"""Integration tests for full Red Room pipeline."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from redroom.orchestrator.langgraph_engine import RedRoomOrchestrator
from redroom.models.schemas import VulnerabilityType


@pytest.mark.asyncio
async def test_full_pipeline_race_condition():
    """Test complete pipeline with race condition vulnerability."""
    
    # Sample git diff with race condition
    git_diff = """
+++ b/app.py
@@ -45,10 +45,12 @@ async def transfer_funds(request: TransferRequest):
+    balance = result[0]
+    if balance >= request.amount:
+        await asyncio.sleep(0.1)
+        cursor.execute("UPDATE accounts SET balance = balance - ?")
"""
    
    with patch('redroom.infrastructure.namespace_lifecycle.subprocess.run'):
        orchestrator = RedRoomOrchestrator()
        
        result = await orchestrator.execute(
            execution_id="test-integration-001",
            git_commit="abc123",
            git_diff=git_diff
        )
        
        # Verify hypothesis was generated
        assert result.hypothesis is not None
        assert result.hypothesis.vulnerability_type == VulnerabilityType.RACE_CONDITION
        assert result.hypothesis.confidence_score > 0.7
        
        # Verify exploit was attempted
        assert result.exploit_result is not None
        
        # Verify patch was generated
        assert result.patch_result is not None
        assert "transaction" in result.patch_result.patch.lower()


@pytest.mark.asyncio
async def test_pipeline_no_vulnerability():
    """Test pipeline with safe code."""
    
    git_diff = """
+++ b/app.py
@@ -10,5 +10,7 @@ def safe_function():
+    # Safe code with no vulnerabilities
+    return "Hello World"
"""
    
    with patch('redroom.infrastructure.namespace_lifecycle.subprocess.run'):
        orchestrator = RedRoomOrchestrator()
        
        result = await orchestrator.execute(
            execution_id="test-integration-002",
            git_commit="def456",
            git_diff=git_diff
        )
        
        # Should not generate hypothesis for safe code
        assert result.hypothesis is None or result.hypothesis.confidence_score < 0.7


@pytest.mark.asyncio
async def test_pipeline_with_contracts():
    """Test pipeline with security contracts."""
    
    git_diff = """
+++ b/app.py
@@ -45,10 +45,12 @@ async def transfer_funds(request: TransferRequest):
+    balance = result[0]
+    if balance >= request.amount:
+        await asyncio.sleep(0.1)
"""
    
    security_contracts = {
        "security_contracts": [
            {
                "endpoint": "/transfer",
                "method": "POST",
                "invariants": [
                    {
                        "name": "atomic_balance_check",
                        "description": "Balance check must be atomic",
                        "rule": "atomic operation required",
                        "severity": "critical"
                    }
                ]
            }
        ]
    }
    
    with patch('redroom.infrastructure.namespace_lifecycle.subprocess.run'):
        orchestrator = RedRoomOrchestrator()
        
        result = await orchestrator.execute(
            execution_id="test-integration-003",
            git_commit="ghi789",
            git_diff=git_diff,
            security_contracts=security_contracts
        )
        
        assert result.hypothesis is not None
        assert "atomic" in result.hypothesis.invariant_break.get("contract_violation", "").lower()


@pytest.mark.asyncio
async def test_pipeline_error_handling():
    """Test pipeline error handling."""
    
    # Invalid git diff
    git_diff = ""
    
    with patch('redroom.infrastructure.namespace_lifecycle.subprocess.run'):
        orchestrator = RedRoomOrchestrator()
        
        result = await orchestrator.execute(
            execution_id="test-integration-004",
            git_commit="jkl012",
            git_diff=git_diff
        )
        
        # Should handle gracefully
        assert result is not None
