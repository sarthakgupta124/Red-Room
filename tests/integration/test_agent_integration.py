"""Integration tests for agent interactions."""

import pytest
from redroom.agents.saboteur.hypothesis_generator import HypothesisGenerator
from redroom.agents.exploit_lab.exploit_generator import ExploitGenerator
from redroom.agents.surgeon.patch_generator import PatchGenerator
from redroom.models.schemas import VulnerabilityType


@pytest.mark.asyncio
async def test_saboteur_to_exploit_lab():
    """Test data flow from Saboteur to Exploit Lab."""
    
    # Generate hypothesis
    saboteur = HypothesisGenerator(model_path="/models/test.onnx")
    
    git_diff = """
+    balance = result[0]
+    if balance >= request.amount:
+        await asyncio.sleep(0.1)
+        cursor.execute("UPDATE accounts SET balance = balance - ?")
"""
    
    hypothesis = await saboteur.analyze_diff(git_diff)
    
    assert hypothesis is not None
    
    # Generate exploit from hypothesis
    exploit_lab = ExploitGenerator(gpu_enabled=False)
    exploit_script = await exploit_lab.generate_exploit(hypothesis)
    
    assert exploit_script is not None
    assert "asyncio" in exploit_script
    assert "httpx" in exploit_script


@pytest.mark.asyncio
async def test_exploit_lab_to_surgeon():
    """Test data flow from Exploit Lab to Surgeon."""
    
    # Create mock exploit result
    from redroom.models.schemas import ExploitResult
    
    exploit_result = ExploitResult(
        exploit_successful=True,
        evidence={
            "http": {"total_requests": 10, "successful": 5},
            "database": {"violations": [{"type": "negative_balance"}]}
        },
        reproducibility_score=1.0,
        execution_time_ms=150,
        shadow_namespace="shadow-test"
    )
    
    # Generate patch
    surgeon = PatchGenerator(llm_provider="mock")
    patch_result = await surgeon.generate_patch(
        vulnerable_code="# vulnerable code",
        exploit_result=exploit_result
    )
    
    assert patch_result is not None
    assert patch_result.patch is not None
    assert patch_result.explanation is not None


@pytest.mark.asyncio
async def test_end_to_end_agent_flow():
    """Test complete agent flow."""
    
    # Step 1: Saboteur analyzes code
    saboteur = HypothesisGenerator(model_path="/models/test.onnx")
    
    git_diff = """
+    balance = result[0]
+    if balance >= request.amount:
+        await asyncio.sleep(0.1)
"""
    
    hypothesis = await saboteur.analyze_diff(git_diff)
    
    if hypothesis and hypothesis.confidence_score > 0.7:
        # Step 2: Exploit Lab generates and executes exploit
        exploit_lab = ExploitGenerator(gpu_enabled=False)
        exploit_script = await exploit_lab.generate_exploit(hypothesis)
        
        # Validate script
        assert exploit_lab.validate_exploit_script(exploit_script)
        
        # Step 3: Surgeon generates patch
        from redroom.models.schemas import ExploitResult
        
        mock_result = ExploitResult(
            exploit_successful=True,
            evidence={},
            reproducibility_score=1.0,
            execution_time_ms=100,
            shadow_namespace="test"
        )
        
        surgeon = PatchGenerator()
        patch_result = await surgeon.generate_patch(git_diff, mock_result)
        
        assert patch_result is not None
        assert "transaction" in patch_result.patch.lower() or "atomic" in patch_result.explanation.lower()
