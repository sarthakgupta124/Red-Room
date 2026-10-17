"""Unit tests for hypothesis generator."""

import pytest
from redroom.agents.saboteur.hypothesis_generator import HypothesisGenerator
from redroom.models.schemas import VulnerabilityType


@pytest.mark.asyncio
async def test_race_condition_detection():
    """Test detection of race condition vulnerability."""
    generator = HypothesisGenerator(model_path="/models/test.onnx")
    
    git_diff = """
    +    balance = result[0]
    +    if balance >= request.amount:
    +        await asyncio.sleep(0.1)
    +        cursor.execute("UPDATE accounts SET balance = balance - ?")
    """
    
    hypothesis = await generator.analyze_diff(git_diff)
    
    assert hypothesis is not None
    assert hypothesis.vulnerability_type == VulnerabilityType.RACE_CONDITION
    assert hypothesis.confidence_score > 0.8


@pytest.mark.asyncio
async def test_no_vulnerability():
    """Test that safe code doesn't generate hypothesis."""
    generator = HypothesisGenerator(model_path="/models/test.onnx")
    
    git_diff = """
    +    # Safe atomic transaction
    +    cursor.execute("BEGIN IMMEDIATE")
    +    cursor.execute("UPDATE accounts SET balance = balance - ? WHERE account_id = ?")
    """
    
    hypothesis = await generator.analyze_diff(git_diff)
    
    # Should not detect vulnerability in safe code
    # (This is a placeholder - actual implementation may vary)
    assert hypothesis is None or hypothesis.confidence_score < 0.5
