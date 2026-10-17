"""Unit tests for orchestrator."""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from redroom.orchestrator.langgraph_engine import RedRoomOrchestrator
from redroom.models.schemas import AgentStatus, VulnerabilityType


@pytest.mark.asyncio
async def test_orchestrator_initialization():
    """Test orchestrator initializes correctly."""
    orchestrator = RedRoomOrchestrator(
        saboteur_enabled=True,
        exploit_lab_enabled=True,
        surgeon_enabled=True
    )
    
    assert orchestrator.saboteur_enabled is True
    assert orchestrator.exploit_lab_enabled is True
    assert orchestrator.surgeon_enabled is True
    assert orchestrator.max_retries == 3


@pytest.mark.asyncio
async def test_orchestrator_workflow_no_vulnerability():
    """Test workflow when no vulnerability is detected."""
    orchestrator = RedRoomOrchestrator()
    
    # Mock the saboteur to return no hypothesis
    with patch('redroom.agents.saboteur.hypothesis_generator.HypothesisGenerator') as mock_gen:
        mock_instance = AsyncMock()
        mock_instance.analyze_diff.return_value = None
        mock_gen.return_value = mock_instance
        
        result = await orchestrator.execute(
            execution_id="test-123",
            git_commit="abc123",
            git_diff="+ some safe code"
        )
        
        assert result.execution_id == "test-123"
        assert result.hypothesis is None
        # Should skip exploit and patch


@pytest.mark.asyncio
async def test_should_exploit_low_confidence():
    """Test that low confidence hypotheses are skipped."""
    orchestrator = RedRoomOrchestrator()
    
    from redroom.models.schemas import Hypothesis
    
    state = {
        "execution_id": "test-123",
        "hypothesis": Hypothesis(
            vulnerability_type=VulnerabilityType.RACE_CONDITION,
            confidence_score=0.5,  # Below threshold
            affected_endpoints=["/test"],
            invariant_break={},
            attack_hypothesis={}
        )
    }
    
    decision = orchestrator._should_exploit(state)
    assert decision == "skip"


@pytest.mark.asyncio
async def test_should_exploit_high_confidence():
    """Test that high confidence hypotheses proceed to exploit."""
    orchestrator = RedRoomOrchestrator()
    
    from redroom.models.schemas import Hypothesis
    
    state = {
        "execution_id": "test-123",
        "hypothesis": Hypothesis(
            vulnerability_type=VulnerabilityType.RACE_CONDITION,
            confidence_score=0.95,  # Above threshold
            affected_endpoints=["/test"],
            invariant_break={},
            attack_hypothesis={}
        )
    }
    
    decision = orchestrator._should_exploit(state)
    assert decision == "exploit"
