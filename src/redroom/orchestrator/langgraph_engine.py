"""LangGraph orchestration engine for The Red Room."""

from typing import TypedDict, Optional, Annotated
from langgraph.graph import StateGraph, END
import structlog
from datetime import datetime

from redroom.models.schemas import (
    Hypothesis,
    ExploitResult,
    PatchResult,
    AgentStatus,
    ExecutionState
)

logger = structlog.get_logger()


class RedRoomState(TypedDict):
    """State for The Red Room workflow."""
    execution_id: str
    git_commit: str
    git_diff: str
    openapi_spec: Optional[dict]
    security_contracts: Optional[dict]
    
    # Agent outputs
    hypothesis: Optional[Hypothesis]
    exploit_result: Optional[ExploitResult]
    patch_result: Optional[PatchResult]
    
    # Status tracking
    status: AgentStatus
    error: Optional[str]
    retry_count: int
    
    # Timestamps
    started_at: str
    updated_at: str


class RedRoomOrchestrator:
    """Orchestrates the three-agent workflow."""
    
    def __init__(
        self,
        saboteur_enabled: bool = True,
        exploit_lab_enabled: bool = True,
        surgeon_enabled: bool = True,
        max_retries: int = 3
    ):
        """Initialize orchestrator."""
        self.saboteur_enabled = saboteur_enabled
        self.exploit_lab_enabled = exploit_lab_enabled
        self.surgeon_enabled = surgeon_enabled
        self.max_retries = max_retries
        
        self.workflow = self._build_workflow()
        logger.info(
            "orchestrator_initialized",
            saboteur=saboteur_enabled,
            exploit_lab=exploit_lab_enabled,
            surgeon=surgeon_enabled
        )
    
    def _build_workflow(self) -> StateGraph:
        """Build the LangGraph workflow."""
        workflow = StateGraph(RedRoomState)
        
        # Add nodes
        workflow.add_node("saboteur", self._run_saboteur)
        workflow.add_node("exploit_lab", self._run_exploit_lab)
        workflow.add_node("surgeon", self._run_surgeon)
        workflow.add_node("handle_error", self._handle_error)
        
        # Define conditional edges
        workflow.add_conditional_edges(
            "saboteur",
            self._should_exploit,
            {
                "exploit": "exploit_lab",
                "skip": END,
                "error": "handle_error"
            }
        )
        
        workflow.add_conditional_edges(
            "exploit_lab",
            self._should_patch,
            {
                "patch": "surgeon",
                "skip": END,
                "retry": "exploit_lab",
                "error": "handle_error"
            }
        )
        
        workflow.add_edge("surgeon", END)
        workflow.add_edge("handle_error", END)
        
        # Set entry point
        workflow.set_entry_point("saboteur")
        
        return workflow.compile()
    
    async def _run_saboteur(self, state: RedRoomState) -> RedRoomState:
        """Run Agent I: The Saboteur."""
        logger.info("running_saboteur", execution_id=state["execution_id"])
        
        try:
            from redroom.agents.saboteur.hypothesis_generator import HypothesisGenerator
            
            generator = HypothesisGenerator(model_path="/models/llama-3-8b-int4.onnx")
            
            hypothesis = await generator.analyze_diff(
                git_diff=state["git_diff"],
                openapi_spec=state.get("openapi_spec"),
                security_contracts=state.get("security_contracts")
            )
            
            state["hypothesis"] = hypothesis
            state["status"] = AgentStatus.ANALYZING
            state["updated_at"] = datetime.utcnow().isoformat()
            
            if hypothesis:
                logger.info(
                    "hypothesis_generated",
                    execution_id=state["execution_id"],
                    vuln_type=hypothesis.vulnerability_type,
                    confidence=hypothesis.confidence_score
                )
            else:
                logger.info(
                    "no_vulnerability_detected",
                    execution_id=state["execution_id"]
                )
            
        except Exception as e:
            logger.error("saboteur_failed", execution_id=state["execution_id"], error=str(e))
            state["error"] = str(e)
            state["status"] = AgentStatus.FAILED
        
        return state
    
    async def _run_exploit_lab(self, state: RedRoomState) -> RedRoomState:
        """Run Agent II: The Exploit Laboratory."""
        logger.info("running_exploit_lab", execution_id=state["execution_id"])
        
        try:
            from redroom.agents.exploit_lab.exploit_generator import ExploitGenerator
            from redroom.infrastructure.namespace_lifecycle import NamespaceLifecycle
            
            generator = ExploitGenerator(gpu_enabled=True)
            namespace_mgr = NamespaceLifecycle()
            
            # Generate exploit script
            exploit_script = await generator.generate_exploit(state["hypothesis"])
            
            # Create shadow namespace
            shadow_ns = namespace_mgr.create_shadow_namespace("demo-fintech")
            
            try:
                # Execute exploit
                exploit_result = await generator.execute_exploit(
                    exploit_script=exploit_script,
                    shadow_namespace=shadow_ns
                )
                
                state["exploit_result"] = exploit_result
                state["status"] = AgentStatus.EXPLOITING
                state["updated_at"] = datetime.utcnow().isoformat()
                
                logger.info(
                    "exploit_completed",
                    execution_id=state["execution_id"],
                    successful=exploit_result.exploit_successful,
                    namespace=shadow_ns
                )
                
            finally:
                # Cleanup shadow namespace
                namespace_mgr.cleanup_namespace(shadow_ns)
            
        except Exception as e:
            logger.error("exploit_lab_failed", execution_id=state["execution_id"], error=str(e))
            state["error"] = str(e)
            state["retry_count"] = state.get("retry_count", 0) + 1
            
            if state["retry_count"] >= self.max_retries:
                state["status"] = AgentStatus.FAILED
        
        return state
    
    async def _run_surgeon(self, state: RedRoomState) -> RedRoomState:
        """Run Agent III: The Surgeon."""
        logger.info("running_surgeon", execution_id=state["execution_id"])
        
        try:
            from redroom.agents.surgeon.patch_generator import PatchGenerator
            from redroom.agents.surgeon.pr_creator import PRCreator
            
            generator = PatchGenerator(llm_provider="gemini")
            pr_creator = PRCreator()
            
            # Generate patch
            patch_result = await generator.generate_patch(
                vulnerable_code=state["git_diff"],
                exploit_result=state["exploit_result"]
            )
            
            # Validate performance
            performance_ok = await generator.validate_performance(
                patch=patch_result.patch,
                baseline_metrics={}
            )
            
            if performance_ok:
                # Create pull request
                pr_url = await pr_creator.create_pr(
                    patch_result=patch_result,
                    exploit_result=state["exploit_result"],
                    hypothesis=state["hypothesis"]
                )
                
                patch_result.pr_url = pr_url
                state["patch_result"] = patch_result
                state["status"] = AgentStatus.COMPLETED
                state["updated_at"] = datetime.utcnow().isoformat()
                
                logger.info(
                    "patch_created",
                    execution_id=state["execution_id"],
                    pr_url=pr_url
                )
            else:
                logger.warning(
                    "performance_validation_failed",
                    execution_id=state["execution_id"]
                )
                state["status"] = AgentStatus.FAILED
                state["error"] = "Performance validation failed"
            
        except Exception as e:
            logger.error("surgeon_failed", execution_id=state["execution_id"], error=str(e))
            state["error"] = str(e)
            state["status"] = AgentStatus.FAILED
        
        return state
    
    def _should_exploit(self, state: RedRoomState) -> str:
        """Decide if we should run exploit lab."""
        if state.get("error"):
            return "error"
        
        hypothesis = state.get("hypothesis")
        if not hypothesis:
            return "skip"
        
        if hypothesis.confidence_score < 0.7:
            logger.info(
                "skipping_exploit_low_confidence",
                execution_id=state["execution_id"],
                confidence=hypothesis.confidence_score
            )
            return "skip"
        
        return "exploit"
    
    def _should_patch(self, state: RedRoomState) -> str:
        """Decide if we should run surgeon."""
        if state.get("error"):
            retry_count = state.get("retry_count", 0)
            if retry_count < self.max_retries:
                return "retry"
            return "error"
        
        exploit_result = state.get("exploit_result")
        if not exploit_result or not exploit_result.exploit_successful:
            logger.info(
                "skipping_patch_exploit_failed",
                execution_id=state["execution_id"]
            )
            return "skip"
        
        return "patch"
    
    async def _handle_error(self, state: RedRoomState) -> RedRoomState:
        """Handle errors in the workflow."""
        logger.error(
            "workflow_error",
            execution_id=state["execution_id"],
            error=state.get("error"),
            status=state["status"]
        )
        
        state["status"] = AgentStatus.FAILED
        state["updated_at"] = datetime.utcnow().isoformat()
        
        return state
    
    async def execute(
        self,
        execution_id: str,
        git_commit: str,
        git_diff: str,
        openapi_spec: Optional[dict] = None,
        security_contracts: Optional[dict] = None
    ) -> ExecutionState:
        """
        Execute the complete Red Room workflow.
        
        Args:
            execution_id: Unique execution identifier
            git_commit: Git commit SHA
            git_diff: Git diff content
            openapi_spec: Optional OpenAPI specification
            security_contracts: Optional security contracts
            
        Returns:
            Final execution state
        """
        logger.info("starting_execution", execution_id=execution_id, commit=git_commit)
        
        # Initialize state
        initial_state: RedRoomState = {
            "execution_id": execution_id,
            "git_commit": git_commit,
            "git_diff": git_diff,
            "openapi_spec": openapi_spec,
            "security_contracts": security_contracts,
            "hypothesis": None,
            "exploit_result": None,
            "patch_result": None,
            "status": AgentStatus.IDLE,
            "error": None,
            "retry_count": 0,
            "started_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat()
        }
        
        # Run workflow
        final_state = await self.workflow.ainvoke(initial_state)
        
        # Convert to ExecutionState
        execution_state = ExecutionState(
            execution_id=final_state["execution_id"],
            status=final_state["status"],
            git_commit=final_state["git_commit"],
            hypothesis=final_state.get("hypothesis"),
            exploit_result=final_state.get("exploit_result"),
            patch_result=final_state.get("patch_result"),
            created_at=datetime.fromisoformat(final_state["started_at"]),
            updated_at=datetime.fromisoformat(final_state["updated_at"])
        )
        
        logger.info(
            "execution_completed",
            execution_id=execution_id,
            status=execution_state.status
        )
        
        return execution_state
