"""FastAPI application for The Red Room orchestrator."""

import uuid
from typing import Optional
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import structlog

from redroom.orchestrator.langgraph_engine import RedRoomOrchestrator
from redroom.models.schemas import ExecutionState
from redroom.utils.logger import setup_logging

# Setup logging
setup_logging()
logger = structlog.get_logger()

# Create FastAPI app
app = FastAPI(
    title="The Red Room Orchestrator",
    description="Autonomous AI Security Ecosystem",
    version="0.1.0"
)

# Initialize orchestrator
orchestrator = RedRoomOrchestrator()


class ScanRequest(BaseModel):
    """Request to scan code for vulnerabilities."""
    git_commit: str
    git_diff: str
    openapi_spec: Optional[dict] = None
    security_contracts: Optional[dict] = None
    repository: Optional[str] = None


class ScanResponse(BaseModel):
    """Response from scan request."""
    execution_id: str
    status: str
    message: str


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "The Red Room",
        "version": "0.1.0",
        "status": "operational",
        "agents": {
            "saboteur": "enabled",
            "exploit_lab": "enabled",
            "surgeon": "enabled"
        }
    }


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "healthy"}


@app.post("/scan", response_model=ScanResponse)
async def scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Scan code for vulnerabilities.
    
    This endpoint triggers the complete Red Room workflow:
    1. Agent I analyzes the diff
    2. Agent II exploits vulnerabilities
    3. Agent III generates patches
    """
    execution_id = str(uuid.uuid4())
    
    logger.info(
        "scan_requested",
        execution_id=execution_id,
        commit=request.git_commit
    )
    
    # Run orchestrator in background
    background_tasks.add_task(
        run_orchestrator,
        execution_id=execution_id,
        git_commit=request.git_commit,
        git_diff=request.git_diff,
        openapi_spec=request.openapi_spec,
        security_contracts=request.security_contracts
    )
    
    return ScanResponse(
        execution_id=execution_id,
        status="started",
        message="Scan initiated. Check /status/{execution_id} for progress."
    )


@app.get("/status/{execution_id}")
async def get_status(execution_id: str):
    """Get status of a scan execution."""
    # TODO: Implement status retrieval from Redis
    return {
        "execution_id": execution_id,
        "status": "running",
        "message": "Status retrieval not yet implemented"
    }


@app.post("/webhook/github")
async def github_webhook(background_tasks: BackgroundTasks):
    """Handle GitHub webhook events."""
    # TODO: Implement GitHub webhook handling
    logger.info("github_webhook_received")
    return {"status": "received"}


async def run_orchestrator(
    execution_id: str,
    git_commit: str,
    git_diff: str,
    openapi_spec: Optional[dict],
    security_contracts: Optional[dict]
):
    """Run the orchestrator workflow."""
    try:
        result = await orchestrator.execute(
            execution_id=execution_id,
            git_commit=git_commit,
            git_diff=git_diff,
            openapi_spec=openapi_spec,
            security_contracts=security_contracts
        )
        
        logger.info(
            "orchestrator_completed",
            execution_id=execution_id,
            status=result.status
        )
        
        # TODO: Store result in Redis/database
        
    except Exception as e:
        logger.error(
            "orchestrator_failed",
            execution_id=execution_id,
            error=str(e)
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
