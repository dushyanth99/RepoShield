"""
Autonomous Security Agent Orchestrator.

Uses Google Antigravity SDK to run an autonomous security agent within a strict
sandbox, intercepting commands via a "Decide" lifecycle hook evaluated by
Google Cloud Model Armor.

Ensures the database session is closed before entering the long reasoning loop
to prevent connection pool starvation.
"""

import os
import logging
from typing import Any, Dict, Optional
from pathlib import Path

# SQLAlchemy 2.0 Async Imports
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

# Models
from backend.models.audit_ledger import AuditLedger, PatchStatus

# Setup Logging
logger = logging.getLogger("reposhield.security_orchestrator")

# ---------------------------------------------------------------------------
# Dynamic Google Cloud & Antigravity SDK Imports (with Mock fallbacks for dev)
# ---------------------------------------------------------------------------
try:
    from google.antigravity import (
        LocalAgentConfig,
        Agent,
        AgentExecutionContext,
        LifecycleHook,
    )
except ImportError:
    logger.warning("google.antigravity SDK not found. Loading Mock implementations.")
    
    class LocalAgentConfig:
        """Mock LocalAgentConfig for development environment."""
        def __init__(self, workspace_dir: str, enable_network: bool):
            self.workspace_dir = workspace_dir
            self.enable_network = enable_network

    class AgentExecutionContext:
        """Mock AgentExecutionContext to allow cancelling execution."""
        def __init__(self):
            self.is_cancelled = False
            self.cancel_reason: Optional[str] = None

        def cancel(self, reason: str) -> None:
            self.is_cancelled = True
            self.cancel_reason = reason
            logger.info(f"Context cancelled. Reason: {reason}")

    class LifecycleHook:
        """Base class for Agent Lifecycle Hooks."""
        pass

    class Agent:
        """Mock Antigravity Agent."""
        def __init__(self, config: LocalAgentConfig):
            self.config = config
            self.hooks: list = []

        def register_hook(self, hook: Any) -> None:
            self.hooks.append(hook)

        async def __aenter__(self) -> "Agent":
            return self

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

        async def run(self, prompt: str, context: AgentExecutionContext) -> str:
            logger.info(f"Agent starting reasoning loop with prompt: {prompt}")
            # Simulate reasoning loop
            return "Reasoning completed successfully."


try:
    from google.cloud import modelarmor_v1
except ImportError:
    logger.warning("google-cloud-modelarmor not found. Loading Mock implementations.")
    
    class MockModelArmorResponse:
        def __init__(self, is_malicious: bool = False, verdict: str = "SECURE"):
            self.is_malicious = is_malicious
            self.verdict = verdict

    class MockModelArmorClient:
        """Mock Model Armor Client."""
        def check_content(self, request: Dict[str, Any]) -> MockModelArmorResponse:
            content = request.get("content", "")
            # Simple heuristic mock detection for safety test
            if "rm -rf" in content or "malicious" in content:
                return MockModelArmorResponse(is_malicious=True, verdict= "BLOCKED")
            return MockModelArmorResponse(is_malicious=False, verdict="SECURE")
            
    modelarmor_v1 = type(
        "modelarmor_v1",
        (),
        {
            "ModelArmorClient": MockModelArmorClient,
            "CheckContentRequest": lambda **kwargs: kwargs,
        }
    )


# ---------------------------------------------------------------------------
# Decide Lifecycle Hook
# Intercepts command execution and calls Google Cloud Model Armor.
# ---------------------------------------------------------------------------
class ModelArmorDecideHook(LifecycleHook):
    """
    Lifecycle hook executed prior to command execution.
    Intercepts the proposed command and passes it to Model Armor for inspection.
    """

    def __init__(
        self,
        job_id: str,
        session_factory: Any,
        model_armor_client: Any,
    ):
        self.job_id = job_id
        self.session_factory = session_factory
        self.model_armor_client = model_armor_client

    async def on_decide(self, context: Any, command: str) -> None:
        """
        Intercept the command string before the agent runs it.
        
        Args:
            context: The current agent execution context (AgentExecutionContext).
            command: The raw command string target for execution.
        """
        logger.info(f"Intercepted command for verification: {command}")

        # Construct Check Content Request
        request = modelarmor_v1.CheckContentRequest(
            content=command,
            source_type="AGENT_EXECUTION_COMMAND"
        )
        
        # Call Model Armor client
        response = self.model_armor_client.check_content(request=request)

        # Evaluate verdict
        if getattr(response, "is_malicious", False) or getattr(response, "verdict", "") == "BLOCKED":
            logger.warning(f"Model Armor blocked malicious command: {command}")
            
            # Open a dedicated short-lived session to record security event
            # to prevent blocking or pool starvation.
            async with self.session_factory() as session:
                try:
                    # Update counter and patch status
                    stmt = (
                        update(AuditLedger)
                        .where(AuditLedger.id == self.job_id)
                        .values(
                            model_armor_blocked=AuditLedger.model_armor_blocked + 1,
                            patch_status=PatchStatus.FAILED
                        )
                    )
                    await session.execute(stmt)
                    await session.commit()
                except Exception as e:
                    logger.error(f"Failed to log Model Armor block to database: {e}")
                    await session.rollback()

            # Terminate execution context immediately
            context.cancel(reason="Security Violation: Command blocked by Model Armor policy.")


# ---------------------------------------------------------------------------
# Autonomous Security Agent Orchestrator
# ---------------------------------------------------------------------------
class AutonomousSecurityOrchestrator:
    """
    Orchestrates the lifecycle of an Antigravity agent run, enforcing sandbox
    constraints, session cleanup, and security checks.
    """

    def __init__(self, db: AsyncSession, session_factory: Any):
        """
        Args:
            db: Current active AsyncSession for initial setup/queries.
            session_factory: The sessionmaker/async_sessionmaker used to open 
                             new independent async sessions for lifecycle hooks.
        """
        self.db = db
        self.session_factory = session_factory
        self.model_armor_client = modelarmor_v1.ModelArmorClient()

    def configure_agent_sandbox(self, job_id: str) -> LocalAgentConfig:
        """
        Creates a LocalAgentConfig mapped to an isolated workspace directory
        with network access disabled to enforce local sandboxing.
        """
        # Determine isolated sandbox workspace path
        workspace_dir = Path(f"./tmp/sandboxes/job_{job_id}").resolve()
        os.makedirs(workspace_dir, exist_ok=True)
        
        logger.info(f"Configuring strict sandbox at workspace: {workspace_dir}")

        # Strict Sandbox Config: local workspace, no network access allowed
        return LocalAgentConfig(
            workspace_dir=str(workspace_dir),
            enable_network=False
        )

    async def execute_remediation(self, job_id: str, file_path: str, prompt: str) -> str:
        """
        Configures, intercepts, and executes the security agent.
        Ensures DB session is returned to the pool prior to the agent's long run loop.
        """
        # 1. Base Setup & Configuration
        config = self.configure_agent_sandbox(job_id)
        
        # 2. Register Lifecycle hook with its own session factory to avoid deadlock
        decide_hook = ModelArmorDecideHook(
            job_id=job_id,
            session_factory=self.session_factory,
            model_armor_client=self.model_armor_client
        )

        # 3. CRITICAL: Commit and close the current session BEFORE launching the
        #    long-running reasoning loop. This returns the connection to the pool,
        #    preventing thread/connection starvation while the agent thinks.
        try:
            # Mark job status in DB as active
            stmt = (
                update(AuditLedger)
                .where(AuditLedger.id == job_id)
                .values(patch_status=PatchStatus.IN_PROGRESS)
            )
            await self.db.execute(stmt)
            await self.db.commit()
        except Exception as e:
            logger.error(f"Error initializing audit ledger: {e}")
            await self.db.rollback()
        finally:
            # Explicitly close and release db connection back to pool
            await self.db.close()

        # 4. Instantiate Agent and execute
        context = AgentExecutionContext()
        
        async with Agent(config) as agent:
            # Register the intercept/decide hook
            agent.register_hook(decide_hook)
            
            logger.info("Antigravity Agent initialized. Entering reasoning loop...")
            
            # Start execution
            try:
                result = await agent.run(prompt=prompt, context=context)
                
                # Check if context was cancelled due to a security violation
                if getattr(context, "is_cancelled", False):
                    raise RuntimeError(f"Agent execution halted: {context.cancel_reason}")
                
                # If finished successfully, update DB status using a fresh session
                async with self.session_factory() as session:
                    stmt = (
                        update(AuditLedger)
                        .where(AuditLedger.id == job_id)
                        .values(patch_status=PatchStatus.PATCHED)
                    )
                    await session.execute(stmt)
                    await session.commit()
                    
                return result
                
            except Exception as e:
                logger.error(f"Orchestration failure or execution blocked: {e}")
                # Log final failure status
                async with self.session_factory() as session:
                    stmt = (
                        update(AuditLedger)
                        .where(AuditLedger.id == job_id)
                        .values(patch_status=PatchStatus.FAILED)
                    )
                    await session.execute(stmt)
                    await session.commit()
                raise e
