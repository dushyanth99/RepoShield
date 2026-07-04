"""
Autonomous Security Agent Orchestrator.

Uses Google Antigravity SDK to run an autonomous security agent within a strict
sandbox, intercepting commands via a "Decide" lifecycle hook evaluated by
Google Cloud Model Armor, and employing a resilient self-healing test-driven
development (TDD) loop.

Ensures the database session is closed before entering the long reasoning loop
to prevent connection pool starvation.
"""

import os
import logging
import asyncio
from functools import partial
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
# Command Result Wrapper
# ---------------------------------------------------------------------------
class CommandResult:
    """Represents the execution outcome of a shell command run inside the sandbox."""
    def __init__(self, exit_code: int, stdout: str, stderr: str):
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr


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
        """Mock Antigravity Agent with command execution and TDD context injection capabilities."""
        def __init__(self, config: LocalAgentConfig):
            self.config = config
            self.hooks: list = []
            self.context_feedbacks: list = []
            self.instructions: str = ""
            self._run_count = 0

        def register_hook(self, hook: Any) -> None:
            self.hooks.append(hook)

        def inject_context(self, context_str: str) -> None:
            """Injects cognitive feedback context into the agent's active memory."""
            self.context_feedbacks.append(context_str)
            logger.info(f"Context injected into Agent memory: {context_str}")

        def update_instructions(self, instructions: str) -> None:
            """Appends or updates instructions for the agent's next action."""
            self.instructions = instructions
            logger.info(f"Agent instructions updated: {instructions}")

        async def run_command(self, command: str) -> CommandResult:
            """Runs a shell command inside the sandbox."""
            logger.info(f"Agent executing command in sandbox: {command}")
            # Mock behavior: first run fails testing suite (exit code 1),
            # second run succeeds (exit code 0) after context feedback injection.
            self._run_count += 1
            if "pytest" in command:
                if self._run_count == 1:
                    return CommandResult(
                        exit_code=1,
                        stdout="pytest run failed",
                        stderr="AssertionError: assert 'unsecure' == 'secure'\nFAILED tests/test_auth.py::test_auth_flow"
                    )
                else:
                    return CommandResult(
                        exit_code=0,
                        stdout="pytest run passed. 1 passed in 0.05s",
                        stderr=""
                    )
            return CommandResult(exit_code=0, stdout="Success", stderr="")

        async def __aenter__(self) -> "Agent":
            return self

        async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
            pass

        async def run(self, prompt: str, context: AgentExecutionContext) -> str:
            logger.info(f"Agent starting reasoning loop with prompt: {prompt}")
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
            if "rm -rf" in content or "malicious" in content:
                return MockModelArmorResponse(is_malicious=True, verdict="BLOCKED")
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
# Background CPU-bound ML Fix Retrieval Offloader
# ---------------------------------------------------------------------------
def _cpu_lookup_historical_fix(stack_trace: str) -> str:
    """
    Synchronous CPU-bound stub — queries vector database or knowledge index
    using the test failure traceback to retrieve a relevant code fix pattern.
    """
    logger.info(f"Querying vector database for stack trace signature: {stack_trace[:50]}...")
    # Simulated database lookup delay
    import time
    time.sleep(0.5)
    return "Fix: Change string allocation check inside auth.py line 45 to validate payload length."


async def offload_historical_fix_lookup(stack_trace: str) -> str:
    """
    Asynchronously retrieves a recommended patch/fix by offloading the vector
    index lookup to a background worker thread.
    """
    return await asyncio.to_thread(
        partial(_cpu_lookup_historical_fix, stack_trace)
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
        """Intercept the command string before the agent runs it."""
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
            
            # Open a dedicated session to record security event
            async with self.session_factory() as session:
                try:
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
    constraints, session cleanup, security checks, and resilient self-healing
    TDD loops.
    """

    def __init__(self, db: AsyncSession, session_factory: Any):
        """
        Args:
            db: Current active AsyncSession for initial setup.
            session_factory: Injected factory maker for independent short-lived sessions.
        """
        self.db = db
        self.session_factory = session_factory
        self.model_armor_client = modelarmor_v1.ModelArmorClient()

    def configure_agent_sandbox(self, job_id: str) -> LocalAgentConfig:
        """
        Creates a LocalAgentConfig mapped to an isolated workspace directory
        with network access disabled to enforce local sandboxing.
        """
        workspace_dir = Path(f"./tmp/sandboxes/job_{job_id}").resolve()
        os.makedirs(workspace_dir, exist_ok=True)
        
        logger.info(f"Configuring strict sandbox at workspace: {workspace_dir}")

        return LocalAgentConfig(
            workspace_dir=str(workspace_dir),
            enable_network=False
        )

    async def execute_remediation(self, job_id: str, prompt: str, test_command: str = "pytest tests/test_auth.py") -> str:
        """
        Configures, intercepts, and executes the security agent.
        Enforces a TDD self-healing loop that catches test execution failures,
        records the intervention, fetches historical fixes, and feeds them back
        to the agent for recursive correction.
        """
        # 1. Base Setup & Configuration
        config = self.configure_agent_sandbox(job_id)
        
        decide_hook = ModelArmorDecideHook(
            job_id=job_id,
            session_factory=self.session_factory,
            model_armor_client=self.model_armor_client
        )

        # 2. Update initial status and release DB connection to avoid pool starvation
        try:
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
            await self.db.close()

        # 3. Instantiate Agent and execute within the self-healing TDD loop
        context = AgentExecutionContext()
        
        async with Agent(config) as agent:
            agent.register_hook(decide_hook)
            logger.info("Antigravity Agent initialized. Entering execution & self-healing loop...")

            max_retries = 3
            current_attempt = 0
            
            while current_attempt < max_retries:
                current_attempt += 1
                logger.info(f"TDD execution attempt {current_attempt}/{max_retries}")
                
                try:
                    # Execute the test command inside the agent's sandbox environment
                    result = await agent.run_command(test_command)
                    
                    if result.exit_code != 0:
                        # Test suite failed: raise a runtime error containing stderr
                        raise RuntimeError(
                            f"Test execution failed (exit code {result.exit_code}). "
                            f"Stderr: {result.stderr}"
                        )
                    
                    # If tests pass, break out of loop
                    logger.info("Test execution completed successfully. Pipeline verified.")
                    break
                    
                except RuntimeError as error:
                    logger.error(f"Captured test failure: {error}")
                    
                    # Safeguard limit checks
                    if current_attempt >= max_retries:
                        logger.error("Reached maximum self-healing limits. Aborting.")
                        raise error

                    # A. Record the self-healing intervention in database ledger using fresh session
                    async with self.session_factory() as session:
                        try:
                            stmt = (
                                update(AuditLedger)
                                .where(AuditLedger.id == job_id)
                                .values(self_healing_count=AuditLedger.self_healing_count + 1)
                            )
                            await session.execute(stmt)
                            await session.commit()
                            logger.info(f"Incremented self-healing intervention count for job {job_id}")
                        except Exception as db_err:
                            logger.error(f"Failed to record self-healing intervention to database: {db_err}")
                            await session.rollback()

                    # B. Retrieve recommended fix based on stack trace (offloaded to thread)
                    suggested_fix = await offload_historical_fix_lookup(str(error))
                    
                    # C. Inject feedback context and instruction adjustments back into the agent
                    cognitive_feedback = (
                        f"Previous test execution failed on try {current_attempt} with error: {error}\n"
                        f"Suggested remediative action: {suggested_fix}"
                    )
                    agent.inject_context(cognitive_feedback)
                    agent.update_instructions(
                        "Rewrite the source code to resolve the error described in cognitive feedback "
                        "and prepare the application for a test re-run."
                    )

            # Start reasoning/completion loop (long processing stage)
            try:
                # If context was cancelled by Model Armor during any command runs, raise it
                if getattr(context, "is_cancelled", False):
                    raise RuntimeError(f"Agent execution halted: {context.cancel_reason}")

                agent_result = await agent.run(prompt=prompt, context=context)
                
                # Check for cancellation again post run
                if getattr(context, "is_cancelled", False):
                    raise RuntimeError(f"Agent execution halted: {context.cancel_reason}")

                # Success write back
                async with self.session_factory() as session:
                    stmt = (
                        update(AuditLedger)
                        .where(AuditLedger.id == job_id)
                        .values(patch_status=PatchStatus.PATCHED)
                    )
                    await session.execute(stmt)
                    await session.commit()
                    
                return agent_result
                
            except Exception as e:
                logger.error(f"Orchestration execution failed or blocked: {e}")
                async with self.session_factory() as session:
                    stmt = (
                        update(AuditLedger)
                        .where(AuditLedger.id == job_id)
                        .values(patch_status=PatchStatus.FAILED)
                    )
                    await session.execute(stmt)
                    await session.commit()
                raise e
