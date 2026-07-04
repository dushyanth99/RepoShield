"""
Autonomous Shield Agent Orchestrator — services/shield_agent.py

Orchestrates the Antigravity agent lifecycle:
  - Strict sandbox via LocalAgentConfig (no network, isolated workspace)
  - Model Armor command interception via a Decide lifecycle hook
  - Resilient TDD self-healing loop (test → fail → retrieve fix → retry)
  - Fully isolated DB sessions to prevent connection pool starvation

Formerly: services/agent_orchestrator.py  (AutonomousSecurityOrchestrator)
"""

import os
import asyncio
import logging
from functools import partial
from pathlib import Path
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import update

from models.audit import VulnerabilityJob, PatchStatusEnum
from config.settings import settings

logger = logging.getLogger("reposhield.shield_agent")


# ---------------------------------------------------------------------------
# CommandResult
# ---------------------------------------------------------------------------
class CommandResult:
    def __init__(self, exit_code: int, stdout: str, stderr: str):
        self.exit_code = exit_code
        self.stdout    = stdout
        self.stderr    = stderr


# ---------------------------------------------------------------------------
# SDK / Client imports with dev-mode mock fallbacks
# ---------------------------------------------------------------------------
try:
    from google.antigravity import (
        LocalAgentConfig,
        Agent,
        AgentExecutionContext,
        LifecycleHook,
    )
except ImportError:
    logger.warning("google.antigravity not found — loading mock implementations.")

    class LocalAgentConfig:
        def __init__(self, workspace_dir: str, enable_network: bool):
            self.workspace_dir  = workspace_dir
            self.enable_network = enable_network

    class AgentExecutionContext:
        def __init__(self):
            self.is_cancelled  = False
            self.cancel_reason: Optional[str] = None

        def cancel(self, reason: str) -> None:
            self.is_cancelled  = True
            self.cancel_reason = reason
            logger.info(f"Execution context cancelled: {reason}")

    class LifecycleHook:
        pass

    class Agent:
        def __init__(self, config: LocalAgentConfig):
            self.config   = config
            self.hooks: list     = []
            self.instructions    = ""
            self._run_count      = 0
            self._feedbacks: list = []

        def register_hook(self, hook: Any) -> None:
            self.hooks.append(hook)

        def inject_context(self, ctx: str) -> None:
            self._feedbacks.append(ctx)
            logger.info(f"Context injected: {ctx}")

        def update_instructions(self, instructions: str) -> None:
            self.instructions = instructions
            logger.info(f"Instructions updated: {instructions}")

        async def run_command(self, command: str) -> CommandResult:
            self._run_count += 1
            logger.info(f"Agent running command (attempt {self._run_count}): {command}")
            if "pytest" in command and self._run_count == 1:
                return CommandResult(
                    exit_code=1,
                    stdout="pytest run failed",
                    stderr="AssertionError: assert 'unsecure' == 'secure'\nFAILED tests/test_auth.py::test_auth_flow",
                )
            return CommandResult(exit_code=0, stdout="pytest passed. 1 passed.", stderr="")

        async def run(self, prompt: str, context: AgentExecutionContext) -> str:
            logger.info(f"Agent reasoning loop started.")
            return "Reasoning completed."

        async def __aenter__(self) -> "Agent":
            return self

        async def __aexit__(self, *_: Any) -> None:
            pass


try:
    from google.cloud import modelarmor_v1
except ImportError:
    logger.warning("google-cloud-modelarmor not found — loading mock client.")

    class _MockMAResponse:
        def __init__(self, is_malicious: bool = False, verdict: str = "SECURE"):
            self.is_malicious = is_malicious
            self.verdict      = verdict

    class _MockMAClient:
        def check_content(self, request: Dict[str, Any]) -> _MockMAResponse:
            content = request.get("content", "")
            if "rm -rf" in content or "malicious" in content:
                return _MockMAResponse(is_malicious=True, verdict="BLOCKED")
            return _MockMAResponse(is_malicious=False, verdict="SECURE")

    modelarmor_v1 = type(
        "modelarmor_v1",
        (),
        {
            "ModelArmorClient":    _MockMAClient,
            "CheckContentRequest": lambda **kw: kw,
        },
    )


# ---------------------------------------------------------------------------
# Background thread: historical fix lookup
# ---------------------------------------------------------------------------
def _cpu_lookup_historical_fix(stack_trace: str) -> str:
    import time as _time
    _time.sleep(0.3)  # simulate vector DB latency
    return (
        f"Fable-5 trace for '{stack_trace[:40]}…': "
        "Fix implicit string allocation mismatch — use parameterised query."
    )


async def offload_historical_fix_lookup(stack_trace: str) -> str:
    return await asyncio.to_thread(partial(_cpu_lookup_historical_fix, stack_trace))


# ---------------------------------------------------------------------------
# Model Armor Decide Hook
# ---------------------------------------------------------------------------
class ModelArmorDecideHook(LifecycleHook):
    """Intercepts every agent command and passes it through Model Armor."""

    def __init__(self, job_id: str, session_factory: Any, model_armor_client: Any):
        self.job_id               = job_id
        self.session_factory      = session_factory
        self.model_armor_client   = model_armor_client

    async def on_decide(self, context: Any, command: str) -> None:
        logger.info(f"Model Armor intercepting command: {command!r}")

        request  = modelarmor_v1.CheckContentRequest(
            content=command,
            source_type="AGENT_EXECUTION_COMMAND",
        )
        response = self.model_armor_client.check_content(request=request)

        if getattr(response, "is_malicious", False) or getattr(response, "verdict", "") == "BLOCKED":
            logger.warning(f"Model Armor BLOCKED command: {command!r}")

            async with self.session_factory() as session:
                try:
                    await session.execute(
                        update(VulnerabilityJob)
                        .where(VulnerabilityJob.id == self.job_id)
                        .values(
                            model_armor_blocked=VulnerabilityJob.model_armor_blocked + 1,
                            patch_status=PatchStatusEnum.FAILED,
                        )
                    )
                    await session.commit()
                except Exception as exc:
                    logger.error(f"DB update failed in ModelArmorDecideHook: {exc}")
                    await session.rollback()

            context.cancel(reason="Security Violation: command blocked by Model Armor.")


# ---------------------------------------------------------------------------
# Shield Agent Orchestrator
# ---------------------------------------------------------------------------
class ShieldAgentOrchestrator:
    """
    Manages the complete lifecycle of a RepoShield autonomous agent run:
    sandbox configuration → Model Armor hook → TDD self-healing loop → DB audit.
    """

    def __init__(self, db_session: AsyncSession, session_factory: Any):
        """
        Args:
            db_session:      Active AsyncSession for initial status write.
                             Closed before the long reasoning loop begins.
            session_factory: AsyncSessionLocal factory for isolated short-lived
                             sessions used inside hooks and the background task.
        """
        self.db              = db_session
        self.session_factory = session_factory
        self.model_armor_client = modelarmor_v1.ModelArmorClient()
        # Settings-driven — no os.getenv() calls scattered across the codebase
        self.model_armor_source: str = settings.model_armor_project_location

    def configure_agent_sandbox(self, job_id: str) -> LocalAgentConfig:
        """Isolated workspace per job; network disabled for strict sandboxing."""
        workspace = Path(f"./tmp/sandboxes/job_{job_id}").resolve()
        os.makedirs(workspace, exist_ok=True)
        logger.info(f"Sandbox configured: {workspace}")
        return LocalAgentConfig(workspace_dir=str(workspace), enable_network=False)

    async def execute_remediation(
        self,
        job_id:       str,
        prompt:       str,
        test_command: str = "pytest tests/",
    ) -> str:
        """
        Full remediation pipeline:
        1. Mark job IN_PROGRESS and release the initial DB session.
        2. Enter the Antigravity agent context.
        3. Run the TDD self-healing loop (max 3 attempts).
        4. Run the agent reasoning loop.
        5. Write final PATCHED / FAILED status via an isolated session.
        """
        config      = self.configure_agent_sandbox(job_id)
        decide_hook = ModelArmorDecideHook(
            job_id=job_id,
            session_factory=self.session_factory,
            model_armor_client=self.model_armor_client,
        )

        # --- Step 1: Write IN_PROGRESS, then close the initial session ---
        try:
            await self.db.execute(
                update(VulnerabilityJob)
                .where(VulnerabilityJob.id == job_id)
                .values(patch_status=PatchStatusEnum.IN_PROGRESS)
            )
            await self.db.commit()
        except Exception as exc:
            logger.error(f"Failed to set IN_PROGRESS for job {job_id}: {exc}")
            await self.db.rollback()
        finally:
            # CRITICAL: return connection to pool before the long loop starts
            await self.db.close()

        # --- Step 2–4: Agent execution ---
        context = AgentExecutionContext()

        async with Agent(config) as agent:
            agent.register_hook(decide_hook)

            # TDD self-healing loop
            max_retries     = 3
            current_attempt = 0

            while current_attempt < max_retries:
                current_attempt += 1
                logger.info(f"TDD attempt {current_attempt}/{max_retries} for job {job_id}")

                try:
                    result = await agent.run_command(test_command)
                    if result.exit_code != 0:
                        raise RuntimeError(
                            f"Tests failed (exit {result.exit_code}). "
                            f"Stderr: {result.stderr}"
                        )
                    logger.info(f"Tests passed on attempt {current_attempt}.")
                    break

                except RuntimeError as err:
                    logger.error(f"Test failure captured: {err}")

                    if current_attempt >= max_retries:
                        raise err

                    # A. Increment self-healing counter in isolated session
                    async with self.session_factory() as session:
                        try:
                            await session.execute(
                                update(VulnerabilityJob)
                                .where(VulnerabilityJob.id == job_id)
                                .values(
                                    self_healing_count=VulnerabilityJob.self_healing_count + 1
                                )
                            )
                            await session.commit()
                            logger.info(f"Self-healing count incremented for job {job_id}")
                        except Exception as db_exc:
                            logger.error(f"Failed to record self-healing event: {db_exc}")
                            await session.rollback()

                    # B. Retrieve historical fix on background thread
                    fix = await offload_historical_fix_lookup(str(err))

                    # C. Inject cognitive feedback into agent memory
                    agent.inject_context(
                        f"Attempt {current_attempt} failed: {err}\nSuggested fix: {fix}"
                    )
                    agent.update_instructions(
                        "Rewrite the source to resolve the error in the cognitive "
                        "feedback and prepare for a re-run."
                    )

            # Reasoning loop
            if getattr(context, "is_cancelled", False):
                raise RuntimeError(f"Agent halted: {context.cancel_reason}")

            agent_result = await agent.run(prompt=prompt, context=context)

            if getattr(context, "is_cancelled", False):
                raise RuntimeError(f"Agent halted post-run: {context.cancel_reason}")

        # --- Step 5: Write final status ---
        async with self.session_factory() as session:
            try:
                await session.execute(
                    update(VulnerabilityJob)
                    .where(VulnerabilityJob.id == job_id)
                    .values(patch_status=PatchStatusEnum.PATCHED)
                )
                await session.commit()
                logger.info(f"Job {job_id} marked PATCHED.")
            except Exception as exc:
                await session.rollback()
                logger.error(f"Failed to mark job PATCHED: {exc}")

        return agent_result
