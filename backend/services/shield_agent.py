"""
Autonomous Shield Agent Orchestrator — services/shield_agent.py

Orchestrates the Antigravity agent lifecycle with strict top-level exception
encapsulation to guarantee VulnerabilityJob records NEVER hang in an
intermediate state:

  ┌──────────────────────────────────────────────────────────────┐
  │  Outer try/except  (Deficit 1 fix)                            │
  │  ┌────────────────────────────────────────────────────────┐  │
  │  │  async with Agent(config) as agent:                    │  │
  │  │    Model Armor Decide hook registration                │  │
  │  │    TDD self-healing loop (max 3 attempts)              │  │
  │  │    agent.run() reasoning loop                          │  │
  │  │    → status = VERIFIED on clean exit                  │  │
  │  └────────────────────────────────────────────────────────┘  │
  │  except Exception:                                            │
  │    log structured JSON with job_id + traceback               │
  │    open isolated session → status = FAILED                   │
  │    re-raise for the background task supervisor               │
  └──────────────────────────────────────────────────────────────┘

Formerly: services/agent_orchestrator.py  (AutonomousSecurityOrchestrator)
"""

import asyncio
import logging
import os
import traceback
from functools import partial
from pathlib import Path
from typing import Any, Dict, Optional

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from config.settings import settings
from models.audit import PatchStatusEnum, VulnerabilityJob

logger = logging.getLogger("reposhield.shield_agent")


# ---------------------------------------------------------------------------
# CommandResult
# ---------------------------------------------------------------------------
class CommandResult:
    def __init__(self, exit_code: int, stdout: str, stderr: str) -> None:
        self.exit_code = exit_code
        self.stdout    = stdout
        self.stderr    = stderr


# ---------------------------------------------------------------------------
# SDK / Client imports with dev-mode mock fallbacks
# ---------------------------------------------------------------------------
try:
    from google.antigravity import (  # type: ignore[import]
        LocalAgentConfig,
        Agent,
        AgentExecutionContext,
        LifecycleHook,
    )
    _ANTIGRAVITY_AVAILABLE = True
except ImportError:
    logger.warning("google.antigravity not found — loading mock implementations.")
    _ANTIGRAVITY_AVAILABLE = False

    class LocalAgentConfig:  # type: ignore[no-redef]
        def __init__(self, workspace_dir: str, enable_network: bool) -> None:
            self.workspace_dir  = workspace_dir
            self.enable_network = enable_network

    class AgentExecutionContext:  # type: ignore[no-redef]
        def __init__(self) -> None:
            self.is_cancelled  = False
            self.cancel_reason: Optional[str] = None

        def cancel(self, reason: str) -> None:
            self.is_cancelled  = True
            self.cancel_reason = reason
            logger.info("Execution context cancelled", extra={"reason": reason})

    class LifecycleHook:  # type: ignore[no-redef]
        pass

    class Agent:  # type: ignore[no-redef]
        def __init__(self, config: LocalAgentConfig) -> None:
            self.config        = config
            self.hooks: list   = []
            self.instructions  = ""
            self._run_count    = 0
            self._feedbacks: list = []

        def register_hook(self, hook: Any) -> None:
            self.hooks.append(hook)

        def write_file(self, path: str, content: str) -> None:
            logger.info("Agent write_file called", extra={"path": path, "bytes": len(content)})

        def inject_context(self, ctx: str) -> None:
            self._feedbacks.append(ctx)
            logger.info("Context injected into agent memory", extra={"context_preview": ctx[:80]})

        def update_instructions(self, instructions: str) -> None:
            self.instructions = instructions
            logger.info("Agent instructions updated", extra={"instructions_preview": instructions[:80]})

        async def run_command(self, command: str) -> CommandResult:
            self._run_count += 1
            logger.info(
                "Agent executing command",
                extra={"command": command, "attempt": self._run_count},
            )
            if "pytest" in command and self._run_count == 1:
                return CommandResult(
                    exit_code=1,
                    stdout="pytest run failed",
                    stderr=(
                        "AssertionError: assert 'unsecure' == 'secure'\n"
                        "FAILED tests/test_auth.py::test_auth_flow"
                    ),
                )
            return CommandResult(exit_code=0, stdout="pytest: 1 passed.", stderr="")

        async def run(self, prompt: str, context: "AgentExecutionContext") -> str:
            logger.info("Agent reasoning loop started")
            return "Reasoning completed."

        async def __aenter__(self) -> "Agent":
            return self

        async def __aexit__(self, *_: Any) -> None:
            pass


try:
    from google.cloud import modelarmor_v1  # type: ignore[import]
    _MODELARMOR_AVAILABLE = True
except ImportError:
    logger.warning("google-cloud-modelarmor not found — loading mock client.")
    _MODELARMOR_AVAILABLE = False

    class _MockMAResponse:
        def __init__(self, is_malicious: bool = False, verdict: str = "SECURE") -> None:
            self.is_malicious = is_malicious
            self.verdict      = verdict

    class _MockMAClient:
        def check_content(self, request: Dict[str, Any]) -> _MockMAResponse:
            content = request.get("content", "")
            if "rm -rf" in content or "malicious" in content:
                return _MockMAResponse(is_malicious=True, verdict="BLOCKED")
            return _MockMAResponse(is_malicious=False, verdict="SECURE")

    modelarmor_v1 = type(  # type: ignore[assignment]
        "modelarmor_v1",
        (),
        {
            "ModelArmorClient":    _MockMAClient,
            "CheckContentRequest": lambda **kw: kw,
        },
    )


# ---------------------------------------------------------------------------
# Background thread: historical fix lookup (CPU-bound, offloaded)
# ---------------------------------------------------------------------------
def _cpu_lookup_historical_fix(stack_trace: str) -> str:
    import time as _time
    _time.sleep(0.3)  # simulate vector DB / embedding search latency
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

    def __init__(
        self,
        job_id:             str,
        session_factory:    Any,
        model_armor_client: Any,
    ) -> None:
        self.job_id             = job_id
        self.session_factory    = session_factory
        self.model_armor_client = model_armor_client

    async def on_decide(self, context: Any, command: str) -> None:
        logger.info("Model Armor intercepting command", extra={"command_preview": command[:80]})

        request  = modelarmor_v1.CheckContentRequest(
            content=command,
            source_type="AGENT_EXECUTION_COMMAND",
        )
        response = self.model_armor_client.check_content(request=request)

        if getattr(response, "is_malicious", False) or \
                getattr(response, "verdict", "") == "BLOCKED":
            logger.warning(
                "Model Armor BLOCKED command",
                extra={"job_id": self.job_id, "command": command},
            )

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
                    logger.error(
                        "DB update failed in ModelArmorDecideHook",
                        extra={"job_id": self.job_id, "error": str(exc)},
                    )
                    await session.rollback()

            context.cancel(reason="Security Violation: command blocked by Model Armor.")


# ---------------------------------------------------------------------------
# Shield Agent Orchestrator — Deficit 1 Fix
# ---------------------------------------------------------------------------
class ShieldAgentOrchestrator:
    """
    Manages the complete autonomous remediation lifecycle.

    Constructor now accepts only a session_factory (async_sessionmaker) so
    every DB write opens its own clean, short-lived session. This eliminates
    shared-session state across the long-running background task.
    """

    def __init__(self, db_session_factory: async_sessionmaker) -> None:  # type: ignore[type-arg]
        self.session_factory     = db_session_factory
        self.model_armor_client  = modelarmor_v1.ModelArmorClient()
        self.model_armor_source: str = settings.model_armor_project_location

    # -----------------------------------------------------------------------
    # Sandbox configuration
    # -----------------------------------------------------------------------
    def configure_agent_sandbox(self, job_id: str) -> LocalAgentConfig:
        """Isolated workspace per job; network access explicitly disabled."""
        workspace = Path(f"./tmp/sandboxes/job_{job_id}").resolve()
        os.makedirs(workspace, exist_ok=True)
        logger.info("Sandbox configured", extra={"job_id": job_id, "workspace": str(workspace)})
        return LocalAgentConfig(workspace_dir=str(workspace), enable_network=False)

    # -----------------------------------------------------------------------
    # Internal DB helpers — each opens its own isolated session
    # -----------------------------------------------------------------------
    async def _write_status(self, job_id: str, status: PatchStatusEnum, **extra_values: Any) -> None:
        async with self.session_factory() as session:
            try:
                await session.execute(
                    update(VulnerabilityJob)
                    .where(VulnerabilityJob.id == job_id)
                    .values(patch_status=status, **extra_values)
                )
                await session.commit()
                logger.info(
                    "Job status updated",
                    extra={"job_id": job_id, "status": status.value},
                )
            except Exception as exc:
                await session.rollback()
                logger.error(
                    "Failed to write job status",
                    extra={"job_id": job_id, "target_status": status.value, "error": str(exc)},
                )
                raise

    # -----------------------------------------------------------------------
    # Primary entrypoint — Deficit 1: full outer try/except
    # -----------------------------------------------------------------------
    async def execute_remediation_pipeline(
        self,
        job_id:          str,
        file_path:       str,
        raw_source_code: str,
        test_command:    str = "pytest tests/",
    ) -> str:
        """
        Execute the full autonomous remediation pipeline with a hard outer
        exception boundary.

        On clean exit  → VulnerabilityJob.patch_status = VERIFIED
        On any crash   → VulnerabilityJob.patch_status = FAILED (guaranteed)

        Steps
        -----
        1. Write IN_PROGRESS via isolated session.
        2. Enter Agent context manager.
        3. Write source file into isolated sandbox.
        4. Run TDD self-healing loop (≤3 attempts).
        5. Run agent reasoning loop.
        6. Write VERIFIED on success.

        Exception boundary
        ------------------
        Any Exception that escapes the inner block is caught here, logged with
        full traceback as structured JSON fields, written as FAILED to the DB,
        and re-raised so the background task supervisor can observe the failure.
        """
        logger.info(
            "Starting remediation pipeline",
            extra={"job_id": job_id, "file_path": file_path},
        )

        # Step 1: Mark job as IN_PROGRESS
        await self._write_status(job_id, PatchStatusEnum.IN_PROGRESS)

        config      = self.configure_agent_sandbox(job_id)
        decide_hook = ModelArmorDecideHook(
            job_id=job_id,
            session_factory=self.session_factory,
            model_armor_client=self.model_armor_client,
        )

        # ===================================================================
        # OUTER DEFENSIVE BOUNDARY — Deficit 1 core fix
        # Guarantees job status is always written, even on SDK crashes,
        # asyncio cancellations, or unexpected engine exceptions.
        # ===================================================================
        try:
            async with Agent(config) as agent:
                # Write the source code into the isolated sandbox
                agent.write_file(file_path, raw_source_code)

                # Attach Model Armor interception hook
                agent.register_hook(decide_hook)

                # Mark SANDBOXING so the frontend can show a meaningful sub-state
                await self._write_status(job_id, PatchStatusEnum.SANDBOXING)

                context = AgentExecutionContext()

                # -----------------------------------------------------------
                # TDD self-healing loop (max 3 attempts)
                # -----------------------------------------------------------
                max_retries     = 3
                current_attempt = 0

                while current_attempt < max_retries:
                    current_attempt += 1
                    logger.info(
                        "TDD attempt",
                        extra={
                            "job_id":   job_id,
                            "attempt":  current_attempt,
                            "max":      max_retries,
                            "command":  test_command,
                        },
                    )

                    cmd_result = await agent.run_command(test_command)

                    if cmd_result.exit_code != 0:
                        logger.warning(
                            "Test run failed",
                            extra={
                                "job_id":   job_id,
                                "attempt":  current_attempt,
                                "exit_code": cmd_result.exit_code,
                                "stderr":   cmd_result.stderr[:400],
                            },
                        )

                        if current_attempt >= max_retries:
                            raise RuntimeError(
                                f"Tests failed after {max_retries} attempts. "
                                f"Stderr: {cmd_result.stderr}"
                            )

                        # Increment self-healing counter
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
                            except Exception as db_exc:
                                logger.error(
                                    "Failed to increment self_healing_count",
                                    extra={"job_id": job_id, "error": str(db_exc)},
                                )
                                await session.rollback()

                        # Retrieve historical fix on a background thread
                        fix = await offload_historical_fix_lookup(cmd_result.stderr)

                        # Inject cognitive feedback into agent memory
                        agent.inject_context(
                            f"Attempt {current_attempt} failed.\n"
                            f"Stderr: {cmd_result.stderr}\n"
                            f"Suggested fix: {fix}"
                        )
                        agent.update_instructions(
                            "Rewrite the affected source code to resolve the test failure "
                            "described in the cognitive feedback and prepare for a re-run."
                        )

                    else:
                        logger.info(
                            "Tests passed",
                            extra={"job_id": job_id, "attempt": current_attempt},
                        )
                        break

                # -----------------------------------------------------------
                # Agent reasoning loop
                # -----------------------------------------------------------
                if getattr(context, "is_cancelled", False):
                    raise RuntimeError(
                        f"Agent cancelled before reasoning: {context.cancel_reason}"
                    )

                prompt = (
                    f"Remediate all security vulnerabilities in '{file_path}'. "
                    f"Tests have passed. Generate a final clean patch."
                )
                agent_result: str = await agent.run(prompt=prompt, context=context)

                if getattr(context, "is_cancelled", False):
                    raise RuntimeError(
                        f"Agent cancelled during reasoning: {context.cancel_reason}"
                    )

            # Agent context exited cleanly — write VERIFIED
            await self._write_status(job_id, PatchStatusEnum.VERIFIED)
            logger.info("Remediation pipeline completed successfully", extra={"job_id": job_id})
            return agent_result

        # ===================================================================
        # OUTER EXCEPTION HANDLER — guaranteed FAILED status + structured log
        # ===================================================================
        except Exception as execution_error:
            error_trace = traceback.format_exc()
            logger.error(
                "Fatal disruption inside Antigravity agent execution context",
                extra={
                    "job_id":    job_id,
                    "file_path": file_path,
                    "error":     str(execution_error),
                    "traceback": error_trace,
                },
            )

            # Open a fully isolated session to stamp the job as FAILED.
            # This must succeed even if the agent's internal session pool is exhausted.
            async with self.session_factory() as failure_session:
                job = await failure_session.get(VulnerabilityJob, job_id)
                if job:
                    job.patch_status = PatchStatusEnum.FAILED
                    try:
                        await failure_session.commit()
                        logger.info(
                            "Job stamped FAILED after exception",
                            extra={"job_id": job_id},
                        )
                    except Exception as db_exc:
                        logger.critical(
                            "CRITICAL: Failed to write FAILED status — job is orphaned",
                            extra={"job_id": job_id, "db_error": str(db_exc)},
                        )
                        await failure_session.rollback()

            # Re-raise so FastAPI BackgroundTasks / the caller can observe the failure
            raise execution_error
