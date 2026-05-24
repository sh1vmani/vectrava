"""Probe abstract base class, run context, and error type.

Every probe across the dow, ipi, and rag modules subclasses `Probe`. The base
class fixes the metadata each probe must declare and the single `run()` contract
the CLI runner drives.

Concurrency note: the runner and `ProbeContext.http` are synchronous today. If a
future probe needs to fire requests concurrently, refactor `ProbeContext.http`
to `httpx.AsyncClient` and `run()` to `async def`. That change touches this
module, the CLI runner loop, and the probe tests. A reference link will be added
here when that work is scheduled.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

from vectrava.core.result import Finding, Severity

if TYPE_CHECKING:
    from collections.abc import Mapping

    import httpx
    import structlog
    from pydantic import JsonValue

    from vectrava.config.scope import ScopeFile


class ProbeError(Exception):
    """Raised when a probe cannot complete a run.

    This signals an operational failure (network error, malformed response,
    unusable target), distinct from a probe running successfully and finding
    nothing. The runner isolates this per probe: it records the error, continues
    other probes, and sets a scan-error exit code.
    """

    def __init__(
        self,
        message: str,
        *,
        probe_name: str | None = None,
        details: object = None,
    ) -> None:
        """Build a probe error.

        Args:
            message: Human readable description of the failure.
            probe_name: Name of the probe that failed, if known.
            details: Optional structured context (response body, exception).
        """
        super().__init__(message)
        self.probe_name = probe_name
        self.details = details


@dataclass
class ProbeContext:
    """Everything a probe needs to run, assembled by the CLI before the run.

    Attributes:
        target: Base target URL, already verified to be within scope.
        endpoint: Resolved endpoint URL, or None to use the probe default.
        credentials: Resolved BYOK key value, or None when the probe needs none.
        scope: The validated scope authorization for this run.
        http: Synchronous HTTP client the probe should use for requests.
        logger: Bound structlog logger for progress and diagnostics.
        options: Reserved for future per-probe tuning supplied by the operator.
    """

    target: str
    endpoint: str | None
    credentials: str | None
    scope: ScopeFile
    http: httpx.Client
    logger: structlog.BoundLogger
    options: Mapping[str, JsonValue]


class Probe(ABC):
    """Base class for every probe.

    Subclasses declare their identity and cost as class variables and implement
    `run()`. Required class variables are checked at class definition time, so a
    misconfigured probe fails fast on import rather than at scan time.
    """

    name: ClassVar[str]
    module: ClassVar[str]
    description: ClassVar[str]
    baseline_severity: ClassVar[Severity]
    estimated_tokens_per_run: ClassVar[int]
    tags: ClassVar[tuple[str, ...]] = ()
    requires_credentials: ClassVar[bool] = True
    default_endpoint: ClassVar[str | None] = None

    _REQUIRED_CLASSVARS: ClassVar[tuple[str, ...]] = (
        "name",
        "module",
        "description",
        "baseline_severity",
        "estimated_tokens_per_run",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Validate that concrete probes declare the required metadata.

        Raises:
            TypeError: if a required class variable is not set on the subclass.
        """
        super().__init_subclass__(**kwargs)
        missing = [var for var in cls._REQUIRED_CLASSVARS if not hasattr(cls, var)]
        if missing:
            joined = ", ".join(missing)
            msg = f"probe {cls.__name__} is missing required class variables: {joined}"
            raise TypeError(msg)

    @abstractmethod
    def run(self, ctx: ProbeContext) -> list[Finding]:
        """Run the probe against the target described by `ctx`.

        Args:
            ctx: The assembled run context.

        Returns:
            Zero or more findings. An empty list means the probe ran and found
            nothing.

        Raises:
            ProbeError: if the probe could not complete (operational failure).
        """

    def make_finding(
        self,
        *,
        message: str,
        target: str,
        level: Severity | None = None,
        evidence: dict[str, JsonValue] | None = None,
        remediation: str | None = None,
    ) -> Finding:
        """Build a Finding pre-filled with this probe's identity.

        Args:
            message: Human readable description of the finding.
            target: The endpoint URL that was probed.
            level: Severity override; defaults to the probe baseline severity.
            evidence: Structured proof for the finding.
            remediation: Optional mitigation guidance.

        Returns:
            A Finding with rule_id, probe, level, and observed_at filled in.
        """
        return Finding(
            rule_id=self.name,
            probe=f"{self.module}.{self.name}",
            level=level if level is not None else self.baseline_severity,
            message=message,
            target=target,
            evidence=evidence if evidence is not None else {},
            remediation=remediation,
            observed_at=datetime.now(UTC),
        )
