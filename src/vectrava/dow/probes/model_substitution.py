"""Model substitution probe.

Sends one short request with the operator's configured model and compares the
model the target reports serving against the model that was requested. A target
that silently serves a different (often more expensive) model than the operator
budgeted for is a Denial-of-Wallet risk. The probe does string comparison only:
it cannot resolve a deployment alias to a canonical model name, and it cannot
rank the cost direction of two model strings, so a reported mismatch is flagged
for human triage rather than judged an upgrade or a downgrade.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from vectrava.core.adapters import build_url
from vectrava.core.probe import Probe, ProbeError
from vectrava.core.registry import register
from vectrava.core.result import Severity
from vectrava.dow.client import call_completion

if TYPE_CHECKING:
    from pydantic import JsonValue

    from vectrava.core.probe import ProbeContext
    from vectrava.core.result import Finding

PROBE_PROMPT: str = "Reply with OK."
PROBE_MAX_TOKENS: int = 16


@register
class ModelSubstitutionProbe(Probe):
    """Flags targets that serve or report a model other than the one requested."""

    name: ClassVar[str] = "model_substitution"
    module: ClassVar[str] = "dow"
    description: ClassVar[str] = (
        "Detects when the target serves a different model than the one requested."
    )
    baseline_severity: ClassVar[Severity] = Severity.MEDIUM
    estimated_tokens_per_run: ClassVar[int] = 1 * (30 + PROBE_MAX_TOKENS)
    tags: ClassVar[tuple[str, ...]] = ("dow", "model", "substitution")
    requires_credentials: ClassVar[bool] = True

    def run(self, ctx: ProbeContext) -> list[Finding]:
        """Send one request and flag a substituted or unreported model."""
        if ctx.credentials is None:
            raise ProbeError("no credential", probe_name=self.name, details={})
        credential = ctx.credentials

        raw_model = ctx.options.get("model")
        if not isinstance(raw_model, str):
            raise ProbeError(
                "--model is required for model_substitution probe",
                probe_name=self.name,
                details={},
            )
        model = raw_model

        raw_max_rps = ctx.options.get("max_rps")
        if isinstance(raw_max_rps, (int, float)) and raw_max_rps > 0:
            min_delay_s = 1.0 / float(raw_max_rps)
        else:
            min_delay_s = 0.0

        endpoint_path = ctx.endpoint or ctx.adapter.default_endpoint_path
        url = build_url(ctx.target, endpoint_path)

        result = call_completion(
            ctx.http,
            adapter=ctx.adapter,
            target_base=ctx.target,
            endpoint_path=endpoint_path,
            credential=credential,
            model=model,
            prompt=PROBE_PROMPT,
            max_tokens=PROBE_MAX_TOKENS,
            min_delay_s=min_delay_s,
        )
        reported = result.model
        matched = reported is not None and reported == model
        if matched:
            return []

        level: Severity | None
        if reported is not None:
            match_status = "mismatch"
            level = None
            message = f"requested model '{model}' but target reported '{reported}'"
        else:
            match_status = "unreported"
            level = Severity.INFORMATIONAL
            message = f"target did not report the served model; requested '{model}'"

        evidence: dict[str, JsonValue] = {
            "requested_model": model,
            "reported_model": reported,
            "model_matched": matched,
            "match_status": match_status,
            "prompt_tokens": result.usage.prompt_tokens,
            "completion_tokens": result.usage.completion_tokens,
            "total_tokens": result.usage.total_tokens,
            "max_tokens_requested": PROBE_MAX_TOKENS,
            "finish_reason": result.finish_reason,
            "sample_prompt": PROBE_PROMPT[:200],
            "latency_ms": result.latency_ms,
            "endpoint": url,
        }
        finding = self.make_finding(
            message=message,
            target=url,
            level=level,
            evidence=evidence,
            remediation=(
                "Verify the target honors the model parameter and reports the served "
                "model in the response; unexplained substitution may indicate cost "
                "manipulation or a misconfigured proxy."
            ),
        )
        return [finding]
