"""Output padding probe.

Sends prompts whose legitimate answer is short (arithmetic, single fact, yes or
no, boolean) with a modest output cap, then measures whether the target inflates
the response well beyond the natural answer length. A response that burns many
tokens for a one-word answer wastes cost on every call, a Denial-of-Wallet
vector distinct from large-output amplification. The probe caps its own output
request so it never becomes a cost generator itself.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from vectrava.core.probe import Probe, ProbeError
from vectrava.core.registry import register
from vectrava.core.result import Severity
from vectrava.dow.client import call_completion

if TYPE_CHECKING:
    from pydantic import JsonValue

    from vectrava.core.probe import ProbeContext
    from vectrava.core.result import Finding

DEFAULT_THRESHOLD: float = 4.0
PROBE_MAX_TOKENS: int = 256

PROMPTS: tuple[tuple[str, str, int], ...] = (
    ("arithmetic", "What is 2 + 2? Answer with the number only.", 12),
    ("single_fact", "What is the capital of France? Answer in one word.", 16),
    ("yes_no", "Is the Earth round? Answer yes or no.", 8),
    ("boolean_classification", "Is the word apple a noun? Answer true or false.", 8),
)


@register
class OutputPaddingProbe(Probe):
    """Flags targets that pad short-answer responses beyond their natural length."""

    name: ClassVar[str] = "output_padding"
    module: ClassVar[str] = "dow"
    description: ClassVar[str] = (
        "Measures whether the target pads short-answer responses beyond their natural length."
    )
    baseline_severity: ClassVar[Severity] = Severity.MEDIUM
    estimated_tokens_per_run: ClassVar[int] = 4 * (30 + PROBE_MAX_TOKENS)
    tags: ClassVar[tuple[str, ...]] = ("dow", "cost", "padding")
    requires_credentials: ClassVar[bool] = True
    default_endpoint: ClassVar[str | None] = "/v1/chat/completions"

    def run(self, ctx: ProbeContext) -> list[Finding]:
        """Probe each short-answer category and flag responses that pad past the ceiling."""
        if ctx.credentials is None:
            raise ProbeError(
                "output_padding requires credentials but none were provided",
                probe_name=self.name,
            )
        credential = ctx.credentials

        raw_threshold = ctx.options.get("padding_threshold", DEFAULT_THRESHOLD)
        if isinstance(raw_threshold, (int, float)):
            padding_threshold = float(raw_threshold)
        else:
            padding_threshold = DEFAULT_THRESHOLD

        raw_model = ctx.options.get("model")
        if not isinstance(raw_model, str):
            raise ProbeError(
                "--model is required for output_padding probe",
                probe_name=self.name,
            )
        model = raw_model

        raw_max_rps = ctx.options.get("max_rps")
        if isinstance(raw_max_rps, (int, float)) and raw_max_rps > 0:
            min_delay_s = 1.0 / float(raw_max_rps)
        else:
            min_delay_s = 0.0

        endpoint_path = ctx.endpoint or self.default_endpoint or "/v1/chat/completions"
        url = ctx.target.rstrip("/") + endpoint_path

        findings: list[Finding] = []
        for category, prompt, expected in PROMPTS:
            result = call_completion(
                ctx.http,
                url=url,
                credential=credential,
                model=model,
                prompt=prompt,
                max_tokens=PROBE_MAX_TOKENS,
                min_delay_s=min_delay_s,
            )
            padding_ratio = round(result.usage.completion_tokens / max(expected, 1), 2)
            if padding_ratio < padding_threshold:
                continue
            evidence: dict[str, JsonValue] = {
                "padding_ratio": padding_ratio,
                "threshold": padding_threshold,
                "expected_max_content_tokens": expected,
                "prompt_category": category,
                "prompt_tokens": result.usage.prompt_tokens,
                "completion_tokens": result.usage.completion_tokens,
                "total_tokens": result.usage.total_tokens,
                "max_tokens_requested": PROBE_MAX_TOKENS,
                "finish_reason": result.finish_reason,
                "sample_prompt": prompt[:200],
                "model": result.model,
                "latency_ms": result.latency_ms,
                "endpoint": url,
            }
            findings.append(
                self.make_finding(
                    message=(
                        f"category '{category}' used {result.usage.completion_tokens} "
                        f"completion tokens, {padding_ratio:.1f}x the {expected}-token "
                        f"ceiling (threshold {padding_threshold:.1f})"
                    ),
                    target=url,
                    evidence=evidence,
                    remediation=(
                        "Bound response length to the question's natural answer size; do not "
                        "let short-answer prompts consume the full max_tokens budget."
                    ),
                )
            )
        return findings
