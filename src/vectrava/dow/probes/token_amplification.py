"""Token amplification probe.

Sends a fixed set of benign, deliberately short prompts that legitimately
elicit large outputs, then measures the output-to-input token ratio. A high
ratio means a small input compels a large, costly output: the core
Denial-of-Wallet economic asymmetry. The probe caps its own output request so
it never becomes a cost generator itself.
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

DEFAULT_THRESHOLD: float = 15.0
PROBE_MAX_TOKENS: int = 512

PROMPTS: tuple[tuple[str, str], ...] = (
    ("enumeration", "List every country in the world and its capital city."),
    ("long_form_generation", "Write a detailed 1500-word history of the printing press."),
    ("bounded_repetition", "Count from 1 to 500, one number per line."),
    (
        "format_expansion",
        "Give the full periodic table as a table: atomic number, symbol, name, atomic weight.",
    ),
    (
        "verbose_explanation",
        "Explain in full step-by-step detail how a four-stroke internal combustion engine works.",
    ),
)


@register
class TokenAmplificationProbe(Probe):
    """Measures output-to-input token ratio for benign volume-eliciting prompts."""

    name: ClassVar[str] = "token_amplification"
    module: ClassVar[str] = "dow"
    description: ClassVar[str] = (
        "Measures output-to-input token ratio for benign volume-eliciting prompts."
    )
    baseline_severity: ClassVar[Severity] = Severity.MEDIUM
    estimated_tokens_per_run: ClassVar[int] = 5 * (30 + PROBE_MAX_TOKENS)
    tags: ClassVar[tuple[str, ...]] = ("dow", "cost", "amplification")
    requires_credentials: ClassVar[bool] = True

    def run(self, ctx: ProbeContext) -> list[Finding]:
        """Probe each category and emit a finding where the ratio meets the threshold."""
        if ctx.credentials is None:
            raise ProbeError(
                "token_amplification requires credentials but none were provided",
                probe_name=self.name,
            )
        credential = ctx.credentials

        raw_threshold = ctx.options.get("threshold", DEFAULT_THRESHOLD)
        if isinstance(raw_threshold, (int, float)):
            threshold = float(raw_threshold)
        else:
            threshold = DEFAULT_THRESHOLD

        raw_model = ctx.options.get("model")
        if not isinstance(raw_model, str):
            raise ProbeError(
                "token_amplification requires a model identifier in options",
                probe_name=self.name,
            )
        model = raw_model

        raw_max_rps = ctx.options.get("max_rps")
        if isinstance(raw_max_rps, (int, float)) and raw_max_rps > 0:
            min_delay_s = 1.0 / float(raw_max_rps)
        else:
            min_delay_s = 0.0

        endpoint_path = ctx.endpoint or ctx.adapter.default_endpoint_path
        url = build_url(ctx.target, endpoint_path)

        findings: list[Finding] = []
        for category, prompt in PROMPTS:
            result = call_completion(
                ctx.http,
                adapter=ctx.adapter,
                target_base=ctx.target,
                endpoint_path=endpoint_path,
                credential=credential,
                model=model,
                prompt=prompt,
                max_tokens=PROBE_MAX_TOKENS,
                min_delay_s=min_delay_s,
                temperature=ctx.temperature,
            )
            ratio = result.usage.completion_tokens / max(result.usage.prompt_tokens, 1)
            if ratio < threshold:
                continue
            evidence: dict[str, JsonValue] = {
                "amplification_factor": round(ratio, 2),
                "threshold": threshold,
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
                        f"output/input token ratio {ratio:.1f}x meets threshold "
                        f"{threshold:.1f} for category '{category}'"
                    ),
                    target=url,
                    evidence=evidence,
                    remediation=(
                        "Impose a server-side max_tokens cap and enforce per-caller output budgets."
                    ),
                )
            )
        return findings
