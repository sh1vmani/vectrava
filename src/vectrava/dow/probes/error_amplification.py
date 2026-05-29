"""Error-path cost amplification probe.

Sends requests that a well-behaved gateway should reject at its input-validation
layer (oversized prompt, nonexistent model, wrong-typed message content) and
checks whether the error response still reports token usage. A usage block on a
rejected request is evidence the target counted tokens before refusing, which
bills the caller for work that never produced a result: a Denial-of-Wallet
vector on the error path.

Unlike the other dow probes, this one imports post_with_retry directly instead
of dow.client.call_completion. call_completion raises ProbeError on every non-2xx
status and discards the body, but this probe must inspect the 4xx/5xx body to
detect a usage block. Do not "fix" this by switching to call_completion: that
would throw away exactly the evidence the probe exists to read.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from vectrava.core.adapters import build_url
from vectrava.core.http import post_with_retry
from vectrava.core.probe import Probe, ProbeError
from vectrava.core.registry import register
from vectrava.core.result import Severity

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydantic import JsonValue

    from vectrava.core.probe import ProbeContext
    from vectrava.core.result import Finding

PROBE_MAX_TOKENS: int = 16
# "a " repeated this many times is a ~100k-character prompt (~50k tokens), which
# exceeds the context window of any current chat model and should be rejected.
OVERSIZED_REPEAT: int = 50_000
# An obviously-fake model name; the vectrava_probe_ prefix makes it grep-able in
# a target's logs so an operator can confirm the probe is the source.
SENTINEL_MODEL: str = "vectrava_probe_nonexistent_model_zzz"


def _oversized_prompt_body(model: str) -> dict[str, object]:
    """Request body whose prompt is far larger than any context window."""
    return {
        "model": model,
        "messages": [{"role": "user", "content": "a " * OVERSIZED_REPEAT}],
        "max_tokens": PROBE_MAX_TOKENS,
    }


def _invalid_model_body(model: str) -> dict[str, object]:
    """Request body naming a model that does not exist.

    The operator model is ignored on purpose: the sentinel is what triggers the
    rejection. The parameter is kept so every shape builder shares one signature.
    """
    del model
    return {
        "model": SENTINEL_MODEL,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": PROBE_MAX_TOKENS,
    }


def _malformed_messages_body(model: str) -> dict[str, object]:
    """Request body whose message content is an integer instead of a string."""
    return {
        "model": model,
        "messages": [{"role": "user", "content": 12345}],
        "max_tokens": PROBE_MAX_TOKENS,
    }


SHAPES: tuple[tuple[str, Callable[[str], dict[str, object]]], ...] = (
    ("oversized_prompt", _oversized_prompt_body),
    ("invalid_model", _invalid_model_body),
    ("malformed_messages", _malformed_messages_body),
)


@register
class ErrorAmplificationProbe(Probe):
    """Flags targets that report token usage on requests they reject."""

    name: ClassVar[str] = "error_amplification"
    module: ClassVar[str] = "dow"
    description: ClassVar[str] = (
        "Sends requests that should be rejected by the target's input-validation "
        "layer and checks whether the error responses still report token usage, "
        "which would indicate billing on failed requests."
    )
    baseline_severity: ClassVar[Severity] = Severity.MEDIUM
    estimated_tokens_per_run: ClassVar[int] = OVERSIZED_REPEAT + 3 * (30 + PROBE_MAX_TOKENS)
    tags: ClassVar[tuple[str, ...]] = ("dow", "cost", "error-path")
    requires_credentials: ClassVar[bool] = True
    default_endpoint: ClassVar[str | None] = "/v1/chat/completions"

    def run(self, ctx: ProbeContext) -> list[Finding]:
        """Send each rejection shape and flag any error response that reports usage."""
        if ctx.credentials is None:
            raise ProbeError(
                "error_amplification requires credentials but none were provided",
                probe_name=self.name,
            )
        credential = ctx.credentials

        raw_model = ctx.options.get("model")
        if not isinstance(raw_model, str):
            raise ProbeError(
                "error_amplification requires a model identifier in options",
                probe_name=self.name,
            )
        model = raw_model

        raw_max_rps = ctx.options.get("max_rps")
        if isinstance(raw_max_rps, (int, float)) and raw_max_rps > 0:
            min_delay_s = 1.0 / float(raw_max_rps)
        else:
            min_delay_s = 0.0

        endpoint_path = ctx.endpoint or self.default_endpoint or "/v1/chat/completions"
        url = build_url(ctx.target, endpoint_path)
        headers = {
            "Authorization": f"Bearer {credential}",
            "Content-Type": "application/json",
        }

        findings: list[Finding] = []
        for label, build_body in SHAPES:
            response = post_with_retry(
                ctx.http,
                url,
                json=build_body(model),
                headers=headers,
                timeout=60.0,
                min_delay_s=min_delay_s,
            )
            if 200 <= response.status_code < 300:
                # The target accepted a request that should have been rejected. That
                # is a different class of issue, out of scope for this probe.
                continue

            try:
                data = response.json()
            except ValueError:
                # A non-JSON error body is acceptable target behavior, not a finding.
                continue
            if not isinstance(data, dict):
                continue
            usage = data.get("usage")
            if not isinstance(usage, dict):
                continue
            total_tokens = usage.get("total_tokens")
            if not isinstance(total_tokens, (int, float)) or total_tokens <= 0:
                continue

            evidence: dict[str, JsonValue] = {
                "shape_label": label,
                "http_status": response.status_code,
                "total_tokens": total_tokens,
                "endpoint": url,
            }
            prompt_tokens = usage.get("prompt_tokens")
            if isinstance(prompt_tokens, (int, float)):
                evidence["prompt_tokens"] = prompt_tokens
            completion_tokens = usage.get("completion_tokens")
            if isinstance(completion_tokens, (int, float)):
                evidence["completion_tokens"] = completion_tokens
            error_obj = data.get("error")
            if isinstance(error_obj, dict):
                error_code = error_obj.get("code")
                if isinstance(error_code, str):
                    evidence["error_code"] = error_code
                error_type = error_obj.get("type")
                if isinstance(error_type, str):
                    evidence["error_type"] = error_type

            findings.append(
                self.make_finding(
                    message=(
                        f"shape '{label}' was rejected with HTTP {response.status_code} "
                        f"but the error response reported {total_tokens} token(s) of usage"
                    ),
                    target=url,
                    evidence=evidence,
                    remediation=(
                        "Reject invalid requests at the gateway before any token counting "
                        "or model dispatch, so failed requests do not bill the caller."
                    ),
                )
            )
        return findings
