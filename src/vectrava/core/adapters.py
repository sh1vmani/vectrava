"""Vendor adapters for request shaping and response parsing.

A VendorAdapter encapsulates the two points where a target's wire protocol shows
through: building the outbound request (URL, body, headers) and parsing the
response into a NormalizedResponse. Probes and shared helpers talk to an adapter
rather than hardcoding one protocol, so supporting another target shape becomes a
new adapter instead of an edit to every probe.

ChatCompletionsAdapter is the first implementation: the chat-completions wire
format that OpenAI-compatible endpoints, including a local Ollama, already speak.
parse_response is non-raising and best-effort. It reports what it found, and what
it could not find as None, leaving error semantics (which absent field is fatal,
which status counts as an error) to the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx
from pydantic import JsonValue


@dataclass(frozen=True)
class NormalizedResponse:
    """A target response parsed into the fields probes consume, protocol-neutral.

    A field is None when the response did not carry it. raw holds the decoded body
    (a dict for a well-formed response, or another JSON value) or None when the
    body was not JSON, so a caller needing a field this shape does not surface can
    still reach it.
    """

    status_code: int
    content: str | None
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None
    finish_reason: str | None
    reported_model: str | None
    raw: JsonValue | None


class VendorAdapter(Protocol):
    """Builds requests and parses responses for one target wire protocol."""

    def build_request(
        self,
        *,
        target_base: str,
        model: str,
        messages: list[dict[str, str]],
        max_tokens: int,
        credential: str,
    ) -> tuple[str, dict[str, object], dict[str, str]]:
        """Return (url, body, headers) for a completion request."""
        ...

    def parse_response(self, response: httpx.Response) -> NormalizedResponse:
        """Parse a response into a NormalizedResponse without raising."""
        ...


class ChatCompletionsAdapter:
    """Adapter for the chat-completions wire format.

    This is the protocol OpenAI-compatible endpoints, including a local Ollama,
    already speak: a messages array and the model in the request body, and the
    reply under choices[0].message.content.
    """

    def build_request(
        self,
        *,
        target_base: str,
        model: str,
        messages: list[dict[str, str]],
        max_tokens: int,
        credential: str,
    ) -> tuple[str, dict[str, object], dict[str, str]]:
        """Build the chat-completions URL, body, and headers."""
        url = target_base.rstrip("/") + "/v1/chat/completions"
        body: dict[str, object] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
        }
        headers = {
            "Authorization": f"Bearer {credential}",
            "Content-Type": "application/json",
        }
        return url, body, headers

    def parse_response(self, response: httpx.Response) -> NormalizedResponse:
        """Best-effort, non-raising extraction of the fields probes consume."""
        status_code = response.status_code
        try:
            body = response.json()
        except ValueError:
            return _empty(status_code, raw=None)
        if not isinstance(body, dict):
            return _empty(status_code, raw=body)

        prompt_tokens, completion_tokens, total_tokens = _extract_usage(body)
        raw_model = body.get("model")
        return NormalizedResponse(
            status_code=status_code,
            content=_extract_content(body),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            finish_reason=_extract_finish_reason(body),
            reported_model=raw_model if isinstance(raw_model, str) else None,
            raw=body,
        )


def _empty(status_code: int, *, raw: JsonValue | None) -> NormalizedResponse:
    """A NormalizedResponse with only the status and raw body populated."""
    return NormalizedResponse(
        status_code=status_code,
        content=None,
        prompt_tokens=None,
        completion_tokens=None,
        total_tokens=None,
        finish_reason=None,
        reported_model=None,
        raw=raw,
    )


def _extract_content(body: dict[str, object]) -> str | None:
    """Read choices[0].message.content if present and a string, else None."""
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    first = choices[0]
    if not isinstance(first, dict):
        return None
    message = first.get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    return content if isinstance(content, str) else None


def _extract_finish_reason(body: dict[str, object]) -> str | None:
    """Read choices[0].finish_reason if present and a string, else None (identity)."""
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        return None
    first = choices[0]
    if not isinstance(first, dict):
        return None
    reason = first.get("finish_reason")
    return reason if isinstance(reason, str) else None


def _extract_usage(body: dict[str, object]) -> tuple[int | None, int | None, int | None]:
    """Read the three usage token counts; each is None unless present and an int."""
    usage = body.get("usage")
    if not isinstance(usage, dict):
        return None, None, None

    def _int_field(name: str) -> int | None:
        value = usage.get(name)
        # bool is a subclass of int; exclude it so a stray True does not count as 1.
        if isinstance(value, bool):
            return None
        return value if isinstance(value, int) else None

    return (
        _int_field("prompt_tokens"),
        _int_field("completion_tokens"),
        _int_field("total_tokens"),
    )
