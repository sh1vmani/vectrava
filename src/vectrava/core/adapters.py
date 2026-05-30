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

from collections.abc import Callable
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


def build_url(target_base: str, endpoint_path: str) -> str:
    """Join a base target URL and an endpoint path into a request URL.

    The single place dow request URLs are assembled, so the base-plus-path rule
    is not duplicated across probes. The chat-completions builder uses it, and the
    error probe (whose request bodies are deliberately malformed and so cannot go
    through build_request) uses it directly for its URL.
    """
    return target_base.rstrip("/") + endpoint_path


class VendorAdapter(Protocol):
    """Builds requests and parses responses for one target wire protocol."""

    default_endpoint_path: str

    def build_request(
        self,
        *,
        target_base: str,
        model: str,
        messages: list[dict[str, str]],
        max_tokens: int,
        credential: str,
        endpoint_path: str,
    ) -> tuple[str, dict[str, object], dict[str, str]]:
        """Return (url, body, headers) for a completion request.

        Each adapter supplies its own default endpoint_path on the concrete
        method; callers that route through this Protocol pass it explicitly.
        """
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

    default_endpoint_path: str = "/v1/chat/completions"

    def build_request(
        self,
        *,
        target_base: str,
        model: str,
        messages: list[dict[str, str]],
        max_tokens: int,
        credential: str,
        endpoint_path: str = "/v1/chat/completions",
    ) -> tuple[str, dict[str, object], dict[str, str]]:
        """Build the chat-completions URL, body, and headers."""
        url = build_url(target_base, endpoint_path)
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


class MessagesAdapter:
    """Adapter for the messages wire format.

    A second target protocol. The model and a messages array ride in the request
    body as in chat-completions, but the system prompt is a top-level system field
    separate from messages, and the assistant reply comes back as a content-block
    array rather than a single string. build_request lifts a leading system message
    out of the messages list into that top-level field; parse_response joins the
    text blocks, so a reply with no text block (for example tool use only) yields no
    content.
    """

    default_endpoint_path: str = "/v1/messages"

    def build_request(
        self,
        *,
        target_base: str,
        model: str,
        messages: list[dict[str, str]],
        max_tokens: int,
        credential: str,
        endpoint_path: str = "/v1/messages",
    ) -> tuple[str, dict[str, object], dict[str, str]]:
        """Build the messages URL, body, and headers, splitting out a leading system turn."""
        url = build_url(target_base, endpoint_path)
        body: dict[str, object] = {"model": model}
        if messages and messages[0]["role"] == "system":
            body["system"] = messages[0]["content"]
            body["messages"] = messages[1:]
        else:
            body["messages"] = messages
        body["max_tokens"] = max_tokens
        headers = {
            "X-Api-Key": credential,
            "anthropic-version": "2023-06-01",
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

        prompt_tokens, completion_tokens = _extract_messages_usage(body)
        stop_reason = body.get("stop_reason")
        raw_model = body.get("model")
        return NormalizedResponse(
            status_code=status_code,
            content=_extract_message_content(body),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=None,
            finish_reason=stop_reason if isinstance(stop_reason, str) else None,
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


def _extract_message_content(body: dict[str, object]) -> str | None:
    """Join the text of every text block in the messages content array, else None."""
    content = body.get("content")
    if not isinstance(content, list):
        return None
    texts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("type") != "text":
            continue
        text = block.get("text")
        if isinstance(text, str):
            texts.append(text)
    return "".join(texts) if texts else None


def _extract_messages_usage(body: dict[str, object]) -> tuple[int | None, int | None]:
    """Read input/output token counts from the messages usage object; each None unless an int."""
    usage = body.get("usage")
    if not isinstance(usage, dict):
        return None, None

    def _int_field(name: str) -> int | None:
        value = usage.get(name)
        # bool is a subclass of int; exclude it so a stray True does not count as 1.
        if isinstance(value, bool):
            return None
        return value if isinstance(value, int) else None

    return _int_field("input_tokens"), _int_field("output_tokens")


# Vendor selection. SUPPORTED_VENDORS is the single source of truth for which
# protocol ids the CLI accepts; the factory registers an adapter for each. They
# must stay in sync: only ids in SUPPORTED_VENDORS are registered, so a value the
# CLI accepts always resolves to an adapter.
SUPPORTED_VENDORS: tuple[str, ...] = ("chat_completions", "messages")

_VENDOR_ADAPTERS: dict[str, Callable[[], VendorAdapter]] = {
    "chat_completions": ChatCompletionsAdapter,
    "messages": MessagesAdapter,
}


def adapter_for(vendor: str) -> VendorAdapter:
    """Return a fresh adapter instance for a supported vendor id.

    The CLI validates the id against SUPPORTED_VENDORS before calling, so this is
    the authoritative backstop: an unregistered id raises ValueError rather than
    silently falling back to a default protocol.
    """
    try:
        factory = _VENDOR_ADAPTERS[vendor]
    except KeyError as exc:
        supported = ", ".join(SUPPORTED_VENDORS)
        raise ValueError(f"unknown vendor {vendor!r}; supported: {supported}") from exc
    return factory()
