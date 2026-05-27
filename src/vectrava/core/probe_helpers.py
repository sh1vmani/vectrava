"""Shared helpers for probe implementations across all modules.

Utilities that more than one probe needs live here, so a single definition
serves every module instead of each probe carrying its own copy. The first
helper extracts assistant content from chat-completions response bodies; helpers
for other response shapes (embeddings, tool calls, and so on) belong here too as
the probe suite grows.
"""

from __future__ import annotations

import httpx

from vectrava.core.http import post_with_retry
from vectrava.core.probe import ProbeError

# Shared pool of topic-neutral filler-turn texts for multi-turn probes. A probe
# that needs benign turns between an injection and a later exploit cycles this
# pool with GENERIC_FILLER_TURNS[(next_turn - 2) % len(GENERIC_FILLER_TURNS)].
# Add an entry only if it is genuinely topic-neutral: no domain framing and no
# trigger-adjacent words (for example "summary", "wrap", "final", "code",
# "marker") that a probe relies on appearing only in its own final turn.
# Frame-coupled filler stays local to the probe that needs it; the co-writing
# filler in multi_turn_refusal_erosion is not generic and is not lifted here.
GENERIC_FILLER_TURNS: tuple[str, ...] = (
    "What is the capital of France?",
    "Can you suggest a good book to read this weekend?",
    "How many days are there in a leap year?",
    "What is a simple recipe for scrambled eggs?",
    "Recommend a short stretching routine for someone who sits all day.",
    "What is the difference between weather and climate?",
    "Give me one fun fact about octopuses.",
    "How do I convert miles to kilometers?",
)


def extract_chat_completion_content(
    body: object,
    label: str,
    probe_name: str,
) -> str:
    """Extract the assistant message content from a chat-completions response.

    Args:
        body: The JSON-decoded response body.
        label: The probe-internal label of the current injection or test case,
            used for error context.
        probe_name: The probe's name attribute, used for error attribution.

    Returns:
        The string content from choices[0]["message"]["content"].

    Raises:
        ProbeError: If body is not a dict, choices is missing, empty, or not a
            list, the first choice is not a dict, message is missing or not a
            dict, or content is missing or not a string.
    """
    try:
        choices = body["choices"]  # type: ignore[index]
        content = choices[0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ProbeError(
            "target response was not a chat-completions object with message content",
            probe_name=probe_name,
            details={"injection_label": label},
        ) from exc
    if not isinstance(content, str):
        raise ProbeError(
            "target response message content was not a string",
            probe_name=probe_name,
            details={"injection_label": label},
        )
    return content


def interleave_padding_chunks(
    chunks: tuple[str, ...],
    filler_chunks: tuple[str, ...],
    target_count: int,
) -> tuple[str, ...]:
    """Interleave filler chunks between attack chunks to reach target_count.

    Padding inserts filler chunks between attack chunks rather than appending at
    the end. This distributes attack content across the source list as a real
    retrieval system would, producing an adversarially realistic stress test for
    high-density RAG pipelines.

    Args:
        chunks: The attack-pattern chunks (typically 3). Returned unchanged if
            len(chunks) >= target_count.
        filler_chunks: Pool of benign filler strings; cycled through if
            target_count - len(chunks) exceeds the pool size.
        target_count: Desired total chunk count after padding. Must be positive;
            values <= len(chunks) skip padding entirely.

    Returns:
        A tuple of length max(len(chunks), target_count) with filler chunks
        interleaved between the original chunks. For target_count=5 and 3 attack
        chunks the result is [c0, f0, c1, f1, c2] (interleaved).
    """
    if target_count <= len(chunks):
        return chunks
    padding_count = target_count - len(chunks)
    padded: list[str] = []
    filler_iter = iter(filler_chunks[i % len(filler_chunks)] for i in range(padding_count))
    for position, chunk in enumerate(chunks):
        padded.append(chunk)
        if position < len(chunks) - 1 and padding_count > 0:
            padded.append(next(filler_iter))
            padding_count -= 1
    while padding_count > 0:
        padded.append(next(filler_iter))
        padding_count -= 1
    return tuple(padded)


def exchange_turn(
    *,
    client: httpx.Client,
    url: str,
    messages: list[dict[str, str]],
    model: str,
    max_tokens: int,
    credential: str,
    probe_name: str,
    label: str,
    turn_index: int,
    timeout: float = 60.0,
    min_delay_s: float = 0.0,
) -> str:
    """Run one chat-completions turn against the target and capture the reply.

    Sends the current `messages` list, fails fast on an HTTP error, extracts the
    assistant content, and appends it back so the conversation grows turn by turn.
    This is the shared single-turn primitive for multi-turn probes; the caller
    owns the outer loop, the detection rule, and the choice of the next user turn.

    The `messages` list is mutated in place: on success an assistant turn
    `{"role": "assistant", "content": content}` is appended before returning.

    Args:
        client: Synchronous HTTP client supplied by the runner.
        url: Fully resolved POST URL.
        messages: The running conversation. Mutated in place (assistant turn
            appended on success).
        model: Model identifier placed in the request body.
        max_tokens: Output cap requested from the target.
        credential: Resolved BYOK value, sent as a Bearer token. Headers are
            built internally; the caller does not pass a header dict.
        probe_name: The calling probe's name, used for error attribution.
        label: The probe-internal label of the current injection or framing case.
        turn_index: The 1-based conversation turn index, combined with `label`
            for error context.
        timeout: Per-request timeout in seconds.
        min_delay_s: Minimum seconds between consecutive requests on the same
            client, forwarded to post_with_retry for rate limiting.

    Returns:
        The assistant message content from this turn.

    Raises:
        ProbeError: on a non-2xx status, or when the response is not a
            chat-completions object with string message content.
    """
    payload: dict[str, object] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
    }
    headers = {
        "Authorization": f"Bearer {credential}",
        "Content-Type": "application/json",
    }
    response = post_with_retry(
        client,
        url,
        json=payload,
        headers=headers,
        timeout=timeout,
        min_delay_s=min_delay_s,
    )
    if response.status_code >= 400:
        raise ProbeError(
            f"target returned HTTP {response.status_code}",
            probe_name=probe_name,
            details={
                "status": response.status_code,
                "injection_label": label,
                "turn": turn_index,
            },
        )

    content = extract_chat_completion_content(
        response.json(), f"{label}:turn{turn_index}", probe_name
    )
    messages.append({"role": "assistant", "content": content})
    return content
