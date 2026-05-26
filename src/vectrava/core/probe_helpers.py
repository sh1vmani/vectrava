"""Shared helpers for probe implementations across all modules.

Utilities that more than one probe needs live here, so a single definition
serves every module instead of each probe carrying its own copy. The first
helper extracts assistant content from chat-completions response bodies; helpers
for other response shapes (embeddings, tool calls, and so on) belong here too as
the probe suite grows.
"""

from __future__ import annotations

from vectrava.core.probe import ProbeError


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
