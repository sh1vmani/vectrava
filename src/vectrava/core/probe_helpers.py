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
