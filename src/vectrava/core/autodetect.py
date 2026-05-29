"""Detect a locally running Ollama for zero-config target resolution.

When the operator omits --target, vectrava probes a local Ollama at its default
port and, on a response, resolves the scan target to that base. The returned
model list is captured now for a later model-selection change; this module only
detects reachability and reports what it found, and never selects a model.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class OllamaDetection:
    """A reachable local Ollama and the model names it reported.

    Attributes:
        base_url: The base URL the detection succeeded against.
        models: Model names from the tags endpoint, order preserved. May be empty
            when Ollama is reachable but has no models pulled.
    """

    base_url: str
    models: tuple[str, ...]


def detect_ollama(
    *,
    client: httpx.Client | None = None,
    base_url: str = "http://localhost:11434",
    timeout: float = 1.0,
) -> OllamaDetection | None:
    """Probe a local Ollama tags endpoint and report reachability.

    Args:
        client: HTTP client to use. When None, a short-timeout client is built and
            closed by this function. When provided, it is used as-is and never
            closed; the caller owns its lifetime.
        base_url: The Ollama base URL to probe.
        timeout: Total request timeout in seconds for the owned client. The
            sub-second connect bound and roughly one-second total are a deliberate
            deviation from the 60s scan convention, because this is a localhost
            liveness probe that must fail fast when nothing is listening.

    Returns:
        An OllamaDetection on a 200 response whose JSON body is a dict with a
        "models" list. None on any transport failure, non-200 status, non-JSON
        body, or unexpected shape.
    """
    url = base_url + "/api/tags"
    if client is None:
        with httpx.Client(timeout=httpx.Timeout(timeout, connect=0.5)) as owned:
            return _probe(owned, url, base_url)
    return _probe(client, url, base_url)


def _probe(client: httpx.Client, url: str, base_url: str) -> OllamaDetection | None:
    """Run the tags GET and parse the response into a detection, or None on miss."""
    try:
        response = client.get(url)
    except httpx.TransportError:
        return None
    if response.status_code != 200:
        return None
    try:
        body = response.json()
    except ValueError:
        return None
    if not isinstance(body, dict):
        return None
    raw_models = body.get("models")
    if not isinstance(raw_models, list):
        return None
    names: list[str] = []
    for entry in raw_models:
        if isinstance(entry, dict):
            name = entry.get("name")
            if isinstance(name, str):
                names.append(name)
    return OllamaDetection(base_url=base_url, models=tuple(names))
