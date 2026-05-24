"""Probe registry: registration, lookup, and filtering.

Probes register with the `@register` class decorator. The CLI and tests look
probes up by name, module, or tag. The registry stores classes; the runner
instantiates them per scan.
"""

from __future__ import annotations

from typing import TypeVar

from vectrava.core.probe import Probe

_REGISTRY: dict[str, type[Probe]] = {}

P = TypeVar("P", bound=Probe)


def register(cls: type[P]) -> type[P]:
    """Register a probe class under its declared name.

    Args:
        cls: The probe subclass to register.

    Returns:
        The same class, so this works as a class decorator.

    Raises:
        ValueError: if a probe with the same name is already registered.
    """
    if cls.name in _REGISTRY:
        existing = _REGISTRY[cls.name].__qualname__
        msg = f"probe name {cls.name!r} is already registered by {existing}"
        raise ValueError(msg)
    _REGISTRY[cls.name] = cls
    return cls


def all() -> list[type[Probe]]:
    """Return every registered probe class."""
    return list(_REGISTRY.values())


def by_module(module: str) -> list[type[Probe]]:
    """Return registered probes belonging to the given module."""
    return [cls for cls in _REGISTRY.values() if cls.module == module]


def by_tag(tag: str) -> list[type[Probe]]:
    """Return registered probes carrying the given tag."""
    return [cls for cls in _REGISTRY.values() if tag in cls.tags]


def get(name: str) -> type[Probe]:
    """Return the probe class registered under `name`.

    Args:
        name: The probe name to look up.

    Returns:
        The probe class.

    Raises:
        KeyError: if no probe is registered under that name.
    """
    try:
        return _REGISTRY[name]
    except KeyError:
        available = ", ".join(sorted(_REGISTRY)) or "(none registered)"
        msg = f"probe {name!r} not found. Available: {available}"
        raise KeyError(msg) from None


def clear() -> None:
    """Remove all registered probes. Intended for test fixtures only."""
    _REGISTRY.clear()
