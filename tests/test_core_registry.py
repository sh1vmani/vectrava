"""Tests for the probe registry: registration, lookup, and filtering."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from vectrava.core import registry
from vectrava.core.probe import Probe
from vectrava.core.result import Severity


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    registry.clear()
    yield
    registry.clear()


def make_probe(name: str, module: str = "dow", tags: tuple[str, ...] = ()) -> type[Probe]:
    return type(
        name,
        (Probe,),
        {
            "name": name,
            "module": module,
            "description": "test probe",
            "baseline_severity": Severity.LOW,
            "estimated_tokens_per_run": 1,
            "tags": tags,
            "run": lambda self, ctx: [],
        },
    )


def test_register_decorator_adds_to_registry() -> None:
    probe_cls = make_probe("p1")
    registry.register(probe_cls)
    assert registry.get("p1") is probe_cls


def test_duplicate_registration_raises() -> None:
    registry.register(make_probe("dup"))
    with pytest.raises(ValueError, match="already registered"):
        registry.register(make_probe("dup"))


def test_all_returns_all_registered_probes() -> None:
    a = make_probe("a")
    b = make_probe("b")
    registry.register(a)
    registry.register(b)
    assert set(registry.all()) == {a, b}


def test_by_module_filters_correctly() -> None:
    dow_probe = make_probe("d", module="dow")
    ipi_probe = make_probe("i", module="ipi")
    registry.register(dow_probe)
    registry.register(ipi_probe)
    assert registry.by_module("dow") == [dow_probe]
    assert registry.by_module("ipi") == [ipi_probe]


def test_by_tag_filters_correctly() -> None:
    cost_probe = make_probe("c", tags=("cost",))
    other_probe = make_probe("o", tags=("other",))
    registry.register(cost_probe)
    registry.register(other_probe)
    assert registry.by_tag("cost") == [cost_probe]


def test_get_returns_probe_class() -> None:
    probe_cls = make_probe("getme")
    registry.register(probe_cls)
    assert registry.get("getme") is probe_cls


def test_get_unknown_name_raises_with_helpful_message() -> None:
    registry.register(make_probe("known"))
    with pytest.raises(KeyError, match=r"not found.*Available.*known"):
        registry.get("missing")
