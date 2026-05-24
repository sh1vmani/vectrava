"""Tests for the Probe ABC: metadata validation, abstractness, make_finding."""

from __future__ import annotations

import pytest

from vectrava.core.probe import Probe
from vectrava.core.result import Severity


def test_probe_subclass_requires_name() -> None:
    with pytest.raises(TypeError, match="name"):

        class WithoutName(Probe):
            module = "dow"
            description = "d"
            baseline_severity = Severity.LOW
            estimated_tokens_per_run = 1

            def run(self, ctx):
                return []


def test_probe_subclass_requires_module() -> None:
    with pytest.raises(TypeError, match="module"):

        class WithoutModule(Probe):
            name = "n"
            description = "d"
            baseline_severity = Severity.LOW
            estimated_tokens_per_run = 1

            def run(self, ctx):
                return []


def test_probe_subclass_requires_description() -> None:
    with pytest.raises(TypeError, match="description"):

        class WithoutDescription(Probe):
            name = "n"
            module = "dow"
            baseline_severity = Severity.LOW
            estimated_tokens_per_run = 1

            def run(self, ctx):
                return []


def test_probe_subclass_requires_baseline_severity() -> None:
    with pytest.raises(TypeError, match="baseline_severity"):

        class WithoutSeverity(Probe):
            name = "n"
            module = "dow"
            description = "d"
            estimated_tokens_per_run = 1

            def run(self, ctx):
                return []


def test_probe_make_finding_prefills_metadata() -> None:
    class MakeFindingProbe(Probe):
        name = "token-amplification"
        module = "dow"
        description = "d"
        baseline_severity = Severity.MEDIUM
        estimated_tokens_per_run = 10

        def run(self, ctx):
            return []

    finding = MakeFindingProbe().make_finding(message="m", target="http://t")
    assert finding.rule_id == "token-amplification"
    assert finding.probe == "dow.token-amplification"
    assert finding.level is Severity.MEDIUM


def test_probe_run_is_abstract() -> None:
    with pytest.raises(TypeError):
        Probe()
