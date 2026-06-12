"""Layer classifiers: produce a `layer` label on each finding.

Each classifier implements `classify(finding) -> (layer, source)` where layer
is one of "app" | "os" | "unknown" and source is a short identifier
("rule", "agent:claude", "agent:gpt-4", ...).

To add a new classifier:
    1. Implement a `Classifier` subclass in a new module.
    2. Register it in `CLASSIFIERS` below, or pass it explicitly.
"""

from __future__ import annotations

from .base import Classifier, Label
from .rule_based import RuleClassifier


CLASSIFIERS: dict[str, Classifier] = {
    "rule": RuleClassifier(),
}

# AgentClassifier instantiates lazily because it reads env vars at construct
# time and raises if no API key is present. Register only when available.
try:
    from .agent import AgentClassifier, is_available as agent_available
    if agent_available():
        CLASSIFIERS["agent"] = AgentClassifier()
except Exception:
    pass


def get(name: str) -> Classifier:
    """Return a classifier by name; defaults to rule-based."""
    return CLASSIFIERS.get(name, CLASSIFIERS["rule"])


__all__ = ["Classifier", "Label", "RuleClassifier", "CLASSIFIERS", "get"]
