"""Layer-classifier protocol.

Classifiers attach a `layer` label to one finding. The label is one of:
    - "app"     application-layer code (PHP, npm/PyPI packages, app binaries,
                language-ecosystem libraries)
    - "os"      operating-system layer (apt/apk/yum-managed packages, system
                libraries, kernel headers)
    - "unknown" classifier could not decide with sufficient confidence

`source` is a short identifier for the policy/audit trail.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Label:
    layer: str           # "app" | "os" | "unknown"
    source: str          # classifier identifier
    confidence: float = 1.0
    reasoning: str = ""  # optional rationale for the label


class Classifier(ABC):
    name: str = ""

    @abstractmethod
    def classify(self, finding: dict) -> Label:
        raise NotImplementedError
