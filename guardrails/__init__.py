"""
llm-guardrails
==============

Lightweight, dependency-free guardrails for LLM applications:
- Prompt injection / jailbreak detection on incoming user input
- Output-side guardrails: PII redaction, secret/canary leakage detection,
  denylist filtering
- A `Guard` wrapper that can sit between your app and any LLM call
"""

from .detector import InjectionDetector, DetectionResult
from .output_filter import OutputFilter, FilterResult
from .guard import Guard, GuardConfig, GuardBlockedError

__all__ = [
    "InjectionDetector",
    "DetectionResult",
    "OutputFilter",
    "FilterResult",
    "Guard",
    "GuardConfig",
    "GuardBlockedError",
]

__version__ = "0.1.0"
