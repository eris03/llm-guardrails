"""
`Guard` ties the input detector and output filter together into a single
object you drop in front of any LLM call — works with any provider since
it never calls a model itself, it only wraps the function you give it.
"""

from __future__ import annotations

import functools
from dataclasses import dataclass, field
from typing import Callable, TypeVar

from .detector import InjectionDetector, DetectionResult, RiskLevel
from .output_filter import OutputFilter, FilterResult

T = TypeVar("T")


class GuardBlockedError(Exception):
    """Raised when input is blocked before ever reaching the model."""

    def __init__(self, detection: DetectionResult):
        self.detection = detection
        super().__init__(
            f"Blocked input (risk={detection.risk_level.value}, "
            f"score={detection.score:.2f}, categories={detection.matched_categories})"
        )


@dataclass
class GuardConfig:
    block_risk_at_least: RiskLevel = RiskLevel.HIGH
    redact_output: bool = True
    canary_tokens: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)
    raise_on_block: bool = True


class Guard:
    """
    Example
    -------
    >>> guard = Guard()
    >>> def call_model(prompt: str) -> str:
    ...     return "some model response"
    >>> safe_call = guard.protect(call_model)
    >>> safe_call("What's the capital of France?")
    'some model response'
    """

    def __init__(self, config: GuardConfig | None = None):
        self.config = config or GuardConfig()
        self.detector = InjectionDetector()
        self.output_filter = OutputFilter(
            canary_tokens=self.config.canary_tokens,
            denylist=self.config.denylist,
        )

    def check_input(self, text: str) -> DetectionResult:
        result = self.detector.scan(text)
        order = [RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        if order.index(result.risk_level) >= order.index(self.config.block_risk_at_least):
            if self.config.raise_on_block:
                raise GuardBlockedError(result)
        return result

    def check_output(self, text: str) -> FilterResult:
        result = self.output_filter.scan(text)
        return result

    def protect(self, fn: Callable[..., str]) -> Callable[..., str]:
        """Decorator: validates the first positional/keyword string arg as
        user input, calls `fn`, then filters its string return value."""

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            prompt = args[0] if args else kwargs.get("prompt", "")
            self.check_input(prompt)
            output = fn(*args, **kwargs)
            filtered = self.check_output(output)
            return filtered.redacted if self.config.redact_output else output

        return wrapper
