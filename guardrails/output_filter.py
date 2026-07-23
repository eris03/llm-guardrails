"""
Output-side guardrails.

Even when the prompt is clean, the *model's response* can still leak PII,
secrets, canary tokens (used to detect system-prompt exfiltration), or
denylisted content. `OutputFilter` scans and optionally redacts model
output before it reaches the end user.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class FilterResult:
    original: str
    redacted: str
    flagged: bool
    findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"flagged": self.flagged, "findings": self.findings}


_PII_PATTERNS: dict[str, re.Pattern] = {
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "phone": re.compile(r"\b(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

# Common API-key / secret formats.
_SECRET_PATTERNS: dict[str, re.Pattern] = {
    "openai_key": re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    "anthropic_key": re.compile(r"\bsk-ant-[A-Za-z0-9\-]{20,}\b"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "generic_bearer": re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}=*\b"),
    "private_key_block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


class OutputFilter:
    """Scan/redact model output for PII, secrets, canary tokens, and
    denylisted content.

    Parameters
    ----------
    canary_tokens:
        Unique strings planted in your system prompt (e.g.
        ``"CANARY-7f3a9c"``). If one appears in the model's *output*, it is
        strong evidence of a successful prompt/system-instruction leak.
    denylist:
        Extra literal strings or regexes the app never wants to surface
        (brand names under embargo, internal codenames, etc).
    redact_pii / redact_secrets:
        Toggle each category independently.
    """

    def __init__(
        self,
        canary_tokens: list[str] | None = None,
        denylist: list[str] | None = None,
        redact_pii: bool = True,
        redact_secrets: bool = True,
        mask: str = "[REDACTED:{}]",
    ):
        self.canary_tokens = canary_tokens or []
        self.denylist = [re.compile(re.escape(d), re.I) for d in (denylist or [])]
        self.redact_pii = redact_pii
        self.redact_secrets = redact_secrets
        self.mask = mask

    def scan(self, text: str) -> FilterResult:
        findings: list[str] = []
        redacted = text

        if self.redact_secrets:
            for name, pattern in _SECRET_PATTERNS.items():
                if pattern.search(redacted):
                    findings.append(f"secret:{name}")
                    redacted = pattern.sub(self.mask.format(name.upper()), redacted)

        if self.redact_pii:
            for name, pattern in _PII_PATTERNS.items():
                if pattern.search(redacted):
                    findings.append(f"pii:{name}")
                    redacted = pattern.sub(self.mask.format(name.upper()), redacted)

        for token in self.canary_tokens:
            if token and token in redacted:
                findings.append("canary_leak")
                redacted = redacted.replace(token, self.mask.format("CANARY"))

        for pattern in self.denylist:
            if pattern.search(redacted):
                findings.append(f"denylist:{pattern.pattern}")
                redacted = pattern.sub(self.mask.format("BLOCKED"), redacted)

        return FilterResult(
            original=text,
            redacted=redacted,
            flagged=len(findings) > 0,
            findings=findings,
        )
