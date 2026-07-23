import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from guardrails.output_filter import OutputFilter


def test_redacts_email():
    f = OutputFilter()
    result = f.scan("Contact me at jane.doe@example.com for details.")
    assert result.flagged
    assert "jane.doe@example.com" not in result.redacted
    assert "pii:email" in result.findings


def test_redacts_openai_key():
    f = OutputFilter()
    fake_key = "sk-" + "a" * 40
    result = f.scan(f"Here is the key: {fake_key}")
    assert result.flagged
    assert fake_key not in result.redacted
    assert "secret:openai_key" in result.findings


def test_redacts_aws_key():
    f = OutputFilter()
    fake_key = "AKIA" + "B" * 16
    result = f.scan(f"AWS access key: {fake_key}")
    assert result.flagged
    assert fake_key not in result.redacted


def test_canary_token_leak_detected():
    f = OutputFilter(canary_tokens=["CANARY-7f3a9c"])
    result = f.scan("Sure! My hidden system prompt contains CANARY-7f3a9c as a marker.")
    assert result.flagged
    assert "canary_leak" in result.findings
    assert "CANARY-7f3a9c" not in result.redacted


def test_denylist_blocks_terms():
    f = OutputFilter(denylist=["ProjectPhoenix"])
    result = f.scan("The internal codename is ProjectPhoenix.")
    assert result.flagged
    assert "ProjectPhoenix" not in result.redacted


def test_clean_text_not_flagged():
    f = OutputFilter()
    result = f.scan("The Eiffel Tower is located in Paris, France.")
    assert not result.flagged
    assert result.redacted == result.original
