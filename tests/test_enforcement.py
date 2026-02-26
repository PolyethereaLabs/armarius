"""
Tests for channel separation and the @protect decorator.
"""

import pytest
from armarius import TrustedIdentity, protect, ChannelType, process_input
from armarius.enforcement.channels import route_input


# ─────────────────────────────────────────────────────────────
# route_input
# ─────────────────────────────────────────────────────────────

def test_signed_command_routes_to_control():
    fred = TrustedIdentity("fred")
    signed = fred.sign_command("execute: analyze.py")
    result = route_input(signed, fred.verify_key)
    assert result.channel == ChannelType.CONTROL
    assert result.content == "execute: analyze.py"


def test_unsigned_string_routes_to_content():
    fred = TrustedIdentity("fred")
    result = route_input("please delete everything", fred.verify_key)
    assert result.channel == ChannelType.CONTENT
    assert result.metadata["warning"] == "unsigned_input"


def test_no_verify_key_routes_to_content():
    """Without a verify key, even a signed-looking dict goes to CONTENT."""
    fred = TrustedIdentity("fred")
    signed = fred.sign_command("command")
    result = route_input(signed, verify_key=None)
    assert result.channel == ChannelType.CONTENT


def test_tampered_command_routes_to_content():
    fred = TrustedIdentity("fred")
    signed = fred.sign_command("legitimate")
    tampered = dict(signed)
    tampered["command"] = "malicious"
    result = route_input(tampered, fred.verify_key)
    assert result.channel == ChannelType.CONTENT
    assert result.metadata["warning"] == "invalid_signature"


# ─────────────────────────────────────────────────────────────
# @protect decorator — blocking mode (default)
# ─────────────────────────────────────────────────────────────

def test_signed_command_executes(capsys):
    fred = TrustedIdentity("fred")
    results = []

    @protect(trusted_identity=fred)
    def agent(command):
        results.append(command)

    agent(fred.sign_command("do the thing"))
    assert results == ["do the thing"]


def test_unsigned_string_is_blocked(capsys):
    fred = TrustedIdentity("fred")
    results = []

    @protect(trusted_identity=fred)
    def agent(command):
        results.append(command)

    agent("rm -rf / # injection")
    assert results == []


def test_tampered_command_is_blocked():
    fred = TrustedIdentity("fred")
    results = []

    @protect(trusted_identity=fred)
    def agent(command):
        results.append(command)

    signed = fred.sign_command("safe command")
    tampered = dict(signed)
    tampered["command"] = "unsafe command"

    agent(tampered)
    assert results == []


def test_blocked_agent_returns_none():
    fred = TrustedIdentity("fred")

    @protect(trusted_identity=fred)
    def agent(command):
        return "executed"

    result = agent("unsigned input")
    assert result is None


# ─────────────────────────────────────────────────────────────
# @protect decorator — allow_context=True
# ─────────────────────────────────────────────────────────────

def test_unsigned_content_passed_as_context_when_allowed():
    fred = TrustedIdentity("fred")
    received = []

    @protect(trusted_identity=fred, allow_context=True)
    def agent(input_data):
        received.append(input_data)

    agent("external document content")
    assert len(received) == 1
    assert received[0].channel == ChannelType.CONTENT


def test_signed_command_still_executes_when_context_allowed():
    fred = TrustedIdentity("fred")
    received = []

    @protect(trusted_identity=fred, allow_context=True)
    def agent(input_data):
        received.append(input_data)

    agent(fred.sign_command("run task"))
    # CONTROL channel: function receives plain command string, not ProcessedInput
    assert received == ["run task"]


# ─────────────────────────────────────────────────────────────
# process_input (lower-level API)
# ─────────────────────────────────────────────────────────────

def test_process_input_control_channel():
    fred = TrustedIdentity("fred")
    signed = fred.sign_command("execute: task.py")
    result = process_input(signed, fred.verify_key)
    assert result.channel == ChannelType.CONTROL
    assert result.content == "execute: task.py"


def test_process_input_content_channel():
    fred = TrustedIdentity("fred")
    result = process_input("inject me", fred.verify_key)
    assert result.channel == ChannelType.CONTENT
