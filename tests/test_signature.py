"""
Tests for the cryptographic signature layer.
"""

import pytest
from armarius.crypto.signature import TrustedIdentity, verify_signature


def test_sign_and_verify_succeeds():
    identity = TrustedIdentity("test")
    signed = identity.sign_command("do something")
    is_valid, message = verify_signature(signed)
    assert is_valid is True
    assert "valid" in message.lower()


def test_signed_dict_has_required_fields():
    identity = TrustedIdentity("test")
    signed = identity.sign_command("do something")
    assert "command" in signed
    assert "signature" in signed
    assert "verify_key" in signed
    assert "metadata" in signed


def test_metadata_contains_timestamp_and_signer():
    identity = TrustedIdentity("alice")
    signed = identity.sign_command("test command")
    assert "timestamp" in signed["metadata"]
    assert signed["metadata"]["signer"] == "alice"


def test_custom_metadata_is_preserved():
    identity = TrustedIdentity("test")
    signed = identity.sign_command("cmd", {"job_id": "42"})
    assert signed["metadata"]["job_id"] == "42"


def test_different_identities_produce_different_keys():
    alice = TrustedIdentity("alice")
    bob = TrustedIdentity("bob")
    assert alice.verify_key != bob.verify_key
