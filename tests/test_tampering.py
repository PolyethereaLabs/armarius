"""
Tests for tampering detection.

These are the tests that matter most for security correctness.
Every path an attacker might take should be covered here.
"""

import pytest
import nacl.encoding
from armarius.crypto.signature import TrustedIdentity, verify_signature


def test_tampered_command_fails():
    """Attacker changes the command after signing."""
    identity = TrustedIdentity("test")
    signed = identity.sign_command("read file.txt")

    tampered = dict(signed)
    tampered["command"] = "delete everything"

    is_valid, message = verify_signature(tampered)
    assert is_valid is False
    assert "invalid" in message.lower()


def test_tampered_metadata_fails():
    """Attacker changes the signer name in metadata."""
    identity = TrustedIdentity("test")
    signed = identity.sign_command("do task")

    tampered = dict(signed)
    tampered["metadata"] = dict(signed["metadata"])
    tampered["metadata"]["signer"] = "attacker"

    is_valid, message = verify_signature(tampered)
    assert is_valid is False


def test_tampered_timestamp_fails():
    """Attacker changes the timestamp in metadata."""
    identity = TrustedIdentity("test")
    signed = identity.sign_command("do task")

    tampered = dict(signed)
    tampered["metadata"] = dict(signed["metadata"])
    tampered["metadata"]["timestamp"] = "1970-01-01T00:00:00"

    is_valid, message = verify_signature(tampered)
    assert is_valid is False


def test_wrong_verify_key_fails():
    """Attacker substitutes a different public key."""
    alice = TrustedIdentity("alice")
    bob = TrustedIdentity("bob")

    signed_by_alice = alice.sign_command("legitimate command")

    # Swap in bob's verify key — now alice's signature won't verify
    swapped = dict(signed_by_alice)
    swapped["verify_key"] = bob.verify_key.encode(
        encoder=nacl.encoding.HexEncoder
    ).decode()

    is_valid, _ = verify_signature(swapped)
    assert is_valid is False


def test_corrupted_signature_fails():
    """Signature bytes are corrupted."""
    identity = TrustedIdentity("test")
    signed = identity.sign_command("command")

    corrupted = dict(signed)
    corrupted["signature"] = "deadbeef" * 8  # garbage hex

    is_valid, message = verify_signature(corrupted)
    assert is_valid is False


def test_empty_command_still_verifies():
    """Edge case: empty string command should still sign and verify correctly."""
    identity = TrustedIdentity("test")
    signed = identity.sign_command("")
    is_valid, _ = verify_signature(signed)
    assert is_valid is True


def test_replay_from_different_identity_fails():
    """
    Attacker copies a signed command from identity A
    and tries to pass it off as coming from identity B.
    The signature is valid, but it's tied to identity A's key.
    """
    alice = TrustedIdentity("alice")
    bob = TrustedIdentity("bob")

    # Alice signs a command
    alices_signed = alice.sign_command("do task")

    # Bob tries to verify it with his own key — should fail
    # (simulates: attacker takes alice's signed payload and tries to
    # use it in a context that expects bob's signature)
    spoofed = dict(alices_signed)
    spoofed["verify_key"] = bob.verify_key.encode(
        encoder=nacl.encoding.HexEncoder
    ).decode()

    is_valid, _ = verify_signature(spoofed)
    assert is_valid is False
