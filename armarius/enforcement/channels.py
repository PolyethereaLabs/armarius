"""
Channel separation — the architectural heart of Armarius.

Every input to a protected agent is routed to one of two channels:

  CONTROL channel  — input is signed and verified. The agent can execute it.
  CONTENT channel  — input is unsigned (or signature is invalid). The agent
                     can read and analyze it, but it cannot execute commands
                     embedded within it.

This boundary is enforced structurally, not by pattern matching or heuristics.
An attacker cannot craft text that "tricks" the classifier — they would need
the private key.
"""

import json
from enum import Enum
from dataclasses import dataclass, field

from armarius.crypto.signature import verify_signature


class ChannelType(Enum):
    CONTROL = "control"   # Signed + verified — can execute
    CONTENT = "content"   # Unsigned or invalid — read-only context


@dataclass
class ProcessedInput:
    """
    The result of routing an input through Armarius.

    Attributes:
        channel:  CONTROL (trusted, executable) or CONTENT (untrusted, read-only)
        content:  The actual string content to work with
        metadata: Routing metadata — signer, timestamp, warnings
    """
    channel: ChannelType
    content: str
    metadata: dict = field(default_factory=dict)


def _looks_signed(input_data) -> bool:
    """Check whether input_data has the shape of a signed command dict."""
    return (
        isinstance(input_data, dict)
        and all(k in input_data for k in ['command', 'signature', 'verify_key', 'metadata'])
    )


def _to_string(input_data) -> str:
    """Safely convert any input to a plain string for content-channel use."""
    if isinstance(input_data, str):
        return input_data
    if isinstance(input_data, dict):
        return json.dumps(input_data)
    return str(input_data)


def route_input(input_data, verify_key=None) -> ProcessedInput:
    """
    Route an input to the appropriate channel.

    If input_data looks like a signed command dict and its signature
    verifies successfully, it goes to the CONTROL channel and its
    command string is returned for execution.

    Everything else — unsigned strings, documents, emails, API responses,
    tool outputs, invalid signatures — goes to the CONTENT channel.
    It can be read, summarized, or discussed, but cannot execute.

    Args:
        input_data:  The raw input to the agent (string or signed dict)
        verify_key:  The TrustedIdentity's verify_key to check against.
                     If None, all inputs are routed to CONTENT.

    Returns:
        ProcessedInput with channel, content, and metadata.
    """
    if verify_key is not None and _looks_signed(input_data):
        is_valid, message = verify_signature(input_data)

        if is_valid:
            return ProcessedInput(
                channel=ChannelType.CONTROL,
                content=input_data['command'],
                metadata=input_data.get('metadata', {})
            )
        else:
            # Signed but invalid — tampering attempt or corrupted payload
            return ProcessedInput(
                channel=ChannelType.CONTENT,
                content=_to_string(input_data),
                metadata={
                    'warning': 'invalid_signature',
                    'reason': message
                }
            )

    # No signature, or no verify_key provided — content channel
    return ProcessedInput(
        channel=ChannelType.CONTENT,
        content=_to_string(input_data),
        metadata={'warning': 'unsigned_input'}
    )
