"""
process_input() — lower-level channel routing with audit logging.

For developers who want direct control over routing logic rather than
using the @protect decorator. Returns a ProcessedInput that the agent
can inspect and act on itself.

Usage:

    from armarius import TrustedIdentity, process_input, ChannelType

    fred = TrustedIdentity("fred")

    def my_agent(raw_input):
        result = process_input(raw_input, fred.verify_key)

        if result.channel == ChannelType.CONTROL:
            execute(result.content)
        elif result.channel == ChannelType.CONTENT:
            log_and_summarize(result.content)
"""

import logging
from armarius.enforcement.channels import route_input, ChannelType, ProcessedInput

logger = logging.getLogger("armarius")


def process_input(input_data, verify_key=None) -> ProcessedInput:
    """
    Route an input to the appropriate channel and log the decision.

    Args:
        input_data:  The raw input (string or signed command dict)
        verify_key:  The TrustedIdentity's verify_key to check against

    Returns:
        ProcessedInput with channel type, content, and metadata.
        Caller is responsible for enforcing the channel boundary.
    """
    result = route_input(input_data, verify_key)

    if result.channel == ChannelType.CONTROL:
        logger.info(
            "[Armarius] CONTROL — executing: %s",
            result.content[:80]
        )
    else:
        warning = result.metadata.get('warning', 'unknown')
        logger.warning(
            "[Armarius] CONTENT — blocked execution (%s): %s",
            warning,
            result.content[:80]
        )

    return result
