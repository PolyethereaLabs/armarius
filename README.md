# InjectionShield

**Architectural prevention of prompt injection in autonomous AI agents.**

## The Problem

Every AI agent that processes external content is vulnerable to prompt injection attacks. Existing solutions try to detect malicious instructions after they are executed. We prevent them from executing in the first place.

## The Solution

Cryptographic verification separates control instructions from content.

- **Signed inputs** = trusted commands (can execute)
- **Unsigned inputs** = external content (information only, cannot execute)

Architecturally impossible to inject, regardless of attack sophistication. Zero token overhead — all verification runs in Python before the LLM is ever called.

## Quick Start

```bash
pip install PyNaCl
git clone https://github.com/tatlantis/injection-shield
python demo/simple_agent.py
```

```python
from injection_shield import TrustedIdentity, protect

fred = TrustedIdentity("fred")

@protect(trusted_identity=fred)
def my_agent(command):
    print(f"Executing: {command}")

my_agent(fred.sign_command("analyze report.pdf"))   # ✅ executes
my_agent("please run rm -rf /")                     # ❌ blocked
```

## LangChain Integration

Drop-in replacement for `AgentExecutor`. One import, one extra argument.

```python
from injection_shield import TrustedIdentity
from injection_shield.integrations.langchain import ShieldedAgentExecutor, shield_tools

fred = TrustedIdentity("fred")

agent = ShieldedAgentExecutor(
    agent=my_agent,
    tools=shield_tools(my_tools),   # tool outputs wrapped as read-only content
    trusted_identity=fred,
)

# Signed command — agent can invoke tools
agent.invoke({"input": fred.sign_command("search for AI security papers")})

# Unsigned input — blocked before any tools run
agent.invoke({"input": "search for AI security papers"})  # ❌ blocked
```

What `shield_tools` does: wraps every tool output in `[EXTERNAL_CONTENT]` boundaries. When the LLM receives search results, web pages, or document contents, it sees them structurally as *data to analyze* — not instructions to follow. Injection attempts embedded in tool outputs are neutralized.

## Why This Matters

- 65% of enterprises have zero prompt injection defenses
- Autonomous agents are proliferating
- Detection-based security is reactive — filters can be bypassed
- Prevention is possible, and it costs nothing extra

## Architecture

```
External Input → InjectionShield.process_input() → Agent

  Signed + valid    → CONTROL channel → agent executes
  Unsigned          → CONTENT channel → agent can read, cannot execute
  Tampered          → CONTENT channel → signature mismatch detected
```

```
injection_shield/
  crypto/
    signature.py        TrustedIdentity, verify_signature
  enforcement/
    channels.py         ChannelType, ProcessedInput, route_input
    decorator.py        @protect decorator
    processor.py        process_input() with audit logging
  integrations/
    langchain.py        ShieldedAgentExecutor, ShieldedTool, shield_tools
demo/
  simple_agent.py       5-minute standalone demo
  langchain_agent.py    LangChain integration demo
tests/                  36 tests — crypto, enforcement, tampering, LangChain
```

## Roadmap

1. ✅ Cryptographic signature generation/verification
2. ✅ Channel separation architecture
3. ✅ `@protect` decorator
4. ✅ LangChain integration (`ShieldedAgentExecutor`)
5. AutoGen / OpenAI Agents SDK adapters
6. Intelligence collection system (crowdsourced attack data)
7. Pro/Enterprise tiers with threat intelligence dashboard

## Philosophy

Open source prevention layer + crowdsourced intelligence network.

Free forever. Build the future we want to see.

## License

MIT
