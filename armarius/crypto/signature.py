import nacl.signing
import nacl.encoding
import json
from datetime import datetime


class TrustedIdentity:
    """
    Represents a trusted identity that can sign commands.

    A TrustedIdentity holds an Ed25519 keypair. Commands signed with
    its private key can be verified by anyone with the public key.
    Only signed-and-verified commands are allowed to execute.
    """

    def __init__(self, name: str):
        self.name = name
        self.signing_key = nacl.signing.SigningKey.generate()
        self.verify_key = self.signing_key.verify_key

    def sign_command(self, command: str, metadata: dict = None) -> dict:
        """
        Sign a command string with this identity's private key.

        Returns a dict containing the command, metadata, signature,
        and public verify key — ready to pass to an @protect-decorated agent.
        """
        if metadata is None:
            metadata = {}
        metadata['timestamp'] = datetime.utcnow().isoformat()
        metadata['signer'] = self.name

        payload = {'command': command, 'metadata': metadata}
        message = json.dumps(payload, sort_keys=True).encode('utf-8')
        signed = self.signing_key.sign(message)

        return {
            'command': command,
            'metadata': metadata,
            'signature': signed.signature.hex(),
            'verify_key': self.verify_key.encode(
                encoder=nacl.encoding.HexEncoder
            ).decode('utf-8')
        }


def verify_signature(signed_command: dict) -> tuple:
    """
    Verify a signed command dict.

    Returns (True, "Signature valid") if the command is authentic
    and unmodified, or (False, reason) if it has been tampered with
    or is otherwise invalid.
    """
    try:
        verify_key = nacl.signing.VerifyKey(
            signed_command['verify_key'],
            encoder=nacl.encoding.HexEncoder
        )
        payload = {
            'command': signed_command['command'],
            'metadata': signed_command['metadata']
        }
        message = json.dumps(payload, sort_keys=True).encode('utf-8')
        signature = bytes.fromhex(signed_command['signature'])
        verify_key.verify(message, signature)
        return (True, "Signature valid")
    except Exception as e:
        return (False, f"Signature invalid: {str(e)}")
