"""
Client-side keypair identity for UpdateMate.

Every reviewer is identified by a public key, not by a self-reported
username. This module generates that keypair, persists it locally, and
signs review submissions with it so the server can verify who actually
sent them (see updatemate_server/auth.py for the verification side).

Reviewer identity is generated as Ed25519 -- small, fast, and with no
padding/hash choices to get wrong. This module deliberately does not
offer a way to generate a reviewer keypair that is meant to double as
(or match) a developer's code-signing key: developers are not expected
to publish reviews under a reviewer identity, and if they want to
publish something, they do so as developers, by submitting a signed
software version, not a review (see updatemate_server/routes.py's
/software/version endpoint). The server can still independently
recognize a review as developer-verified if its signing key genuinely
matches the reviewed binary's code-signing certificate (see
updatemate_server/auth.is_developer_submission) -- this module simply does
not steer reviewers toward manufacturing that match.

No dependency on lief or win32api: this module works anywhere Python and
`cryptography` do, unlike the rest of updatemate_client.
"""
import json
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

DEFAULT_KEY_PATH = Path.home() / ".updatemate" / "identity.pem"


def generate_keypair():
    """Generates a new local Ed25519 identity keypair.

    Returns (private_key, public_key).
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def save_private_key(private_key, path: Path = DEFAULT_KEY_PATH):
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    try:
        path.chmod(0o600)  # best-effort; no-op on platforms that don't support it
    except (NotImplementedError, OSError):
        pass


def load_private_key(path: Path = DEFAULT_KEY_PATH):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_or_create_identity(path: Path = DEFAULT_KEY_PATH):
    """Loads the local identity keypair, generating and persisting a new
    one on first use. This is the one function most callers need."""
    if path.is_file():
        private_key = load_private_key(path)
        return private_key, private_key.public_key()
    private_key, public_key = generate_keypair()
    save_private_key(private_key, path)
    return private_key, public_key


def public_key_to_pem(public_key) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _canonical_review_payload(version_id: str, reviewer: str, comment: str, review: str) -> bytes:
    """Must exactly match updatemate_server.auth.canonical_review_payload."""
    obj = {
        "version_id": version_id,
        "reviewer": reviewer,
        "comment": comment,
        "review": review,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_data(private_key, data: bytes) -> bytes:
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return private_key.sign(data)
    raise ValueError(f"Unsupported private key type: {type(private_key).__name__}")


def build_signed_review(private_key, version_id: str, reviewer: str, comment: str, review: str) -> dict:
    """Builds the review payload's signed core -- ready to have CAPTCHA
    fields attached by the caller (Section 6.5 of the paper; see
    gui.py's _submit_review) and then be json.dumps()'d and POST'd to
    /software/version/<version_id>/add_review -- including the signature
    over its own content and the PEM public key the server should verify
    it against. This function does not handle the CAPTCHA challenge
    itself, since solving one needs a human in the loop, which is a UI
    concern, not a signing concern."""
    payload = _canonical_review_payload(version_id, reviewer, comment, review)
    signature = sign_data(private_key, payload)
    return {
        "reviewer": reviewer,
        "comment": comment,
        "review": review,
        "signer_public_key": public_key_to_pem(private_key.public_key()),
        "signature": signature.hex(),
    }
