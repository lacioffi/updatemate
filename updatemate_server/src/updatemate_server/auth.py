"""
Public-key identity and signature verification for UPDATEMATE.

Design in one paragraph: users and developers are identified by an
asymmetric keypair, not by a self-reported username. A review is only
accepted by the server if it carries a valid signature -- over a
canonical representation of its own content -- that verifies against the
public key the submitter claims as their identity. A review is
additionally marked ``developer_verified`` when that same public key
matches a code-signing certificate embedded in the Authenticode-style
PKCS#7 signature of the software version being reviewed, i.e. the same
keypair that was used to sign the binary itself. Possession of the
code-signing private key *is* the proof of developer identity: no
separate registration step is required.

This module only depends on the ``cryptography`` library, so it runs
anywhere the server runs. It does not need LIEF (which stays a
client-side-only, Windows-only dependency used to pull the raw
``signatures[].raw_data`` blob out of a live PE file in the first
place -- see updatemate_client/file_manager.py). Everything past that
point -- parsing the PKCS#7 blob, walking the certificate chain,
verifying signatures -- is standard X.509/PKCS#7 handling that
``cryptography`` already provides, and is exercised identically whether
the blob came from a real Authenticode-signed binary or from the
synthetic one built by scripts/demo_auth_flow.py.
"""
import hashlib
import json
from typing import Iterable, List


class SignatureError(ValueError):
    """A review submission was missing a signature, or its signature did
    not verify. Kept as a distinct type (rather than a bare ValueError) so
    the HTTP layer can tell an authentication failure (401) apart from an
    ordinary bad request (400)."""


class CaptchaError(SignatureError):
    """A review submission from a non-developer-verified reviewer was
    missing a solved CAPTCHA challenge, or the submitted answer was wrong,
    expired, or already consumed. Subclasses SignatureError so the
    existing 401 handling in routes.py catches this without any change
    there -- this is a distinct *reason* for authentication to fail, not
    a distinct HTTP-level category.

    This exists because a valid signature alone does not bound how many
    identities an attacker can create (Section 8.1 of the paper): a fresh
    Ed25519 keypair is free to generate and takes microseconds to sign
    with. A CAPTCHA does not fix that either, but it targets a different
    and, for this threat, more relevant resource than compute: it asks
    for evidence a human was present at submission time, which is what
    actually bounds how many reviews one attacker can cheaply automate --
    see updatemate_server/captcha.py for the mechanism and its own, explicitly
    stated limitations."""

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID


def canonical_review_payload(version_id: str, reviewer: str, comment: str, review: str) -> bytes:
    """
    Deterministic byte representation of a review's content, bound to the
    specific software version it targets. This -- not the raw request
    JSON, whose key order and whitespace are not guaranteed -- is what
    gets signed and verified. Binding the version_id into the payload
    stops a signed review from being replayed against a different
    version than the one its author actually reviewed.
    """
    obj = {
        "version_id": version_id,
        "reviewer": reviewer,
        "comment": comment,
        "review": review,
    }
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def load_public_key_pem(pem_str: str):
    """Loads a PEM-encoded SubjectPublicKeyInfo (RSA, EC, or Ed25519)."""
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def _public_key_der(public_key) -> bytes:
    """Canonical bytes for a public key, used both for fingerprinting and
    for equality checks (public key objects are not directly comparable)."""
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def public_key_fingerprint(public_key) -> str:
    """Stable identity for a public key: sha256 of its DER encoding, hex.

    This is what a review's ``signer_id`` is set to -- a self-certifying
    identity nobody but the keypair's owner can produce a valid signature
    for, in contrast to the free-text ``reviewer`` display name, which
    remains present for readability but is never trusted as an identity."""
    return hashlib.sha256(_public_key_der(public_key)).hexdigest()


def verify_signature(public_key, signature: bytes, data: bytes) -> bool:
    """Verifies `signature` over `data` for whichever key type `public_key`
    is (RSA, EC, or Ed25519). Returns False -- never raises -- on any
    malformed input, so a crafted submission can't crash the caller."""
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, data)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def verify_review_signature(version_id: str, reviewer: str, comment: str, review: str,
                             signer_public_key_pem: str, signature_hex: str) -> bool:
    """End-to-end check: does `signature_hex` verify, under
    `signer_public_key_pem`, over the canonical payload for this review?"""
    try:
        public_key = load_public_key_pem(signer_public_key_pem)
        signature = bytes.fromhex(signature_hex)
    except Exception:
        return False
    payload = canonical_review_payload(version_id, reviewer, comment, review)
    return verify_signature(public_key, signature, payload)


def extract_code_signing_public_keys(raw_data_hex: str) -> List[bytes]:
    """
    Parses a hex-encoded Authenticode-style PKCS#7 SignedData blob -- the
    same `signatures[].raw_data` field updatemate_client already extracts
    from a real PE file -- and returns the DER SubjectPublicKeyInfo of
    every embedded certificate whose Extended Key Usage includes
    codeSigning. A single Authenticode blob typically carries a whole
    chain (root CA, intermediate CA, sometimes a timestamp-authority
    chain too), so this filters down to the end-entity certificate(s)
    actually authorized to sign code -- the developer's own cert -- as
    opposed to the CAs and timestamp responders that travel alongside it.

    Falls back to a simple "not anyone's issuer" leaf heuristic for
    certificates that lack an Extended Key Usage extension entirely
    (self-signed demo certificates may skip it if not built carefully).

    Returns an empty list -- never raises -- if the blob can't be parsed
    or carries no plausible signing certificate. That is treated as "no
    developer key known for this version", not as an error: not every
    submission is expected to carry a complete, well-formed chain.
    """
    try:
        raw = bytes.fromhex(raw_data_hex)
        certs = pkcs7.load_der_pkcs7_certificates(raw)
    except Exception:
        return []

    issuer_names = {c.issuer.rfc4514_string() for c in certs}

    code_signing = []
    fallback_leaves = []
    for cert in certs:
        matched_eku = False
        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
            if ExtendedKeyUsageOID.CODE_SIGNING in eku:
                code_signing.append(_public_key_der(cert.public_key()))
                matched_eku = True
        except Exception:
            pass
        if not matched_eku and cert.subject.rfc4514_string() not in issuer_names:
            fallback_leaves.append(_public_key_der(cert.public_key()))

    return code_signing or fallback_leaves



def is_developer_submission(signer_public_key_pem: str, version_raw_data_hex_list: Iterable[str]) -> bool:
    """True if the review's signing key matches any code-signing
    certificate found across the software version's own signature
    blob(s) -- i.e., the review was signed with the same keypair that
    signed the binary being reviewed."""
    try:
        signer_der = _public_key_der(load_public_key_pem(signer_public_key_pem))
    except Exception:
        return False

    for raw_data_hex in version_raw_data_hex_list:
        if signer_der in extract_code_signing_public_keys(raw_data_hex):
            return True
    return False
