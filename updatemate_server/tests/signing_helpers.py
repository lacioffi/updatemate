"""
Test-only helpers for constructing signed material: a self-signed
"code-signing" certificate + PKCS7 blob (standing in for a real Authenticode
signature on a binary), and signed review payloads.

None of this is used by application code -- it exists so the auth tests
below can exercise the real verification path (updatemate_server.auth) against
freshly-generated keys instead of only the one fixed Google Authenticode
fixture in tests/data, which we have no private key for and so can never
use to test the *positive* developer-verification case.
"""
import datetime
import hashlib
import json

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from updatemate_server import captcha


def _solve_captcha_for_test() -> dict:
    """Generates a real CAPTCHA challenge and answers it via
    captcha.debug_peek_answer -- the same test-only escape hatch
    documented in updatemate_server/captcha.py, standing in for a human
    reading the rendered image."""
    challenge = captcha.generate_challenge()
    answer = captcha.debug_peek_answer(challenge["challenge_id"])
    return {"captcha_challenge_id": challenge["challenge_id"], "captcha_answer": answer}


def build_self_signed_code_signing_cert(private_key, common_name="Demo Software Publisher",
                                         org_name="UPDATEMATE Demo (not a real CA)"):
    """A self-signed X.509 cert carrying the CODE_SIGNING Extended Key Usage,
    signed by `private_key` (must be RSA -- PKCS7SignatureBuilder needs an
    RSA or EC signer; RSA is what most real Authenticode certs use anyway)."""
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
    )
    return builder.sign(private_key, hashes.SHA256())


def sign_binary_pkcs7(private_key, cert, binary_bytes: bytes) -> str:
    """Produces a DER PKCS7 SignedData blob over `binary_bytes`, hex-encoded
    the same way real Signature.raw_data is stored in the ledger."""
    der = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(binary_bytes)
        .add_signer(cert, private_key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    )
    return der.hex()


def build_signed_version_data(private_key, product_name: str, product_version: str,
                               binary_bytes: bytes = b"MZ...totally a real executable... beep boop") -> dict:
    """A full SoftwareVersion-shaped dict, "signed" by a freshly-built
    self-signed code-signing cert for `private_key`, ready to hand to
    SoftwareVersion(...)/add_software_version."""
    cert = build_self_signed_code_signing_cert(private_key)
    raw_data_hex = sign_binary_pkcs7(private_key, cert, binary_bytes)
    file_hash = hashlib.sha256(binary_bytes).hexdigest()
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    return {
        "file_properties": {
            "FixedFileInfo": {},
            "StringFileInfo": {
                "ProductName": product_name,
                "ProductVersion": product_version,
            },
        },
        "signatures": [
            {
                "general": "PKCS7",
                "hash": file_hash,
                "raw_data": raw_data_hex,
                "certificates": [
                    {
                        "issuer": cert.issuer.rfc4514_string(),
                        "subject": cert.subject.rfc4514_string(),
                        "signature_algorithm": cert.signature_algorithm_oid._name,
                        "valid_from": list(not_before.timetuple())[:6],
                        "valid_to": list(not_after.timetuple())[:6],
                    }
                ],
            }
        ],
    }


def _canonical_review_payload(version_id: str, reviewer: str, comment: str, review: str) -> bytes:
    """Must exactly match updatemate_server.auth.canonical_review_payload."""
    obj = {"version_id": version_id, "reviewer": reviewer, "comment": comment, "review": review}
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_review_data(private_key, version_id: str, reviewer: str, comment: str, review: str) -> dict:
    """A full review dict -- reviewer/comment/review plus signer_public_key
    and signature -- signed with `private_key` over the given version_id."""
    payload = _canonical_review_payload(version_id, reviewer, comment, review)
    if isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        signature = private_key.sign(payload)
    else:
        raise ValueError(f"Unsupported private key type: {type(private_key).__name__}")

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    review_data = {
        "reviewer": reviewer,
        "comment": comment,
        "review": review,
        "signer_public_key": public_pem,
        "signature": signature.hex(),
    }
    # Solved unconditionally, same as the real GUI: harmless if the review
    # turns out to be developer-verified (the server won't require it),
    # necessary otherwise.
    review_data.update(_solve_captcha_for_test())
    return review_data
