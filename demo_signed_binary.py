#!/usr/bin/env python3
"""
End-to-end demo of UPDATEMATE's public-key authentication.

This is a standalone script, not a pytest test: it boots a real instance of
the updatemate_server Flask app, talks to it over real HTTP with `requests`
(the same way updatemate_client does, double-JSON-encoding included), and
walks through the exact scenario that was asked for:

  1. Generate a keypair and use it to build a self-signed "code-signing"
     certificate -- standing in for a real Authenticode certificate, which
     is normally issued by a CA but which this script has no way to
     obtain. This is the "bogus key" the binary below is signed with.
  2. Construct a tiny placeholder binary and Authenticode-style PKCS7-sign
     it with that key, exactly like a real Windows PE would carry a real
     Authenticode signature in its `signatures[].raw_data` field.
  3. Submit that "binary" to the server as a new SoftwareVersion.
  4. Submit a review of it, signed with the *same* key -- the server should
     recognize that this reviewer is also the developer who signed the
     binary, and mark the review `developer_verified: true`.
  5. Submit a second review signed with an *unrelated* key -- a perfectly
     valid, accepted review, but *not* developer-verified.
  6. Attempt to submit a review with no signature at all, and one with a
     signature that doesn't match its content -- both must be rejected
     with HTTP 401, proving the server actually enforces this rather than
     just decorating reviews that happen to carry the fields.

Run it from the repo root:

    python3 demo_signed_binary.py

It uses its own throwaway data directory (a temp dir, not the repo's
merkle_data/) and a background copy of the real server on 127.0.0.1, so it
is safe to run repeatedly and does not touch any other state.
"""
import datetime
import hashlib
import json
import os
import sys
import tempfile
import threading
import time

# The server's on-disk paths (merkle_data/, version_signing_index.json) are
# relative to the current working directory at import time, so point this
# demo at its own throwaway directory *before* importing anything from
# updatemate_server -- keeps this run isolated from any other data on disk.
_DEMO_DIR = tempfile.mkdtemp(prefix="updatemate_demo_")
os.chdir(_DEMO_DIR)

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "updatemate_server", "src"))

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from updatemate_server.app import create_app
from updatemate_server.auth import canonical_review_payload
from updatemate_server import captcha

HOST, PORT = "127.0.0.1", 5757
BASE_URL = f"http://{HOST}:{PORT}"


# --------------------------------------------------------------------------
# Signing helpers -- what a real developer's toolchain would do to their
# binary, and what updatemate_client.auth does to sign a review. Kept inline
# here (rather than imported) so this file reads top-to-bottom on its own.
# --------------------------------------------------------------------------

def build_self_signed_code_signing_cert(private_key, common_name, org_name):
    """A self-signed cert carrying the CODE_SIGNING Extended Key Usage. A
    real Authenticode cert would be issued by a trusted CA -- this is the
    "bogus" stand-in: self-signed, trusted by nobody, but structurally
    identical to a real one, which is all the server actually inspects."""
    name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
        .sign(private_key, hashes.SHA256())
    )


def authenticode_sign(private_key, cert, binary_bytes: bytes) -> str:
    """DER PKCS7 SignedData over `binary_bytes`, hex-encoded -- the same
    shape as a real Signature.raw_data blob (e.g. tests/data/chrome_1.json)."""
    der = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(binary_bytes)
        .add_signer(cert, private_key, hashes.SHA256())
        .sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    )
    return der.hex()


def solve_captcha_like_a_human_would() -> dict:
    """Fetches a real CAPTCHA challenge from the same in-process store the
    server checks against, then answers it via captcha.debug_peek_answer
    -- the test-only escape hatch documented in updatemate_server/captcha.py,
    standing in for an actual person reading the rendered image. A real
    client has no equivalent; it only ever sees the PNG."""
    challenge = captcha.generate_challenge()
    answer = captcha.debug_peek_answer(challenge["challenge_id"])
    return {"captcha_challenge_id": challenge["challenge_id"], "captcha_answer": answer}


def sign_review(private_key, version_id, reviewer, comment, review, attach_captcha=True) -> dict:
    payload = canonical_review_payload(version_id, reviewer, comment, review)
    if isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(private_key, ed25519.Ed25519PrivateKey):
        signature = private_key.sign(payload)
    else:
        raise ValueError(f"Unsupported key type: {type(private_key).__name__}")
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
    if attach_captcha:
        review_data.update(solve_captcha_like_a_human_would())
    return review_data


def post(path, payload_dict):
    """Mirrors updatemate_client's actual wire behavior: gui.py hands
    api_client json.dumps()'d strings, which requests then encodes *again*
    as the JSON body -- so the server's `json.loads(request.get_json())`
    double-decode lines up with what actually arrives on the wire."""
    return requests.post(f"{BASE_URL}{path}", json=json.dumps(payload_dict), timeout=5)


# --------------------------------------------------------------------------
# 0. Boot a real server instance against the throwaway data directory.
# --------------------------------------------------------------------------

app = create_app()
server_thread = threading.Thread(
    target=lambda: app.run(host=HOST, port=PORT, debug=False, use_reloader=False),
    daemon=True,
)
server_thread.start()

for _ in range(50):
    try:
        requests.get(f"{BASE_URL}/health-check", timeout=0.2)
        break
    except requests.exceptions.ConnectionError:
        time.sleep(0.1)
else:
    print("Server never came up.", file=sys.stderr)
    sys.exit(1)

print(f"updatemate_server running at {BASE_URL} (data dir: {_DEMO_DIR})\n")

checks = []


def check(label, condition):
    status = "PASS" if condition else "FAIL"
    checks.append(condition)
    print(f"[{status}] {label}")


# --------------------------------------------------------------------------
# 1 & 2. The developer's keypair, cert, "binary", and its signature.
# --------------------------------------------------------------------------

developer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
developer_cert = build_self_signed_code_signing_cert(
    developer_key, common_name="Demo Software Publisher",
    org_name="UPDATEMATE Demo (bogus key -- not a real CA)",
)

binary_bytes = b"MZ...totally a real executable... beep boop"
raw_data_hex = authenticode_sign(developer_key, developer_cert, binary_bytes)
file_hash = hashlib.sha256(binary_bytes).hexdigest()

print("Generated a bogus RSA keypair and a self-signed CODE_SIGNING certificate:")
print(f"  Subject: {developer_cert.subject.rfc4514_string()}")
print(f"  Signed a {len(binary_bytes)}-byte placeholder binary -> "
      f"{len(raw_data_hex) // 2}-byte PKCS7 blob\n")

# --------------------------------------------------------------------------
# 3. Submit the "binary" as a new SoftwareVersion.
# --------------------------------------------------------------------------

version_payload = {
    "file_properties": {
        "FixedFileInfo": {},
        "StringFileInfo": {
            "ProductName": "Demo Signed App",
            "ProductVersion": "1.0.0",
        },
    },
    "signatures": [
        {
            "general": "PKCS7",
            "hash": file_hash,
            "raw_data": raw_data_hex,
            "certificates": [
                {
                    "issuer": developer_cert.issuer.rfc4514_string(),
                    "subject": developer_cert.subject.rfc4514_string(),
                    "signature_algorithm": developer_cert.signature_algorithm_oid._name,
                    "valid_from": list(developer_cert.not_valid_before_utc.timetuple())[:6],
                    "valid_to": list(developer_cert.not_valid_after_utc.timetuple())[:6],
                }
            ],
        }
    ],
}

r = post("/software/version", version_payload)
check("Submit signed binary as a new software version (HTTP 201)", r.status_code == 201)
version_id = f"Demo_Signed_App-{file_hash}"
print(f"  -> version_id = {version_id}\n")

# --------------------------------------------------------------------------
# 4. Review signed with the SAME key -> developer-verified.
# --------------------------------------------------------------------------

# Note attach_captcha=False here: a developer-verified review is exempt
# from the CAPTCHA gate (Section 6.5) -- it's already bound to a scarce,
# high-value credential (the same key that signed the binary itself), so
# this demonstrates the exemption is real, not just untested.
dev_review = sign_review(
    developer_key, version_id, "The Developer",
    "This is my own release, verified with my own signing key.", "ok",
    attach_captcha=False,
)
r = post(f"/software/version/{version_id}/add_review", dev_review)
body = r.json() if r.ok else {}
check("Developer's own review is accepted with no CAPTCHA attached (HTTP 201)", r.status_code == 201)
check("Developer's own review is marked developer_verified=True",
      body.get("developer_verified") is True)
print(f"  -> {body}\n")

# --------------------------------------------------------------------------
# 5. Review signed with an UNRELATED key -> accepted, but not verified.
# --------------------------------------------------------------------------

stranger_key = ed25519.Ed25519PrivateKey.generate()
stranger_review = sign_review(
    stranger_key, version_id, "Random Reviewer", "Seems to work fine for me.", "ok",
)
r = post(f"/software/version/{version_id}/add_review", stranger_review)
body = r.json() if r.ok else {}
check("Unrelated reviewer's signed review is accepted (HTTP 201)", r.status_code == 201)
check("Unrelated reviewer's review is NOT developer_verified",
      body.get("developer_verified") is False)
print(f"  -> {body}\n")

# --------------------------------------------------------------------------
# 6. Rejections: no signature, a tampered signature, and a missing CAPTCHA.
# --------------------------------------------------------------------------

r = post(f"/software/version/{version_id}/add_review", {
    "reviewer": "Mallory", "comment": "Trust me.", "review": "ok",
})
check("Unsigned review is rejected (HTTP 401)", r.status_code == 401)
print(f"  -> {r.status_code} {r.json()}\n")

tampered = sign_review(stranger_key, version_id, "Mallory", "Original comment", "ok")
tampered["comment"] = "This is not what was actually signed."
r = post(f"/software/version/{version_id}/add_review", tampered)
check("Tampered/invalid signature is rejected (HTTP 401)", r.status_code == 401)
print(f"  -> {r.status_code} {r.json()}\n")

no_captcha = sign_review(
    ed25519.Ed25519PrivateKey.generate(), version_id, "Bot",
    "I am definitely a human.", "ok", attach_captcha=False,
)
r = post(f"/software/version/{version_id}/add_review", no_captcha)
check("Validly signed, non-developer review WITHOUT a CAPTCHA is rejected (HTTP 401)",
      r.status_code == 401)
print(f"  -> {r.status_code} {r.json()}\n")

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------

r = requests.get(f"{BASE_URL}/software/version/{version_id}")
print("Final review list for this version:")
for review in r.json()["reviews"]:
    badge = " [DEVELOPER VERIFIED]" if review.get("developer_verified") else ""
    print(f"  - {review['reviewer']}{badge}: {review['review']} -- {review['comment']}")

print()
if all(checks):
    print(f"All {len(checks)} checks passed.")
else:
    print(f"{sum(checks)}/{len(checks)} checks passed -- see FAIL lines above.")
    sys.exit(1)
