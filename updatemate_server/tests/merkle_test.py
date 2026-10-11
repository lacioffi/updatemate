## Tests the basic operation of merkle tree data structures

import sys
import os
import json
import time
import glob
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from updatemate_server.merkle import SoftwareRegistry, SoftwareReview
from updatemate_server.classes import SoftwareVersion
from updatemate_server.auth import SignatureError, CaptchaError
from updatemate_server import captcha

sys.path.append(os.path.dirname(__file__))
from signing_helpers import build_signed_version_data, sign_review_data

DATA_PATH = "merkle_test_data/"

# Path setup to import from parent directory
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

### Setup ###
#Ensure merkle data folder exists
if not os.path.exists(DATA_PATH):
    os.makedirs(DATA_PATH)

#Delete existing merkle data
for filename in os.listdir(DATA_PATH):
    file_path = os.path.join(DATA_PATH, filename)
    try:
        if os.path.isfile(file_path) or os.path.islink(file_path):
            os.remove(file_path)  # Deletes files or symbolic links
    except Exception as e:
        print(f'Failed to delete {file_path}. Reason: {e}')

#Create and build new registry
main_registry = SoftwareRegistry(DATA_PATH)

# Path to data folder
data_folder = os.path.join(os.path.dirname(__file__), 'data')

# Find all .json files in a/tests/data
json_files = glob.glob(os.path.join(data_folder, "*.json"))

# Load and process each file
for file_path in json_files:
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.loads(f.read())
        software_version = SoftwareVersion(data)
        #filename = os.path.basename(file_path)
        #print(f"--- Processing: {filename} ---")
        main_registry.add_software_version(software_version)


def test_get_software_versions():
    versions = main_registry.get_software_versions("Google Chrome")
    print(versions)
    assert len(versions) == 3
    assert versions[0]["signatures"][0]["hash"] == "676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429"
    assert versions[1]["signatures"][0]["hash"] == "ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f"

def test_human_readable_report():
    report = main_registry.get_human_readable_report("Google Chrome", print_certs=False)
    assert "Version ID: Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f" in report

def test_software_reviews():
    # Reviews are identified by a keypair, not by the free-text `reviewer`
    # field, and a signature is bound to one specific version_id -- so
    # unlike the old unauthenticated test, we sign a fresh payload per
    # target version rather than reusing one review object across both.
    alice_key = ed25519.Ed25519PrivateKey.generate()
    version_a = "Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429"
    version_b = "Google_Chrome-82ad9ce8534e6de68cebc14699b28509c8c85fda36100d09ab79919c16c217f7"

    review_a = SoftwareReview(sign_review_data(
        alice_key, version_a, "Alice", "This version is vulnerable to CVE-something.", "vulnerable"
    ))
    review_b = SoftwareReview(sign_review_data(
        alice_key, version_b, "Alice", "This version is vulnerable to CVE-something.", "vulnerable"
    ))
    main_registry.add_version_review(version_a, review_a)
    main_registry.add_version_review(version_b, review_b)
    reviews = main_registry.get_version_reviews(version_a)
    assert len(reviews) == 1
    assert reviews[0]["review"] == "vulnerable"
    assert reviews[0]["signer_id"] == review_a.signer_id
    # Alice's key never signed Chrome's binary, so she isn't developer-verified.
    assert reviews[0]["developer_verified"] is False


def test_review_missing_signature_is_rejected():
    version_a = "Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429"
    review = SoftwareReview({
        "reviewer": "Mallory",
        "comment": "Trust me, it's fine.",
        "review": "ok",
    })
    with pytest.raises(SignatureError):
        main_registry.add_version_review(version_a, review)


def test_review_invalid_signature_is_rejected():
    version_a = "Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429"
    mallory_key = ed25519.Ed25519PrivateKey.generate()
    review_data = sign_review_data(mallory_key, version_a, "Mallory", "Tampered comment", "ok")
    # Tamper with the signed content after signing -- the signature no
    # longer matches the payload it was computed over.
    review_data["comment"] = "This is definitely not what was signed."
    review = SoftwareReview(review_data)
    with pytest.raises(SignatureError):
        main_registry.add_version_review(version_a, review)


def test_review_missing_captcha_is_rejected():
    version_a = "Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429"
    mallory_key = ed25519.Ed25519PrivateKey.generate()
    review_data = sign_review_data(mallory_key, version_a, "Mallory", "No CAPTCHA here", "ok")
    del review_data["captcha_challenge_id"]
    del review_data["captcha_answer"]
    review = SoftwareReview(review_data)
    with pytest.raises(CaptchaError):
        main_registry.add_version_review(version_a, review)


def test_review_wrong_captcha_answer_is_rejected():
    version_a = "Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429"
    mallory_key = ed25519.Ed25519PrivateKey.generate()
    review_data = sign_review_data(mallory_key, version_a, "Mallory", "Wrong answer here", "ok")
    review_data["captcha_answer"] = "WRONG"
    review = SoftwareReview(review_data)
    with pytest.raises(CaptchaError):
        main_registry.add_version_review(version_a, review)


def test_review_captcha_is_single_use():
    version_a = "Google_Chrome-676b876b97ce6a80327efa7ff2fd61c885a7084879ebf7655f3d3aa361775429"
    mallory_key = ed25519.Ed25519PrivateKey.generate()
    review_data = sign_review_data(mallory_key, version_a, "Mallory", "First submission", "ok")
    review = SoftwareReview(dict(review_data))
    main_registry.add_version_review(version_a, review)

    # Replaying the exact same, already-consumed challenge/answer pair for
    # a second review must fail -- a solved CAPTCHA is single-use, so an
    # attacker can't solve one and stamp arbitrarily many reviews with it.
    replay_key = ed25519.Ed25519PrivateKey.generate()
    replay_data = sign_review_data(replay_key, version_a, "Mallory2", "Replayed CAPTCHA", "ok")
    replay_data["captcha_challenge_id"] = review_data["captcha_challenge_id"]
    replay_data["captcha_answer"] = review_data["captcha_answer"]
    replay_review = SoftwareReview(replay_data)
    with pytest.raises(CaptchaError):
        main_registry.add_version_review(version_a, replay_review)


def test_developer_verified_review():
    # A developer's key signs both the binary and their own review of it.
    developer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    version_data = build_signed_version_data(developer_key, "Demo Software", "1.0.0")
    software_version = SoftwareVersion(version_data)
    main_registry.add_software_version(software_version)
    version_id = software_version.software_version_id

    dev_review = SoftwareReview(sign_review_data(
        developer_key, version_id, "The Developer",
        "Fixed the thing, verified it myself.", "ok",
    ))
    main_registry.add_version_review(version_id, dev_review)
    assert dev_review.developer_verified is True

    # A reviewer using an unrelated key gets a valid, but non-developer,
    # review recorded against the same version.
    stranger_key = ed25519.Ed25519PrivateKey.generate()
    stranger_review = SoftwareReview(sign_review_data(
        stranger_key, version_id, "Random Reviewer", "Seems fine to me.", "ok",
    ))
    main_registry.add_version_review(version_id, stranger_review)
    assert stranger_review.developer_verified is False

    reviews = main_registry.get_version_reviews(version_id)
    assert len(reviews) == 2
    verified_flags = {r["reviewer"]: r["developer_verified"] for r in reviews}
    assert verified_flags["The Developer"] is True
    assert verified_flags["Random Reviewer"] is False

    # Neither stored record carries CAPTCHA fields: captcha.py's contract
    # is that a solved challenge leaves no lasting evidence in the ledger.
    for stored_review in reviews:
        assert "captcha_challenge_id" not in stored_review
        assert "captcha_answer" not in stored_review


def test_developer_verified_review_is_exempt_from_captcha():
    # The exemption only means something if it holds with NO captcha
    # fields present at all -- not merely alongside a valid one, which
    # test_developer_verified_review already covers incidentally.
    developer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    version_data = build_signed_version_data(developer_key, "Exempt Software", "1.0.0",
                                              binary_bytes=b"MZ...a different placeholder binary")
    software_version = SoftwareVersion(version_data)
    main_registry.add_software_version(software_version)
    version_id = software_version.software_version_id

    dev_review_data = sign_review_data(
        developer_key, version_id, "The Developer", "No captcha attached.", "ok",
    )
    del dev_review_data["captcha_challenge_id"]
    del dev_review_data["captcha_answer"]
    dev_review = SoftwareReview(dev_review_data)
    main_registry.add_version_review(version_id, dev_review)
    assert dev_review.developer_verified is True

    # A non-developer review to the same version, missing its captcha,
    # is still rejected -- the exemption is specific to developer_verified,
    # not to "any review against a version that has one".
    stranger_key = ed25519.Ed25519PrivateKey.generate()
    stranger_review_data = sign_review_data(
        stranger_key, version_id, "Random Reviewer", "No captcha either.", "ok",
    )
    del stranger_review_data["captcha_challenge_id"]
    del stranger_review_data["captcha_answer"]
    stranger_review = SoftwareReview(stranger_review_data)
    with pytest.raises(CaptchaError):
        main_registry.add_version_review(version_id, stranger_review)


def test_get_software_report():
    report = main_registry.get_human_readable_report("Google Chrome")
    assert "Version ID: Google_Chrome-ec4f88362c38bfb8f17465c45f8be2614c1f9e3c0ead77ae25e8e94a9411ab5f" in report
    print(report)
