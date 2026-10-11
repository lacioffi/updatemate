from typing import List, Optional


class FileProperties:
    def __init__(self, data: dict):
        self.FixedFileInfo = data["FixedFileInfo"]
        self.StringFileInfo = data["StringFileInfo"]


class Certificate:
    def __init__(self, data: dict):
        self.issuer: str = data["issuer"]
        self.subject: str = data["subject"]
        self.signature_algorithm: str = data["signature_algorithm"]
        self.valid_from: List[int] = data["valid_from"]
        self.valid_to: List[int] = data["valid_to"]


class Signature:
    def __init__(self, data: dict):
        self.general: str = data["general"]
        self.hash: str = data["hash"]
        self.raw_data: str = data["raw_data"]

        self.certificates: List[Certificate] = [
            Certificate(c) for c in data.get("certificates", [])
        ]


class SoftwareVersion:
    def __init__(self, data: dict):
        self.file_properties = FileProperties(data["file_properties"])

        self.signatures: List[Signature] = [
            Signature(s) for s in data.get("signatures", [])
        ]

        self.first_seen: Optional[str] = None
        self.software_version_id: Optional[str] = None

class SoftwareReview:
    VALID_REVIEWS = {"ok", "vulnerable", "malicious", "degraded"}

    def __init__(self, data: dict):
        self.reviewer: str = data["reviewer"]
        self.comment: str = data["comment"]
        review = data["review"]
        if review not in self.VALID_REVIEWS:
            raise ValueError(f"Invalid review value: {review}. Must be one of {self.VALID_REVIEWS}")
        self.review: str = review
        self.time_received: Optional[str] = None

        # Public-key identity. `reviewer` above is a free-text display name
        # and is never trusted on its own -- the actual identity of whoever
        # submitted this review is the keypair that signed it. Both fields
        # are required for a review to reach the ledger (enforced in
        # SoftwareRegistry.add_version_review, not here, so library code
        # that builds a SoftwareReview directly -- e.g. while replaying or
        # migrating existing ledger data -- can still do so without a
        # signature already attached).
        self.signer_public_key: Optional[str] = data.get("signer_public_key")
        self.signature: Optional[str] = data.get("signature")

        # CAPTCHA challenge response (see updatemate_server/captcha.py),
        # required only for reviews that do not turn out to be
        # developer-verified. These are read here purely to be verified
        # and then discarded by SoftwareRegistry.add_version_review --
        # they are deliberately never part of the object's persisted,
        # ledger-serialized state (see captcha.py's docstring for why).
        self.captcha_challenge_id: Optional[str] = data.get("captcha_challenge_id")
        self.captcha_answer: Optional[str] = data.get("captcha_answer")

        # Computed server-side once the signature above has been verified;
        # never trust these two if they are present in *submitted* data.
        self.signer_id: Optional[str] = None
        self.developer_verified: bool = False
