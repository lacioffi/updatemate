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