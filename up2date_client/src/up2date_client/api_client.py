import os
import requests


class APIClient:
    def __init__(self, base_url=None, timeout=5):
        self.base_url = (base_url or os.environ.get('SERVER_URL') or 'http://localhost:5000').rstrip('/')
        self.timeout = timeout

    def health_check(self):
        r = requests.get(f"{self.base_url}/health-check", timeout=self.timeout)
        r.raise_for_status()
        return r.text

    def add_software_version(self, version_data: dict):
        r = requests.post(
            f"{self.base_url}/software/version",
            json=version_data,
            timeout=self.timeout
        )
        r.raise_for_status()
        return r.json()

    def get_version_reviews(self, version_id: str):
        r = requests.get(
            f"{self.base_url}/software/version/{version_id}",
            timeout=self.timeout
        )
        r.raise_for_status()
        return r.json()

    def add_version_review(self, version_id: str, review_data: dict):
        r = requests.post(
            f"{self.base_url}/software/version/{version_id}/add_review",
            json=review_data,
            timeout=self.timeout
        )
        r.raise_for_status()
        return r.json()

    def get_software_report(self, software_name: str):
        r = requests.get(
            f"{self.base_url}/software/{software_name}",
            timeout=self.timeout
        )
        r.raise_for_status()
        return r.json()

    def get_software_versions(self, software_name: str):
        r = requests.get(
            f"{self.base_url}/software/{software_name}/versions",
            timeout=self.timeout
        )
        r.raise_for_status()
        return r.json()