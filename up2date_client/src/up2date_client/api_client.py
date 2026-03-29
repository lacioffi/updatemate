import os
import requests

class APIClient:
    def __init__(self, base_url=None, timeout=5):
        self.base_url = (base_url or os.environ.get('SERVER_URL') or 'http://localhost:5000').rstrip('/')
        self.timeout = timeout

    def get_items(self):
        r = requests.get(f"{self.base_url}/items", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def add_item(self, name):
        r = requests.post(f"{self.base_url}/items", json={"name": name}, timeout=self.timeout)
        r.raise_for_status()
        return r.json()