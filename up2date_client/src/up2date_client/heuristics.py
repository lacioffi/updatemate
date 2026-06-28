import json
import os
import requests


def check_freeze_replay_attack(reviews, versions: list, current_file_version: str) -> tuple[str, str]:
    """Detects if user is stuck on older version with bad review while newer versions exist."""
    if not versions or not reviews or not current_file_version or type(reviews) != list:
        return "OK", "Insufficient data for freeze attack check"

    has_bad_review = False
    for review in reviews:
        try:
            r = json.loads(review) if isinstance(review, str) else review
            if r.get("review") in ("vulnerable", "malicious", "degraded"):
                has_bad_review = True
                break
        except:
            continue

    if not has_bad_review:
        return "OK", "No bad reviews for current version"

    has_newer_version = False
    for version in versions:
        try:
            v = json.loads(version) if isinstance(version, str) else version
            version_file_version = v.get("file_properties", {}).get("FileVersion", "") or ""
            if version_file_version and version_file_version > current_file_version:
                has_newer_version = True
                break
        except:
            continue

    if has_newer_version:
        return "BAD", f"Current version {current_file_version} has bad review(s) while newer versions exist"
    return "OK", "Current version has bad review but no newer versions available"

def check_widespread_malware(reviews) -> tuple[str, str]:
    """Detects if version has high proportion of negative reviews."""
    if not reviews or type(reviews) != list:
        return "OK", "No reviews available"

    count_good = 0
    count_bad = 0
    for review in reviews:
        try:
            r = json.loads(review) if isinstance(review, str) else review
            if r.get("review") in ("ok", "OK"):
                count_good += 1
            elif r.get("review") in ("malicious", "vulnerable", "degraded"):
                count_bad += 1
        except:
            continue

    if count_good + count_bad == 0:
        return "OK", "No valid reviews"

    total_reviews = count_good + count_bad
    if total_reviews < 2:
        return "BAD", f"Insufficient reviews ({total_reviews}) to assess malware risk"

    bad_proportion = count_bad / total_reviews
    if bad_proportion > 0.3:
        return "BAD", f"High proportion of negative reviews ({bad_proportion:.1%})"
    return "OK", f"Negative review proportion acceptable ({bad_proportion:.1%})"


def check_targeted_malware(reviews) -> tuple[str, str]:
    """Detects if version is not popular (possible targeted attack)."""
    if len(reviews) < 2 or type(reviews) != list:
        return "BAD", "Less than 2 reviews - possible targeted version?"
    return "OK", "Community feedback available"


def check_abusech(file_hash: str) -> tuple[str, str]:
    """Check file SHA256 against MalwareBazaar (abuse.ch).

    Requires the ABUSECH_API_KEY environment variable to be set.
    A 'hash_not_found' response means the file is not a known malware sample.
    A 'ok' response means the file IS in MalwareBazaar — flagged as BAD.
    """
    api_key = os.environ.get("ABUSECH_API_KEY", "").strip()
    if not api_key:
        return "UNKNOWN", "abuse.ch: no API key configured, check skipped"

    if not file_hash:
        return "UNKNOWN", "No file hash available for abuse.ch check"

    url = "https://mb-api.abuse.ch/api/v1/"

    try:
        resp = requests.post(
            url,
            headers={"Auth-Key": api_key},
            data={"query": "get_info", "hash": file_hash},
            timeout=15,
        )

        if resp.status_code != 200:
            return "UNKNOWN", f"abuse.ch returned HTTP {resp.status_code}"

        data = resp.json()
        query_status = data.get("query_status", "")

        if query_status == "hash_not_found":
            return "OK", "abuse.ch: hash not found in MalwareBazaar — not a known malware sample"

        if query_status == "ok":
            sample = (data.get("data") or [{}])[0]
            signature = sample.get("signature") or "unknown family"
            tags = ", ".join(sample.get("tags") or [])
            detail = f"{signature} ({tags})" if tags else signature
            return "BAD", f"abuse.ch: found in MalwareBazaar as '{detail}'. URL: {url}"

        return "OK", f"abuse.ch: unexpected query status '{query_status}'"

    except requests.exceptions.Timeout:
        return "OK", "abuse.ch check timed out"
    except requests.exceptions.ConnectionError:
        return "OK", "abuse.ch check failed: no connection"
    except Exception as e:
        return "OK", f"abuse.ch check failed: {e}"


def check_circl_hashlookup(file_hash: str) -> tuple[str, str]:
    """Check file SHA256 against CIRCL's hashlookup database (known-good records only).

    200 → file is a known-good executable (OK).
    404 → file is not in the known-good database; status is UNKNOWN.
    """
    if not file_hash:
        return "UNKNOWN", "No file hash available for CIRCL hashlookup"

    url = f"https://hashlookup.circl.lu/lookup/sha256/{file_hash}"

    try:
        resp = requests.get(url, headers={"Accept": "application/json"}, timeout=15)

        if resp.status_code == 404:
            return "UNKNOWN", f"CIRCL hashlookup: hash not in known-good database. URL: {url}"

        if resp.status_code != 200:
            return "UNKNOWN", f"CIRCL hashlookup returned HTTP {resp.status_code}. URL: {url}"

        data = resp.json()
        product = data.get("ProductName") or data.get("FileName") or "unknown product"
        return "OK", f"CIRCL hashlookup: recognised as '{product}' (known good). URL: {url}"

    except requests.exceptions.Timeout:
        return "UNKNOWN", "CIRCL hashlookup timed out"
    except requests.exceptions.ConnectionError:
        return "UNKNOWN", "CIRCL hashlookup failed: no connection"
    except Exception as e:
        return "UNKNOWN", f"CIRCL hashlookup failed: {e}"
