import json
import os
import requests


def check_known_version(versions: list, version_id: str) -> tuple[str, str]:
    """Check whether the current software version exists in the community database."""
    if not versions or not version_id:
        return "BAD", "Version not seen before — no community record. This could be a targeted attack or a new version. Please check with the software vendor."

    for version in versions:
        try:
            v = json.loads(version) if isinstance(version, str) else version
            if v.get("software_version_id") == version_id:
                return "OK", "Version is known in the community database. Someone else has seen this version before."
        except:
            continue

    return "BAD", "Version not seen before — no community record. This could be a targeted attack or a new version. Please check with the software vendor."


def check_freeze_replay_attack(reviews, versions: list, current_file_version: str) -> tuple[str, str]:
    """Detects if user is stuck on older version with bad review while newer versions exist."""
    if not versions or not reviews or not current_file_version or type(reviews) != list:
        return "UNKNOWN", "Insufficient data for freeze attack check"

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
        return "OK", "No bad reviews for current version. You don't seem to be stuck on an older version with known issues."

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
        return "BAD", f"Current version {current_file_version} has bad review(s) while newer versions exist. You may be stuck on an older version with known issues. Please check with the software vendor."
    return "OK", "Current version has bad reviews, but no newer versions are known. Although risky, this does not appear to be a freeze/replay attack. Please check with the software vendor."

def check_bad_software(reviews, threshold: float = 0.3) -> tuple[str, str]:
    """Detects if version has high proportion of negative reviews.

    `threshold` is the fraction of bad-to-total reviews above which the
    version is flagged BAD (default 0.3, matching the deployed default
    discussed in Section 6.3 of the paper). Exposed as a parameter, rather
    than a hardcoded constant, purely for configurability: a production
    deployment could adopt a different threshold, or time-windowed
    statistics, without touching this function's logic (Section 6.3).

    Returns UNKNOWN, not OK, when there are no reviews to assess: an
    empty or malformed `reviews` list is a lack of data, not a clean
    verdict, and should not be reported the same way as an actually
    reviewed, low-risk version."""
    if not reviews or type(reviews) != list:
        return "UNKNOWN", "No reviews available"

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
        return "UNKNOWN", "No valid reviews have been submitted yet."

    total_reviews = count_good + count_bad
    if total_reviews < 2:
        return "UNKNOWN", f"Insufficient reviews ({total_reviews}) to assess quality/safety of this version."

    bad_proportion = count_bad / total_reviews
    if bad_proportion > threshold:
        return "BAD", f"This version has a high proportion of negative reviews (over {bad_proportion:.1%}). You should be cautious and check the reviews and/or with the software vendor before using this version."
    return "OK", f"This version has an acceptable proportion of negative reviews (under {bad_proportion:.1%})."


def check_CA_change(versions: list, version_id: str) -> tuple[str, str]:
    """Flags when a version's signing certificate chain shares no
    certificate authority with any other known version of the same
    software: a developer who has always signed through the same CA
    infrastructure suddenly switching to a completely different one may
    indicate a release signed through a separate, compromised certificate.

    Compares the *full* set of certificate issuers for `version_id` --
    every CA that appears anywhere in its signing chain(s), not just the
    leaf certificate's issuer -- against the union of issuers seen across
    every other known version of this software. Using the whole chain
    rather than only the leaf avoids false alarms on routine certificate
    renewal: a vendor that renews its code-signing certificate through the
    same root/intermediate CA still shares at least one issuer with its
    own history, even though the leaf certificate itself is brand new.

    Returns UNKNOWN (not OK) when there isn't enough data to compare --
    the version isn't found, it has no certificate data, or there are no
    other known versions yet to compare against -- since an absence of
    data is not the same as a clean verdict."""
    if not versions or not version_id or type(versions) != list:
        return "UNKNOWN", "Insufficient data for CA-change check"

    def _parse(v):
        try:
            return json.loads(v) if isinstance(v, str) else v
        except Exception:
            return None

    def _issuers(v: dict) -> set:
        issuers = set()
        for sig in (v.get("signatures") or []):
            for cert in (sig.get("certificates") or []):
                issuer = cert.get("issuer")
                if issuer:
                    issuers.add(issuer)
        return issuers

    current_issuers = None
    history_issuers = set()

    for raw in versions:
        v = _parse(raw)
        if not v:
            continue
        if v.get("software_version_id") == version_id:
            if current_issuers is None:
                current_issuers = _issuers(v)
            continue
        history_issuers |= _issuers(v)

    if current_issuers is None:
        return "UNKNOWN", "Current version not found among known versions; cannot compare certificate chains."

    if not current_issuers:
        return "UNKNOWN", "No certificate information available for the current version."

    if not history_issuers:
        return "UNKNOWN", "No other known versions of this software to compare the signing certificate chain against."

    if current_issuers.isdisjoint(history_issuers):
        return "BAD", (
            "This version's certificate chain shares no certificate authority with any "
            "other known version of this software. This could indicate a release signed "
            "through a separate, compromised certificate. Please check with the software vendor."
        )

    return "OK", "This version's signing certificate chain shares at least one certificate authority with other known versions."


def check_targeted_malware(reviews) -> tuple[str, str]:
    """Detects if version is not popular (possible targeted attack)."""
    if len(reviews) < 2 or type(reviews) != list:
        return "BAD", "Less than 2 reviews exist for this version. You maybe be the victim of a targeted version. Check with the vendor and the community."
    return "OK", "This version has multiple community reviews, so it is less likely to be a targeted attack."


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
