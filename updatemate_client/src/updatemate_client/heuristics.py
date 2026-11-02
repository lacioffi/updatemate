import json
import os
import requests


def _parse_entry(v):
    """Best-effort JSON-decode of a ledger entry that may arrive as a
    pre-parsed dict or as a raw JSON string, mirroring the pattern every
    heuristic in this module already uses for `reviews`/`versions`
    elements. Returns None on anything unparseable rather than raising."""
    try:
        return json.loads(v) if isinstance(v, str) else v
    except Exception:
        return None


def _community_reviews(reviews: list) -> list:
    """Reviews with `developer_verified` not set -- i.e. submitted by
    someone other than the keypair that signed the binary being
    reviewed (Section 6.5 of the paper exempts exactly that keypair from
    the CAPTCHA gate, on data-input-pipeline grounds, not because its
    reviews are trusted as neutral).

    Every heuristic below that reads review content filters through this
    first, by design: a developer's own review of their own software is
    not an independent community signal, and a developer-verified review
    is never counted toward any of these verdicts, in either direction.
    This is what keeps a compromised code-signing key from being able to
    move a heuristic's output at all, despite being exempt from CAPTCHA
    and able to submit as many signed reviews as it likes -- the
    exemption only ever affects submission friction, never what the
    community-facing heuristics compute. A developer-verified review is
    still recorded in the ledger and shown to users (Section 6.3): it is
    meant to carry release metadata (notes, test results, and the like),
    not to influence these alerts.

    Parses dict-or-JSON-string entries defensively, like `_parse_entry`,
    and silently drops anything unparseable rather than raising."""
    out = []
    for review in reviews or []:
        r = _parse_entry(review)
        if not r or r.get("developer_verified"):
            continue
        out.append(r)
    return out


def _version_label(v: dict) -> str:
    """Human-readable declared version string (e.g. "12.4.1") for a
    stored version entry. Mirrors gui.py's _extract_version_label: prefers
    StringFileInfo.ProductVersion, which the server always preserves, over
    file_properties.FileVersion, which classes.py's FileProperties drops
    on a server round-trip."""
    fp = (v.get("file_properties") or {})
    sfi = (fp.get("StringFileInfo") or {})
    return (
        sfi.get("ProductVersion")
        or sfi.get("FileVersion")
        or fp.get("FileVersion")
        or ""
    )


def check_rare_version(versions: list, version_id: str, review_counts: dict) -> tuple[str, str]:
    """Flags a version that has fewer than 10% of the reviews its
    immediate predecessor in the ledger has.

    `versions` must be in ledger order (the order get_software_versions
    returns them in -- oldest first): the "predecessor" of a version is
    simply the entry immediately before it in that list, for the same
    software. `review_counts` maps software_version_id -> total review
    count (e.g. ok + bad), since the raw version entries carry no review
    data of their own -- the caller (gui.py) builds this from the same
    per-version review lookups that populate the Known Versions tab.

    IMPORTANT CAVEAT: this will misfire on every brand-new version of
    actively-used software, since a version that has only existed for a
    day or two will almost always have far fewer reviews than one that's
    been out for months -- with no malicious intent involved at all. This
    is NOT a reliable standalone signal for that reason; it's a coarse,
    noisy warning sign at best, meant to surface candidates worth a
    second look (e.g. a release deliberately kept away from most of the
    user base so it accumulates few reviews), not a verdict. A BAD result
    here deserves more skepticism than the other heuristics' BAD results,
    precisely because "nobody's reviewed it yet" and "this was pushed to
    a targeted few on purpose" look identical from review counts alone.

    Returns UNKNOWN when there's no predecessor to compare against (this
    is the first known version of the software, or isn't found at all),
    or when the predecessor itself has zero recorded reviews (nothing to
    compute a ratio against)."""
    if not versions or not version_id or type(versions) != list:
        return "UNKNOWN", "Insufficient data for rare-version check"

    index = None
    for i, raw in enumerate(versions):
        v = _parse_entry(raw)
        if v and v.get("software_version_id") == version_id:
            index = i
            break

    if index is None:
        return "UNKNOWN", "Version not found among known versions; cannot compare against its predecessor."

    if index == 0:
        return "UNKNOWN", "This is the first known version of this software; there is no predecessor to compare against."

    predecessor = _parse_entry(versions[index - 1])
    predecessor_id = predecessor.get("software_version_id") if predecessor else None
    predecessor_count = (review_counts or {}).get(predecessor_id, 0)

    if not predecessor_count:
        return "UNKNOWN", "The predecessor version has no recorded reviews yet; nothing to compare against."

    current_count = (review_counts or {}).get(version_id, 0)
    ratio = current_count / predecessor_count

    if ratio < 0.10:
        return "BAD", (
            f"This version has only {current_count} review(s), under 10% of the "
            f"{predecessor_count} its predecessor has. This could indicate a release reviewed "
            "by only a small slice of the user base -- but it will also just be true of any "
            "brand-new version that hasn't had time to accumulate reviews yet, so treat this as "
            "a weak warning sign, not a verdict. Please check with the software vendor."
        )

    return "OK", (
        f"This version has {current_count} review(s), a reasonable proportion ({ratio:.1%}) of "
        f"its predecessor's {predecessor_count}."
    )


def check_version_duplicate(versions: list, version_id: str, review_counts: dict) -> tuple[str, str]:
    """Flags when the version being checked shares its declared version
    string (e.g. ProductVersion "12.4.1") with another, unrelated entry in
    this software's ledger history -- a different software_version_id,
    i.e. a genuinely different binary/signature, not the same release
    resubmitted -- and that other entry has MORE reviews than this one.

    The ledger's identity scheme (software_version_id) is built from the
    signature hash, not the human-readable version string (see merkle.py's
    add_software_version), so nothing stops two unrelated binaries from
    both claiming to be "12.4.1". When that happens and the entry you're
    looking at is the less-reviewed of the pair, it's a plausible sign
    that this one is impersonating an already-established, well-reviewed
    version number rather than being the genuine article.

    Like check_rare_version, this is a coarse, noisy signal: a legitimate
    same-numbered re-release (e.g. a quick hotfix that didn't bump the
    version string) would also trigger it, with no malicious intent
    involved. Treat a BAD result here as a prompt to go look at *why* two
    entries share this version number, not as a verdict on its own.

    `versions` is the full list of known version entries for this
    software (any order); `review_counts` maps software_version_id ->
    total review count, for the same reason given in check_rare_version."""
    if not versions or not version_id or type(versions) != list:
        return "UNKNOWN", "Insufficient data for version-duplicate check"

    current = None
    for raw in versions:
        v = _parse_entry(raw)
        if v and v.get("software_version_id") == version_id:
            current = v
            break

    if current is None:
        return "UNKNOWN", "Version not found among known versions; cannot check for duplicate version strings."

    current_label = _version_label(current)
    if not current_label:
        return "UNKNOWN", "No declared version string available for this version."

    current_count = (review_counts or {}).get(version_id, 0)

    duplicates = []
    for raw in versions:
        v = _parse_entry(raw)
        if not v:
            continue
        other_id = v.get("software_version_id")
        if not other_id or other_id == version_id:
            continue
        if _version_label(v) != current_label:
            continue
        duplicates.append((other_id, (review_counts or {}).get(other_id, 0)))

    if not duplicates:
        return "OK", "No other known version of this software declares the same version string."

    better_reviewed = [d for d in duplicates if d[1] > current_count]
    if better_reviewed:
        other_id, other_count = max(better_reviewed, key=lambda d: d[1])
        return "BAD", (
            f"Another, unrelated version entry ({other_id}) declares the exact same version "
            f"string (\"{current_label}\") and has more reviews ({other_count} vs {current_count} "
            "for this one). This could indicate this version is impersonating an already-"
            "established release. Please check with the software vendor."
        )

    return "OK", (
        f"Other version entries share this version string (\"{current_label}\"), but none has "
        "more reviews than this one."
    )


def check_freeze_replay_attack(reviews, versions: list, current_file_version: str) -> tuple[str, str]:
    """Detects if user is stuck on older version with bad review while newer versions exist."""
    if not versions or not reviews or not current_file_version or type(reviews) != list:
        return "UNKNOWN", "Insufficient data for freeze attack check"

    has_bad_review = False
    for r in _community_reviews(reviews):
        if r.get("review") in ("vulnerable", "malicious", "degraded"):
            has_bad_review = True
            break

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

#: Review tags that report a *security* issue (the binary is vulnerable or
#: actively malicious) vs. a *quality* issue (the binary works as intended,
#: more or less, but is worse to use than before: slower, missing a feature,
#: buggier). "ok" is a positive signal for both categories and isn't listed
#: here; see `_bad_proportion_check` for how it's counted.
#:
#: This split exists because lumping both into one "bad review" tally, as an
#: earlier version of check_bad_software did, let a purely non-security
#: complaint (e.g. a slow update) push a version's reviews over the
#: malicious-software threshold -- conflating "this update is annoying" with
#: "this update is dangerous." check_bad_software now reads only
#: SECURITY_REVIEW_TAGS; check_degraded_software, below, reads only
#: QUALITY_REVIEW_TAGS. Neither function counts a review tagged with the
#: other category at all, in either direction: a security reviewer's
#: "degraded" tag doesn't dilute check_bad_software's denominator, and vice
#: versa.
SECURITY_REVIEW_TAGS = frozenset({"malicious", "vulnerable"})
QUALITY_REVIEW_TAGS = frozenset({"degraded"})


def _bad_proportion_check(reviews, bad_tags: frozenset, threshold: float, kind: str) -> tuple[str, str]:
    """Shared logic behind check_bad_software and check_degraded_software:
    flags a version whose community reviews are more than `threshold`
    fraction tagged with one of `bad_tags`, out of (reviews tagged "ok") +
    (reviews tagged with one of `bad_tags`).

    A review tagged with neither "ok" nor a member of `bad_tags` -- e.g. a
    "degraded" review when `bad_tags` is SECURITY_REVIEW_TAGS -- is excluded
    from the count entirely: it is neither good nor bad evidence for *this*
    `kind` of problem, so it affects neither the numerator nor the
    denominator. This is what keeps check_bad_software and
    check_degraded_software from leaking into each other's verdicts.

    `kind` is a short label ("security"/"quality") used only in the
    returned message text.

    Returns UNKNOWN, not OK, when there are no applicable reviews to
    assess: an empty or malformed `reviews` list, or one containing only
    reviews of the other category, is a lack of data for this check, not a
    clean verdict, and should not be reported the same way as an actually
    reviewed, low-risk version."""
    if not reviews or type(reviews) != list:
        return "UNKNOWN", f"No reviews available to assess {kind}"

    count_good = 0
    count_bad = 0
    for r in _community_reviews(reviews):
        tag = r.get("review")
        if tag in ("ok", "OK"):
            count_good += 1
        elif tag in bad_tags:
            count_bad += 1

    if count_good + count_bad == 0:
        return "UNKNOWN", f"No reviews relevant to {kind} have been submitted yet."

    total_reviews = count_good + count_bad
    if total_reviews < 2:
        return "UNKNOWN", f"Insufficient {kind}-relevant reviews ({total_reviews}) to assess this version."

    bad_proportion = count_bad / total_reviews
    if bad_proportion > threshold:
        return "BAD", f"This version has a high proportion of negative {kind} reviews (over {bad_proportion:.1%}). You should be cautious and check the reviews and/or with the software vendor before using this version."
    return "OK", f"This version has an acceptable proportion of negative {kind} reviews (under {bad_proportion:.1%})."


def check_bad_software(reviews, threshold: float = 0.3) -> tuple[str, str]:
    """Detects if a version has a high proportion of negative SECURITY
    reviews, i.e. reviews tagged "malicious" or "vulnerable"
    (SECURITY_REVIEW_TAGS). A "degraded" (quality) review is not counted
    here at all, in either direction -- see check_degraded_software for the
    quality counterpart, and the module-level SECURITY_REVIEW_TAGS /
    QUALITY_REVIEW_TAGS comment for why the two are kept separate.

    `threshold` is the fraction of bad-to-total reviews above which the
    version is flagged BAD (default 0.3, matching the deployed default
    discussed in Section 6.3 of the paper). Exposed as a parameter, rather
    than a hardcoded constant, purely for configurability: a production
    deployment could adopt a different threshold, or time-windowed
    statistics, without touching this function's logic (Section 6.3)."""
    return _bad_proportion_check(reviews, SECURITY_REVIEW_TAGS, threshold, "security")


def check_degraded_software(reviews, threshold: float = 0.3) -> tuple[str, str]:
    """Quality counterpart to check_bad_software: flags a version whose
    community reviews are more than `threshold` fraction tagged "degraded"
    (QUALITY_REVIEW_TAGS) -- a complaint about the software working worse
    than before, not about it being unsafe. A "malicious" or "vulnerable"
    (security) review is not counted here at all, in either direction;
    see check_bad_software for the security counterpart.

    Same threshold semantics and default as check_bad_software (0.3); see
    that function's docstring for why it's a parameter rather than a
    constant."""
    return _bad_proportion_check(reviews, QUALITY_REVIEW_TAGS, threshold, "quality")


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
    """Detects if version is not popular (possible targeted attack).

    Counts only community reviews (`_community_reviews`): a developer
    key cannot inflate this count past the threshold by submitting its
    own CAPTCHA-free reviews, since none of them are counted here."""
    if type(reviews) != list or len(_community_reviews(reviews)) < 2:
        return "BAD", "Less than 2 community reviews exist for this version. You maybe be the victim of a targeted version. Check with the vendor and the community."
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
