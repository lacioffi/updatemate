import json


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
