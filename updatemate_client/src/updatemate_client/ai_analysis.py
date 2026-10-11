import json
import logging
import os
import random
import re
import time
import requests


def _strip_url(text: str) -> str:
    """Remove trailing 'URL: http...' segments that heuristics append to comments."""
    return re.sub(r'\.\s*URL:\s*https?://\S+', '.', text).strip()


def _extract_json(text: str) -> dict:
    """Robustly extract the first JSON object from a string.

    Tries multiple strategies so preamble text, markdown fences, and trailing
    content don't cause a parse failure.
    """
    # Strategy 1: the whole thing is already clean JSON
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: strip markdown code fences (```json ... ``` or ``` ... ```)
    fenced = re.sub(r"```(?:json)?\s*(.*?)\s*```", r"\1", text, flags=re.DOTALL).strip()
    if fenced and fenced != text:
        try:
            return json.loads(fenced)
        except json.JSONDecodeError:
            pass

    # Strategy 3: find the first '{' and let raw_decode stop at the matching '}'
    start = text.find("{")
    if start != -1:
        obj, _ = json.JSONDecoder().raw_decode(text[start:])
        return obj

    raise json.JSONDecodeError("No JSON object found", text, 0)


def analyze_with_gemini(program_data: dict, heuristic_results: dict) -> tuple[str, str]:
    """Call Gemini with all binary data and return (short_verdict, detailed_analysis).

    Returns ("", reason) when the API key is missing or the call fails.
    """
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        return "", "Gemini API key not configured. Add it via the Configuration button."

    meta = program_data.get("_meta", {})
    fp   = program_data.get("file_properties", {})
    sfi  = fp.get("StringFileInfo") or {}

    program_name = meta.get("program_name", "Unknown")
    path         = meta.get("path", "Unknown")
    company      = sfi.get("CompanyName", "Unknown")
    file_version = fp.get("FileVersion", "Unknown")
    sha256       = program_data.get("sha256", "Unknown")
    signed       = "Yes" if program_data.get("signatures") else "No"

    # Reviews — cap at 5, truncate each comment
    reviews = meta.get("reviews", [])
    review_lines = []
    for rev in reviews[:5]:
        try:
            r = json.loads(rev) if isinstance(rev, str) else rev
            comment = (r.get("comment") or "")[:120]
            review_lines.append(
                f"  [{r.get('review', '?')}] {r.get('reviewer', 'Anonymous')}: {comment}"
            )
        except Exception:
            pass
    reviews_text = "\n".join(review_lines) if review_lines else "  No reviews available"
    if len(reviews) > 5:
        reviews_text += f"\n  (+{len(reviews) - 5} more not shown)"

    # Heuristics — strip long URLs, truncate comments
    ok_count      = heuristic_results.get("ok_count", 0)
    bad_count     = heuristic_results.get("bad_count", 0)
    unknown_count = heuristic_results.get("unknown_count", 0)
    results       = heuristic_results.get("results", {})

    heuristic_lines = []
    for check_name, check_result in results.items():
        status  = check_result.get("status", "UNKNOWN")
        comment = _strip_url(check_result.get("comment", ""))[:150]
        heuristic_lines.append(f"  {check_name}: [{status}] {comment}")
    heuristics_text = "\n".join(heuristic_lines) if heuristic_lines else "  None"

    prompt = f"""You are a cybersecurity analyst assistant embedded in UpdateMate, a community-driven \
software update transparency tool for Windows users.

A new process was detected on the user's machine. Analyze all available data and assess whether \
this executable appears safe, suspicious, or dangerous.

FILE INFORMATION:
  Program:          {program_name}
  Path:             {path}
  Company:          {company}
  File Version:     {file_version}
  Digitally Signed: {signed}
  SHA-256:          {sha256}

COMMUNITY REVIEWS ({len(reviews)} total):
{reviews_text}

AUTOMATED HEURISTIC RESULTS ({ok_count} OK / {bad_count} BAD / {unknown_count} Unknown):
{heuristics_text}

Note that the check_circl_hashlookup API only checks for known good files, especially from operating systems and such, so if it is unknown, it does not necessarily mean it is malicious. Also, the heuristics are not perfect and may produce false positives or false negatives.

Remember that you have been trained on past data, so don't worry if a version is higher than you expect.

Based on all the above, respond with ONLY a JSON object — no markdown, no preamble, no trailing text:
{{"verdict": "<2-5 word verdict, e.g. Likely safe / Exercise caution / Probably malicious>", "analysis": "<2-4 sentences explaining your reasoning, covering the most important signals>"}}"""

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-2.5-flash:generateContent?key={api_key}"
    )
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "maxOutputTokens": 5000},
    }

    resp = None
    for attempt in range(4):
        try:
            resp = requests.post(url, json=payload, timeout=30)
        except requests.exceptions.Timeout:
            return "", "Gemini request timed out."
        except requests.exceptions.ConnectionError:
            return "", "Gemini request failed: no connection."
        except Exception as exc:
            return "", f"Gemini request failed: {exc}"

        if resp.status_code == 429:
            wait = (2 ** attempt) + random.uniform(0.0, 1.0)
            time.sleep(wait)
            continue
        break

    if resp.status_code != 200:
        return "", f"Gemini API returned HTTP {resp.status_code}: {resp.text[:300]}"

    try:
        parts = resp.json()["candidates"][0]["content"]["parts"]
        # Gemini 2.5 thinking models prepend thought parts marked with "thought": true.
        # Only join parts that are actual model output.
        raw_text = "\n".join(
            p["text"] for p in parts if not p.get("thought", False) and "text" in p
        ).strip()
    except (KeyError, IndexError):
        return "", f"Unexpected Gemini response structure: {resp.text[:300]}"

    try:
        result   = _extract_json(raw_text)
        verdict  = result.get("verdict", "Unknown")
        analysis = result.get("analysis", "No analysis provided.")
        return verdict, analysis
    except (json.JSONDecodeError, ValueError) as exc:
        logging.error(f"AI JSON parse failed: {exc!r} | raw_text={raw_text!r}")
        return "See analysis", raw_text
