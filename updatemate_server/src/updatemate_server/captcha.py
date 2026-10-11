"""
Barebones proof-of-humanity gate for review submissions (Section 6.5 of
the paper).

Signing (updatemate_server/auth.py) answers *who* submitted a review; it does
not answer *how many* reviews one attacker can cheaply automate, since
generating a fresh keypair costs nothing. A developer-verified review is
already exempt from that concern -- it is bound to the same key that
signed the reviewed binary, a scarce, high-value credential (Section 6.4).
Everyone else is asked to solve a short, server-generated visual challenge
before their review is accepted; the paper discusses why this only raises,
rather than removes, the cost of Sybil manipulation (Section 8.1). This
is the same mechanism essentially every public review or comment form on
the web already uses for exactly this reason.

This is a deliberately barebones, self-hosted implementation, not a
production-grade CAPTCHA: a real deployment should swap this for a
commercial provider (e.g. hCaptcha, reCAPTCHA, Cloudflare Turnstile),
which offer far stronger resistance to automated/ML solvers than the
simple distorted-text image generated here. We implement our own rather
than integrate a third-party service because doing so would require API
keys we do not hold and would introduce an external service dependency
into a research PoC (the same trade-off already discussed for the
optional AI-assistance feature); what this module demonstrates is the
mechanism -- a human-facing challenge gating the anonymous
review-submission path -- not a state-of-the-art anti-bot system.

Honest limitation, stated here rather than left implicit: unlike a
signature or a proof-of-work nonce, a solved CAPTCHA leaves no lasting,
independently re-checkable evidence in the ledger. Verification is a
one-time, server-side event at submission time; an auditor reading the
ledger afterward has no way to confirm a human solved anything, only that
the server's own bookkeeping said so. We therefore do not persist any
CAPTCHA fields into the stored review record (see merkle.py) -- there is
no cryptographic value in keeping them, and keeping them would misleadingly
suggest otherwise.
"""
import base64
import io
import random
import secrets
import string
import time

from PIL import Image, ImageDraw, ImageFont

CHALLENGE_LENGTH = 5
CHALLENGE_TTL_SECONDS = 300  # a challenge must be solved within 5 minutes
_ALPHABET = string.ascii_uppercase + string.digits

# In-memory challenge store: challenge_id -> (answer, expires_at). This is
# adequate for the PoC's single-process Flask dev server (Section 6.1); a
# multi-process production deployment would need a shared store (e.g.
# Redis) instead.
_CHALLENGES = {}


def _render_challenge_image(text: str) -> bytes:
    """Renders `text` as a small, mildly distorted PNG -- enough to defeat
    a naive text-scrape of the HTTP response, not a serious OCR pipeline.
    This modesty is intentional and stated in this module's docstring."""
    width, height = 160, 60
    image = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(image)

    for _ in range(6):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        shade = random.randint(150, 200)
        draw.line((x1, y1, x2, y2), fill=(shade, shade, shade), width=1)

    try:
        font = ImageFont.truetype("DejaVuSans-Bold.ttf", 32)
    except OSError:
        font = ImageFont.load_default()

    x_cursor = 10
    for ch in text:
        char_img = Image.new("RGBA", (30, 50), (255, 255, 255, 0))
        char_draw = ImageDraw.Draw(char_img)
        char_draw.text((5, 5), ch, font=font, fill=(20, 20, 20, 255))
        angle = random.randint(-25, 25)
        char_img = char_img.rotate(angle, expand=True)
        y_offset = random.randint(0, 12)
        image.paste(char_img, (x_cursor, y_offset), char_img)
        x_cursor += 26

    buf = io.BytesIO()
    image.save(buf, format="PNG")
    return buf.getvalue()


def _purge_expired(now: float):
    expired = [cid for cid, (_, expires_at) in _CHALLENGES.items() if expires_at < now]
    for cid in expired:
        _CHALLENGES.pop(cid, None)


def generate_challenge() -> dict:
    """Creates a new challenge, stores its expected answer server-side,
    and returns {"challenge_id", "image_base64"} -- never the answer
    itself."""
    now = time.time()
    _purge_expired(now)

    answer = "".join(random.choices(_ALPHABET, k=CHALLENGE_LENGTH))
    challenge_id = secrets.token_hex(16)
    _CHALLENGES[challenge_id] = (answer, now + CHALLENGE_TTL_SECONDS)

    image_bytes = _render_challenge_image(answer)
    return {
        "challenge_id": challenge_id,
        "image_base64": base64.b64encode(image_bytes).decode("ascii"),
    }


def verify_and_consume(challenge_id: str, answer: str) -> bool:
    """Checks `answer` against the stored expected value for
    `challenge_id` and, whether it matches or not, consumes (deletes) the
    challenge so it cannot be replayed -- each challenge is single-use."""
    if not challenge_id or not answer:
        return False
    entry = _CHALLENGES.pop(challenge_id, None)
    if entry is None:
        return False
    expected_answer, expires_at = entry
    if time.time() > expires_at:
        return False
    return answer.strip().upper() == expected_answer


def debug_peek_answer(challenge_id: str):
    """TEST-ONLY escape hatch: returns the expected answer for a
    still-open challenge without consuming it, so automated tests and the
    non-interactive demo script can simulate "a human solved the CAPTCHA"
    without an actual person reading the rendered image. Real clients
    have no equivalent -- they only ever see the PNG returned by
    generate_challenge(). Mirrors how tests/signing_helpers.py stands in
    for a real Authenticode signature elsewhere in this test suite."""
    entry = _CHALLENGES.get(challenge_id)
    return entry[0] if entry else None
