"""What the employee reads back, a minute after pressing the button.

Short on purpose. People skim these, and the goal is one thing they'll remember
next time, not a lecture.
"""

_HEADLINES = {
    "malicious": "This is phishing. Please don't click anything in it.",
    "suspicious": "This looks suspicious. Leave it alone for now.",
    "likely_safe": "We didn't find anything wrong with this one.",
}

_BODY = {
    "malicious": (
        "Thanks for reporting it. We've sent the details to our team and the sender is going on our block list. "
        "If you already clicked a link or opened an attachment, tell IT right away. That's not a problem, it just "
        "means we can act sooner."
    ),
    "suspicious": (
        "Thanks for reporting it. An analyst is taking a look and you'll hear back if there's anything you need to do. "
        "Until then, please don't click links, open attachments or reply."
    ),
    "likely_safe": (
        "Our checks came up clean, but no check is perfect. If something about the message still feels off, "
        "trust that and tell us. You were right to ask."
    ),
}

_FALLBACK_LESSON = "When a message creates pressure to act fast, slow down. That pressure is usually the point."


def pick_lesson(analysis: dict) -> tuple[str, str]:
    """Returns (lesson, what_stood_out). Uses the most confident finding that has a lesson."""
    for f in analysis.get("findings", []):
        if f.get("lesson"):
            hint = f["evidence"][0] if f.get("evidence") else f["title"]
            return f["lesson"], hint
    return _FALLBACK_LESSON, ""


def employee_message(analysis: dict, case_ref: str) -> tuple[str, str]:
    label = analysis["verdict"]["label"]
    lesson, hint = pick_lesson(analysis)
    parts = [_HEADLINES[label], "", _BODY[label]]
    if label != "likely_safe" and hint:
        parts += ["", f"What stood out: {hint}"]
    if label != "likely_safe":
        parts += ["", f"Quick tip: {lesson}"]
    parts += ["", f"Reference: {case_ref}"]
    return f"[Unhook] {_HEADLINES[label]}", "\n".join(parts)
