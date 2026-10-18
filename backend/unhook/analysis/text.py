import re
from dataclasses import dataclass, field

_I = re.IGNORECASE

URGENCY = [
    r"\burgent(?:ly)?\b", r"\bimmediately\b", r"within (?:the next )?\d+ ?(?:hours?|hrs?|days?)",
    r"\bfinal (?:notice|warning|reminder)\b", r"\b(?:account|access|mailbox) (?:will be |has been |is )?(?:suspended|deactivated|disabled|terminated|locked|closed)\b",
    r"\bexpires? (?:today|soon|in)\b", r"\bact now\b", r"\blast chance\b", r"\bimmediate action\b",
    r"\bfailure to (?:comply|respond|verify|act)\b",
]
CREDENTIALS = [
    r"\bverify your (?:account|identity|email|password|information)\b",
    r"\b(?:confirm|update|validate|re-?enter|reset) your (?:password|credentials|login|account|details|information|payment)\b",
    r"\bsign[- ]?in\b", r"\blog[- ]?in\b", r"\bpassword (?:expires?|expiry|reset|will expire)\b",
    r"\bsecurity alert\b", r"\bunusual (?:sign[- ]?in|activity)\b", r"\bverification code\b",
    r"\bmailbox (?:is )?(?:full|storage|quota)\b", r"\bkeep (?:the )?same password\b", r"\bmfa\b|\b2fa\b|multi-?factor",
]
PAYMENT = [
    r"\bwire transfer\b", r"\bgift cards?\b", r"\bdirect deposit\b", r"\bpayroll\b", r"\binvoice\b",
    r"\bremittance\b", r"\bbank (?:details|account)\b", r"\bpayment (?:is )?(?:overdue|pending|failed|declined)\b",
    r"\bpurchase order\b", r"\bw-?2\b", r"\bupdate (?:my|your) (?:banking|bank)\b", r"\bbitcoin\b|\bcrypto(?:currency)?\b",
]
THREAT = [
    r"\blegal action\b", r"\bunauthori[sz]ed\b", r"\bsuspicious activity\b", r"\bcompromised\b",
    r"\bfraud(?:ulent)?\b", r"\bpenalt(?:y|ies)\b", r"\barrest\b", r"\bviolation\b", r"\bsuspend(?:ed)?\b",
]
GREETING = re.compile(
    r"^\s*(?:dear|hello|hi)\s+(?:valued\s+)?(?:customer|user|member|account holder|client|sir|madam|email user|webmail user|employee)\b", _I | re.M
)
QR = re.compile(r"scan (?:the|this|your|our)?\s*(?:qr|barcode)|\bqr[- ]?code\b", _I)
REPLY_PREFIX = re.compile(r"^\s*(?:re|fwd?)\s*:", _I)

ROLE_PHRASES = [
    "it support", "help desk", "helpdesk", "service desk", "payroll", "human resources", "hr department",
    "hr team", "accounts payable", "accounting", "administrator", "security team", "ceo", "director",
    "superintendent", "principal", "finance", "billing", "mail admin", "system admin", "webmaster",
    "technical support", "it department", "it team",
]


@dataclass
class TextSignals:
    urgency: list[str] = field(default_factory=list)
    credentials: list[str] = field(default_factory=list)
    payment: list[str] = field(default_factory=list)
    threat: list[str] = field(default_factory=list)
    generic_greeting: bool = False
    qr_lure: bool = False
    fake_reply: bool = False


def _hits(patterns: list[str], text: str) -> list[str]:
    found = []
    for pattern in patterns:
        m = re.search(pattern, text, _I)
        # Overlapping patterns can land on the same words; show each phrase once.
        if m and m.group(0).lower() not in found:
            found.append(m.group(0).lower())
    return found


def read_signals(subject: str, body: str, has_thread_headers: bool) -> TextSignals:
    blob = f"{subject}\n{body[:20000]}"
    return TextSignals(
        urgency=_hits(URGENCY, blob),
        credentials=_hits(CREDENTIALS, blob),
        payment=_hits(PAYMENT, blob),
        threat=_hits(THREAT, blob),
        generic_greeting=bool(GREETING.search(body[:500])),
        qr_lure=bool(QR.search(blob)),
        # "RE:" in the subject of a message that isn't part of any thread is a classic trick.
        fake_reply=bool(REPLY_PREFIX.match(subject)) and not has_thread_headers,
    )
