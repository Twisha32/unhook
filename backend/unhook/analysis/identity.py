import re
from dataclasses import dataclass

from .brands import BRANDS, FREEMAIL, LURE_WORDS, Brand
from .hostutil import registered_domain
from .message import ParsedMessage
from .text import ROLE_PHRASES

_EMAIL_IN_NAME = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_NAME_FILLER = {"no", "reply", "noreply", "team", "the", "from", "inc", "corp", "corporation", "customer",
                "care", "department", "dept", "official", "notifications", "notification", "365", "co", "llc", "and"}


@dataclass
class IdentityReport:
    sender_domain: str
    sender_registered: str
    sender_freemail: bool
    reply_to_domain: str = ""
    reply_to_mismatch: bool = False
    reply_to_freemail: bool = False
    display_email_spoof: str = ""
    display_brand: str = ""
    protected_name: str = ""
    freemail_role: str = ""
    brand_claims: tuple[str, ...] = ()


def _words(text: str) -> list[str]:
    return re.findall(r"[a-z0-9]+", text.lower())


def brand_owns(brand: Brand, *domains: str) -> bool:
    return any(registered_domain(d) in brand.domains for d in domains if d)


def display_is_brand(display: str, brand: Brand) -> bool:
    """True when the display name is basically just the brand plus filler words.

    'PayPal Security Team' qualifies. 'Clever Kids Daycare' does not, which keeps
    ordinary small businesses from being flagged as impersonators of Clever.
    """
    words = _words(display)
    if not words:
        return False
    brand_words = {w for k in brand.keywords for w in _words(k)}
    if not brand_words & set(words):
        return False
    allowed = brand_words | _NAME_FILLER | LURE_WORDS
    return all(w in allowed for w in words)


def claims_brand(text: str, brand: Brand) -> bool:
    low = text.lower()
    for keyword in brand.keywords:
        if len(keyword) <= 3:
            continue
        if re.search(rf"(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])", low):
            return True
    return False


def read_identity(msg: ParsedMessage, link_domains: set[str], org_domains: list[str], protected_names: list[str]) -> IdentityReport:
    sender = msg.sender
    sdom = sender.domain
    rep = IdentityReport(
        sender_domain=sdom,
        sender_registered=registered_domain(sdom) if sdom else "",
        sender_freemail=sdom in FREEMAIL,
    )
    org = {d.lower() for d in org_domains}

    if msg.reply_to and msg.reply_to.domain:
        rep.reply_to_domain = msg.reply_to.domain
        rep.reply_to_mismatch = registered_domain(msg.reply_to.domain) != rep.sender_registered
        rep.reply_to_freemail = msg.reply_to.domain in FREEMAIL

    m = _EMAIL_IN_NAME.search(sender.display)
    if m and registered_domain(m.group(0).rsplit("@", 1)[1]) != rep.sender_registered:
        rep.display_email_spoof = m.group(0).lower()

    for brand in BRANDS:
        if display_is_brand(sender.display, brand) and not brand_owns(brand, sdom):
            rep.display_brand = brand.name
            break

    display_norm = " ".join(_words(sender.display))
    for name in protected_names:
        want = " ".join(_words(name))
        if want and want in display_norm and rep.sender_registered not in org:
            rep.protected_name = name
            break

    if rep.sender_freemail:
        for phrase in ROLE_PHRASES:
            if re.search(rf"\b{re.escape(phrase)}\b", sender.display.lower()):
                rep.freemail_role = phrase
                break

    # Does the message talk as a brand while neither the sender nor any link belongs to it?
    head = f"{msg.subject}\n{msg.visible_text[:300]}"
    claims = []
    for brand in BRANDS:
        if claims_brand(head, brand) and not brand_owns(brand, sdom, *link_domains):
            claims.append(brand.name)
    rep.brand_claims = tuple(claims)
    return rep
