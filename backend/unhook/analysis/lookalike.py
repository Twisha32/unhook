import unicodedata
from dataclasses import dataclass

from .brands import BRANDS, LURE_WORDS, Brand
from .hostutil import split_host, to_unicode

# Characters that pass for ASCII letters at a glance. Curated by hand rather than
# pulling in the full Unicode confusables table: this covers what actually shows up
# in phishing domains (Cyrillic and Greek lookalikes, dotless i, and so on).
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "ӏ": "l", "к": "k", "м": "m", "т": "t",
    "ɡ": "g", "ɑ": "a", "ı": "i", "ł": "l", "ℓ": "l", "ⅼ": "l", "ⅰ": "i", "ǀ": "l", "ɩ": "l",
    "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "υ": "u", "ω": "w",
    "ʋ": "v", "ṗ": "p", "ȷ": "j", "ɢ": "g", "ᴀ": "a", "ᴄ": "c", "ᴇ": "e", "ᴏ": "o",
}
_DIGIT_FOLD = {"0": "o", "3": "e", "5": "s", "4": "a", "8": "b"}
_MULTI = (("rn", "m"), ("vv", "w"), ("cl", "d"))


@dataclass
class Lookalike:
    host: str
    registered: str
    brand: str
    kind: str  # homoglyph | brand_subdomain | typosquat | combosquat | tld_swap
    detail: str


def skeletons(label: str) -> set[str]:
    """What a hurried reader would take this label to be. '1' could be l or i."""
    label = unicodedata.normalize("NFKC", label.lower())
    label = "".join(_CONFUSABLES.get(ch, ch) for ch in label)
    label = "".join(_DIGIT_FOLD.get(ch, ch) for ch in label)
    out = set()
    for one in ("l", "i"):
        s = label.replace("1", one)
        for src, dst in _MULTI:
            s = s.replace(src, dst)
        out.add(s.replace("-", ""))
    return out


def scripts_in(label: str) -> set[str]:
    found = set()
    for ch in label:
        if ch.isalpha():
            found.add(unicodedata.name(ch, "UNKNOWN").split(" ")[0])
    return found


def is_mixed_script(host: str) -> bool:
    return any(len(scripts_in(label)) > 1 for label in to_unicode(host).split("."))


def osa_distance(a: str, b: str) -> int:
    """Edit distance counting a swap of two neighbours as one edit."""
    if a == b:
        return 0
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[len(a)][len(b)]


def org_brand(domains: list[str]) -> list[Brand]:
    return [Brand("your organisation", (), (d.lower(),)) for d in domains if d]


def check_host(host: str, brands: list[Brand] | None = None, extra: list[Brand] | None = None) -> Lookalike | None:
    """Return the most convincing lookalike finding for a host, or None."""
    pool = list(brands if brands is not None else BRANDS) + list(extra or [])
    shown = to_unicode(host.lower())
    parts = split_host(shown)
    registered = parts.registered
    if not registered or not parts.label:
        return None
    if any(registered in b.domains for b in pool):
        return None  # it *is* the brand (or a subdomain of it)

    label = parts.label
    tokens = label.split("-")
    label_skeletons = set(skeletons(label))
    for token in tokens:
        label_skeletons |= skeletons(token)
    candidates: list[tuple[int, Lookalike]] = []

    for brand in pool:
        for legit in brand.domains:
            legit_parts = split_host(legit)
            bl = legit_parts.label
            if len(bl) < 3:
                continue
            # microsoft.com.account-check.example
            if f".{legit}." in f".{shown}." and not shown.endswith(f".{legit}"):
                candidates.append((1, Lookalike(host, registered, brand.name, "brand_subdomain",
                                                f"has {legit} at the front, but the real domain is {registered}")))
                continue
            # paypal.account-check.example
            if len(bl) >= 5 and bl in parts.subdomain.split(".") and label != bl:
                candidates.append((1, Lookalike(host, registered, brand.name, "brand_subdomain",
                                                f"uses '{bl}' as a subdomain of {registered}")))
                continue
            if label == bl:
                if len(bl) >= 5:
                    candidates.append((4, Lookalike(host, registered, brand.name, "tld_swap",
                                                    f"reuses the name of {legit} under a different ending")))
                continue
            if len(bl) >= 5 and bl in label_skeletons and bl not in tokens:
                candidates.append((0, Lookalike(host, registered, brand.name, "homoglyph",
                                                f"reads like {legit} once lookalike characters are folded")))
                continue
            if len(bl) >= 6:
                limit = 1 if len(bl) < 11 else 2
                if any(0 < osa_distance(s, bl) <= limit for s in label_skeletons if abs(len(s) - len(bl)) <= limit):
                    candidates.append((2, Lookalike(host, registered, brand.name, "typosquat",
                                                    f"is one or two keystrokes away from {legit}")))
                    continue
            remainder_ok = False
            if bl in tokens:
                remainder_ok = True
            elif len(bl) >= 6 and bl in label:
                remainder_ok = True
            elif len(bl) >= 4 and (label.startswith(bl) or label.endswith(bl)):
                remainder = label.replace(bl, "", 1)
                remainder_ok = remainder in LURE_WORDS
            if remainder_ok:
                candidates.append((3, Lookalike(host, registered, brand.name, "combosquat",
                                                f"wraps the name from {legit} in extra words")))

    if not candidates:
        return None
    candidates.sort(key=lambda c: c[0])
    return candidates[0][1]
