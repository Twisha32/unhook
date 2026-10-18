import re
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

from .brands import FREE_HOSTING_SUFFIXES, SUSPICIOUS_TLDS, URL_SHORTENERS
from .hostutil import FILE_LIKE_TLDS, has_known_suffix, is_ip, registered_domain, split_host
from .message import Link

# Click-tracking domains used by legitimate senders. The anchor text rarely matches
# the href for these, and flagging every newsletter as a mismatch would be noise.
TRACKERS = {
    "sendgrid.net", "list-manage.com", "mandrillapp.com", "hubspotlinks.com", "hs-sites.com",
    "mailchimp.com", "constantcontact.com", "campaign-archive.com", "mkto-ab.com", "exct.net",
    "salesforce.com", "pardot.com", "marketo.com", "klaviyo.com", "customeriomail.com",
    "mailgun.org", "sparkpostmail.com", "rs6.net", "eloqua.com", "e2ma.net", "ct.sendgrid.net",
}

# Anchor text like "budget.xlsx" or "notes.md" looks like a domain but is a file name.
_FILE_LIKE = FILE_LIKE_TLDS

_TEXT_DOMAIN = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/\s:?#]|$)", re.I)


@dataclass
class UrlInfo:
    url: str
    host: str
    domain: str
    text: str = ""
    source: str = "html"
    flags: list[str] = field(default_factory=list)
    wrapped_from: str = ""

    @property
    def is_web(self) -> bool:
        return self.url.lower().startswith(("http://", "https://"))


def _unwrap_proofpoint_v2(value: str) -> str:
    return unquote(value.replace("-", "%").replace("_", "/"))


def unwrap(url: str) -> str:
    """Peel off the link-protection wrappers that mail gateways add.

    Reported mail has usually been through one already, and the wrapper domain
    (outlook.com, proofpoint.com) is always 'clean'. We want the real destination.
    """
    for _ in range(3):
        try:
            parts = urlsplit(url)
        except ValueError:
            return url
        host = (parts.hostname or "").lower()
        query = parse_qs(parts.query)
        target = None
        if host.endswith("safelinks.protection.outlook.com") and "url" in query:
            target = query["url"][0]
        elif host == "urldefense.proofpoint.com" and parts.path.startswith("/v2/") and "u" in query:
            target = _unwrap_proofpoint_v2(query["u"][0])
        elif host == "urldefense.com" and parts.path.startswith("/v3/"):
            m = re.search(r"/v3/__(.+?)__;", url)
            if m:
                target = m.group(1)
        elif host in {"www.google.com", "google.com"} and parts.path == "/url":
            target = (query.get("q") or query.get("url") or [None])[0]
        elif host == "l.facebook.com" and "u" in query:
            target = query["u"][0]
        if not target or not target.lower().startswith(("http://", "https://")) or target == url:
            return url
        url = target
    return url


def analyze_url(link: Link) -> UrlInfo | None:
    raw = link.href.strip()
    if not raw:
        return None
    scheme = raw.split(":", 1)[0].lower() if ":" in raw else ""
    if scheme in {"mailto", "tel", "sms", "cid"} or raw.startswith("#"):
        return None
    if scheme in {"javascript", "data"}:
        return UrlInfo(raw[:200], "", "", link.text, link.source, [f"{scheme}_scheme"])
    if scheme not in {"http", "https", "ftp"}:
        return None

    final = unwrap(raw)
    try:
        parts = urlsplit(final)
        host = (parts.hostname or "").lower().rstrip(".")
        port = parts.port
    except ValueError:
        return None
    if not host:
        return None

    info = UrlInfo(final, host, registered_domain(host), link.text, link.source, [])
    if final != raw:
        info.wrapped_from = raw
    flags = info.flags
    sp = split_host(host)

    if is_ip(host):
        flags.append("ip_host")
    if "xn--" in host:
        flags.append("punycode")
    if parts.username is not None:
        flags.append("userinfo")
    if info.domain in URL_SHORTENERS:
        flags.append("shortener")
    if sp.subdomain.count(".") >= 3:
        flags.append("deep_subdomains")
    if len(final) > 250:
        flags.append("very_long")
    if port and port not in (80, 443):
        flags.append("odd_port")
    if sp.suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        flags.append("risky_tld")
    if any(host == s or host.endswith("." + s) for s in FREE_HOSTING_SUFFIXES):
        flags.append("free_hosting")
    if scheme == "http":
        flags.append("no_tls")

    if link.text and info.domain not in TRACKERS:
        m = _TEXT_DOMAIN.search(link.text.strip())
        if m:
            shown_host = m.group(1).lower()
            explicit = "://" in link.text or link.text.strip().lower().startswith("www.")
            looks_like_domain = has_known_suffix(shown_host) and (explicit or shown_host.rsplit(".", 1)[-1] not in _FILE_LIKE)
            shown = registered_domain(shown_host) if looks_like_domain else ""
            if shown and shown != info.domain:
                flags.append("text_mismatch")
    return info


def analyze_links(links: list[Link]) -> list[UrlInfo]:
    seen: dict[str, UrlInfo] = {}
    for link in links:
        info = analyze_url(link)
        if info is None:
            continue
        existing = seen.get(info.url)
        if existing is None:
            seen[info.url] = info
        elif "text_mismatch" in info.flags and "text_mismatch" not in existing.flags:
            seen[info.url] = info  # keep the copy that carries the anchor text evidence
    return list(seen.values())
