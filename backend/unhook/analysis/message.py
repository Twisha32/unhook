import email
import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.utils import parseaddr

from bs4 import BeautifulSoup

MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024

_URL_IN_TEXT = re.compile(r"""(?:https?://|www\.)[^\s<>"'\[\]{}|\\^`]+""", re.I)
_HIDDEN_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(?:px|pt|em|%)?\s*(?:;|$|!)"
    r"|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$|!)|max-height\s*:\s*0|mso-hide\s*:\s*all",
    re.I,
)
_FORWARD_MARKERS = re.compile(
    r"-{2,}\s*forwarded message\s*-{2,}|-{2,}\s*original message\s*-{2,}|begin forwarded message", re.I
)


@dataclass
class Address:
    display: str = ""
    address: str = ""

    @property
    def domain(self) -> str:
        return self.address.rsplit("@", 1)[1].lower() if "@" in self.address else ""


@dataclass
class Link:
    href: str
    text: str = ""
    source: str = "html"  # html | form | text | macro


@dataclass
class Form:
    action: str
    has_password: bool
    input_types: list[str] = field(default_factory=list)


@dataclass
class Attachment:
    filename: str
    declared_type: str
    data: bytes = field(repr=False)

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def md5(self) -> str:
        return hashlib.md5(self.data, usedforsecurity=False).hexdigest()


@dataclass
class ParsedMessage:
    raw_sha256: str
    size: int
    subject: str
    sender: Address
    reply_to: Address | None
    return_path: Address | None
    to: list[Address]
    message_id: str
    in_reply_to: str
    date: str
    headers: dict[str, list[str]]
    text: str
    html: str
    visible_text: str
    links: list[Link]
    forms: list[Form]
    attachments: list[Attachment]
    hidden_chars: int
    image_count: int
    inline_forward: bool
    notes: list[str] = field(default_factory=list)

    @property
    def received_hops(self) -> int:
        return len(self.headers.get("received", []))


def _addr(value) -> Address | None:
    if not value:
        return None
    display, address = parseaddr(str(value))
    return Address(display.strip(), address.strip().lower())


def _body_text(part) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError, AssertionError, KeyError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _inner_bytes(part) -> bytes | None:
    """Bytes of a message carried inside another one, however the client attached it."""
    payload = part.get_payload()
    if isinstance(payload, list) and payload:
        return payload[0].as_bytes()  # nested message the parser already understood
    return part.get_payload(decode=True) or None  # base64'd .eml attachments


def _clean_url(url: str) -> str:
    return url.rstrip(".,;:!?)>]}'\"")


def _soup(html: str) -> BeautifulSoup:
    try:
        return BeautifulSoup(html, "lxml")
    except Exception:
        return BeautifulSoup(html, "html.parser")


def _read_html(html: str):
    """Returns (visible_text, links, forms, hidden_chars, image_count)."""
    soup = _soup(html)
    for tag in soup(["script", "style", "head", "title"]):
        tag.decompose()

    hidden = [el for el in soup.find_all(style=_HIDDEN_STYLE)]
    hidden_ids = {id(el) for el in hidden}
    hidden_chars = 0
    for el in hidden:
        if any(id(p) in hidden_ids for p in el.parents):
            continue  # already counted through its hidden ancestor
        hidden_chars += len(el.get_text(strip=True))

    links: list[Link] = []
    forms: list[Form] = []
    for a in soup.find_all(["a", "area"], href=True):
        text = a.get_text(" ", strip=True)
        if not text:
            img = a.find("img")
            text = (img.get("alt") or "").strip() if img else ""
        links.append(Link(a["href"].strip(), text, "html"))
    for f in soup.find_all("form"):
        types = [(i.get("type") or "text").lower() for i in f.find_all("input")]
        forms.append(Form((f.get("action") or "").strip(), "password" in types, types))
        if f.get("action"):
            links.append(Link(f["action"].strip(), "", "form"))
    for fr in soup.find_all("iframe", src=True):
        links.append(Link(fr["src"].strip(), "", "html"))
    if not forms and soup.find("input", {"type": re.compile("^password$", re.I)}):
        forms.append(Form("", True, ["password"]))

    images = len(soup.find_all("img"))
    for el in hidden:
        el.decompose()
    visible = re.sub(r"[ \t\r\f\v]+", " ", soup.get_text("\n"))
    visible = re.sub(r"\n\s*\n+", "\n", visible).strip()
    return visible, links, forms, hidden_chars, images


def parse(raw: bytes) -> ParsedMessage:
    msg = email.message_from_bytes(raw, policy=policy.default)
    notes: list[str] = []

    headers: dict[str, list[str]] = {}
    try:
        for key, value in msg.items():
            headers.setdefault(key.lower(), []).append(str(value))
    except Exception as exc:  # truly mangled headers; keep whatever we got
        notes.append(f"header parse stopped early: {exc.__class__.__name__}")

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []
    inline_images = 0

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        filename = part.get_filename() or ""
        disposition = part.get_content_disposition()
        is_attachment = bool(filename) or disposition == "attachment"

        if ctype == "message/rfc822":
            attachments.append(Attachment(filename or "forwarded-message.eml", ctype, _inner_bytes(part) or b""))
        elif is_attachment:
            data = part.get_payload(decode=True) or b""
            if len(data) > MAX_ATTACHMENT_BYTES:
                notes.append(f"attachment {filename!r} truncated at {MAX_ATTACHMENT_BYTES} bytes")
                data = data[:MAX_ATTACHMENT_BYTES]
            attachments.append(Attachment(re.sub(r"[\\/]", "_", filename) or "unnamed", ctype, data))
        elif ctype == "text/plain":
            text_parts.append(_body_text(part))
        elif ctype == "text/html":
            html_parts.append(_body_text(part))
        elif ctype.startswith("image/"):
            inline_images += 1
        elif not ctype.startswith("multipart/"):
            data = part.get_payload(decode=True) or b""
            attachments.append(Attachment(filename or "unnamed", ctype, data))

    text = "\n".join(text_parts)
    html = "\n".join(html_parts)

    links: list[Link] = []
    forms: list[Form] = []
    hidden_chars = 0
    image_count = inline_images
    visible = text
    if html:
        visible, html_links, forms, hidden_chars, imgs = _read_html(html)
        links.extend(html_links)
        image_count += imgs
        if text.strip() and len(text) > len(visible):
            visible = text

    seen = {link.href for link in links}
    for blob in (text, visible):
        for found in _URL_IN_TEXT.findall(blob):
            url = _clean_url(found)
            if url.lower().startswith("www."):
                url = "http://" + url
            if url not in seen:
                seen.add(url)
                links.append(Link(url, "", "text"))

    reply_to = _addr(msg.get("reply-to"))
    return_path = _addr(msg.get("return-path"))
    to = [a for a in (_addr(v) for v in str(msg.get("to", "")).split(",")) if a and a.address]

    inline_forward = bool(_FORWARD_MARKERS.search(text[:4000] or visible[:4000]))

    return ParsedMessage(
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
        subject=str(msg.get("subject", "") or "").strip(),
        sender=_addr(msg.get("from")) or Address(),
        reply_to=reply_to if reply_to and reply_to.address else None,
        return_path=return_path if return_path and return_path.address else None,
        to=to,
        message_id=str(msg.get("message-id", "") or "").strip(),
        in_reply_to=str(msg.get("in-reply-to", "") or "").strip(),
        date=str(msg.get("date", "") or "").strip(),
        headers=headers,
        text=text,
        html=html,
        visible_text=visible,
        links=links,
        forms=forms,
        attachments=attachments,
        hidden_chars=hidden_chars,
        image_count=image_count,
        inline_forward=inline_forward,
        notes=notes,
    )


def unwrap_report(raw: bytes, org_domains: list[str] | None = None) -> tuple[bytes, str, bool]:
    """Staff forward suspicious mail. Pull the original out of the forward.

    Returns (original_bytes, reporter_address, was_unwrapped). When the report is a
    forward-as-attachment we get the original headers back intact, which is what the
    authentication checks need. Inline forwards can't be unwrapped reliably, so the
    caller treats header-based findings on those with suspicion.
    """
    outer = email.message_from_bytes(raw, policy=policy.default)
    reporter = parseaddr(str(outer.get("from", "")))[1].lower()
    rfc822 = [p for p in outer.walk()
              if p.get_content_type() == "message/rfc822" or (p.get_filename() or "").lower().endswith(".eml")]
    if not rfc822:
        return raw, reporter, False

    reporter_domain = reporter.rsplit("@", 1)[-1]
    from_staff = bool(org_domains) and reporter_domain in {d.lower() for d in org_domains}
    only_attachment = len(rfc822) == 1 and len(list(outer.iter_attachments())) == 1
    if not (from_staff or only_attachment):
        return raw, reporter, False

    inner = _inner_bytes(rfc822[0])
    if not inner:
        return raw, reporter, False
    return inner, reporter, True
