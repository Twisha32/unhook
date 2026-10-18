import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache

import tldextract

# Offline on purpose: the bundled public suffix snapshot is plenty, and the analyser
# should never make a network request just to split a hostname.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)

# Reserved by RFC 2606/6761. Test fixtures and docs use these so nothing we ship can
# ever point at a real site.
RESERVED_TLDS = {"example", "test", "invalid", "localhost", "local"}


@dataclass(frozen=True)
class HostParts:
    subdomain: str
    label: str  # the registrable label, e.g. "paypal" in login.paypal.com
    suffix: str

    @property
    def registered(self) -> str:
        if not self.label:
            return ""
        return f"{self.label}.{self.suffix}" if self.suffix else self.label


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


@lru_cache(maxsize=4096)
def split_host(host: str) -> HostParts:
    host = host.strip().strip(".").lower()
    if not host or is_ip(host):
        return HostParts("", host, "")
    labels = host.split(".")
    if labels[-1] in RESERVED_TLDS:
        if len(labels) == 1:
            return HostParts("", labels[0], "")
        return HostParts(".".join(labels[:-2]), labels[-2], labels[-1])
    ext = _extract(host)
    if not ext.suffix:
        # Unknown TLD: treat the last label as the suffix so we still get a label to compare.
        if len(labels) == 1:
            return HostParts("", labels[0], "")
        return HostParts(".".join(labels[:-2]), labels[-2], labels[-1])
    return HostParts(ext.subdomain, ext.domain, ext.suffix)


def has_known_suffix(host: str) -> bool:
    host = host.strip().strip(".").lower()
    if not host or is_ip(host):
        return False
    if host.rsplit(".", 1)[-1] in RESERVED_TLDS:
        return True
    return bool(_extract(host).suffix)


def registered_domain(host: str) -> str:
    return split_host(host).registered


def to_unicode(host: str) -> str:
    """Decode xn-- labels so homoglyph checks see what the victim sees."""
    out = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        out.append(label)
    return ".".join(out)


def defang(value: str) -> str:
    """Make a URL or domain inert in text: hxxps://evil[.]example/path."""
    value = value.replace("http://", "hxxp://").replace("https://", "hxxps://")
    value = value.replace("ftp://", "fxp://")
    head, sep, tail = value.partition("/")
    # Only the scheme-less host portion (or host after ://) gets dots replaced.
    if value.startswith(("hxxp://", "hxxps://", "fxp://")):
        scheme, _, rest = value.partition("://")
        host, slash, path = rest.partition("/")
        return f"{scheme}://{host.replace('.', '[.]')}{slash}{path}"
    return head.replace(".", "[.]") + sep + tail


# File names that happen to look like domains (budget.xlsx, setup.zip) stay readable.
FILE_LIKE_TLDS = {"zip", "mov", "py", "sh", "pl", "md", "ps", "rs", "pdf", "doc", "docx", "xls", "xlsx", "ppt",
                  "pptx", "txt", "csv", "png", "jpg", "jpeg", "gif", "exe", "js", "html", "htm", "json", "xml"}
# Labels may be non-ASCII (internationalised names), so lookalike hosts get defanged too.
_DOTTED = re.compile(r"(?<![\w.\[@/-])((?:[\w-]+\.)+[a-z]{2,24})(?![\w\]])", re.I)


def defang_text(text: str) -> str:
    """Defang every hostname in a sentence, leaving file names alone."""

    def fix(m: re.Match) -> str:
        host = m.group(1)
        if host.rsplit(".", 1)[-1].lower() in FILE_LIKE_TLDS or not has_known_suffix(host):
            return host
        return host.replace(".", "[.]")

    return _DOTTED.sub(fix, text)
