import re
from dataclasses import dataclass, field

from .hostutil import registered_domain

_COMMENT = re.compile(r"\([^)]*\)")
_RESULT = re.compile(r"^(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)
_PROP = re.compile(r"([a-z]+\.[a-z\-]+)\s*=\s*([^\s;]+)", re.I)
_POLICY = re.compile(r"\bp\s*=\s*(none|quarantine|reject)", re.I)


@dataclass
class AuthResult:
    present: bool = False
    authserv: str = ""
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    dmarc_policy: str = ""
    spf_domain: str = ""
    dkim_domains: list[str] = field(default_factory=list)
    spf_aligned: bool | None = None
    dkim_aligned: bool | None = None

    @property
    def failed(self) -> list[str]:
        bad = {"fail", "softfail", "permerror"}
        return [name for name in ("spf", "dkim", "dmarc") if getattr(self, name) in bad]


def _rank(current: str, new: str) -> str:
    # With several DKIM signatures one pass is enough; otherwise keep the worst result.
    if current == "none":
        return new
    if "pass" in (current, new):
        return "pass"
    return new if new in {"fail", "permerror"} else current


def _parse_header(value: str, result: AuthResult) -> None:
    raw_policy = _POLICY.search(value)
    cleaned = _COMMENT.sub(" ", value)
    parts = [p.strip() for p in cleaned.split(";") if p.strip()]
    if not parts:
        return
    result.present = True
    result.authserv = parts[0].split()[0]
    for part in parts[1:]:
        m = _RESULT.match(part)
        if not m:
            continue
        method, verdict = m.group(1).lower(), m.group(2).lower()
        props = {k.lower(): v for k, v in _PROP.findall(part)}
        if method == "spf":
            result.spf = verdict
            mailfrom = props.get("smtp.mailfrom", "")
            result.spf_domain = mailfrom.rsplit("@", 1)[-1].lower().strip("<>")
        elif method == "dkim":
            result.dkim = _rank(result.dkim, verdict)
            if "header.d" in props:
                result.dkim_domains.append(props["header.d"].lower())
        elif method == "dmarc":
            result.dmarc = verdict
            if raw_policy:
                result.dmarc_policy = raw_policy.group(1).lower()


def read_auth(headers: dict[str, list[str]], from_domain: str, trusted_servers: list[str] | None = None) -> AuthResult:
    """Read the receiving server's verdict, not whatever the sender claims.

    Anyone can stuff a fake Authentication-Results header into a message, but the
    receiving MTA prepends its own, so the top-most one is the one to believe. When
    the organisation tells us its authserv-ids we insist on one of those.
    """
    result = AuthResult()
    candidates = headers.get("authentication-results", [])
    if trusted_servers:
        wanted = {s.lower() for s in trusted_servers}
        candidates = [c for c in candidates if c.split(";")[0].strip().split(" ")[0].lower() in wanted]
    if candidates:
        _parse_header(candidates[0], result)

    if result.spf == "none" and headers.get("received-spf"):
        first_word = headers["received-spf"][0].strip().split(" ")[0].lower()
        if first_word in {"pass", "fail", "softfail", "neutral", "none", "permerror", "temperror"}:
            result.spf = first_word
            result.present = True

    if from_domain:
        want = registered_domain(from_domain)
        if result.spf_domain:
            result.spf_aligned = registered_domain(result.spf_domain) == want
        if result.dkim_domains:
            result.dkim_aligned = any(registered_domain(d) == want for d in result.dkim_domains)
    return result
