"""The rule set.

Each rule is a small function with a fixed confidence: roughly "how often is a
message that trips this actually phishing", written down as a number we can argue
about. Rules are grouped, because signals inside a group tend to travel together (a
message failing SPF usually fails DKIM too). Within a group we take the strongest
rule; across groups we combine them as independent evidence.

Adding a rule means adding a function here and a positive and a negative case in
tests/test_rules.py. A meta-test fails the build if either is missing.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from .attachments import AttachmentReport
from .authres import AuthResult
from .brands import BRANDS
from .hostutil import defang as d
from .hostutil import defang_text, registered_domain
from .identity import IdentityReport, brand_owns
from .intel import IntelHit
from .lookalike import Lookalike
from .message import ParsedMessage
from .text import TextSignals
from .trace import Trace
from .urls import UrlInfo

GROUPS = ("auth", "identity", "domain", "url", "attachment", "content", "intel")


@dataclass
class Ctx:
    msg: ParsedMessage
    auth: AuthResult
    ident: IdentityReport
    urls: list[UrlInfo]
    atts: list[AttachmentReport]
    text: TextSignals
    sender_lookalike: Lookalike | None = None
    link_lookalikes: list[Lookalike] = field(default_factory=list)
    mixed_script_hosts: list[str] = field(default_factory=list)
    intel: list[IntelHit] = field(default_factory=list)
    ages: dict[str, int | None] = field(default_factory=dict)
    traces: dict[str, Trace] = field(default_factory=dict)
    org_domains: list[str] = field(default_factory=list)

    @property
    def has_payload(self) -> bool:
        # A QR code image is a payload too, even though there's no URL in the text.
        return bool(self.urls or self.atts or (self.text.qr_lure and self.msg.image_count))


@dataclass
class Hit:
    evidence: list[str]
    confidence: float | None = None


@dataclass
class Rule:
    id: str
    title: str
    group: str
    confidence: float
    attack: tuple[str, ...]
    lesson: str
    fn: Callable[[Ctx], "list[str] | Hit | None"]


@dataclass
class Finding:
    rule_id: str
    title: str
    group: str
    confidence: float
    evidence: list[str]
    attack: list[str]
    lesson: str

    @property
    def detail(self) -> str:
        return self.evidence[0] if self.evidence else ""


RULES: list[Rule] = []


def rule(id: str, title: str, group: str, confidence: float, attack: tuple[str, ...] = (), lesson: str = ""):
    assert group in GROUPS, group

    def register(fn):
        RULES.append(Rule(id, title, group, confidence, attack, lesson, fn))
        return fn

    return register


def _links_of(c: Ctx, flag: str) -> list[UrlInfo]:
    return [u for u in c.urls if flag in u.flags]


# --- authentication ---------------------------------------------------------

@rule("AUTH_DMARC_FAIL", "Sender failed DMARC", "auth", 0.45, ("T1566",),
      "A failed sender check means the message may be forged. If it claims to be from someone you know, confirm with them another way.")
def _dmarc_fail(c: Ctx):
    if c.msg.inline_forward or c.auth.dmarc != "fail":
        return None
    policy = f" (domain policy: {c.auth.dmarc_policy})" if c.auth.dmarc_policy else ""
    return [f"DMARC failed for {d(c.ident.sender_domain)}{policy}"]


@rule("AUTH_SPF_DKIM_FAIL", "SPF or DKIM check failed", "auth", 0.22, ("T1566",),
      "Real mail from a company is signed. Failed signatures are one more reason to slow down.")
def _spf_dkim_fail(c: Ctx):
    if c.msg.inline_forward:
        return None
    bad = [name.upper() for name in ("spf", "dkim") if getattr(c.auth, name) in {"fail", "softfail", "permerror"}]
    if not bad:
        return None
    return [f"{' and '.join(bad)} did not pass for {d(c.ident.sender_domain)}"]


# --- identity ---------------------------------------------------------------

@rule("ID_REPLY_TO_MISMATCH", "Replies go to a different domain", "identity", 0.30, ("T1566", "T1656"),
      "Look at where a reply would actually land. If it isn't the sender's own domain, the person writing may not be who they say.")
def _reply_to(c: Ctx):
    i = c.ident
    if c.msg.inline_forward or not i.reply_to_mismatch:
        return None
    ev = f"From {d(i.sender_domain)} but replies go to {d(i.reply_to_domain)}"
    if i.reply_to_freemail and not i.sender_freemail:
        return Hit([ev + " (a free mailbox)"], 0.50)
    return [ev]


@rule("ID_DISPLAY_EMAIL_SPOOF", "Display name contains a different address", "identity", 0.55, ("T1656",),
      "A name in quotes can say anything. The address behind it is the part that counts.")
def _display_spoof(c: Ctx):
    if c.msg.inline_forward or not c.ident.display_email_spoof:
        return None
    return [f"Display name shows {d(c.ident.display_email_spoof)} but the message was sent from {d(c.msg.sender.address)}"]


@rule("ID_DISPLAY_BRAND", "Display name poses as a brand", "identity", 0.45, ("T1656",),
      "The name on a message is free text. Check the address, not just who it says it is.")
def _display_brand(c: Ctx):
    if c.msg.inline_forward or not c.ident.display_brand:
        return None
    return [f"Display name \"{c.msg.sender.display}\" claims {c.ident.display_brand}, sent from {d(c.ident.sender_domain)}"]


@rule("ID_PROTECTED_NAME", "Display name matches a protected person", "identity", 0.75, ("T1656",),
      "Leaders get impersonated constantly. An odd request from the boss's name deserves a phone call, not a reply.")
def _protected_name(c: Ctx):
    if c.msg.inline_forward or not c.ident.protected_name:
        return None
    return [f"Display name matches {c.ident.protected_name}, sent from external domain {d(c.ident.sender_domain)}"]


@rule("ID_FREEMAIL_ROLE", "Free mailbox using an authority title", "identity", 0.35, ("T1656",),
      "IT, payroll and HR don't write from free mailboxes. A title in the name proves nothing.")
def _freemail_role(c: Ctx):
    if c.msg.inline_forward or not c.ident.freemail_role:
        return None
    return [f"\"{c.msg.sender.display}\" writes from {d(c.ident.sender_domain)} while using the title '{c.ident.freemail_role}'"]


@rule("ID_BRAND_NO_INFRA", "Talks as a brand, links nowhere near it", "identity", 0.40, ("T1656", "T1598.003"),
      "When a message says it's from a well-known company, go to that company's site yourself instead of using the link.")
def _brand_claim(c: Ctx):
    if not c.ident.brand_claims or not c.has_payload:
        return None
    names = ", ".join(c.ident.brand_claims[:3])
    return [f"Opens as {names} but neither the sender nor any link uses a domain that belongs to it"]


@rule("ID_FAKE_REPLY", "Fake reply thread", "identity", 0.20, ("T1566",),
      "A subject starting with 'RE:' makes a cold message look like a conversation you've already had. Check for the thread.")
def _fake_reply(c: Ctx):
    if not c.text.fake_reply or not (c.text.credentials or c.text.payment or c.has_payload):
        return None
    return [f"Subject \"{c.msg.subject[:80]}\" starts like a reply, but the message has no thread headers"]


# --- domains ----------------------------------------------------------------

@rule("DOM_LOOKALIKE_SENDER", "Sender domain imitates a known domain", "domain", 0.65, ("T1583.001", "T1656"),
      "Read the domain letter by letter. Attackers register names that look right at a glance.")
def _lookalike_sender(c: Ctx):
    if c.msg.inline_forward or not c.sender_lookalike:
        return None
    lk = c.sender_lookalike
    return [f"Sender domain {d(lk.host)} {lk.detail} (imitating {lk.brand})"]


@rule("DOM_LOOKALIKE_LINK", "A link points at a lookalike domain", "domain", 0.70, ("T1583.001", "T1204.001"),
      "Hover before you click. The link's domain, not its text, tells you where you'll land.")
def _lookalike_link(c: Ctx):
    if not c.link_lookalikes:
        return None
    return [f"Link to {d(lk.host)} {lk.detail} (imitating {lk.brand})" for lk in c.link_lookalikes[:4]]


@rule("DOM_MIXED_SCRIPT", "Domain mixes alphabets", "domain", 0.80, ("T1583.001", "T1656"),
      "Some letters in other alphabets are identical to English ones. That 'a' might not be an 'a'.")
def _mixed_script(c: Ctx):
    if not c.mixed_script_hosts:
        return None
    return [f"{d(h)} mixes letters from different alphabets" for h in c.mixed_script_hosts[:3]]


@rule("DOM_PUNYCODE", "Internationalised domain name", "domain", 0.25, ("T1583.001",),
      "Domains starting with 'xn--' hide non-English letters. Be wary when one shows up in a message about your account.")
def _punycode(c: Ctx):
    hosts = [u.host for u in _links_of(c, "punycode")]
    if "xn--" in c.ident.sender_domain:
        hosts.append(c.ident.sender_domain)
    return [f"{d(h)} is an internationalised (xn--) domain" for h in dict.fromkeys(hosts)][:3] or None


@rule("DOM_YOUNG", "Domain was registered very recently", "domain", 0.30, ("T1583.001",),
      "Legitimate services have been around a while. A domain registered last week asking for a login is a red flag.")
def _young(c: Ctx):
    young = sorted((age, dom) for dom, age in c.ages.items() if age is not None and age <= 90)
    if not young:
        return None
    age, dom = young[0]
    note = f"{d(dom)} was registered {age} day{'s' if age != 1 else ''} ago"
    return Hit([note], 0.45 if age <= 30 else 0.25)


# --- urls -------------------------------------------------------------------

@rule("URL_IP_HOST", "Link goes to a raw IP address", "url", 0.45, ("T1204.001",),
      "Real companies use names, not numbers. A link to an IP address is almost never legitimate.")
def _ip_host(c: Ctx):
    links = _links_of(c, "ip_host")
    return [f"Link to IP address {d(u.host)}" for u in links[:3]] or None


@rule("URL_TEXT_MISMATCH", "Link text shows one site, link goes to another", "url", 0.50, ("T1204.001", "T1566.002"),
      "What a link says and where it goes can differ. Hover to see the real destination before clicking.")
def _text_mismatch(c: Ctx):
    links = _links_of(c, "text_mismatch")
    return [f"Link reads \"{u.text[:60]}\" but goes to {d(u.host)}" for u in links[:3]] or None


@rule("URL_USERINFO", "Link hides its real host behind a login prefix", "url", 0.55, ("T1204.001",),
      "In 'paypal.com@other.example' everything before the @ is decoration. The site is what comes after.")
def _userinfo(c: Ctx):
    links = _links_of(c, "userinfo")
    return [f"Link {d(u.url[:90])} has credentials-style text before the real host" for u in links[:2]] or None


@rule("URL_SHORTENER", "Link is shortened", "url", 0.18, ("T1204.001",),
      "Short links hide where they lead. If you weren't expecting one, don't open it.")
def _shortener(c: Ctx):
    links = _links_of(c, "shortener")
    return [f"Shortened link via {d(u.domain)} could not be resolved without visiting it" for u in links[:2]] or None


@rule("URL_RISKY_TLD", "Link uses a high-abuse top-level domain", "url", 0.15, ("T1204.001",),
      "Some endings (.zip, .top, .click and friends) are cheap and heavily abused.")
def _risky_tld(c: Ctx):
    links = _links_of(c, "risky_tld")
    return [f"{d(u.host)} ends in a high-abuse TLD" for u in links[:3]] or None


@rule("URL_FREE_HOSTING", "Link is on throwaway hosting", "url", 0.15, ("T1204.001",),
      "Free site builders are quick for attackers to spin up. A 'login' page on one is suspect.")
def _free_hosting(c: Ctx):
    links = _links_of(c, "free_hosting")
    if not links or not (c.text.credentials or c.text.urgency or c.text.payment):
        return None
    return [f"{d(u.host)} is free hosting, used in a message that asks for action" for u in links[:2]]


@rule("URL_SCRIPT_SCHEME", "Link runs script or embeds data", "url", 0.40, ("T1204.001",),
      "Links that start with javascript: or data: don't take you to a website. They run code.")
def _script_scheme(c: Ctx):
    links = [u for u in c.urls if "javascript_scheme" in u.flags or "data_scheme" in u.flags]
    return [f"Link uses a {'javascript' if 'javascript_scheme' in u.flags else 'data'}: scheme" for u in links[:2]] or None


@rule("URL_LONG_CHAIN", "Link bounces through several sites", "url", 0.35, ("T1204.001", "T1566.002"),
      "Several redirects before the page appears is a way of laundering a bad link.")
def _long_chain(c: Ctx):
    out = []
    for t in c.traces.values():
        hosts = t.distinct_hosts
        if len(t.hops) >= 3 and len(hosts) >= 3:
            out.append(f"{d(t.start_url[:70])} redirects through {len(t.hops)} hops across {len(hosts)} hosts, landing on {d(t.final_host)}")
    return out or None


@rule("URL_LANDING_LOGIN_FORM", "Link lands on a password form", "url", 0.65, ("T1598.003", "T1204.001"),
      "A page that wants your password after you followed an email link should be treated as a trap. Go to the site directly.")
def _landing_form(c: Ctx):
    out = []
    for t in c.traces.values():
        if t.password_form and t.final_host:
            dom = registered_domain(t.final_host)
            if dom not in {registered_domain(o) for o in c.org_domains} and not any(dom in b.domains for b in BRANDS):
                out.append(f"{d(t.final_host)} serves a password form after {len(t.hops)} hop(s)")
    return out or None


@rule("URL_LANDING_BRAND_MISMATCH", "Landing page uses a brand it doesn't own", "url", 0.60, ("T1598.003", "T1656"),
      "A page can copy a company's look exactly. The address bar is the one thing it can't fake.")
def _landing_brand(c: Ctx):
    out = []
    for t in c.traces.values():
        blob = f"{t.title} {t.text_excerpt[:400]}".lower()
        for brand in BRANDS:
            if any(len(k) > 3 and k in blob for k in brand.keywords) and not brand_owns(brand, t.final_host):
                if t.password_form or "sign in" in blob or "log in" in blob:
                    out.append(f"Landing page at {d(t.final_host)} presents itself as {brand.name}")
                    break
    return out or None


# --- attachments ------------------------------------------------------------

def _att(c: Ctx, flag: str) -> list[AttachmentReport]:
    return [a for a in c.atts if flag in a.flags]


@rule("ATT_DANGEROUS_EXT", "Attachment can run code", "attachment", 0.65, ("T1566.001", "T1204.002"),
      "Files like .exe, .js, .iso or .lnk run programs. Real colleagues don't send those.")
def _dangerous(c: Ctx):
    return [f"{a.filename} ({a.size} bytes) has an executable extension (.{a.extension})" for a in _att(c, "dangerous_extension")] or None


@rule("ATT_DOUBLE_EXT", "Attachment hides its real extension", "attachment", 0.90, ("T1566.001", "T1036.007"),
      "'invoice.pdf.exe' is a program wearing a PDF's name. Turn on file extensions and read to the end.")
def _double_ext(c: Ctx):
    return [f"{a.filename} has a document-style name over a .{a.extension} file" for a in _att(c, "double_extension")] or None


@rule("ATT_DISGUISED_EXE", "Attachment is a program disguised as something else", "attachment", 0.92, ("T1566.001", "T1036.008"),
      "The file's contents didn't match its name. That mismatch is deliberate.")
def _disguised(c: Ctx):
    return [f"{a.filename} is named like a .{a.extension} file but its contents are a {a.sniffed.upper()} executable" for a in _att(c, "disguised_executable")] or None


@rule("ATT_TYPE_MISMATCH", "Attachment type doesn't match its name", "attachment", 0.55, ("T1566.001", "T1036.008"),
      "A file whose contents don't match its extension is trying to get past a filter or past you.")
def _type_mismatch(c: Ctx):
    return [f"{a.filename} is named .{a.extension} but looks like {a.sniffed} (expected {'/'.join(a.detail.get('expected', []))})" for a in _att(c, "type_mismatch")] or None


@rule("ATT_MACRO_AUTOEXEC", "Office file with a macro that runs on open", "attachment", 0.88, ("T1566.001", "T1204.002", "T1059.005"),
      "Never click 'Enable content' on a file you didn't expect. That button is how macro malware starts.")
def _macro_auto(c: Ctx):
    out = []
    for a in _att(c, "macro_autoexec"):
        m = a.macros
        susp = f", suspicious keywords: {', '.join(m.suspicious[:4])}" if m and m.suspicious else ""
        out.append(f"{a.filename} contains VBA that runs automatically ({', '.join(m.autoexec[:3]) if m else ''}){susp}")
    return out or None


@rule("ATT_MACRO", "Office file contains macros", "attachment", 0.50, ("T1566.001", "T1059.005"),
      "Documents that carry macros are rarely needed for ordinary business. Ask before opening.")
def _macro(c: Ctx):
    return [f"{a.filename} contains VBA macros" for a in _att(c, "macro")] or None


@rule("ATT_ACTIVE_HTML", "HTML attachment", "attachment", 0.50, ("T1566.001", "T1598.003"),
      "An HTML attachment is a web page that opens from your own computer. It's a common way to fake a login screen.")
def _active_html(c: Ctx):
    return [f"{a.filename} is an HTML/SVG file that opens as a local web page" for a in _att(c, "active_html") if "dangerous_extension" not in a.flags] or None


@rule("ATT_PDF_ACTIVE", "PDF with active content", "attachment", 0.45, ("T1566.001", "T1204.002"),
      "A PDF should just be a document. One that launches things or runs scripts isn't.")
def _pdf_active(c: Ctx):
    return [f"{a.filename} contains {', '.join(a.detail.get('pdf_markers', []))}" for a in _att(c, "pdf_active")] or None


@rule("ATT_ENCRYPTED_ARCHIVE", "Password-protected archive", "attachment", 0.40, ("T1566.001", "T1027"),
      "Password-protected zips are a way to slip past scanners. A password sent in the same email is no protection at all.")
def _encrypted(c: Ctx):
    found = _att(c, "encrypted_archive")
    if not found:
        return None
    evidence = [f"{a.filename} is an encrypted archive" for a in found]
    if re.search(r"password\s*(?:is|:)", c.msg.visible_text, re.I):
        # The password travels with the file, so the encryption only keeps scanners out.
        return Hit(evidence + ["The message body supplies the password"], 0.55)
    return evidence


# --- content ----------------------------------------------------------------

@rule("TXT_CREDENTIAL_URGENCY", "Asks you to sign in, and fast", "content", 0.38, ("T1566.002", "T1598.003"),
      "Pressure plus a login request is the classic pairing. Pause, then go to the site on your own.")
def _cred_urgency(c: Ctx):
    t = c.text
    if t.credentials and (t.urgency or t.threat) and c.has_payload:
        phrases = (t.credentials[:2] + (t.urgency or t.threat)[:2])
        return ["Wording asks for credentials under pressure: " + "; ".join(f"\"{p}\"" for p in phrases)]
    return None


@rule("TXT_PAYMENT_PRESSURE", "Money request with warning signs", "content", 0.35, ("T1566", "T1656"),
      "Requests to move money or change bank details need a second channel. Call the person on a number you already have.")
def _payment(c: Ctx):
    t = c.text
    if t.payment and (t.urgency or c.ident.reply_to_mismatch or c.ident.sender_freemail):
        why = "urgent wording" if t.urgency else ("a different reply address" if c.ident.reply_to_mismatch else "a free mailbox sender")
        evidence = [f"Money-related wording (\"{t.payment[0]}\") combined with {why}"]
        # Gift cards and wire transfers are what business-email-compromise actually asks for.
        if any(k in " ".join(t.payment) for k in ("gift card", "wire transfer")):
            return Hit(evidence, 0.55)
        return evidence
    return None


@rule("TXT_HIDDEN_CONTENT", "Large amount of hidden text", "content", 0.28, ("T1027",),
      "Hidden text is there for scanners, not for you. It's a sign the sender is trying to look ordinary.")
def _hidden(c: Ctx):
    if c.msg.hidden_chars >= 300:
        return [f"{c.msg.hidden_chars} characters of text are hidden from the reader"]
    return None


@rule("TXT_QR_LURE", "QR code in a short message", "content", 0.30, ("T1566", "T1204.001"),
      "A QR code hides the link from filters and from you. Only scan codes you expected, and check where they go.")
def _qr(c: Ctx):
    if c.text.qr_lure and len(c.msg.visible_text) < 600:
        evidence = ["Short message pushes a QR code, which hides the destination link"]
        if c.text.credentials or c.text.urgency:
            return Hit(evidence + ["The QR code comes with account or deadline wording"], 0.50)
        return evidence
    return None


@rule("HTML_PASSWORD_FORM", "Password form inside the email", "content", 0.70, ("T1598.003",),
      "Real companies never ask for a password inside an email. If you see a login box here, it's a trap.")
def _password_form(c: Ctx):
    forms = [f for f in c.msg.forms if f.has_password]
    if not forms:
        return None
    where = d(forms[0].action) if forms[0].action else "an unspecified address"
    return [f"The email body contains a password field that submits to {where}"]


@rule("TXT_GENERIC_GREETING", "Generic greeting on an account message", "content", 0.12, ("T1566",),
      "Messages from a service you use usually know your name. 'Dear customer' is a tell.")
def _generic(c: Ctx):
    if c.text.generic_greeting and c.text.credentials:
        return ["Greets a 'valued customer/user' while asking about account access"]
    return None


# --- threat intel -----------------------------------------------------------

@rule("INTEL_URL_LISTED", "Link is on a threat-intelligence list", "intel", 0.97, ("T1566.002", "T1204.001"),
      "This link is already known to be bad. Don't open it.")
def _intel_url(c: Ctx):
    hits = [h for h in c.intel if h.kind in {"url", "host"}]
    return [f"{h.source}: {d(h.indicator)} - {h.detail}" for h in hits[:3]] or None


@rule("INTEL_HASH_KNOWN", "Attachment is known malware", "intel", 0.97, ("T1566.001", "T1204.002"),
      "This file's fingerprint matches known malware. Don't open it.")
def _intel_hash(c: Ctx):
    hits = [h for h in c.intel if h.kind == "hash"]
    return [f"{h.source}: {h.indicator[:16]}... - {h.detail}" for h in hits[:3]] or None


def evaluate(ctx: Ctx) -> list[Finding]:
    findings = []
    for r in RULES:
        out = r.fn(ctx)
        if not out:
            continue
        if isinstance(out, Hit):
            evidence, confidence = out.evidence, out.confidence if out.confidence is not None else r.confidence
        else:
            evidence, confidence = out, r.confidence
        findings.append(Finding(r.id, r.title, r.group, confidence, [defang_text(line) for line in evidence], list(r.attack), r.lesson))
    findings.sort(key=lambda f: f.confidence, reverse=True)
    return findings


def combine(findings: list[Finding]) -> tuple[float, dict[str, float]]:
    """Strongest rule per group, then noisy-OR across groups."""
    by_group: dict[str, float] = {}
    for f in findings:
        by_group[f.group] = max(by_group.get(f.group, 0.0), f.confidence)
    miss = 1.0
    for p in by_group.values():
        miss *= 1.0 - p
    return 1.0 - miss, by_group
