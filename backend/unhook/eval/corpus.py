import mailbox
import random
from collections.abc import Iterator
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path


@dataclass
class Sample:
    id: str
    label: int  # 1 = phishing, 0 = legitimate
    source: str
    raw: bytes


def read_mbox(path: Path, label: int, source: str) -> Iterator[Sample]:
    box = mailbox.mbox(str(path), create=False)
    for key in box.iterkeys():
        try:
            raw = box.get_bytes(key)
        except Exception:
            continue
        if raw.strip():
            yield Sample(f"{path.name}:{key}", label, source, raw)


def read_dir(path: Path, label: int, source: str) -> Iterator[Sample]:
    """One message per file, the layout the SpamAssassin archives unpack to."""
    for file in sorted(Path(path).rglob("*")):
        if file.is_file() and not file.name.startswith(".") and file.name != "cmds":
            raw = file.read_bytes()
            if raw.strip():
                yield Sample(f"{file.parent.name}/{file.name}", label, source, raw)


def read_any(path: Path, label: int, source: str) -> Iterator[Sample]:
    path = Path(path)
    if path.is_dir():
        # A folder of .mbox files, or a folder of single messages.
        mboxes = sorted(path.glob("*.mbox")) + sorted(p for p in path.iterdir() if p.is_file() and p.suffix == "" and p.name.startswith("phishing"))
        if mboxes:
            for m in mboxes:
                yield from read_mbox(m, label, source)
        else:
            yield from read_dir(path, label, source)
    else:
        yield from read_mbox(path, label, source)


# --- synthetic corpus ---------------------------------------------------------
# A plumbing test, not a benchmark. The generator and the rules were written by the
# same person, so scores on this data say the pipeline runs end to end and nothing
# about how it does on real mail. It includes some evasive phishing and some noisy
# legitimate mail so the numbers aren't a perfect 1.000, but the mix is made up.

_BRANDS = ["Microsoft 365", "PayPal", "Apple ID", "DocuSign", "Amazon", "Dropbox", "DHL", "Chase", "Netflix", "Zoom"]
_LURE_WORDS = ["secure", "verify", "support", "account", "login", "alert", "billing", "service"]
_URGENCY = ["within 24 hours", "immediately", "today", "as soon as possible", "before your account is suspended"]
_NAMES = ["Jordan", "Priya", "Marcus", "Elena", "Sam", "Noor", "Tyler", "Mei", "Andre", "Hannah"]
_ORGS = [f"{w}.example" for w in ("ridgeline", "cedarbrook", "harborview", "northgate", "fairmont", "willowcreek", "lakeshore",
                                  "pinecrest", "summit-health", "riverbend", "oakhaven", "brightwater", "stonebridge",
                                  "meadowlark", "clearfield", "eastport", "highland", "maplewood", "juniper", "kestrel",
                                  "foxglove", "granite", "hollow-oak", "ironwood", "larkspur", "mosaic", "nettle",
                                  "orchard", "plover", "quarry")]
_TOPICS = ["the fall budget", "Thursday's agenda", "the volunteer schedule", "lab safety training", "the grant report",
           "parent night", "the vendor contract", "intake forms", "the clinic roster", "the council packet"]
_FREEMAIL = ["gmail.com", "outlook.com", "yahoo.com", "proton.me"]


def _msg(sender, subject, body, html=None, reply_to=None, auth=None, attach=None):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = sender, "staff@org.example", subject
    m["Date"] = "Mon, 12 Oct 2026 09:14:22 -0500"
    m["Message-ID"] = f"<{random.getrandbits(48):x}@gen.invalid>"
    if reply_to:
        m["Reply-To"] = reply_to
    if auth:
        m["Authentication-Results"] = auth
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    if attach:
        name, data = attach
        m.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return bytes(m)


def _ok(org):
    return f"mx.{org}; spf=pass smtp.mailfrom={org}; dkim=pass header.d={org}; dmarc=pass (p=none) header.from={org}"


def _phish(rng: random.Random) -> bytes:
    brand = rng.choice(_BRANDS)
    word = rng.choice(_LURE_WORDS)
    label = brand.split()[0].lower()
    flavor = rng.choice(["lookalike", "ip", "bec", "attachment", "mismatch", "freehost", "plain", "forms", "plain", "forms"])
    when = rng.choice(_URGENCY)
    ref = rng.randrange(10**6)
    fail = "mx.org.example; spf=fail smtp.mailfrom=x.example; dkim=none; dmarc=fail (p=reject) header.from=x.example"
    auth = fail if rng.random() < 0.35 else None
    if flavor == "lookalike":
        dom = f"{label.replace('l', '1', 1)}-{word}.example"
        link = f"https://{dom}/{word}/{ref}"
        return _msg(f'"{brand} Support" <no-reply@{dom}>', f"Action required: verify your {brand} account",
                    f"Dear customer, we noticed unusual activity on case {ref}. Verify your account {when}: {link}",
                    f'<p>Dear customer,</p><p>Verify your account {when}.</p><a href="{link}">Sign in to {label}.com</a>', auth=auth)
    if flavor == "ip":
        link = f"http://203.0.113.{rng.randrange(1, 250)}/{word}"
        return _msg(f'"{brand}" <alerts@{label}-{word}.example>', f"Your {brand} package could not be delivered",
                    f"Reschedule delivery {when}: {link}", f'<a href="{link}">Track your parcel at {label}.com</a>', auth=auth)
    if flavor == "bec":
        name = rng.choice(_NAMES)
        return _msg(f'"{name} (Director)" <{name.lower()}.{ref % 97}@{rng.choice(_FREEMAIL)}>', "Quick favor",
                    f"Are you available? I need gift cards purchased {when}. I'll reimburse you. Reply to me here.",
                    reply_to=f"{name.lower()}.private{ref % 53}@proton.me")
    if flavor == "attachment":
        ext = rng.choice(["pdf.exe", "doc.js", "xls.scr", "pdf.vbs"])
        return _msg(f'"Accounts" <billing@{label}-{word}.example>', "Invoice overdue", f"Please see the attached invoice and pay {when}.",
                    attach=(f"Invoice_{ref % 10000}.{ext}", b"MZ" + b"\x00" * 64), auth=auth)
    if flavor == "mismatch":
        dom = f"{word}-{label}.example"
        return _msg(f'"{brand}" <service@{dom}>', f"Confirm your {brand} details",
                    f"Please confirm your password {when}.", f'<a href="https://{dom}/c/{ref}">https://www.{label}.com/account</a> to confirm your password {when}.', auth=auth)
    if flavor == "freehost":
        host = rng.choice(["pages.dev", "web.app", "netlify.app", "weebly.com"])
        return _msg(f'"{brand} Team" <team@{label}-{word}.example>', "Shared document waiting",
                    f"A document was shared with you. Sign in to view {when}.", f'<a href="https://{label}{ref % 999}.{host}/view">Open document</a>', auth=auth)
    if flavor == "plain":
        # Evasive: a person-sounding note from a free mailbox with one innocuous-looking link.
        name = rng.choice(_NAMES)
        return _msg(f'"{name}" <{name.lower()}{ref % 89}@{rng.choice(_FREEMAIL)}>', rng.choice(["Document for you", "Following up", "Files from today"]),
                    f"Hi, sharing the file we discussed ({ref}). Open it here: https://{word}{ref % 999}-files.{rng.choice(['com', 'net', 'org'])}/d/{ref}")
    org = rng.choice(_ORGS)  # evasive: compromised legitimate account, link to a shared form
    return _msg(f'"IT Notice" <it@{org}>', "Mailbox re-validation", f"Please re-validate your mailbox {when}: https://docs.google.com/forms/d/e/{ref}x/viewform",
                f'<a href="https://docs.google.com/forms/d/e/{ref}x/viewform">Re-validate mailbox</a>', auth=_ok(org))


def _ham(rng: random.Random) -> bytes:
    name, other, topic = rng.choice(_NAMES), rng.choice(_NAMES), rng.choice(_TOPICS)
    org = rng.choice(_ORGS)
    ref = rng.randrange(10**6)
    flavor = rng.choice(["note", "newsletter", "receipt", "reminder", "thread", "docusign", "marketing", "alert", "note", "thread"])
    ok = _ok(org)
    if flavor == "note":
        return _msg(f'"{name}" <{name.lower()}@{org}>', f"Notes on {topic}", f"Hi {other}, here are my notes on {topic} (ref {ref}). Happy to talk it through tomorrow.", auth=ok)
    if flavor == "newsletter":
        return _msg(f'"Community News" <news@{org}>', f"This week: {topic}", f"Updates on {topic}.\nRead more: https://u123.ct.sendgrid.net/ls/click?upn={ref}",
                    f'<p>Updates on {topic}.</p><a href="https://u123.ct.sendgrid.net/ls/click?upn=1">Read more</a>', auth=ok)
    if flavor == "receipt":
        return _msg('"Amazon.com" <auto-confirm@amazon.com>', f"Your order #{ref} has shipped", "Your package is on the way. Track it in your account.",
                    '<p>Your package is on the way.</p><a href="https://www.amazon.com/progress-tracker/1">Track package</a>', auth="mx.org.example; spf=pass smtp.mailfrom=amazon.com; dkim=pass header.d=amazon.com; dmarc=pass (p=quarantine) header.from=amazon.com")
    if flavor == "reminder":
        return _msg(f'"{name}" <{name.lower()}@{org}>', f"Reminder: {topic} due Friday",
                    f"Quick reminder (#{ref}) that {topic} is due by Friday at 5pm. Please confirm if you will miss the deadline.", auth=ok)
    if flavor == "thread":
        return _msg(f'"{name}" <{name.lower()}@{org}>', f"Re: {topic}", f"Thanks {other}, agreed ({ref}). I'll add it to the shared drive.", auth=ok)
    if flavor == "marketing":
        # Noisy but legitimate: urgency, a shortened link and a different reply address.
        return _msg(f'"{org.split(".")[0].title()} Offers" <offers@{org}>', "Last chance: registration ends today!",
                    f"Registration closes today. Sign in to your account to save your spot (offer {ref}): https://bit.ly/{ref:x}",
                    reply_to=f"replies@mailer-{org}", auth=ok)
    if flavor == "alert":
        return _msg('"Google" <no-reply@accounts.google.com>', "Security alert", f"Your account was just signed in to from a new device. If this was you, no action is needed (ref {ref}). Review activity within 24 hours: https://myaccount.google.com/notifications",
                    auth="mx.org.example; spf=pass smtp.mailfrom=accounts.google.com; dkim=pass header.d=accounts.google.com; dmarc=pass (p=reject) header.from=accounts.google.com")
    return _msg('"DocuSign" <dse@docusign.net>', "Please review and sign", f"A document is ready to review and sign.\nhttps://na3.docusign.net/Signing/EmailStart.aspx?a={ref}",
                auth="mx.org.example; spf=pass smtp.mailfrom=docusign.net; dkim=pass header.d=docusign.net; dmarc=pass (p=reject) header.from=docusign.net")


def synthetic(n_phish: int = 400, n_ham: int = 600, seed: int = 7) -> list[Sample]:
    rng = random.Random(seed)
    out = [Sample(f"syn-phish-{i}", 1, "synthetic-phish", _phish(rng)) for i in range(n_phish)]
    out += [Sample(f"syn-ham-{i}", 0, "synthetic-ham", _ham(rng)) for i in range(n_ham)]
    return out
