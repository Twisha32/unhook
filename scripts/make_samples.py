"""Builds the .eml fixtures in samples/ and the manifest that describes them.

Everything here is synthetic. Domains use reserved TLDs (.example) or documentation
IP ranges, so none of it can point at a real site, and the "malware" is a few
harmless bytes with an executable's magic number. Run it again and you get
byte-identical files.
"""

import io
import json
import random
import zipfile
from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"
ORG = "ridgewood-usd.example"
PNG_1PX = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d49444154789c6360f8cfc0f01f0005000201a5f645400000000049454e44ae426082"
)


def auth_results(spf="pass", dkim="pass", dmarc="pass", domain="", policy="none", dkim_d=None):
    dkim_part = f"dkim={dkim}" + (f" header.d={dkim_d or domain}" if dkim != "none" else "")
    return (
        f"mx.{ORG}; spf={spf} smtp.mailfrom={domain}; {dkim_part}; "
        f"dmarc={dmarc} (p={policy}) header.from={domain}"
    )


def build(name, *, sender, to="staff@" + ORG, subject, text, html=None, reply_to=None, auth=None,
          attachments=(), inline_png=False, hops=2, in_reply_to=None, date="Mon, 12 Oct 2026 09:14:22 -0500"):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = date
    msg["Message-ID"] = f"<{name}@mail.sample.invalid>"
    if reply_to:
        msg["Reply-To"] = reply_to
    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to
    if auth:
        msg["Authentication-Results"] = auth
    for i in range(hops):
        msg["Received"] = f"from relay{i}.sample.invalid by mx.{ORG} with ESMTPS; {date}"
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
        if inline_png:
            msg.get_payload()[1].add_related(PNG_1PX, "image", "png", cid="<qr1>")
    for filename, data, mt, st in attachments:
        msg.add_attachment(data, maintype=mt, subtype=st, filename=filename)
    (OUT / f"{name}.eml").write_bytes(bytes(msg))


def encrypted_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("Payment_Details.txt")
        info.flag_bits |= 0x1  # claims to be encrypted; the payload is just filler
        zf.writestr(info, b"filler bytes, not actually encrypted\n")
    data = bytearray(buf.getvalue())
    # zipfile resets the flags when writing, so set the "encrypted" bit by hand in
    # both the local header (offset 6) and the central directory entry (offset 8).
    data[6] |= 0x1
    central = data.find(b"PK\x01\x02")
    data[central + 8] |= 0x1
    return bytes(data)


SAMPLES = []


def add(name, label, expect, summary, **kw):
    SAMPLES.append({"file": f"{name}.eml", "label": label, "expect": expect, "summary": summary})
    build(name, **kw)


def main():
    random.seed(20261012)  # the email module picks MIME boundaries at random; pin them
    OUT.mkdir(exist_ok=True)

    add("01-m365-password-expiry", "phish", "malicious",
        "Credential lure from a lookalike of Microsoft's domain. Passes its own SPF/DKIM, because attackers authenticate the domains they own.",
        sender='"Microsoft 365 Support" <no-reply@micr0soft-support.example>',
        subject="Action required: your password expires in 24 hours",
        auth=auth_results(domain="micr0soft-support.example"),
        text="Your Microsoft 365 password expires today.\n\nKeep the same password: https://login.microsoftonline.com.session-verify.example/keep\n\nIf you do not act within 24 hours your account will be suspended.\n",
        html='<p>Dear user,</p><p>Your <b>Microsoft 365</b> password expires <b>today</b>. Sign in to keep the same password.</p>'
             '<p><a href="https://login.microsoftonline.com.session-verify.example/keep">https://login.microsoftonline.com/keep-password</a></p>'
             '<p>If you do not act within 24 hours your account will be suspended.</p>')

    add("02-invoice-double-extension", "phish", "malicious",
        "Vendor invoice that is really a program named like a PDF.",
        sender='"Accounts Receivable" <billing@northfield-logistics.example>',
        subject="Invoice 4471 - payment overdue",
        auth=auth_results(domain="northfield-logistics.example"),
        text="Hello,\n\nPlease find invoice 4471 attached. Payment is overdue, please remit today to avoid a late fee.\n\nRegards,\nAccounts Receivable\n",
        attachments=[("Invoice_4471.pdf.exe", b"MZ" + b"\x90\x00" * 32 + b"harmless filler, not executable", "application", "octet-stream")])

    add("03-superintendent-gift-cards", "phish", "malicious",
        "Classic executive impersonation from a free mailbox, asking for gift cards.",
        sender='"Elaine Whitfield" <elaine.whitfield.office@gmail.com>',
        reply_to="e.whitfield.private@proton.me",
        subject="Quick favor",
        auth=auth_results(domain="gmail.com", dkim_d="gmail.com"),
        text="Hi,\n\nAre you at your desk? I'm in a meeting and can't talk. I need you to buy gift cards for a staff appreciation surprise. It's urgent, I'll reimburse you today. Reply as soon as you see this.\n\nElaine\n")

    add("04-docusign-html-attachment", "phish", "malicious",
        "A 'document to review' that is an HTML file opened from disk, from a sender that has nothing to do with DocuSign.",
        sender='"DocuSign" <dse@docusign-review-center.example>',
        subject="Completed: Please review and sign - Q4 Contract",
        auth=auth_results(domain="docusign-review-center.example"),
        text="A document has been shared with you via DocuSign. Open the attached file to review and sign.\n",
        attachments=[("Contract_Q4_Review.html", b"<html><body><p>Loading secure document...</p><script>/* stub */</script></body></html>", "text", "html")])

    add("05-hr-payroll-lookalike", "phish", "suspicious",
        "Direct-deposit change request from a domain that wraps the district's own name.",
        sender='"HR Payroll" <payroll@ridgewood-usd-hr.example>',
        subject="Action needed: confirm your direct deposit details",
        auth=auth_results(domain="ridgewood-usd-hr.example"),
        text="Dear employee,\n\nWe are updating payroll records. Please confirm your direct deposit details before Friday using the secure form below.\n\nhttps://ridgewood-usd-hr.example/payroll/confirm\n\nHuman Resources\n")

    add("06-parcel-ip-link", "phish", "malicious",
        "Missed-delivery notice linking to a bare IP address (a documentation address, not a real host).",
        sender='"DHL Express" <tracking@dhl-parcel-notice.example>',
        subject="Your parcel could not be delivered",
        auth=auth_results(domain="dhl-parcel-notice.example"),
        text="We attempted to deliver your parcel but nobody was home. Reschedule delivery within 24 hours or the parcel will be returned.\n\nhttp://203.0.113.45/dhl/reschedule\n",
        html='<p>We attempted to deliver your parcel. Reschedule within 24 hours.</p><p><a href="http://203.0.113.45/dhl/reschedule">Track your DHL parcel at dhl.com</a></p>')

    add("07-qr-mfa-reset", "phish", "suspicious",
        "Short message pushing a QR code, which hides the destination from link scanners.",
        sender='"IT Service Desk" <servicedesk@it-helpdesk-alerts.example>',
        subject="MFA reset required",
        auth=auth_results(domain="it-helpdesk-alerts.example"),
        text="Your multi-factor authentication token has expired. Scan the QR code in this message to re-enroll within 24 hours.\n",
        html='<p>Your multi-factor authentication token has expired.</p><p>Scan the QR code below to re-enroll within 24 hours.</p><img src="cid:qr1" alt="QR code" width="160" height="160">',
        inline_png=True)

    add("08-district-newsletter", "legit", "likely_safe",
        "Ordinary newsletter with click-tracking links through an email service provider.",
        sender='"Ridgewood Communications" <news@ridgewood-usd.example>',
        subject="This week at Ridgewood: schedules, lunch menus, and the fall concert",
        auth=auth_results(domain="ridgewood-usd.example"),
        text="Fall concert is Thursday at 6:30pm in the main gym. Lunch menus and the revised bus schedule are linked below.\n\nRead more: https://u1234.ct.sendgrid.net/ls/click?upn=abc123\n",
        html='<h2>This week at Ridgewood</h2><p>Fall concert is Thursday at 6:30pm in the main gym.</p>'
             '<p><a href="https://u1234.ct.sendgrid.net/ls/click?upn=abc123">Read the full newsletter</a></p>'
             '<p style="display:none">Preheader text for inbox previews: lunch menus, bus routes and the concert.</p>')

    add("09-docusign-genuine", "legit", "likely_safe",
        "A real DocuSign envelope, to prove that review-and-sign language alone isn't flagged.",
        sender='"DocuSign" <dse_na3@docusign.net>',
        subject="Please review and sign: Facilities Services Agreement",
        auth=auth_results(domain="docusign.net"),
        text="Jordan Lee sent you a document to review and sign.\n\nReview document: https://na3.docusign.net/Signing/EmailStart.aspx?a=1f2e3d\n",
        html='<p>Jordan Lee sent you a document to review and sign.</p><p><a href="https://na3.docusign.net/Signing/EmailStart.aspx?a=1f2e3d">REVIEW DOCUMENT</a></p>')

    add("10-staff-meeting", "legit", "likely_safe",
        "Internal scheduling email between colleagues.",
        sender='"Marcus Delgado" <mdelgado@ridgewood-usd.example>',
        subject="Re: Thursday PD agenda",
        in_reply_to="<prev-thread@mail.sample.invalid>",
        auth=auth_results(domain="ridgewood-usd.example"),
        text="Thanks Priya. I've moved the PD session to room 214 and added the assessment calendar to the shared drive. Let me know if the projector is still flaky.\n\nMarcus\n")

    add("11-wrapped-link-lookalike", "phish", "malicious",
        "Reported through a gateway that wrapped the link in Proofpoint URL Defense. The real destination is a PayPal lookalike.",
        sender='"PayPal Service" <service@paypa1-secure.example>',
        subject="We've limited your account",
        auth=auth_results(domain="paypa1-secure.example"),
        text="We noticed unusual activity and limited your PayPal account. Confirm your identity to restore access: "
             "https://urldefense.proofpoint.com/v2/url?u=https-3A__paypa1-2Dsecure.example_confirm&d=DwMFaQ&c=abc\n",
        html='<p>We noticed unusual activity and limited your PayPal account.</p>'
             '<p><a href="https://urldefense.proofpoint.com/v2/url?u=https-3A__paypa1-2Dsecure.example_confirm&amp;d=DwMFaQ&amp;c=abc">Confirm your identity</a></p>')

    add("12-sharepoint-colleague", "legit", "likely_safe",
        "A colleague sharing a file from SharePoint. Hard negative: the link is on microsoft infrastructure.",
        sender='"Priya Raman" <praman@ridgewood-usd.example>',
        subject="Priya shared 'Fall assessment calendar' with you",
        auth=auth_results(domain="ridgewood-usd.example"),
        text="Priya shared a file with you.\n\nhttps://ridgewoodusd.sharepoint.com/:x:/s/curriculum/EaBc123\n",
        html='<p>Priya shared a file with you.</p><p><a href="https://ridgewoodusd.sharepoint.com/:x:/s/curriculum/EaBc123">Fall assessment calendar.xlsx</a></p>')

    add("13-homoglyph-apple-id", "phish", "malicious",
        "Sender domain swaps a Latin 'a' for a Cyrillic one (xn--pple-43d.example).",
        sender='"Apple ID" <appleid@xn--pple-43d.example>',
        subject="Your Apple ID has been locked",
        auth=auth_results(domain="xn--pple-43d.example"),
        text="Your Apple ID was locked for security reasons. Verify your account to unlock it: https://xn--pple-43d.example/unlock\n")

    add("14-encrypted-zip", "phish", "suspicious",
        "Password-protected archive with the password in the body, a way around attachment scanners.",
        sender='"Legal Department" <notices@counsel-notice-desk.example>',
        subject="Document package - password inside",
        auth=auth_results(domain="counsel-notice-desk.example"),
        text="Please open the attached archive for the document package. The password is 4471.\n",
        attachments=[("Document_Package.zip", encrypted_zip(), "application", "zip")])

    add("15-irs-spoofed-sender", "phish", "malicious",
        "Spoofs the IRS domain outright. Fails DMARC against a reject policy.",
        sender='"Internal Revenue Service" <refunds@irs.gov>',
        subject="Your tax refund is ready - claim within 24 hours",
        auth=auth_results(spf="fail", dkim="none", dmarc="fail", domain="irs.gov", policy="reject"),
        text="You are eligible for a refund. Claim it within 24 hours or it will be forfeited: https://irs-refund-claim.example/start\n")

    add("16-vendor-bank-change", "phish", "suspicious",
        "Vendor asking to change bank details, with replies routed to a free mailbox.",
        sender='"Acme Supplies Billing" <billing@acme-supplies.example>',
        reply_to="acme.billing.dept@gmail.com",
        subject="Updated remittance details for invoice 88213",
        auth=auth_results(domain="acme-supplies.example"),
        text="Hello,\n\nOur bank account has changed. Please update your records and send the next remittance for invoice 88213 to the new account in the attached details. Reply to this address to confirm.\n\nAcme Supplies\n")

    add("17-it-password-reminder", "legit", "likely_safe",
        "Genuine internal reminder about password expiry that links to the district's own single sign-on.",
        sender='"Ridgewood IT" <it@ridgewood-usd.example>',
        subject="Your district password expires in 3 days",
        auth=auth_results(domain="ridgewood-usd.example"),
        text="Your district password expires in 3 days. Sign in to the staff portal to update it: https://sso.ridgewood-usd.example/portal\n\nQuestions? Stop by the IT office in room 101.\n")

    manifest = {"org": {"domains": [ORG], "protected_names": ["Elaine Whitfield"]}, "samples": SAMPLES}
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {len(SAMPLES)} samples to {OUT}")


if __name__ == "__main__":
    main()
