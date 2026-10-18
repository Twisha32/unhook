"""Numeric features for the statistical model.

Only things that can be computed from the message alone. Domain age, threat-intel
hits and sandbox results stay out on purpose: a historical corpus can't supply
them, and a model trained without them can't lean on them by accident. Those
signals reach the verdict through rules instead.
"""

import math

from .rules import Ctx

# name -> what a person would call it in the "why" panel
FEATURES: dict[str, str] = {
    "links_log": "Number of links",
    "distinct_link_domains": "Different link domains",
    "link_density": "Links per 100 words",
    "ip_link": "Link to raw IP address",
    "punycode_link": "Internationalised domain in a link",
    "userinfo_link": "Link with login-style prefix",
    "shortener_links": "Shortened links",
    "text_mismatch_links": "Link text differs from destination",
    "risky_tld_links": "High-abuse TLD in a link",
    "free_hosting_links": "Throwaway hosting in a link",
    "deep_subdomain_links": "Deeply nested subdomain",
    "plain_http_links": "Link without TLS",
    "max_url_len_log": "Longest URL",
    "lookalike_link": "Lookalike link domain",
    "lookalike_sender": "Lookalike sender domain",
    "mixed_script": "Mixed-alphabet domain",
    "brand_claim_no_infra": "Brand claim without brand domain",
    "display_brand": "Display name poses as a brand",
    "display_email_spoof": "Display name shows another address",
    "reply_to_mismatch": "Reply-To differs from sender",
    "reply_to_freemail": "Reply-To is a free mailbox",
    "sender_freemail": "Sender uses a free mailbox",
    "freemail_role": "Authority title on a free mailbox",
    "has_form": "HTML form in the email",
    "password_form": "Password field in the email",
    "hidden_chars_log": "Hidden text",
    "image_heavy": "Mostly images, little text",
    "text_len_log": "Message length",
    "urgency_hits": "Urgency wording",
    "credential_hits": "Credential wording",
    "payment_hits": "Payment wording",
    "threat_hits": "Threat wording",
    "generic_greeting": "Generic greeting",
    "qr_lure": "QR code lure",
    "fake_reply": "Fake reply thread",
    "attachments": "Number of attachments",
    "att_dangerous": "Executable attachment",
    "att_double_ext": "Double file extension",
    "att_disguised": "Disguised executable",
    "att_type_mismatch": "File type mismatch",
    "att_macro": "Macro in attachment",
    "att_macro_auto": "Auto-run macro",
    "att_active_html": "HTML attachment",
    "att_pdf_active": "Active PDF content",
    "att_encrypted": "Encrypted archive",
    "spf_fail": "SPF failed",
    "dkim_fail": "DKIM failed",
    "dmarc_fail": "DMARC failed",
    "subject_caps_ratio": "Capitals in subject",
    "subject_exclaims": "Exclamation marks in subject",
}

FEATURE_NAMES = list(FEATURES)


def _count(urls, flag, cap=5):
    return float(min(sum(1 for u in urls if flag in u.flags), cap))


def extract(c: Ctx) -> dict[str, float]:
    msg, urls, atts, t, i, a = c.msg, c.urls, c.atts, c.text, c.ident, c.auth
    words = max(len(msg.visible_text.split()), 1)
    web = [u for u in urls if u.is_web]
    subject = msg.subject
    letters = [ch for ch in subject if ch.isalpha()]
    forwarded = msg.inline_forward

    def att(flag):
        return float(any(flag in x.flags for x in atts))

    return {
        "links_log": math.log1p(len(urls)),
        "distinct_link_domains": math.log1p(len({u.domain for u in web})),
        "link_density": min(len(urls) / (words / 100), 20.0),
        "ip_link": float(any("ip_host" in u.flags for u in urls)),
        "punycode_link": float(any("punycode" in u.flags for u in urls)),
        "userinfo_link": float(any("userinfo" in u.flags for u in urls)),
        "shortener_links": _count(urls, "shortener"),
        "text_mismatch_links": _count(urls, "text_mismatch"),
        "risky_tld_links": _count(urls, "risky_tld"),
        "free_hosting_links": _count(urls, "free_hosting"),
        "deep_subdomain_links": _count(urls, "deep_subdomains"),
        "plain_http_links": _count(urls, "no_tls"),
        "max_url_len_log": math.log1p(max((len(u.url) for u in urls), default=0)),
        "lookalike_link": float(bool(c.link_lookalikes)),
        "lookalike_sender": float(bool(c.sender_lookalike) and not forwarded),
        "mixed_script": float(bool(c.mixed_script_hosts)),
        "brand_claim_no_infra": float(bool(i.brand_claims) and c.has_payload),
        "display_brand": float(bool(i.display_brand) and not forwarded),
        "display_email_spoof": float(bool(i.display_email_spoof) and not forwarded),
        "reply_to_mismatch": float(i.reply_to_mismatch and not forwarded),
        "reply_to_freemail": float(i.reply_to_freemail and not forwarded),
        "sender_freemail": float(i.sender_freemail and not forwarded),
        "freemail_role": float(bool(i.freemail_role) and not forwarded),
        "has_form": float(bool(msg.forms)),
        "password_form": float(any(f.has_password for f in msg.forms)),
        "hidden_chars_log": math.log1p(msg.hidden_chars),
        "image_heavy": float(msg.image_count > 0 and len(msg.visible_text) < 200),
        "text_len_log": math.log1p(len(msg.visible_text)),
        "urgency_hits": float(min(len(t.urgency), 4)),
        "credential_hits": float(min(len(t.credentials), 4)),
        "payment_hits": float(min(len(t.payment), 4)),
        "threat_hits": float(min(len(t.threat), 4)),
        "generic_greeting": float(t.generic_greeting),
        "qr_lure": float(t.qr_lure),
        "fake_reply": float(t.fake_reply),
        "attachments": float(min(len(atts), 5)),
        "att_dangerous": att("dangerous_extension"),
        "att_double_ext": att("double_extension"),
        "att_disguised": att("disguised_executable"),
        "att_type_mismatch": att("type_mismatch"),
        "att_macro": att("macro") or att("macro_autoexec"),
        "att_macro_auto": att("macro_autoexec"),
        "att_active_html": att("active_html"),
        "att_pdf_active": att("pdf_active"),
        "att_encrypted": att("encrypted_archive"),
        # Auth results count only when the receiving server actually recorded some.
        "spf_fail": float(a.present and a.spf in {"fail", "softfail"} and not forwarded),
        "dkim_fail": float(a.present and a.dkim == "fail" and not forwarded),
        "dmarc_fail": float(a.present and a.dmarc == "fail" and not forwarded),
        "subject_caps_ratio": (sum(ch.isupper() for ch in letters) / len(letters)) if len(letters) >= 6 else 0.0,
        "subject_exclaims": float(min(subject.count("!"), 3)),
    }


def vector(values: dict[str, float]) -> list[float]:
    return [values[name] for name in FEATURE_NAMES]
