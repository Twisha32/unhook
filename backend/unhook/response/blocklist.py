"""Turn an analysis into indicators, and indicators into feed formats.

Blocking the wrong domain is worse than missing a phish, so this errs toward
conservative: nothing from big shared platforms is blocked by domain, the
organisation's own domains are never exported, and only verdicts we trust make it
into the feed (malicious automatically, suspicious once an analyst confirms).
"""

import csv
import io
import json
from datetime import UTC, datetime

from ..analysis.brands import BRANDS, FREEMAIL, SHARED_PLATFORMS
from ..analysis.hostutil import is_ip, registered_domain

_BRAND_DOMAINS = {dom for b in BRANDS for dom in b.domains}
_NEVER_BLOCK = _BRAND_DOMAINS | SHARED_PLATFORMS | FREEMAIL


def extract_indicators(analysis: dict, org_domains: list[str] | None = None) -> list[dict]:
    org = {registered_domain(d) for d in (org_domains or [])}
    out: dict[tuple[str, str], dict] = {}

    def add(kind, value, why):
        if value and (kind, value) not in out:
            out[(kind, value)] = {"kind": kind, "value": value, "reason": why}

    bad_rules = {f["rule_id"] for f in analysis.get("findings", [])}
    for u in analysis.get("urls", []):
        if u["source"] == "macro" or not u["host"] or not u["url"].lower().startswith(("http://", "https://")):
            continue
        suspicious_link = bool(
            {"ip_host", "userinfo", "text_mismatch", "risky_tld", "free_hosting", "punycode"} & set(u["flags"])
            or u.get("intel")
            or "DOM_LOOKALIKE_LINK" in bad_rules
            or "HTML_PASSWORD_FORM" in bad_rules
            or "TXT_CREDENTIAL_URGENCY" in bad_rules
            or "ID_BRAND_NO_INFRA" in bad_rules
        )
        if not suspicious_link:
            continue
        domain = u["domain"]
        if is_ip(u["host"]):
            add("ip", u["host"], "link goes to a raw IP address")
        elif domain in org or domain in _NEVER_BLOCK:
            add("url", u["url"], "link on a shared platform")
        else:
            add("domain", domain, "domain used in a phishing link")
    sender = analysis.get("message", {}).get("from", {}).get("domain", "")
    sender_dom = registered_domain(sender) if sender else ""
    if sender_dom and sender_dom not in _NEVER_BLOCK and sender_dom not in org and (
        {"DOM_LOOKALIKE_SENDER", "ID_DISPLAY_BRAND", "DOM_MIXED_SCRIPT", "AUTH_DMARC_FAIL"} & bad_rules
    ):
        add("domain", sender_dom, "sender domain impersonates another sender")
    for a in analysis.get("attachments", []):
        if set(a["flags"]) & {"dangerous_extension", "double_extension", "disguised_executable", "macro_autoexec", "macro"} or a.get("intel"):
            add("sha256", a["sha256"], f"attachment {a['filename']}")
    return list(out.values())


def render(indicators: list[dict], fmt: str) -> tuple[str, str]:
    """Returns (body, media_type). Indicators are dicts with kind/value/reason/case."""
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    domains = sorted({i["value"] for i in indicators if i["kind"] == "domain"})
    if fmt == "txt":
        header = f"# Unhook domain blocklist, generated {stamp}\n"
        return header + "\n".join(domains) + ("\n" if domains else ""), "text/plain"
    if fmt == "rpz":
        lines = [f"; Unhook response policy zone, generated {stamp}",
                 "$TTL 300", "@ IN SOA localhost. root.localhost. (1 1h 15m 30d 1h)", "  IN NS localhost."]
        lines += [f"{d} CNAME ." for d in domains] + [f"*.{d} CNAME ." for d in domains]
        return "\n".join(lines) + "\n", "text/plain"
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["kind", "value", "reason", "case", "added"])
        for i in sorted(indicators, key=lambda x: (x["kind"], x["value"])):
            w.writerow([i["kind"], i["value"], i.get("reason", ""), i.get("case", ""), i.get("added", "")])
        return buf.getvalue(), "text/csv"
    if fmt == "json":
        return json.dumps({"generated": stamp, "indicators": indicators}, indent=2), "application/json"
    raise ValueError(f"unknown format {fmt!r}")
