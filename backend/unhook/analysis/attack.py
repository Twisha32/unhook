from .rules import Finding

TECHNIQUES = {
    "T1566": "Phishing",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1566.002": "Phishing: Spearphishing Link",
    "T1598.003": "Phishing for Information: Spearphishing Link",
    "T1656": "Impersonation",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1204.001": "User Execution: Malicious Link",
    "T1204.002": "User Execution: Malicious File",
    "T1036.007": "Masquerading: Double File Extension",
    "T1036.008": "Masquerading: Masquerade File Type",
    "T1059.005": "Command and Scripting Interpreter: Visual Basic",
    "T1027": "Obfuscated Files or Information",
}


def map_findings(findings: list[Finding]) -> list[dict]:
    """Roll the per-rule technique tags up into one list for the case."""
    if not findings:
        return []
    seen: dict[str, list[str]] = {"T1566": []}
    for f in findings:
        for tid in f.attack:
            seen.setdefault(tid, []).append(f.rule_id)
        # The parent technique is implied by anything we flag.
        seen["T1566"].append(f.rule_id)
        if f.rule_id.startswith(("URL_", "DOM_LOOKALIKE_LINK", "INTEL_URL")):
            seen.setdefault("T1566.002", []).append(f.rule_id)
        if f.rule_id.startswith(("ATT_", "INTEL_HASH")):
            seen.setdefault("T1566.001", []).append(f.rule_id)
    out = []
    for tid, rule_ids in seen.items():
        out.append({"id": tid, "name": TECHNIQUES.get(tid, tid), "rules": sorted(set(rule_ids)),
                    "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"})
    out.sort(key=lambda t: t["id"])
    return out
