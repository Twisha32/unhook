"""Analyst case notes, with a leash on the LLM.

The model may only restate evidence our own parser extracted. We hand it numbered
evidence, require every claim to cite it, and then check the draft ourselves:

* every cited id exists
* every domain, URL, IP, address, hash, ATT&CK id and number in a claim also appears
  in the evidence that claim cites
* no attribution or campaign talk the evidence doesn't contain

If anything fails, the draft is thrown away and a deterministic note built straight
from the findings is used instead. The check covers facts, not tone: it can't prove
a sentence is a fair summary, which is why the dashboard shows the cited evidence
next to every claim.
"""

import json
import logging
import re
from dataclasses import asdict, dataclass
from typing import Protocol

from ..analysis.hostutil import has_known_suffix

log = logging.getLogger(__name__)


@dataclass
class EvidenceItem:
    id: str
    kind: str  # message | auth | finding | url | attachment | trace | intel | model
    text: str


@dataclass
class Violation:
    kind: str
    claim: str
    detail: str


# --- evidence --------------------------------------------------------------

def build_evidence(analysis: dict) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []

    def add(kind, text):
        items.append(EvidenceItem(f"E{len(items) + 1}", kind, text))

    m = analysis["message"]
    sender = m["from"]
    add("message", f"Sender: \"{sender['display']}\" <{_fang(sender['address'])}>; subject: \"{m['subject'][:140]}\"; "
                   f"{m['received_hops']} relay hop(s) recorded")
    a = analysis["auth"]
    if a["present"]:
        add("auth", f"Authentication results from {a['authserv'] or 'the receiving server'}: SPF {a['spf']}, DKIM {a['dkim']}, DMARC {a['dmarc']}")
    else:
        add("auth", "No authentication results were recorded in the message headers")
    for f in analysis["findings"]:
        for line in f["evidence"]:
            add("finding", f"[{f['rule_id']}] {line}")
    for u in analysis["urls"]:
        if u["flags"] or u["intel"] or u.get("trace"):
            bits = [u["defanged"][:140]]
            if u["flags"]:
                bits.append("flags: " + ", ".join(u["flags"]))
            if u.get("age_days") is not None:
                bits.append(f"domain age {u['age_days']} days")
            add("url", "; ".join(bits))
            t = u.get("trace")
            if t:
                add("trace", f"Sandbox visit of {u['defanged'][:100]} ended at {t['final_url'][:120]} after {len(t['hops'])} hop(s)"
                             + ("; page asks for a password" if t["password_form"] else ""))
    for att in analysis["attachments"]:
        bits = [f"{att['filename']} ({att['size']} bytes, sha256 {att['sha256']})"]
        if att["flags"]:
            bits.append("flags: " + ", ".join(att["flags"]))
        add("attachment", "; ".join(bits))
    mdl = analysis.get("model")
    if mdl and mdl["contributions"]:
        top = ", ".join(f"{c['label']} ({c['contribution']:+.2f})" for c in mdl["contributions"][:4])
        add("model", f"Statistical model score {mdl['score']:.2f}; strongest drivers: {top}")
    v = analysis["verdict"]
    add("message", f"Combined score {v['score']:.2f} against thresholds {v['thresholds']['suspicious']:.2f} (suspicious) and {v['thresholds']['malicious']:.2f} (malicious)")
    return items


def _fang(value: str) -> str:
    return value.replace(".", "[.]") if value else value


# --- entity extraction ------------------------------------------------------

_REFANG = (("hxxps", "https"), ("hxxp", "http"), ("fxp://", "ftp://"), ("[.]", "."), ("(.)", "."), ("[@]", "@"), ("[at]", "@"), ("[:]", ":"))
_URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.I)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_HASH = re.compile(r"\b[a-f0-9]{16,64}\b", re.I)
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_NUMBER = re.compile(r"(?<![\w.])\d+(?:\.\d+)?(?![\w])")

SPECULATION = (
    "campaign", "threat actor", "apt", "nation-state", "attributed", "attribution", "ransomware group",
    "known to", "typically associated", "operated by", "commonly used by", "this group",
)


def refang(text: str) -> str:
    for src, dst in _REFANG:
        text = text.replace(src, dst)
    return text


def entities(text: str) -> dict[str, set[str]]:
    clean = refang(text)
    found = {
        "url": {u.rstrip(".,;").lower() for u in _URL.findall(clean)},
        "email": {e.lower() for e in _EMAIL.findall(clean)},
        "ip": set(_IPV4.findall(clean)),
        "hash": {h.lower() for h in _HASH.findall(clean)},
        "technique": set(_TECHNIQUE.findall(clean)),
    }
    without = _URL.sub(" ", _EMAIL.sub(" ", clean))
    found["domain"] = {d.lower() for d in _DOMAIN.findall(without) if has_known_suffix(d) and not _IPV4.fullmatch(d)}
    found["number"] = set(_NUMBER.findall(_IPV4.sub(" ", without)))
    return found


# --- verification -----------------------------------------------------------

def verify(note: dict, evidence: list[EvidenceItem], analysis: dict) -> list[Violation]:
    by_id = {e.id: e for e in evidence}
    everything = " ".join(refang(e.text).lower() for e in evidence)
    allowed_techniques = {t["id"] for t in analysis.get("attack", [])}
    problems: list[Violation] = []

    claims = note.get("claims")
    if not isinstance(claims, list) or not claims:
        return [Violation("no_claims", "", "the note makes no cited claims")]

    for claim in claims:
        text = str(claim.get("text", ""))
        cited = claim.get("evidence") or []
        if not cited:
            problems.append(Violation("uncited", text, "claim cites no evidence"))
            continue
        missing = [c for c in cited if c not in by_id]
        if missing:
            problems.append(Violation("bad_citation", text, f"unknown evidence id {', '.join(map(str, missing))}"))
            continue
        support = " ".join(refang(by_id[c].text).lower() for c in cited)
        problems += _check_text(text, support, everything, allowed_techniques, strict=True)

    # Summary and actions are checked against the whole evidence set, since they
    # pull things together rather than cite one line.
    for field in ("summary",):
        problems += _check_text(str(note.get(field, "")), everything, everything, allowed_techniques, strict=False)
    for action in note.get("actions", []) or []:
        problems += _check_text(str(action), everything, everything, allowed_techniques, strict=False)

    label = analysis["verdict"]["label"]
    stated = str(note.get("verdict", label))
    if stated != label:
        problems.append(Violation("verdict_mismatch", stated, f"note says {stated}, analysis says {label}"))
    return problems


def _check_text(text: str, support: str, everything: str, techniques: set[str], strict: bool) -> list[Violation]:
    out = []
    ents = entities(text)
    for kind in ("url", "email", "ip", "hash", "domain"):
        for value in ents[kind]:
            if value not in support:
                where = "the cited evidence" if strict else "the evidence"
                out.append(Violation(f"invented_{kind}", text, f"{value} does not appear in {where}"))
    for tid in ents["technique"]:
        if tid not in techniques:
            out.append(Violation("invented_technique", text, f"{tid} was not mapped for this message"))
    for number in ents["number"]:
        if not re.search(rf"(?<![\w.]){re.escape(number)}(?![\w])", support):
            out.append(Violation("invented_number", text, f"the number {number} is not in the evidence"))
    low = text.lower()
    for term in SPECULATION:
        if re.search(rf"\b{re.escape(term)}\b", low) and term not in everything:
            out.append(Violation("speculation", text, f"'{term}' goes beyond what the evidence says"))
    return out


# --- writers -----------------------------------------------------------------

class NoteWriter(Protocol):
    name: str

    def write(self, evidence: list[EvidenceItem], analysis: dict) -> dict: ...


class TemplateWriter:
    """Builds the note straight from findings. Always passes verification."""

    name = "template"

    def write(self, evidence: list[EvidenceItem], analysis: dict) -> dict:
        v = analysis["verdict"]
        findings = analysis["findings"]
        finding_items = [e for e in evidence if e.kind == "finding"]
        claims = []
        for item in finding_items[:6]:
            claims.append({"text": item.text.split("] ", 1)[-1].rstrip(".") + ".", "evidence": [item.id]})
        if not claims:
            auth = next((e for e in evidence if e.kind == "auth"), None)
            claims.append({"text": "No rule matched this message.", "evidence": [auth.id if auth else evidence[0].id]})
        label = {"malicious": "malicious", "suspicious": "suspicious", "likely_safe": "likely safe"}[v["label"]]
        lead = findings[0]["title"].lower() if findings else "no rule matches"
        summary = f"Rated {label} with a combined score of {v['score']:.2f}. Strongest signal: {lead}."
        actions = {
            "malicious": ["Block the indicators in this case.", "Search mail logs for other recipients of this message and pull it from their inboxes.",
                          "Check whether the reporter or anyone else clicked or opened an attachment."],
            "suspicious": ["Review the cited evidence and confirm or dismiss the case.", "If confirmed, approve the indicators for the block list."],
            "likely_safe": ["No action needed. Close the case if the reporter is satisfied."],
        }[v["label"]]
        return {"verdict": v["label"], "summary": summary, "claims": claims, "actions": actions}


_SYSTEM = (
    "You write case notes for a security analyst who triages reported phishing email. "
    "You are given numbered evidence extracted by an automated parser. Use ONLY facts stated in that evidence. "
    "Do not infer who is behind the message, name campaigns or groups, or add domains, addresses, hashes, "
    "numbers or technique IDs that are not in the evidence. Every claim must cite one or more evidence ids. "
    "Reply with JSON only, in this shape: "
    '{"summary": "<two sentences>", "claims": [{"text": "<one fact>", "evidence": ["E1"]}], "actions": ["<next step>"]}'
)


class AnthropicWriter:
    def __init__(self, model: str, api_key: str | None = None):
        import anthropic  # optional dependency

        self.name = f"anthropic:{model}"
        self.model = model
        self.client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()

    def write(self, evidence: list[EvidenceItem], analysis: dict) -> dict:
        listing = "\n".join(f"{e.id} ({e.kind}): {e.text}" for e in evidence)
        user = f"Verdict from the pipeline: {analysis['verdict']['label']}.\n\nEvidence:\n{listing}\n\nWrite the case note."
        resp = self.client.messages.create(model=self.model, max_tokens=1200, system=_SYSTEM,
                                           messages=[{"role": "user", "content": user}])
        raw = "".join(block.text for block in resp.content if getattr(block, "type", "") == "text")
        raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
        note = json.loads(raw)
        note["verdict"] = analysis["verdict"]["label"]
        return note


def writer_from_settings(settings) -> NoteWriter:
    if settings.case_note_provider == "anthropic":
        try:
            return AnthropicWriter(settings.llm_model)
        except Exception as exc:  # missing package or key; fall back rather than fail the case
            log.warning("LLM note writer unavailable (%s); using the template writer", exc)
    return TemplateWriter()


def generate_note(analysis: dict, writer: NoteWriter | None = None) -> dict:
    evidence = build_evidence(analysis)
    fallback = TemplateWriter()
    rejected = None
    if writer is not None and writer.name != "template":
        try:
            draft = writer.write(evidence, analysis)
            problems = verify(draft, evidence, analysis)
            if not problems:
                return _package(draft, evidence, writer.name, None)
            rejected = {"writer": writer.name, "violations": [asdict(p) for p in problems]}
            log.info("rejected %d unsupported statement(s) from %s", len(problems), writer.name)
        except Exception as exc:
            rejected = {"writer": writer.name, "violations": [{"kind": "writer_error", "claim": "", "detail": str(exc)[:200]}]}
    draft = fallback.write(evidence, analysis)
    leftover = verify(draft, evidence, analysis)
    assert not leftover, f"template note failed its own verification: {leftover}"
    return _package(draft, evidence, "template", rejected)


def _package(draft: dict, evidence: list[EvidenceItem], source: str, rejected: dict | None) -> dict:
    return {
        "source": source,
        "verdict": draft.get("verdict"),
        "summary": draft.get("summary", ""),
        "claims": draft.get("claims", []),
        "actions": draft.get("actions", []),
        "evidence": [asdict(e) for e in evidence],
        "rejected_draft": rejected,
    }
