"""Does the case-note checker actually catch fabrications?

We can't measure a real LLM in CI, so we do the next best thing: take a faithful note,
splice in one known fabrication at a time, and require the checker to flag it. The same
module can also run a live writer over a set of analyses and report how often its first
draft had to be thrown away.
"""

import copy
from collections import Counter
from dataclasses import dataclass

from ..response.casenote import NoteWriter, TemplateWriter, build_evidence, verify


def _claim(text, evidence=("E1",)):
    return lambda note: note["claims"].append({"text": text, "evidence": list(evidence)})


# kind -> (how to corrupt a note, which violation kinds count as catching it)
FABRICATIONS = {
    "invented_domain": (_claim("The sender domain was previously linked to credential theft at billing-update-portal.com."), {"invented_domain"}),
    "invented_ip": (_claim("The link resolves to 198.51.100.77."), {"invented_ip"}),
    "invented_hash": (_claim("The attachment hash is 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08."), {"invented_hash"}),
    "invented_number": (_claim("The domain was registered 412 days before the message was sent."), {"invented_number"}),
    "invented_technique": (_claim("This maps to MITRE ATT&CK T1190."), {"invented_technique"}),
    "speculation": (_claim("This is part of a campaign targeting schools."), {"speculation"}),
    "uncited": (_claim("The message is clearly malicious.", evidence=()), {"uncited"}),
    "bad_citation": (_claim("The sender failed checks.", evidence=("E999",)), {"bad_citation"}),
}


@dataclass
class Result:
    kind: str
    injected: int
    caught: int


def seeded_detection(analyses: list[dict]) -> tuple[list[Result], int, int]:
    """Per-kind detection results, plus (faithful notes checked, faithful notes wrongly rejected)."""
    injected, caught = Counter(), Counter()
    clean_total = clean_rejected = 0
    for analysis in analyses:
        evidence = build_evidence(analysis)
        base = TemplateWriter().write(evidence, analysis)
        clean_total += 1
        if verify(base, evidence, analysis):
            clean_rejected += 1
        for kind, (corrupt, expected) in FABRICATIONS.items():
            note = copy.deepcopy(base)
            corrupt(note)
            injected[kind] += 1
            if {v.kind for v in verify(note, evidence, analysis)} & expected:
                caught[kind] += 1
    return [Result(k, injected[k], caught[k]) for k in FABRICATIONS], clean_total, clean_rejected


def live_rejection_rate(analyses: list[dict], writer: NoteWriter) -> dict:
    """How often a real writer's first draft fails the check, and why."""
    drafts = rejected = errors = 0
    reasons: Counter = Counter()
    for analysis in analyses:
        evidence = build_evidence(analysis)
        try:
            draft = writer.write(evidence, analysis)
        except Exception:
            errors += 1
            continue
        drafts += 1
        problems = verify(draft, evidence, analysis)
        if problems:
            rejected += 1
            reasons.update(p.kind for p in problems)
    return {"drafts": drafts, "rejected": rejected, "writer_errors": errors, "reasons": dict(reasons)}
