import copy

import pytest
from conftest import SAMPLES

from unhook.analysis import analyze, offline_services
from unhook.eval.hallucination import FABRICATIONS, live_rejection_rate, seeded_detection
from unhook.response.casenote import (
    TemplateWriter,
    build_evidence,
    entities,
    generate_note,
    refang,
    verify,
)


@pytest.fixture(scope="module")
def analyses(manifest):
    svc = offline_services(None, manifest["org"]["domains"])
    svc.protected_names = manifest["org"]["protected_names"]
    return [analyze((SAMPLES / s["file"]).read_bytes(), svc, online=False) for s in manifest["samples"]]


@pytest.fixture(scope="module")
def phish(analyses):
    return analyses[0]  # 01-m365-password-expiry


class ScriptedWriter:
    """Stands in for an LLM that returns a canned draft."""

    def __init__(self, draft, name="scripted"):
        self.draft, self.name = draft, name

    def write(self, evidence, analysis):
        return copy.deepcopy(self.draft)


def faithful(analysis):
    return TemplateWriter().write(build_evidence(analysis), analysis)


def test_template_notes_always_verify(analyses):
    for a in analyses:
        assert verify(faithful(a), build_evidence(a), a) == []


def test_evidence_is_numbered_and_defanged(phish):
    ev = build_evidence(phish)
    assert [e.id for e in ev][:3] == ["E1", "E2", "E3"]
    assert "micr0soft-support.example" not in " ".join(e.text for e in ev)


def test_entity_extraction_refangs():
    ents = entities("Link to hxxps://evil[.]example/a and 203.0.113.9, mail bob[@]corp[.]example, T1566.002, 412 days")
    assert "evil.example" in ents["domain"] or "https://evil.example/a" in ents["url"]
    assert "203.0.113.9" in ents["ip"] and "T1566.002" in ents["technique"] and "412" in ents["number"]
    assert refang("hxxp://a[.]b") == "http://a.b"


def test_file_names_with_odd_extensions_are_not_treated_as_domains():
    assert entities("Invoice_4471.pdf.exe has a document-style name")["domain"] == set()


@pytest.mark.parametrize("kind", sorted(FABRICATIONS))
def test_each_kind_of_fabrication_is_caught(analyses, kind):
    corrupt, expected = FABRICATIONS[kind]
    for a in analyses:
        ev = build_evidence(a)
        note = faithful(a)
        corrupt(note)
        assert {v.kind for v in verify(note, ev, a)} & expected, (kind, a["message"]["subject"])


def test_seeded_detection_is_perfect_and_never_rejects_faithful_notes(analyses):
    results, clean, rejected = seeded_detection(analyses)
    assert rejected == 0 and clean == len(analyses)
    assert all(r.caught == r.injected for r in results)


def test_claim_must_be_supported_by_the_evidence_it_cites(phish):
    ev = build_evidence(phish)
    note = faithful(phish)
    # A true fact, but cited against the wrong evidence line.
    note["claims"] = [{"text": "DMARC passed.", "evidence": [next(e.id for e in ev if e.kind == "message")]}]
    note["claims"][0]["text"] = "Sent from micr0soft-support[.]example, which is lookalike of microsoft.com."
    problems = verify(note, ev, phish)
    assert any(p.kind == "invented_domain" for p in problems)


def test_verdict_must_match_the_analysis(phish):
    note = faithful(phish)
    note["verdict"] = "likely_safe"
    assert any(p.kind == "verdict_mismatch" for p in verify(note, build_evidence(phish), phish))


def test_good_llm_draft_is_accepted(phish):
    ev = build_evidence(phish)
    first = next(e for e in ev if e.kind == "finding")
    draft = {"verdict": phish["verdict"]["label"], "summary": "This message imitates a Microsoft sign-in page.",
             "claims": [{"text": first.text.split("] ", 1)[-1], "evidence": [first.id]}], "actions": ["Block the indicators."]}
    note = generate_note(phish, ScriptedWriter(draft, "llm"))
    assert note["source"] == "llm" and note["rejected_draft"] is None


def test_lying_llm_draft_is_replaced_by_the_template_note(phish):
    draft = {"verdict": phish["verdict"]["label"], "summary": "Linked to a campaign by a known threat actor.",
             "claims": [{"text": "The sender used billing-update-portal.com.", "evidence": ["E1"]}], "actions": []}
    note = generate_note(phish, ScriptedWriter(draft, "llm"))
    assert note["source"] == "template"
    kinds = {v["kind"] for v in note["rejected_draft"]["violations"]}
    assert "invented_domain" in kinds and "speculation" in kinds
    assert verify(note, build_evidence(phish), phish) == []


def test_unparseable_draft_falls_back_without_raising(phish):
    class Broken:
        name = "broken"

        def write(self, evidence, analysis):
            raise ValueError("not json")

    note = generate_note(phish, Broken())
    assert note["source"] == "template" and note["rejected_draft"]["violations"][0]["kind"] == "writer_error"


def test_live_rejection_rate_counts_bad_drafts(analyses):
    bad = {"verdict": "malicious", "summary": "s", "claims": [{"text": "uncited", "evidence": []}], "actions": []}

    class Always:
        name = "always-bad"

        def write(self, evidence, analysis):
            return {**bad, "verdict": analysis["verdict"]["label"]}

    stats = live_rejection_rate(analyses, Always())
    assert stats["rejected"] == stats["drafts"] == len(analyses) and stats["reasons"]["uncited"] == len(analyses)
