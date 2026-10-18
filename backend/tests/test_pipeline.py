import json
import math

import pytest
from conftest import SAMPLES, eml

from unhook.analysis import analyze, offline_services
from unhook.analysis.features import FEATURE_NAMES, FEATURES
from unhook.analysis.model import Calibration, LinearModel
from unhook.analysis.rules import Finding, combine
from unhook.analysis.verdict import decide
from unhook.response import blocklist


def svc_for(manifest, model=None):
    svc = offline_services(model, manifest["org"]["domains"])
    svc.protected_names = manifest["org"]["protected_names"]
    return svc


def test_every_sample_gets_the_verdict_it_was_written_for(manifest):
    svc = svc_for(manifest)
    wrong = []
    for item in manifest["samples"]:
        a = analyze((SAMPLES / item["file"]).read_bytes(), svc, online=False)
        if a["verdict"]["label"] != item["expect"]:
            wrong.append((item["file"], item["expect"], a["verdict"]["label"]))
    assert not wrong


def test_analysis_is_json_serialisable_and_has_the_shape_the_dashboard_reads(manifest):
    a = analyze((SAMPLES / "01-m365-password-expiry.eml").read_bytes(), svc_for(manifest), online=False)
    json.dumps(a)
    assert {"message", "auth", "urls", "attachments", "findings", "rules", "verdict", "attack", "indicators"} <= set(a)
    assert a["findings"][0]["confidence"] >= a["findings"][-1]["confidence"]


def test_evidence_is_defanged_but_raw_urls_are_kept_for_lookups(manifest):
    a = analyze((SAMPLES / "11-wrapped-link-lookalike.eml").read_bytes(), svc_for(manifest), online=False)
    text = " ".join(line for f in a["findings"] for line in f["evidence"])
    assert "paypa1-secure[.]example" in text and "paypa1-secure.example" not in text
    assert any(u["url"].startswith("https://paypa1-secure.example") for u in a["urls"])
    assert all("[.]" in u["defanged"] for u in a["urls"] if u["host"].count("."))


def test_attack_mapping_includes_parent_and_link_techniques(manifest):
    a = analyze((SAMPLES / "01-m365-password-expiry.eml").read_bytes(), svc_for(manifest), online=False)
    ids = {t["id"] for t in a["attack"]}
    assert {"T1566", "T1566.002"} <= ids
    attach = analyze((SAMPLES / "02-invoice-double-extension.eml").read_bytes(), svc_for(manifest), online=False)
    assert "T1566.001" in {t["id"] for t in attach["attack"]}


def test_a_message_with_no_findings_has_no_techniques():
    a = analyze(eml(), offline_services(), online=False)
    assert a["findings"] == [] and a["attack"] == [] and a["verdict"]["label"] == "likely_safe"


def test_inline_forwards_skip_sender_based_findings():
    raw = eml(sender='"PayPal Support" <fwd@org.example>', text="FYI\n---------- Forwarded message ---------\nplease check")
    a = analyze(raw, offline_services(org_domains=["org.example"]), online=False)
    assert not {"ID_DISPLAY_BRAND", "DOM_LOOKALIKE_SENDER"} & {f["rule_id"] for f in a["findings"]}
    assert any("Forwarded inline" in n for n in a["notes"])


# --- scoring -----------------------------------------------------------------

def finding(group, confidence, rule_id="X"):
    return Finding(rule_id, "t", group, confidence, [], [], "")


def test_strongest_rule_per_group_then_noisy_or():
    p, groups = combine([finding("auth", 0.5), finding("auth", 0.2), finding("url", 0.5)])
    assert groups == {"auth": 0.5, "url": 0.5}
    assert math.isclose(p, 0.75)


def test_no_findings_means_zero():
    assert combine([])[0] == 0.0


def test_a_critical_finding_floors_the_score_even_if_the_model_disagrees():
    cal = Calibration(alpha=0.9)
    v = decide(0.9, 0.05, [finding("intel", 0.97)], cal)
    assert v.label == "malicious" and v.score >= 0.97


def test_blend_uses_alpha():
    cal = Calibration(alpha=0.25)
    assert math.isclose(decide(0.8, 0.0, [], cal).score, 0.6)
    assert decide(0.2, None, [], cal).score == 0.2


@pytest.mark.parametrize("score,label", [(0.0, "likely_safe"), (0.39, "likely_safe"), (0.40, "suspicious"), (0.79, "suspicious"), (0.80, "malicious")])
def test_thresholds(score, label):
    assert decide(score, None, [], Calibration()).label == label


# --- model -------------------------------------------------------------------

def make_model():
    n = len(FEATURE_NAMES)
    coef = [0.0] * n
    coef[FEATURE_NAMES.index("password_form")] = 2.0
    coef[FEATURE_NAMES.index("text_len_log")] = -0.5
    return LinearModel("test", FEATURE_NAMES, [0.0] * n, [1.0] * n, coef, -1.0)


def test_explanation_adds_up_to_the_score():
    m = make_model()
    values = {name: 0.0 for name in FEATURE_NAMES}
    values["password_form"], values["text_len_log"] = 1.0, 3.0
    explained = m.explain(values, top=50)
    logit = explained["baseline"] + sum(c["contribution"] for c in explained["contributions"])
    assert math.isclose(1 / (1 + math.exp(-logit)), explained["score"], abs_tol=1e-3)
    assert explained["contributions"][0]["feature"] == "password_form"


def test_model_round_trips_through_json(tmp_path):
    m = make_model()
    m.calibration = Calibration(0.3, 0.35, 0.7)
    m.save(tmp_path / "m.json")
    loaded = LinearModel.load(tmp_path / "m.json")
    assert loaded.coef == m.coef and loaded.calibration.malicious == 0.7


def test_missing_model_file_means_no_model(tmp_path):
    assert LinearModel.load(tmp_path / "nope.json") is None


def test_every_feature_has_a_human_label():
    assert set(FEATURES) == set(FEATURE_NAMES)


def test_pipeline_attaches_the_model_explanation(manifest):
    a = analyze((SAMPLES / "01-m365-password-expiry.eml").read_bytes(), svc_for(manifest, make_model()), online=False)
    assert a["model"]["version"] == "test"
    assert a["verdict"]["model_score"] is not None


# --- indicators ----------------------------------------------------------------

def test_phishing_domains_become_indicators(manifest):
    a = analyze((SAMPLES / "01-m365-password-expiry.eml").read_bytes(), svc_for(manifest), online=False)
    values = {(i["kind"], i["value"]) for i in a["indicators"]}
    assert ("domain", "session-verify.example") in values
    assert ("domain", "micr0soft-support.example") in values


def test_big_platforms_are_never_blocked_by_domain():
    raw = eml(subject="Verify your account within 24 hours", text="x",
              html='<a href="https://docs.google.com/forms/d/e/abc/viewform">Sign in now</a>')
    a = analyze(raw, offline_services(), online=False)
    kinds = {(i["kind"], i["value"].startswith("https://docs.google.com")) for i in a["indicators"]}
    assert ("domain", False) not in {(k, v) for k, v in kinds if k == "domain"}
    assert all(i["kind"] != "domain" or "google" not in i["value"] for i in a["indicators"])


def test_the_organisations_own_domain_is_never_exported(manifest):
    a = analyze((SAMPLES / "05-hr-payroll-lookalike.eml").read_bytes(), svc_for(manifest), online=False)
    assert all("ridgewood-usd.example" != i["value"] for i in a["indicators"])


def test_blocklist_formats():
    items = [{"kind": "domain", "value": "bad.example", "reason": "r", "case": "UH-00001", "added": "2026-10-01"},
             {"kind": "sha256", "value": "a" * 64, "reason": "r", "case": "UH-00001", "added": "2026-10-01"}]
    txt, _ = blocklist.render(items, "txt")
    assert "bad.example" in txt and "a" * 64 not in txt
    rpz, _ = blocklist.render(items, "rpz")
    assert "bad.example CNAME ." in rpz and "*.bad.example CNAME ." in rpz
    csv_body, _ = blocklist.render(items, "csv")
    assert csv_body.splitlines()[0] == "kind,value,reason,case,added" and len(csv_body.splitlines()) == 3
    assert json.loads(blocklist.render(items, "json")[0])["indicators"][0]["value"] == "bad.example"
    with pytest.raises(ValueError):
        blocklist.render(items, "xml")
