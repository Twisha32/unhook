import bz2
import functools
import http.server
import io
import tarfile
import threading

import numpy as np
import pytest

from unhook.eval import corpus, fetch
from unhook.eval.metrics import (
    CostModel,
    best_thresholds,
    cluster_bootstrap,
    confusion,
    economics,
    rates,
    thin,
)
from unhook.eval.run import _bucket, evaluate_corpus, summarize


@pytest.fixture(scope="module")
def synthetic_report():
    return evaluate_corpus(corpus.synthetic(400, 600, seed=5), CostModel(), workers=1, log=lambda *_: None,
                           corpus_meta={"name": "test", "kind": "synthetic"})


def test_report_has_everything_the_dashboard_reads(synthetic_report):
    report, model = synthetic_report
    for key in ("corpus", "assumptions", "operating_point", "metrics", "economics", "ablation", "per_rule", "curves", "scores", "limitations"):
        assert key in report
    assert report["metrics"]["flag"]["ci95"]["recall"][0] <= report["metrics"]["flag"]["recall"] <= report["metrics"]["flag"]["ci95"]["recall"][1] + 1e-9
    assert model.calibration.suspicious < model.calibration.malicious
    assert summarize(report)


def test_the_split_is_by_sender_and_every_split_has_both_classes(synthetic_report):
    report, _ = synthetic_report
    assert report["corpus"]["split_by"] == "sender domain"
    for part in report["corpus"]["splits"].values():
        assert part["phish"] >= 20 and part["ham"] >= 20


def test_same_sender_always_lands_in_the_same_bucket():
    assert _bucket("a.example", 7) == _bucket("a.example", 7)
    assert len({_bucket(f"d{i}.example", 7) for i in range(200)}) > 50  # and it spreads well


def test_economics_are_internally_consistent(synthetic_report):
    report, _ = synthetic_report
    e = report["economics"]["per_1000"]
    assert e["minutes_saved"] == pytest.approx(e["baseline_minutes"] - e["triage_minutes"], abs=0.2)
    assert report["metrics"]["auc_roc"] > 0.9  # sanity check on a toy corpus, not a benchmark


def test_ablation_lists_rules_model_and_both(synthetic_report):
    names = [a["name"] for a in synthetic_report[0]["ablation"]]
    assert names == ["Rules only", "Model only", "Rules + model (shipped)"]


def test_per_rule_precision_is_computed_from_test_hits(synthetic_report):
    rows = {r["rule_id"]: r for r in synthetic_report[0]["per_rule"]}
    assert rows["DOM_LOOKALIKE_SENDER"]["phish_hits"] > 0
    assert all(r["precision"] is None or 0 <= r["precision"] <= 1 for r in rows.values())


def test_scores_are_sorted_and_bounded(synthetic_report):
    for arr in synthetic_report[0]["scores"].values():
        assert arr == sorted(arr) and all(0 <= v <= 1 for v in arr)


# --- metrics ---------------------------------------------------------------------

def test_thresholds_separate_cleanly_separable_scores():
    phish = np.array([0.9, 0.92, 0.95, 0.97])
    ham = np.array([0.01, 0.05, 0.1, 0.12])
    ts, tm = best_thresholds(phish, ham, CostModel())
    assert 0.12 < ts <= 0.9 and ts + 0.05 <= tm


def test_economics_with_known_rates():
    cm = CostModel(manual_minutes=10, triaged_review_minutes=4, malicious_review_minutes=1, miss_minutes=100, block_error_minutes=20, prevalence=0.5)
    r = {"p_m": 0.8, "p_s": 0.1, "p_l": 0.1, "h_m": 0.0, "h_s": 0.2, "h_l": 0.8}
    e = economics(r, cm)["per_1000"]
    # 500 phish: 400 x 1 + 50 x 4 = 600; 500 ham: 100 x 4 = 400
    assert e["triage_minutes"] == 1000.0
    assert e["minutes_saved"] == 9000.0  # review time only
    assert e["net_minutes_saved"] == 10000.0 - (1000.0 + 50 * 100)  # after paying for the misses
    assert e["missed_phish"] == 50.0 and e["false_blocks"] == 0.0
    assert e["total_cost_minutes"] == 1000.0 + 50 * 100


def test_rates_partition_the_scores():
    r = rates(np.array([0.1, 0.5, 0.9]), np.array([0.2, 0.3]), 0.4, 0.8)
    assert r["p_m"] + r["p_s"] + r["p_l"] == pytest.approx(1.0)
    assert (r["p_m"], r["p_s"], r["h_l"]) == (pytest.approx(1 / 3), pytest.approx(1 / 3), 1.0)


def test_confusion_matrix():
    c = confusion(np.array([0.9, 0.2]), np.array([0.8, 0.1, 0.1]), 0.5)
    assert (c["tp"], c["fn"], c["fp"], c["tn"]) == (1, 1, 1, 2)
    assert c["precision"] == 0.5 and c["recall"] == 0.5


def test_cluster_bootstrap_returns_ordered_intervals():
    rng = np.random.default_rng(0)
    scores = np.concatenate([rng.uniform(0.5, 1, 80), rng.uniform(0, 0.6, 120)])
    labels = np.concatenate([np.ones(80), np.zeros(120)]).astype(int)
    groups = np.array([f"g{i % 25}" for i in range(200)])
    ci = cluster_bootstrap(scores, labels, groups, 0.5, n=100)
    assert all(0 <= lo <= hi <= 1 for lo, hi in ci.values())


def test_thin_keeps_endpoints():
    pts = list(range(500))
    out = thin(pts, 50)
    assert len(out) == 50 and out[0] == 0 and out[-1] == 499


# --- fetching ------------------------------------------------------------------------

def _tar_bz2(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return bz2.compress(buf.getvalue())


MBOX = (b"From a@b.example Mon Oct 12 09:14:22 2026\nFrom: a@b.example\nSubject: one\n\nbody one\n\n"
        b"From c@d.example Mon Oct 12 09:15:22 2026\nFrom: c@d.example\nSubject: two\n\nbody two\n\n")


def _serve(root):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(root))
    handler.log_message = lambda *a, **k: None
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _tree(root, ham_archive: bytes):
    (root / "n").mkdir(parents=True)
    (root / "s").mkdir()
    (root / "n" / "index.html").write_text('<a href="phishing0.mbox">x</a><a href="private-phishing4.mbox">p</a><a href="README.txt">r</a>')
    (root / "n" / "phishing0.mbox").write_bytes(MBOX)
    (root / "n" / "private-phishing4.mbox").write_bytes(MBOX)
    (root / "s" / "index.html").write_text('<a href="20030228_easy_ham.tar.bz2">h</a><a href="20050311_spam_2.tar.bz2">s</a>')
    (root / "s" / "20030228_easy_ham.tar.bz2").write_bytes(ham_archive)
    (root / "s" / "20050311_spam_2.tar.bz2").write_bytes(_tar_bz2({"spam/1": b"Subject: spam\n\nbuy\n"}))


GOOD_HAM = _tar_bz2({"easy_ham/0001.abc": b"From: a@b.example\nSubject: hi\n\nhello\n", "easy_ham/0002.def": b"From: c@d.example\nSubject: yo\n\nhey\n"})


@pytest.fixture
def mirror(tmp_path):
    _tree(tmp_path / "www", GOOD_HAM)
    server = _serve(tmp_path / "www")
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


def test_fetch_downloads_only_what_it_should_and_loads_labels(mirror, tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, "PAUSE_SECONDS", 0)
    dest = tmp_path / "corpora"
    manifest = fetch.fetch_all(dest, f"{mirror}/n/", f"{mirror}/s/", log=lambda *_: None)
    assert list(manifest["nazario"]) == ["phishing0.mbox"]  # the private mailbox is skipped
    assert list(manifest["spamassassin"]) == ["20030228_easy_ham.tar.bz2"]  # spam is skipped
    assert len(manifest["nazario"]["phishing0.mbox"]["sha256"]) == 64
    samples, meta = fetch.load_real(dest)
    assert sorted((s.label, s.source) for s in samples) == [(0, "spamassassin-easy-ham")] * 2 + [(1, "nazario")] * 2
    assert meta["kind"] == "real" and "CC BY 4.0" in meta["licenses"]["nazario"]


def test_fetch_is_idempotent(mirror, tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, "PAUSE_SECONDS", 0)
    dest = tmp_path / "corpora"
    fetch.fetch_all(dest, f"{mirror}/n/", f"{mirror}/s/", log=lambda *_: None)
    logged = []
    fetch.fetch_all(dest, f"{mirror}/n/", f"{mirror}/s/", log=logged.append)
    assert logged == []


def test_a_hostile_archive_cannot_write_outside_the_destination(tmp_path, monkeypatch):
    monkeypatch.setattr(fetch, "PAUSE_SECONDS", 0)
    _tree(tmp_path / "www", _tar_bz2({"../escaped.txt": b"nope"}))
    server = _serve(tmp_path / "www")
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        with pytest.raises(tarfile.FilterError):
            fetch.fetch_all(tmp_path / "corpora", f"{base}/n/", f"{base}/s/", log=lambda *_: None)
    finally:
        server.shutdown()
    assert not (tmp_path / "escaped.txt").exists()
