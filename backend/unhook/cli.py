import argparse
import json
import os
import sys
from pathlib import Path

from .analysis.hostutil import defang
from .analysis.model import LinearModel
from .analysis.pipeline import Services, analyze, offline_services

USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
_CODES = {"red": 31, "yellow": 33, "green": 32, "dim": 2, "bold": 1, "cyan": 36}


def paint(text: str, *styles: str) -> str:
    if not USE_COLOR:
        return text
    return "".join(f"\033[{_CODES[s]}m" for s in styles) + text + "\033[0m"


VERDICT_STYLE = {"malicious": ("red", "bold"), "suspicious": ("yellow", "bold"), "likely_safe": ("green", "bold")}


def _services(args) -> Services:
    model = None
    if not getattr(args, "no_model", False):
        path = Path(args.model) if getattr(args, "model", None) else None
        if path is None:
            from .settings import DEFAULT_MODEL_PATH

            path = DEFAULT_MODEL_PATH
        model = LinearModel.load(path)
    svc = offline_services(model, args.org_domain or [])
    svc.protected_names = args.protect or []
    return svc


def render_analysis(a: dict) -> str:
    v, m = a["verdict"], a["message"]
    label = v["label"].replace("_", " ").upper()
    out = [f"{paint(f' {label} ', *VERDICT_STYLE[v['label']])}  score {v['score']:.2f}   {m['subject'][:80]}",
           paint(f"from {m['from']['display']!r} <{defang(m['from']['address'])}>", "dim")]
    au = a["auth"]
    out.append(paint("auth ", "dim") + (f"spf={au['spf']} dkim={au['dkim']} dmarc={au['dmarc']}" if au["present"] else "no authentication results in headers"))
    out.append("")
    if not a["findings"]:
        out.append("no rules matched")
    for f in a["findings"]:
        out.append(f"{paint('*', 'cyan')} {f['confidence']:.2f}  {paint(f['rule_id'], 'bold')}  {f['title']}")
        for line in f["evidence"][:3]:
            out.append(paint(f"        {line}", "dim"))
    if a.get("model"):
        out.append("")
        out.append(f"model {a['model']['score']:.2f}  " + ", ".join(f"{c['label']} {c['contribution']:+.2f}" for c in a["model"]["contributions"][:4]))
    if a["attack"]:
        out.append("")
        out.append(paint("ATT&CK ", "dim") + ", ".join(t["id"] for t in a["attack"]))
    if a["indicators"]:
        out.append(paint("indicators ", "dim") + ", ".join(defang(i["value"]) for i in a["indicators"][:6]))
    return "\n".join(out)


def cmd_analyze(args):
    raw = Path(args.file).read_bytes()
    result = analyze(raw, _services(args), online=False)
    print(json.dumps(result, indent=2) if args.json else render_analysis(result))


def cmd_samples(args):
    root = Path(args.dir)
    manifest = json.loads((root / "manifest.json").read_text())
    svc = offline_services(None if args.no_model else LinearModel.load(Path(args.model)) if args.model else None, manifest["org"]["domains"])
    svc.protected_names = manifest["org"]["protected_names"]
    wrong = 0
    for item in manifest["samples"]:
        a = analyze((root / item["file"]).read_bytes(), svc, online=False)
        got = a["verdict"]["label"]
        mark = paint("ok ", "green") if got == item["expect"] else paint("MISS", "red")
        wrong += got != item["expect"]
        print(f"{mark} {item['file']:<34} expected {item['expect']:<12} got {got:<12} {a['verdict']['score']:.2f}")
    print(f"\n{len(manifest['samples']) - wrong}/{len(manifest['samples'])} as expected")
    return 1 if wrong else 0


def cmd_eval(args):
    from .eval import corpus
    from .eval.fetch import load_real
    from .eval.metrics import CostModel
    from .eval.run import evaluate_corpus, summarize, write_report

    if args.corpus == "real":
        samples, meta = load_real(Path(args.data))
        if not samples:
            print(f"no corpus files under {args.data}. Run `unhook corpora fetch` first.", file=sys.stderr)
            return 2
    else:
        samples = corpus.synthetic()
        meta = {"name": "Synthetic smoke corpus", "kind": "synthetic",
                "sources": [{"name": "generator", "label": "mixed", "count": len(samples)}]}
    cost = CostModel(prevalence=args.prevalence)
    report, model = evaluate_corpus(samples, cost, seed=args.seed, workers=args.workers, corpus_meta=meta)
    write_report(report, Path(args.out))
    print(summarize(report))
    print(f"\nreport written to {args.out}")
    if args.write_model:
        model.save(Path(args.write_model))
        print(f"model written to {args.write_model}")
    return 0


def cmd_corpora(args):
    from .eval.fetch import fetch_all

    fetch_all(Path(args.dest))
    print(f"corpora ready under {args.dest}")


def cmd_notes_check(args):
    from .eval.hallucination import seeded_detection

    root = Path(args.dir)
    manifest = json.loads((root / "manifest.json").read_text())
    svc = offline_services(None, manifest["org"]["domains"])
    svc.protected_names = manifest["org"]["protected_names"]
    analyses = [analyze((root / s["file"]).read_bytes(), svc, online=False) for s in manifest["samples"]]
    results, clean_total, clean_rejected = seeded_detection(analyses)
    print(f"faithful notes wrongly rejected: {clean_rejected}/{clean_total}")
    for r in results:
        print(f"{r.kind:<20} caught {r.caught}/{r.injected}")
    return 0 if clean_rejected == 0 and all(r.caught == r.injected for r in results) else 1


def cmd_demo(args):
    from .demo import build_demo

    build_demo(Path(args.out), Path(args.samples))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="unhook", description="Phishing triage for teams without a SOC")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_org(p):
        p.add_argument("--org-domain", action="append", help="your own domain (repeatable)")
        p.add_argument("--protect", action="append", help="a name attackers might impersonate (repeatable)")
        p.add_argument("--model", help="path to a model.json")
        p.add_argument("--no-model", action="store_true", help="rules only")

    p = sub.add_parser("analyze", help="analyse one .eml offline")
    p.add_argument("file")
    p.add_argument("--json", action="store_true")
    add_org(p)
    p.set_defaults(fn=cmd_analyze)

    p = sub.add_parser("samples", help="run every file in samples/ and compare with the manifest")
    p.add_argument("--dir", default="samples")
    p.add_argument("--model")
    p.add_argument("--no-model", action="store_true")
    p.set_defaults(fn=cmd_samples)

    p = sub.add_parser("eval", help="train and evaluate on a corpus")
    p.add_argument("--corpus", choices=["synthetic", "real"], default="synthetic")
    p.add_argument("--data", default="data/corpora")
    p.add_argument("--out", default="eval/reports/latest.json")
    p.add_argument("--write-model", help="save the trained model here")
    p.add_argument("--prevalence", type=float, default=0.25)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--workers", type=int, default=None)
    p.set_defaults(fn=cmd_eval)

    p = sub.add_parser("corpora", help="download the public evaluation corpora")
    p.add_argument("action", choices=["fetch"])
    p.add_argument("--dest", default="data/corpora")
    p.set_defaults(fn=cmd_corpora)

    p = sub.add_parser("notes-check", help="seed fabrications into case notes and confirm the checker flags them")
    p.add_argument("--dir", default="samples")
    p.set_defaults(fn=cmd_notes_check)

    p = sub.add_parser("demo-data", help="build the static data the dashboard demo runs on")
    p.add_argument("--out", default="dashboard/public/demo")
    p.add_argument("--samples", default="samples")
    p.set_defaults(fn=cmd_demo)

    args = parser.parse_args(argv)
    sys.exit(args.fn(args) or 0)


if __name__ == "__main__":
    main()
