# Published evaluation results

`nazario-spamassassin.json` is the report from the **Evaluate on public corpora** workflow
(GitHub Actions run 39086357674, 17 October 2026, seed 7, default cost assumptions). It was
produced by `unhook eval --corpus real` on the Nazario phishing archives and the SpamAssassin
ham sets, fetched on the runner and never committed.

The file holds aggregates only: metrics, curves, stored test-split scores, per-rule hit counts,
per-source flag rates and the trained model's weights. It contains no message text.

The analysis code that produced it is the same as at commit `58ac630`. Later commits changed only
the database layer, the workflow and the compose files. To reproduce, run the workflow again, or:

```bash
unhook corpora fetch --dest data/corpora
unhook eval --corpus real --data data/corpora --out eval/reports/latest.json --write-model model/model.json
```

Corpus contents change slowly but they do change, so a rerun on a later day can differ slightly. How to
read the numbers, and why to be careful with them, is in [docs/evaluation.md](../../docs/evaluation.md).
