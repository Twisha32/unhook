# Evaluation

The point of this harness is to make it hard to fool yourself. It reports what Unhook does on mail it didn't train on, and prices the mistakes in something a small team can reason about.

## Running it

```bash
unhook corpora fetch --dest data/corpora        # polite, skips what it already has, writes a manifest with hashes
unhook eval --corpus real --data data/corpora \
    --out eval/reports/latest.json --write-model model/model.json
```

Or use the **Evaluate on public corpora** workflow in the Actions tab, which does the same on a GitHub runner and publishes `report.json`, `model.json` and a text summary to the `eval-results` branch. The dashboard's Evaluation page reads `eval/reports/latest.json`.

`unhook eval` without `--corpus real` runs on a synthetic corpus. That run is a smoke test of the plumbing, not a benchmark: the generator and the rules were written by the same person, so the numbers say the pipeline works end to end and nothing about real mail. The generator deliberately includes evasive phishing (a plain note from a free mailbox with one link, a compromised account pointing at a shared form) and noisy legitimate mail (marketing, security alerts, e-signature requests) so the score isn't a perfect 1.000, but the mix is invented. The dashboard labels demo data as synthetic on every evaluation screen.

## Data

| Corpus | Role | Licence and handling |
|---|---|---|
| [Nazario phishing corpus](https://monkey.org/~jose/phishing/) | phishing (label 1) | CC BY 4.0, credit Jose Nazario. The `private-*` mailbox is skipped. |
| [SpamAssassin public corpus](https://spamassassin.apache.org/old/publiccorpus/) (easy and hard ham) | legitimate mail (label 0) | No formal licence. Copyright stays with the senders and the readme asks that messages not be sent into live mail systems, so they're read from disk only. Spam sets aren't used. |

Both are fetched at run time into a git-ignored folder. Neither is committed or redistributed.

## Method

- **Dedupe first.** Messages with the same subject and body are collapsed. The same text filed as both phishing and legitimate is dropped as label noise, and the report says how many of each were removed.
- **Split by sender, not by message.** Messages from the same sender domain land in the same split (60% train, 20% validation, 20% test), so the model can't memorise a campaign and then be graded on it. Free-mail domains hold thousands of unrelated senders, so those are grouped by address. If a split ends up too small to measure (one huge sender), the harness falls back to message-level splitting and says so in the report, with a note that the intervals are then optimistic.
- **Train, tune, test.** The model is fit on train. Its regularisation strength, the rules/model blend weight and the two verdict thresholds are chosen on validation, by minimising the cost model below. Every number in the report comes from the untouched test split.
- **Honest intervals.** 95% intervals come from a cluster bootstrap: whole sender groups are resampled, because two messages from one sender aren't independent.
- **Ablation.** Rules only, model only, and the shipped blend are each scored with their own thresholds, so you can see what each part contributes.
- **Per-rule precision.** For every rule, how often it fired on phishing and on legitimate mail in the test split.
- **Stored scores.** The report keeps the sorted test scores, so the dashboard recomputes the economics in your browser when you change a slider, without needing a server.

## The cost model

Accuracy numbers don't tell a small organisation whether the tool is worth running, so errors are priced in analyst-minutes. Every figure is an assumption stored in the report and editable in the dashboard.

| Assumption | Default | Meaning |
|---|---|---|
| `manual_minutes` | 8 | Someone reads every report and decides, with no tooling. |
| `triaged_review_minutes` | 3 | An analyst checks a suspicious case that arrives with the evidence attached. |
| `malicious_review_minutes` | 1 | An analyst glances at a case that was already blocked. |
| `miss_minutes` | 240 | A phish auto-closed as safe: roughly half a day of incident response. |
| `block_error_minutes` | 15 | Cleanup after wrongly blocking something legitimate. |
| `prevalence` | 0.25 | Share of reports that really are phishing. |

These are placeholders for a small organisation, not measurements. Replace them with yours.

The report gives two time figures, and they mean different things:

- `minutes_saved` is **gross**: the review time saved against doing everything by hand. It ignores mistakes, so a tool that closes everything as safe would look wonderful.
- `net_minutes_saved` is the **headline**: gross savings minus the cost of missed phish and wrongful blocks. This is the one that tells you whether the tool pays for itself.

Because corpus prevalence isn't your prevalence, precision is recomputed at the assumed prevalence rather than read off the corpus.

## The first real run

Run 39086357674 on 17 October 2026, seed 7, default costs. 15,427 messages were read and 4,779 near-duplicates removed. The split was 6,699 train, 2,290 validation and 1,658 test (1,107 phishing and 551 legitimate). The blend weight chosen on validation was 0.75 model, with the queue threshold at 0.08 and the auto-block threshold at 0.67. The report is committed as [`eval/results/nazario-spamassassin.json`](../eval/results/nazario-spamassassin.json).

| | Precision | Recall | False-positive rate |
|---|---|---|---|
| Review queue (score of 0.08 or more) | 73.6% on the test mix, 31.6% at 25% prevalence | 99.0% (95% CI 98.3 to 99.6) | 71.3% (CI 63.5 to 79.2) |
| Auto-block (score of 0.67 or more) | 99.5% | 78.3% | 0.7% (4 of 551) |

| Variant | AUC | Recall | False-positive rate | Missed per 1,000 | Net minutes saved per 1,000 |
|---|---|---|---|---|---|
| Rules only | 0.758 | 66.6% | 28.3% | 83.6 | -13,007 |
| Model only | 0.972 | 99.1% | 73.9% | 2.3 | 5,342 |
| Rules + model (shipped) | 0.973 | 99.0% | 71.3% | 2.5 | 5,377 |

Where the flags landed: 99% of the Nazario phishing, 72% of the easy ham (528 messages) and 48% of the hard ham (only 23 messages survived de-duplication, so that figure is loose).

What to take from it:

- **The queue threshold is a cost decision.** With a miss priced at 240 minutes and a review at 3, the optimiser would rather flag nearly everything than miss one. That's the right answer to the question the cost model asks, and a poor experience for the person working the queue. The dashboard sliders show how quickly recall drops as the threshold rises. Choose a threshold from your own costs.
- **The auto-block line is the strong result.** At 0.67, four of 551 legitimate messages would have been blocked, and nearly four in five phishing messages were caught without a human.
- **The rules alone don't carry their weight here.** They miss a third of the phishing and flag more than a quarter of the legitimate mail, which under these costs is worse than not having them. Two rules drag: Reply-To mismatch (58 phishing hits against 117 legitimate, 33% precision, because mailing lists set Reply-To deliberately) and fake reply threads (33 against 39, 46%). The strongest rules were very precise: link text that disagrees with its destination (278 against 2), credential wording under pressure (185 against 1), display-name brand claims (110 against 0), failed SPF or DKIM (87 against 0) and raw-IP links (79 against 0).
- **Some of that precision is the corpus.** Failed SPF or DKIM never fires on the legitimate mail because 2000s mailing-list archives mostly lack those headers, while the newer phishing carries them. A rule can look perfect for reasons that have nothing to do with phishing.
- **Don't trust the model's 0.97 yet.** Era is the obvious shortcut for it to learn, and its largest weights include message length, URL length and the number of distinct link domains. Only mail from your own organisation can settle that.
- **None of these rules were tuned on this split.** If you change a rule because of what it did here, rerun with a different `--seed` or a fresh sample, or the numbers stop being held out.

## Known weaknesses of these corpora

The report prints these in its `limitations` list, and the dashboard shows them under the results.

- The rules were written by people who have read these corpora, so rule recall on them is optimistic. Treat the first real numbers as an upper bound.
- The public ham is old mailing-list traffic and the phishing is mostly bank and webmail lures. A model can learn that difference (HTML, link count, formatting) instead of learning "phishing". Be suspicious of strong model-only numbers.
- Historical mail has little usable sender-authentication data and no domain-age lookups, threat-intel hits or sandbox traces, so those signals are barely exercised here. They're a large part of what makes the live system better than the offline score suggests, and none of that is measured.
- Public corpora age. Phishing in 2026 looks different from phishing in 2005.

The most useful number you'll ever get comes from your own mail: run `unhook eval` with your own labelled reports once you have a few hundred.

## The case-note checker

`unhook notes-check` evaluates a different thing: whether the checker catches fabricated claims in case notes. It seeds each of eight kinds of fabrication (an invented domain, IP, hash, number, technique, a speculation about attribution, a claim with no citation, a bad citation) into a faithful note for every sample, and confirms that each is caught and no faithful note is rejected. Currently that's 17 of 17 caught for every kind and no false rejections. This validates the checker, not any particular language model. To measure a live model's fabrication rate, point `eval/hallucination.py` at it and read the rejection rate.
