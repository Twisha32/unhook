# Architecture

![Architecture](assets/architecture.svg)

Unhook is two Python packages, a dashboard and some glue. The analysis engine is a pure library: bytes in, a JSON-serialisable analysis out. Everything else (the API, the queue, the database, the sandbox) hangs off it, which is why the engine can run from the command line with no services at all.

## One report, start to finish

1. **Intake.** `POST /api/reports` (or the IMAP poller) stores the raw message in Postgres and queues a Celery task. The API answers immediately with a report id. If a staff member forwarded the message, `unwrap_report` pulls out the original and notes who reported it, so the reply goes to the right person.
2. **Parse.** `analysis/message.py` turns the raw bytes into a `Message`: headers, the sender and reply-to, text and HTML parts (hidden text counted), links with their visible text, forms, attachments. Parsing is defensive. Malformed MIME is normal in this domain and never an error.
3. **Evidence gathering.** `analysis/pipeline.py` builds a context from the parsed message:
   - authentication results from the `Authentication-Results` header (`authres.py`)
   - sender identity checks: free mail, display-name spoofing, protected names, Reply-To mismatch (`identity.py`)
   - lookalike and homoglyph checks on every domain (`lookalike.py`)
   - per-link analysis: flags, shorteners, IP hosts, text-versus-target mismatch (`urls.py`)
   - attachment inspection: magic-byte sniffing, double extensions, `oletools` for macros, PDF markers, encrypted archives, SHA-256 (`attachments.py`)
   - passive intelligence: RDAP domain age, URLhaus, MalwareBazaar and local feeds (`domainage.py`, `intel.py`)
   - optional active tracing through the sandbox (`trace.py`)
4. **Rules.** `analysis/rules.py` holds 41 rules in seven groups (auth, identity, domain, url, attachment, content, intel). Each returns evidence lines, carries a confidence, a plain-language lesson and ATT&CK technique IDs, and may raise its own confidence when the evidence is stronger than usual.
5. **Combine.** The strongest rule in each group counts, and groups combine with a noisy-OR, so ten weak signals from the same group don't outvote one strong one, and independent kinds of evidence reinforce each other.
6. **Model.** `analysis/features.py` extracts around fifty offline features (no network, no state). A logistic regression in `analysis/model.py` scores them, and because it's linear, the contribution of each feature is exact, not approximated. The dashboard shows the top drivers.
7. **Verdict.** `analysis/verdict.py` blends the two: `score = (1 - alpha) * rules + alpha * model`. Any single finding at or above 0.85 floors the score, so a known-bad hash or an auto-running macro can't be watered down by a model that never saw the evidence. Two thresholds, chosen during evaluation, split `likely_safe`, `suspicious` and `malicious`. With no trained model, the rules alone decide.
8. **Case workflow.** `service.py` dedupes by message hash (a second report adds to the first case), creates indicators, and sets their state:
   - malicious: indicators go live on the blocklist immediately
   - suspicious: indicators wait as `pending` until an analyst confirms
   - likely safe: the case closes itself
   - a false-positive resolution removes the case's indicators from the feed
9. **Case note.** `response/casenote.py` builds numbered evidence from the analysis and asks a writer for a short note. The default writer is a template. The optional LLM writer returns structured JSON, and `verify` checks it before it's shown (see below).
10. **Reply.** `response/lessons.py` composes the employee message: verdict, what stood out, one lesson from the strongest rule, and a reference number. `response/notify.py` sends it over SMTP, or logs it when SMTP isn't configured.

## The case-note checker

The LLM writer is optional, and it is boxed in. It receives only numbered evidence lines (`E1`, `E2`, ...) that the parser already extracted. It must return a verdict, a summary, claims that each cite evidence ids, and suggested actions. `verify` then rejects the draft if:

- the verdict differs from the analysis
- a claim cites no evidence, or cites an evidence id that doesn't exist
- a claim names a domain, URL, email address, IP address, hash or number that isn't in the evidence lines it cites (the summary and the suggested actions are checked against all the evidence instead, since they pull things together)
- an ATT&CK technique appears that the analysis didn't map for this message
- the wording speculates beyond the evidence, using terms such as threat-actor attribution or campaign names that the evidence never mentions

A rejected draft is replaced by the template note, and the rejected draft and its violations are kept on the case so you can see how often the model strays. `unhook notes-check` seeds each kind of fabrication into faithful notes for all 17 samples and confirms every one is caught and no faithful note is rejected. That tests the checker. It doesn't test a live model, whose fabrication rate you can measure by pointing `eval/hallucination.py` at it.

## Services

| Service | Role |
|---|---|
| `api` | FastAPI. Intake, case workflow, blocklist export, stats. |
| `worker` | Celery. Runs the analysis and case notes. The only service allowed to talk to the sandbox. |
| `postgres` | Reports, cases, indicators. SQLite works for local development. |
| `redis` | Celery broker. |
| `dashboard` | nginx serving the static React build and proxying `/api`. |
| `ingest` | Optional IMAP poller. |
| `sandbox`, `egress` | Optional link tracing, on isolated networks. See [safety.md](safety.md). |

## Dashboard

React, Vite and TypeScript with no UI framework. Charts are hand-built SVG (score ring, donut, sparklines, ROC and precision-recall curves, waterfall). It runs in two modes: against the API, or in demo mode on static JSON, which is what GitHub Pages serves. In demo mode, analyst actions work in memory and reset on reload. The Evaluation page recomputes the economics in the browser from stored test scores, so the sliders move real numbers without a server.

## Design choices worth knowing

- **Rules first, model second.** Rules are explainable and testable one at a time. The model catches combinations the rules don't name. Neither is trusted alone, and the ablation in the evaluation report shows what each adds.
- **Offline features only.** The model never sees network-derived signals. That keeps it trainable on historical mail and keeps its behaviour reproducible.
- **Defang at the edge.** Evidence is defanged when it's produced, not when it's displayed, so every consumer (dashboard, reply email, LLM prompt) gets the safe form.
- **No migrations yet.** The schema is created on start-up, under a Postgres advisory lock so the API, worker and mailbox poller can all boot at once on an empty database. Add Alembic before the first schema change you can't afford to lose data in.
