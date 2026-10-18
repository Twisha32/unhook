# Safety model

Unhook handles hostile content for a living, so this page says what it does to keep that content away from you, and where the protection stops.

The rules the project holds itself to:

1. Never visit a suspicious link from a machine you care about.
2. Prefer passive lookups to active ones.
3. Use only public samples, and never build phishing pages, even for testing.

## Passive by default

With no configuration, Unhook never contacts a suspicious site. It judges links from the email itself (the visible text against the real target, the lookalike analysis, IP hosts, shorteners, free hosting) and from third-party databases:

| Lookup | What leaves your network | Needs |
|---|---|---|
| RDAP | the registered domain name, to `rdap.org`, which redirects to the registry | nothing (`UNHOOK_RDAP_ENABLED`) |
| URLhaus | a suspect URL or host, to abuse.ch | free Auth-Key |
| MalwareBazaar | an attachment's SHA-256, never the file | free Auth-Key |
| Local feeds | nothing | a file path |

The RDAP check skips reserved names (`.example`, `.test`) and raw IP addresses without making a request. Every lookup times out quietly, and no answer is never treated as "clean". Domains on shared platforms (Google, Microsoft, Dropbox and the like) are not looked up as hosts, only by exact URL, because a listing for the platform says nothing about one page on it.

If you'd rather nothing leave your network, switch the lookups off and use a local feed file.

## Active tracing is opt-in

Following the redirect chain finds things passive checks can't: a shortener that lands on a credential form, a decoy that bounces to a kit. It also means something, somewhere, connects to the attacker. So it's off until you set `UNHOOK_SANDBOX_URL`, and when it's on, that something is a locked-down container rather than your worker or your laptop.

### How the jail is built

```
worker ──(sandbox_link, internal)──▶ sandbox ──(jail, internal)──▶ egress proxy ──(outbound)──▶ internet
```

- The three networks are declared in `docker-compose.yml`. `sandbox_link` and `jail` are `internal: true`, so they have no route out. Only the proxy joins `outbound`.
- The sandbox container is read-only with a small tmpfs, drops every Linux capability, sets `no-new-privileges`, runs as an unprivileged user, and has process, memory and CPU limits.
- The sandbox's API has no authentication of its own. It's reachable only from the worker's private network, which is the control. Don't publish its port.
- The worker never talks to the internet about a suspect link. It asks the sandbox.

### The egress policy

The proxy and the tracer share one policy in `sandbox/unhook_sandbox/guard.py`:

- Only `http` and `https`, no credentials in the URL, and only ports 80, 443, 8080 and 8443. Phishing kits sit on default ports, and refusing the rest stops the sandbox being pointed at someone's Redis or SSH.
- **Addresses, not names.** The person who owns a phishing domain also owns its DNS, so the policy judges every IP a name resolves to. If *any* answer is non-public, the whole name is refused, which defeats DNS records that mix a public and a private address.
- A public address means `ipaddress.is_global` is true. Loopback, RFC 1918, link-local (including the cloud metadata address `169.254.169.254`), CGNAT, multicast and reserved ranges are all refused. IPv4-mapped IPv6, 6to4 and NAT64 forms are unwrapped and judged as the IPv4 address they hide.
- **No time-of-check gap.** The proxy connects to the exact address it vetted. Without a proxy, the tracer resolves, vets, then connects to the vetted address (keeping the name for TLS), so DNS can't change its answer between the check and the connection.
- Redirects are followed manually, up to ten hops, and every hop goes through the policy again. A `<meta http-equiv="refresh">` counts as a hop.
- Bodies are capped (512 KiB by default), anything that isn't text is never read, cookies aren't kept, no JavaScript runs in the default mode, and there's a hard deadline per trace.
- Certificate verification is deliberately off. Phishing sites often have broken or self-signed certificates, and the point is to see what they serve. Nothing sensitive is ever sent to them.

CI proves the last mile on every push: it starts the real compose stack and asserts that the sandbox, asked to trace `http://169.254.169.254/latest/meta-data/`, comes back refused.

### Browser mode and `--no-sandbox`

`UNHOOK_SANDBOX_MODE=browser` loads the link in headless Chromium, which catches kits that only reveal themselves once JavaScript runs. Every request the page makes, including subresources, passes through the same policy before it leaves, downloads are refused, service workers are blocked, and only the main frame's navigation is recorded.

Chromium is launched with `--no-sandbox`. That is a real trade-off. Chromium's own sandbox needs user namespaces, which an unprivileged container doesn't have, so without the flag it won't start. With it, a Chromium exploit isn't contained by the browser sandbox, and the container becomes the only boundary. That's why the container is read-only with no capabilities and no route to anywhere except a proxy that refuses private addresses.

If that trade-off is wrong for you:

- stay on the default `http` mode, which executes nothing, or
- run the sandbox on a separate machine or VM, so the container isn't your last line of defence, or
- don't enable active tracing at all and rely on the passive checks.

## What this does not protect against

- **The attacker learns something.** An active trace shows the phisher a request from your egress IP, with a Chrome-like user agent. Kits sometimes cloak or alert on analysts. If you need to avoid that, stay passive.
- **A container escape.** The jail assumes the container boundary holds. It's a sound default, not a guarantee, which is why the compose file removes capabilities and routes.
- **Cloaked content.** A kit that serves a clean page to the sandbox and a live one to victims will look clean. Treat "no evidence found at the destination" as the absence of a signal, never as safety.
- **Public data leaving the network.** The passive lookups above send indicators to third parties. Check that's acceptable under your policies.
- **A false sense of finality.** The verdict is triage. A person still decides on anything that matters.

## Data you are holding

- **Raw reported emails are stored in the database,** including bodies and attachments. They contain personal information, often other people's. Treat the database and its backups as sensitive, and set a retention policy. Unhook doesn't delete reports on its own yet.
- **The API is open when `UNHOOK_API_TOKEN` is empty.** That's fine on localhost and wrong anywhere else. Set a token and put the API behind TLS. The blocklist endpoints also accept `?token=` so a DNS filter can poll them, so don't log full URLs with the token in them.
- **LLM case notes send evidence to a third party.** If you set `UNHOOK_CASE_NOTE_PROVIDER=anthropic`, numbered evidence lines (defanged, derived from the message, which can include subject text and addresses) go to the Anthropic API. The default template writer sends nothing anywhere.
- **Replies go to whoever reported.** The reporter address comes from the form or the forwarding sender. Don't expose the intake endpoint to the internet unauthenticated, or it becomes a way to send mail to arbitrary addresses.

## Samples and corpora

- Everything in `samples/` is fictional and generated by `scripts/make_samples.py`. Domains use the reserved `.example` TLD, IPs use the documentation range `203.0.113.0/24`, and none of them point at anything real. There is no phishing kit, page, or working lure in the repository, and none is built for testing.
- The evaluation corpora are downloaded at run time to a git-ignored folder and read in place. The Nazario archives are CC BY 4.0. The SpamAssassin corpus asks that its messages not be sent into live mail systems, so Unhook only reads them from disk. Neither is redistributed, and the downloader skips the private Nazario mailbox.
- Archive extraction refuses paths that escape the destination, and there's a test for it.

## Reporting a problem

If you find a way past the egress policy, or a way to make Unhook contact something it shouldn't, please open a private security advisory on the GitHub repository rather than a public issue.
