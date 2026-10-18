import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from ..response.blocklist import extract_indicators
from . import attachments as att_mod
from . import features as feature_mod
from .attack import map_findings
from .authres import read_auth
from .brands import BRANDS, SHARED_PLATFORMS
from .domainage import AgeLookup, NoAge, RdapClient
from .hostutil import defang, is_ip, registered_domain
from .identity import read_identity
from .intel import BazaarClient, Intel, LocalFeed, UrlhausClient
from .lookalike import check_host, is_mixed_script, org_brand
from .message import Link, ParsedMessage, parse
from .model import Calibration, LinearModel
from .rules import Ctx, combine, evaluate
from .text import read_signals
from .trace import NullTracer, SandboxTracer, Tracer
from .urls import TRACKERS, UrlInfo, analyze_links
from .verdict import decide

ANALYSIS_VERSION = 1
MAX_LINKS = 200
MAX_INTEL_URLS = 20
MAX_TRACED = 3
MAX_AGE_DOMAINS = 8

_KNOWN_GOOD = {dom for b in BRANDS for dom in b.domains} | SHARED_PLATFORMS | TRACKERS


@dataclass
class Services:
    intel: Intel = field(default_factory=Intel)
    ages: AgeLookup = field(default_factory=NoAge)
    tracer: Tracer = field(default_factory=NullTracer)
    model: LinearModel | None = None
    org_domains: list[str] = field(default_factory=list)
    protected_names: list[str] = field(default_factory=list)
    trusted_authserv: list[str] = field(default_factory=list)

    @property
    def calibration(self) -> Calibration:
        return self.model.calibration if self.model else Calibration()


def services_from_settings(settings) -> Services:
    feed = LocalFeed.from_path(settings.urlhaus_feed_path)
    urlhaus = UrlhausClient(settings.urlhaus_auth_key) if settings.urlhaus_auth_key else None
    bazaar = BazaarClient(settings.bazaar_auth_key) if settings.bazaar_auth_key else None
    return Services(
        intel=Intel(feed, urlhaus, bazaar),
        ages=RdapClient() if settings.rdap_enabled else NoAge(),
        tracer=SandboxTracer(settings.sandbox_url) if settings.sandbox_url else NullTracer(),
        model=LinearModel.load(settings.model_path),
        org_domains=settings.org_domains,
        protected_names=settings.protected_names,
    )


def offline_services(model: LinearModel | None = None, org_domains: list[str] | None = None) -> Services:
    """No network at all. Used by the eval harness and most tests."""
    return Services(model=model, org_domains=org_domains or [])


def _interesting(info: UrlInfo, org: set[str]) -> bool:
    return info.is_web and not is_ip(info.host) and info.domain not in _KNOWN_GOOD and info.domain not in org


def _pmap(fn, items):
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=min(6, len(items))) as pool:
        return list(pool.map(fn, items))


def build_context(msg: ParsedMessage, services: Services, online: bool = True) -> Ctx:
    org = {registered_domain(d) for d in services.org_domains}
    extra = org_brand(services.org_domains)

    atts = att_mod.inspect_all(msg.attachments)
    links = list(msg.links[:MAX_LINKS])
    for report in atts:
        if report.macros:
            links.extend(Link(ioc.rstrip("'\".,;)"), "", "macro") for ioc in report.macros.iocs if ioc.lower().startswith("http"))
    urls = analyze_links(links)

    from_domain = msg.sender.domain
    auth = read_auth(msg.headers, from_domain, services.trusted_authserv)
    has_thread = bool(msg.in_reply_to or msg.headers.get("references"))
    text = read_signals(msg.subject, msg.visible_text, has_thread)

    link_domains = {u.domain for u in urls if u.is_web and u.domain}
    ident = read_identity(msg, link_domains, services.org_domains, services.protected_names)

    link_lookalikes, seen_domains = [], set()
    for u in urls:
        if not u.is_web or is_ip(u.host) or u.domain in seen_domains:
            continue
        seen_domains.add(u.domain)
        hit = check_host(u.host, extra=extra)
        if hit:
            link_lookalikes.append(hit)

    sender_lookalike = None
    if from_domain and not msg.inline_forward:
        sender_lookalike = check_host(from_domain, extra=extra)

    mixed = [h for h in {u.host for u in urls if u.is_web} | ({from_domain} if from_domain else set()) if h and is_mixed_script(h)]

    ctx = Ctx(msg=msg, auth=auth, ident=ident, urls=urls, atts=atts, text=text,
              sender_lookalike=sender_lookalike, link_lookalikes=link_lookalikes,
              mixed_script_hosts=mixed, org_domains=services.org_domains)

    if online:
        _enrich(ctx, services, org)
    return ctx


def _enrich(ctx: Ctx, services: Services, org: set[str]) -> None:
    candidates = [u for u in ctx.urls if _interesting(u, org)]
    sender = ctx.ident.sender_registered
    domains = list(dict.fromkeys(
        [u.domain for u in candidates]
        + ([sender] if sender and not ctx.ident.sender_freemail and sender not in _KNOWN_GOOD and sender not in org
           and not ctx.msg.inline_forward else [])
    ))[:MAX_AGE_DOMAINS]

    def age(domain):
        return domain, services.ages.age_days(domain)

    def intel_for(info):
        return services.intel.check_url(info)

    def hash_for(report):
        return services.intel.check_hash(report.sha256)

    urls_for_intel = [u for u in ctx.urls if u.is_web][:MAX_INTEL_URLS]
    tracked = _pick_traces(ctx, org)

    def trace(info):
        return info.url, services.tracer.trace(info.url)

    for domain, days in _pmap(age, domains):
        ctx.ages[domain] = days
    for hits in _pmap(intel_for, urls_for_intel):
        ctx.intel.extend(hits)
    for hit in _pmap(hash_for, ctx.atts):
        if hit:
            ctx.intel.append(hit)
    if not isinstance(services.tracer, NullTracer):
        for url, result in _pmap(trace, tracked):
            if result is not None:
                ctx.traces[url] = result


def _pick_traces(ctx: Ctx, org: set[str]) -> list[UrlInfo]:
    odd = {"shortener", "text_mismatch", "ip_host", "userinfo", "risky_tld", "free_hosting"}
    lookalike_domains = {lk.registered for lk in ctx.link_lookalikes}
    scored = []
    for u in ctx.urls:
        if not (u.is_web and u.domain not in org and (u.domain not in _KNOWN_GOOD or "shortener" in u.flags)):
            continue
        weight = len(odd & set(u.flags)) + (2 if u.domain in lookalike_domains else 0) + 1
        scored.append((weight, u))
    scored.sort(key=lambda pair: -pair[0])
    return [u for _, u in scored[:MAX_TRACED]]


def _url_dict(info: UrlInfo, ctx: Ctx) -> dict:
    intel = [h for h in ctx.intel if h.kind in {"url", "host"} and h.indicator in {info.url, info.host}]
    trace = ctx.traces.get(info.url)
    out = {
        "url": info.url,
        "defanged": defang(info.url),
        "host": info.host,
        "domain": info.domain,
        "text": info.text[:120],
        "source": info.source,
        "flags": info.flags,
        "wrapped": bool(info.wrapped_from),
        "age_days": ctx.ages.get(info.domain),
        "intel": [{"source": h.source, "detail": h.detail, "reference": h.reference} for h in intel],
    }
    if trace:
        out["trace"] = {
            "hops": [{"url": defang(h.url), "status": h.status, "note": h.note} for h in trace.hops],
            "final_url": defang(trace.final_url),
            "final_host": trace.final_host,
            "title": trace.title,
            "password_form": trace.password_form,
            "mode": trace.mode,
            "error": trace.error,
            "screenshot_b64": trace.screenshot_b64,
        }
    return out


def _att_dict(report: att_mod.AttachmentReport, ctx: Ctx) -> dict:
    intel = [h for h in ctx.intel if h.kind == "hash" and h.indicator == report.sha256]
    out = {
        "filename": report.filename,
        "size": report.size,
        "sha256": report.sha256,
        "md5": report.md5,
        "declared_type": report.declared_type,
        "sniffed": report.sniffed,
        "extension": report.extension,
        "flags": report.flags,
        "intel": [{"source": h.source, "detail": h.detail, "reference": h.reference} for h in intel],
    }
    if report.macros and report.macros.present:
        out["macros"] = {"autoexec": report.macros.autoexec[:10], "suspicious": report.macros.suspicious[:10]}
    return out


def analyze_message(msg: ParsedMessage, services: Services, online: bool = True) -> dict:
    t0 = time.perf_counter()
    ctx = build_context(msg, services, online)
    t1 = time.perf_counter()

    findings = evaluate(ctx)
    rules_score, groups = combine(findings)

    values = feature_mod.extract(ctx)
    model_part = None
    model_score = None
    if services.model:
        model_part = services.model.explain(values)
        model_score = model_part["score"]
    verdict = decide(rules_score, model_score, findings, services.calibration)
    t2 = time.perf_counter()

    sender = msg.sender
    analysis = {
        "version": ANALYSIS_VERSION,
        "message": {
            "subject": msg.subject,
            "from": {"display": sender.display, "address": sender.address, "domain": sender.domain},
            "reply_to": msg.reply_to.address if msg.reply_to else None,
            "to_count": len(msg.to),
            "date": msg.date,
            "message_id": msg.message_id,
            "sha256": msg.raw_sha256,
            "size": msg.size,
            "received_hops": msg.received_hops,
            "inline_forward": msg.inline_forward,
            "excerpt": msg.visible_text[:600],
        },
        "auth": {
            "present": ctx.auth.present,
            "authserv": ctx.auth.authserv,
            "spf": ctx.auth.spf,
            "dkim": ctx.auth.dkim,
            "dmarc": ctx.auth.dmarc,
            "dmarc_policy": ctx.auth.dmarc_policy,
            "spf_aligned": ctx.auth.spf_aligned,
            "dkim_aligned": ctx.auth.dkim_aligned,
        },
        "urls": [_url_dict(u, ctx) for u in ctx.urls],
        "attachments": [_att_dict(a, ctx) for a in ctx.atts],
        "findings": [
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "group": f.group,
                "confidence": round(f.confidence, 3),
                "evidence": f.evidence,
                "attack": f.attack,
                "lesson": f.lesson,
            }
            for f in findings
        ],
        "rules": {"score": round(rules_score, 4), "groups": {k: round(v, 3) for k, v in groups.items()}},
        "model": model_part,
        "verdict": verdict.to_dict(),
        "attack": map_findings(findings),
        "notes": list(msg.notes) + (["Forwarded inline: original headers are unavailable, so sender checks were skipped."] if msg.inline_forward else []),
        "timings_ms": {"collect": round((t1 - t0) * 1000), "score": round((t2 - t1) * 1000)},
    }
    analysis["indicators"] = extract_indicators(analysis)
    return analysis


def analyze(raw: bytes, services: Services, online: bool = True) -> dict:
    return analyze_message(parse(raw), services, online)
