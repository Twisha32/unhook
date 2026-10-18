"""Passive threat-intel lookups.

Nothing here touches the suspicious URL itself. We only ask third-party databases
whether they have seen it. Every provider fails quiet: a timeout or an error means
"no answer", never "clean".
"""

import logging
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from .brands import SHARED_PLATFORMS
from .urls import UrlInfo

log = logging.getLogger(__name__)

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1"
BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
CACHE_SECONDS = 6 * 3600


@dataclass
class IntelHit:
    source: str
    kind: str  # url | host | hash
    indicator: str
    detail: str
    reference: str = ""


class LocalFeed:
    """Plain-text blocklists dropped into a folder or pointed at by one file.

    Understands hosts-file lines (`127.0.0.1 bad.example`), bare hostnames and full
    URLs, which covers the URLhaus text/host exports and OpenPhish's feed.txt.
    """

    def __init__(self, paths: list[Path] | None = None):
        self.hosts: dict[str, str] = {}
        self.urls: dict[str, str] = {}
        for path in paths or []:
            self._load(Path(path))

    @classmethod
    def from_path(cls, path: Path | None) -> "LocalFeed":
        if not path:
            return cls()
        path = Path(path)
        files = sorted(path.glob("*.txt")) if path.is_dir() else [path]
        return cls([p for p in files if p.exists()])

    def _load(self, path: Path) -> None:
        source = path.stem
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError as exc:
            log.warning("could not read feed %s: %s", path, exc)
            return
        for line in lines:
            line = line.strip()
            if not line or line.startswith(("#", "//")):
                continue
            token = line.split()[-1] if line.split()[0] in {"127.0.0.1", "0.0.0.0"} else line.split()[0]
            if token.lower().startswith(("http://", "https://")):
                self.urls[token.rstrip("/").lower()] = source
            else:
                self.hosts[token.lower()] = source

    def __len__(self) -> int:
        return len(self.hosts) + len(self.urls)

    def lookup(self, info: UrlInfo, host_ok: bool) -> IntelHit | None:
        key = info.url.rstrip("/").lower()
        if key in self.urls:
            return IntelHit(self.urls[key], "url", info.url, "URL is on a local blocklist")
        if host_ok and info.host in self.hosts:
            return IntelHit(self.hosts[info.host], "host", info.host, "host is on a local blocklist")
        return None


class _Cached:
    def __init__(self):
        self._cache: dict[str, tuple[float, object]] = {}

    def _get(self, key):
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < CACHE_SECONDS:
            return True, hit[1]
        return False, None

    def _put(self, key, value):
        self._cache[key] = (time.time(), value)
        return value


class UrlhausClient(_Cached):
    """abuse.ch URLhaus. Needs a free Auth-Key since 2025. Covers malware delivery
    URLs rather than credential phishing, so it's one signal among several."""

    def __init__(self, auth_key: str, client: httpx.Client | None = None, timeout: float = 4.0):
        super().__init__()
        self.auth_key = auth_key
        self.client = client or httpx.Client(timeout=timeout)

    def _post(self, path: str, data: dict) -> dict | None:
        try:
            resp = self.client.post(f"{URLHAUS_API}/{path}/", data=data, headers={"Auth-Key": self.auth_key})
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.info("urlhaus %s lookup failed: %s", path, exc)
            return None

    def url(self, url: str) -> IntelHit | None:
        cached, value = self._get(f"u:{url}")
        if cached:
            return value
        body = self._post("url", {"url": url})
        hit = None
        if body and body.get("query_status") == "ok":
            tags = ", ".join(body.get("tags") or []) or "no tags"
            hit = IntelHit("urlhaus", "url", url, f"listed in URLhaus ({body.get('url_status', 'unknown')}, {body.get('threat', 'unknown')}; {tags})", body.get("urlhaus_reference", ""))
        return self._put(f"u:{url}", hit)

    def host(self, host: str) -> IntelHit | None:
        cached, value = self._get(f"h:{host}")
        if cached:
            return value
        body = self._post("host", {"host": host})
        hit = None
        if body and body.get("query_status") == "ok":
            hit = IntelHit("urlhaus", "host", host, f"host serves {body.get('url_count', '?')} URLs listed in URLhaus ({body.get('urls_online', '?')} online)", body.get("urlhaus_reference", ""))
        return self._put(f"h:{host}", hit)


class BazaarClient(_Cached):
    """abuse.ch MalwareBazaar hash lookup."""

    def __init__(self, auth_key: str, client: httpx.Client | None = None, timeout: float = 4.0):
        super().__init__()
        self.auth_key = auth_key
        self.client = client or httpx.Client(timeout=timeout)

    def sha256(self, digest: str) -> IntelHit | None:
        cached, value = self._get(digest)
        if cached:
            return value
        hit = None
        try:
            resp = self.client.post(BAZAAR_API, data={"query": "get_info", "hash": digest}, headers={"Auth-Key": self.auth_key})
            resp.raise_for_status()
            body = resp.json()
            if body.get("query_status") == "ok" and body.get("data"):
                row = body["data"][0]
                family = row.get("signature") or "unnamed family"
                hit = IntelHit("malwarebazaar", "hash", digest, f"known sample in MalwareBazaar ({family}, {row.get('file_type', 'unknown type')})", f"https://bazaar.abuse.ch/sample/{digest}/")
        except (httpx.HTTPError, ValueError) as exc:
            log.info("bazaar lookup failed: %s", exc)
            return None
        return self._put(digest, hit)


class Intel:
    def __init__(self, feed: LocalFeed | None = None, urlhaus: UrlhausClient | None = None, bazaar: BazaarClient | None = None):
        self.feed = feed or LocalFeed()
        self.urlhaus = urlhaus
        self.bazaar = bazaar

    @property
    def active(self) -> bool:
        return bool(len(self.feed) or self.urlhaus or self.bazaar)

    def check_url(self, info: UrlInfo) -> list[IntelHit]:
        if not info.is_web:
            return []
        # A hit on google.com or sharepoint.com says nothing about the whole domain,
        # so for shared platforms only the exact URL counts.
        host_ok = info.domain not in SHARED_PLATFORMS
        hits = []
        local = self.feed.lookup(info, host_ok)
        if local:
            hits.append(local)
        if self.urlhaus:
            for hit in (self.urlhaus.url(info.url), self.urlhaus.host(info.host) if host_ok else None):
                if hit:
                    hits.append(hit)
        return hits

    def check_hash(self, sha256: str) -> IntelHit | None:
        return self.bazaar.sha256(sha256) if self.bazaar else None
