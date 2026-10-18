import logging
import time
from datetime import UTC, datetime
from typing import Protocol

import httpx

from .hostutil import RESERVED_TLDS, is_ip

log = logging.getLogger(__name__)

CACHE_SECONDS = 24 * 3600


class AgeLookup(Protocol):
    def age_days(self, domain: str) -> int | None: ...


class NoAge:
    def age_days(self, domain: str) -> int | None:
        return None


class RdapClient:
    """Domain registration age from RDAP. This asks the registry, not the website."""

    def __init__(self, client: httpx.Client | None = None, timeout: float = 4.0):
        self.client = client or httpx.Client(timeout=timeout, follow_redirects=True)
        self._cache: dict[str, tuple[float, int | None]] = {}

    def age_days(self, domain: str) -> int | None:
        domain = domain.lower().strip(".")
        if not domain or is_ip(domain) or domain.rsplit(".", 1)[-1] in RESERVED_TLDS:
            return None
        cached = self._cache.get(domain)
        if cached and time.time() - cached[0] < CACHE_SECONDS:
            return cached[1]
        age = self._fetch(domain)
        if age is not None:  # don't cache failures, the next report might get through
            self._cache[domain] = (time.time(), age)
        return age

    def _fetch(self, domain: str) -> int | None:
        try:
            resp = self.client.get(f"https://rdap.org/domain/{domain}")
            if resp.status_code != 200:
                return None
            for event in resp.json().get("events", []):
                if event.get("eventAction") == "registration":
                    when = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                    if when.tzinfo is None:
                        when = when.replace(tzinfo=UTC)
                    return max((datetime.now(UTC) - when).days, 0)
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            log.info("rdap lookup for %s failed: %s", domain, exc)
        return None
