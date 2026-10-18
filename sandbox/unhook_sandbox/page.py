"""What we read out of a fetched page. Nothing here executes anything."""

import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

_META_REFRESH = re.compile(r"^\s*\d+\s*;\s*(?:url\s*=\s*)?['\"]?(?P<url>[^'\"]+)", re.IGNORECASE)


def read(html: str, base_url: str) -> dict:
    soup = BeautifulSoup(html, "lxml")
    title = re.sub(r"\s+", " ", soup.title.get_text()).strip()[:200] if soup.title else ""

    refresh = None
    for meta in soup.find_all("meta", attrs={"http-equiv": re.compile("^refresh$", re.IGNORECASE)}):
        found = _META_REFRESH.match(meta.get("content", ""))
        if found:
            refresh = urljoin(base_url, found.group("url").strip())
            break

    password = bool(soup.find("input", attrs={"type": re.compile("^password$", re.IGNORECASE)}))

    form_hosts: list[str] = []
    for form in soup.find_all("form"):
        host = urlsplit(urljoin(base_url, form.get("action") or "")).hostname
        if host and host not in form_hosts:
            form_hosts.append(host)

    for tag in soup(["script", "style", "noscript", "template", "head"]):
        tag.decompose()
    text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))

    return {"title": title, "text_excerpt": text[:600], "password_form": password,
            "form_hosts": form_hosts, "refresh": refresh}
