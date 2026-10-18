"""Download the public corpora used for evaluation.

Nothing from these corpora is stored in the repository. They are fetched on demand
into data/corpora/ (git-ignored) and read in place.

* Nazario phishing corpus, https://monkey.org/~jose/phishing/ (CC BY 4.0). Credit:
  Jose Nazario. The `private-*` mailbox is deliberately skipped.
* SpamAssassin public corpus, https://spamassassin.apache.org/old/publiccorpus/.
  No formal licence; the readme says copyright stays with the original senders and
  asks that the messages not be sent into live mail systems. We read them from disk
  for research and never redistribute them. Only the ham sets are used.
"""

import hashlib
import json
import re
import tarfile
import time
from datetime import UTC, datetime
from pathlib import Path

import httpx

from .corpus import Sample, read_dir, read_mbox

NAZARIO_URL = "https://monkey.org/~jose/phishing/"
SPAMASSASSIN_URL = "https://spamassassin.apache.org/old/publiccorpus/"
USER_AGENT = "unhook-eval/0.1 (research; github.com/Twisha32/unhook)"
HAM_ARCHIVE = re.compile(r"^\d{8}_(easy_ham|hard_ham|easy_ham_2)\.tar\.bz2$")
NAZARIO_FILE = re.compile(r"^(phishing[\w.-]*|\d{8}\.mbox)$")
PAUSE_SECONDS = 1.5


def _index(client: httpx.Client, url: str) -> list[str]:
    html = client.get(url).raise_for_status().text
    return sorted(set(re.findall(r'href="([^"?/][^"]*)"', html)))


def _download(client: httpx.Client, url: str, dest: Path) -> dict:
    sha, size = hashlib.sha256(), 0
    tmp = dest.with_suffix(dest.suffix + ".part")
    with client.stream("GET", url) as resp:
        resp.raise_for_status()
        with tmp.open("wb") as fh:
            for chunk in resp.iter_bytes(1 << 16):
                fh.write(chunk)
                sha.update(chunk)
                size += len(chunk)
    tmp.rename(dest)
    return {"url": url, "sha256": sha.hexdigest(), "bytes": size, "fetched": datetime.now(UTC).isoformat()}


def fetch_all(dest: Path, nazario_url: str = NAZARIO_URL, spamassassin_url: str = SPAMASSASSIN_URL, log=print) -> dict:
    dest = Path(dest)
    (dest / "nazario").mkdir(parents=True, exist_ok=True)
    (dest / "spamassassin").mkdir(parents=True, exist_ok=True)
    manifest: dict = {"nazario": {}, "spamassassin": {}}
    with httpx.Client(headers={"User-Agent": USER_AGENT}, timeout=60, follow_redirects=True) as client:
        for name in _index(client, nazario_url):
            if not NAZARIO_FILE.match(name) or name.startswith("private"):
                continue
            target = dest / "nazario" / name
            if not target.exists():
                log(f"fetching {name}")
                manifest["nazario"][name] = _download(client, nazario_url + name, target)
                time.sleep(PAUSE_SECONDS)
        for name in _index(client, spamassassin_url):
            if not HAM_ARCHIVE.match(name):
                continue
            archive = dest / "spamassassin" / name
            out_dir = dest / "spamassassin" / name.replace(".tar.bz2", "")
            if not out_dir.exists():
                log(f"fetching {name}")
                manifest["spamassassin"][name] = _download(client, spamassassin_url + name, archive)
                with tarfile.open(archive, "r:bz2") as tf:
                    tf.extractall(out_dir, filter="data")  # "data" refuses absolute paths and links
                time.sleep(PAUSE_SECONDS)
    sums = dest / "CHECKSUMS.json"
    previous = json.loads(sums.read_text()) if sums.exists() else {"nazario": {}, "spamassassin": {}}
    for key in manifest:
        previous[key].update(manifest[key])
    sums.write_text(json.dumps(previous, indent=2) + "\n")
    return previous


def load_real(root: Path) -> tuple[list[Sample], dict]:
    root = Path(root)
    samples: list[Sample] = []
    sources = []
    for path in sorted((root / "nazario").glob("*")):
        if path.is_file() and not path.name.endswith(".part") and not path.name.startswith("private") and path.suffix in {"", ".mbox"}:
            try:
                got = list(read_mbox(path, 1, "nazario"))
            except Exception:
                continue
            samples += got
            sources.append({"name": path.name, "label": "phishing", "count": len(got)})
    for folder in sorted((root / "spamassassin").iterdir()) if (root / "spamassassin").exists() else []:
        if folder.is_dir():
            kind = "hard-ham" if "hard" in folder.name else "easy-ham"
            got = list(read_dir(folder, 0, f"spamassassin-{kind}"))
            samples += got
            sources.append({"name": folder.name, "label": "legitimate", "count": len(got)})
    meta = {
        "name": "Nazario phishing corpus + SpamAssassin ham",
        "kind": "real",
        "sources": sources,
        "licenses": {
            "nazario": "CC BY 4.0, credit Jose Nazario (https://monkey.org/~jose/phishing/)",
            "spamassassin": "Public corpus, copyright remains with original senders; research use, not redistributed",
        },
    }
    return samples, meta
