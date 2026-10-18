import io
import zipfile
from dataclasses import dataclass, field

from .message import Attachment

MAX_MACRO_SCAN_BYTES = 8 * 1024 * 1024

# Extensions that execute or launch something when opened on a normal workstation.
DANGEROUS_EXT = {
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "psm1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta",
    "lnk", "msi", "msp", "jar", "cpl", "reg", "iso", "img", "vhd", "dll", "chm", "appx", "one", "gadget",
}
ACTIVE_HTML_EXT = {"html", "htm", "xhtml", "shtml", "svg", "mht", "mhtml"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tar", "cab", "ace", "arj"}
DOC_LIKE_EXT = {"pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "rtf", "txt", "csv", "png", "jpg", "jpeg", "gif"}
MACRO_EXT = {"docm", "xlsm", "pptm", "dotm", "xltm", "xlam", "doc", "xls", "ppt", "dot", "xlt"}

# What the first bytes say a file really is.
_MAGIC = [
    (b"MZ", "pe"),
    (b"\x7fELF", "elf"),
    (bytes.fromhex("D0CF11E0A1B11AE1"), "ole2"),
    (b"%PDF-", "pdf"),
    (b"{\\rtf", "rtf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x1f\x8b", "gzip"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "lnk"),
]

# Which sniffed types are acceptable for a given extension.
_EXPECTED = {
    "pdf": {"pdf"}, "doc": {"ole2"}, "xls": {"ole2"}, "ppt": {"ole2"}, "dot": {"ole2"},
    "docx": {"ooxml"}, "xlsx": {"ooxml"}, "pptx": {"ooxml"}, "docm": {"ooxml"}, "xlsm": {"ooxml"}, "pptm": {"ooxml"},
    "zip": {"zip", "ooxml", "jar"}, "rar": {"rar"}, "7z": {"7z"}, "gz": {"gzip"},
    "png": {"png"}, "jpg": {"jpeg"}, "jpeg": {"jpeg"}, "gif": {"gif"},
    "rtf": {"rtf"}, "txt": {"text"}, "csv": {"text"},
    "exe": {"pe"}, "dll": {"pe"}, "scr": {"pe"},
}
_EXECUTABLE_KINDS = {"pe", "elf", "lnk"}


@dataclass
class MacroReport:
    present: bool = False
    autoexec: list[str] = field(default_factory=list)
    suspicious: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)


@dataclass
class AttachmentReport:
    filename: str
    size: int
    sha256: str
    md5: str
    declared_type: str
    extension: str
    sniffed: str
    flags: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)
    macros: MacroReport | None = None


def extension_chain(filename: str) -> list[str]:
    name = filename.lower().strip().rstrip(". ")
    return name.split(".")[1:] if "." in name else []


def sniff(data: bytes) -> str:
    head = data[:16]
    for sig, kind in _MAGIC:
        if head.startswith(sig):
            return kind
    if head.startswith(b"PK"):
        return _sniff_zip(data)
    snippet = data[:2048].lstrip().lower()
    if snippet.startswith((b"<!doctype html", b"<html", b"<script", b"<svg", b"<?xml version", b"<head", b"<body")) or b"<script" in snippet:
        return "html"
    if data and all(b < 128 for b in data[:512]):
        return "text"
    return "unknown"


def _sniff_zip(data: bytes) -> str:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
    except (zipfile.BadZipFile, OSError, ValueError):
        return "zip"
    if "[Content_Types].xml" in names and any(n.startswith(("word/", "xl/", "ppt/")) for n in names):
        return "ooxml"
    if "META-INF/MANIFEST.MF" in names:
        return "jar"
    return "zip"


def _zip_encrypted(data: bytes) -> bool:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return any(info.flag_bits & 0x1 for info in zf.infolist())
    except (zipfile.BadZipFile, OSError, ValueError):
        return False


def scan_macros(data: bytes, filename: str) -> MacroReport | None:
    """Static macro triage with oletools. Nothing is executed."""
    if len(data) > MAX_MACRO_SCAN_BYTES:
        return None
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return None
    try:
        parser = VBA_Parser(filename, data=data)
    except Exception:
        return None  # not an Office container, or one oletools can't open
    try:
        if not parser.detect_vba_macros():
            return MacroReport(present=False)
        report = MacroReport(present=True)
        for kind, keyword, _desc in parser.analyze_macros():
            if kind == "AutoExec":
                report.autoexec.append(str(keyword))
            elif kind == "Suspicious":
                report.suspicious.append(str(keyword))
            elif kind == "IOC":
                report.iocs.append(str(keyword))
        return report
    except Exception:
        return MacroReport(present=True)
    finally:
        parser.close()


def _pdf_active_markers(data: bytes) -> list[str]:
    found = []
    for marker in (b"/JavaScript", b"/JS", b"/OpenAction", b"/Launch", b"/EmbeddedFile", b"/AA"):
        if marker in data[:2_000_000]:
            found.append(marker.decode().lstrip("/"))
    return found


def inspect(att: Attachment) -> AttachmentReport:
    chain = extension_chain(att.filename)
    ext = chain[-1] if chain else ""
    kind = sniff(att.data)
    rep = AttachmentReport(att.filename, att.size, att.sha256, att.md5, att.declared_type, ext, kind)
    flags = rep.flags

    if ext in DANGEROUS_EXT:
        flags.append("dangerous_extension")
    if ext in ACTIVE_HTML_EXT or kind == "html":
        flags.append("active_html")

    # invoice.pdf.exe: a document-looking name hiding a real extension that runs.
    if len(chain) >= 2 and chain[-2] in DOC_LIKE_EXT and (ext in DANGEROUS_EXT or ext in ACTIVE_HTML_EXT):
        flags.append("double_extension")

    if kind in _EXECUTABLE_KINDS and ext not in {"exe", "dll", "scr", "lnk", "com", "pif"}:
        flags.append("disguised_executable")
    elif ext in _EXPECTED and kind not in _EXPECTED[ext] and kind != "unknown":
        # Text-ish files often sniff as "text" or "html" under odd extensions; only flag
        # when the sniffed type is a different binary family.
        if not (kind in {"text", "html"} and ext in {"txt", "csv"}):
            flags.append("type_mismatch")
            rep.detail["expected"] = sorted(_EXPECTED[ext])

    if ext in MACRO_EXT or kind in {"ole2", "ooxml"}:
        macros = scan_macros(att.data, att.filename)
        rep.macros = macros
        if macros and macros.present:
            flags.append("macro_autoexec" if macros.autoexec else "macro")

    if kind == "pdf":
        markers = _pdf_active_markers(att.data)
        if markers:
            flags.append("pdf_active")
            rep.detail["pdf_markers"] = markers

    if kind == "zip" and _zip_encrypted(att.data):
        flags.append("encrypted_archive")
    if ext in ARCHIVE_EXT and kind in {"zip", "rar", "7z"}:
        rep.detail["archive"] = True
    return rep


def inspect_all(attachments: list[Attachment]) -> list[AttachmentReport]:
    return [inspect(a) for a in attachments if a.declared_type != "message/rfc822"]

