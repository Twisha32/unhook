"""A small egress proxy that enforces the IP policy.

The sandbox container has no route to the internet. Its only way out is this
proxy, which sits on both the sandbox network and the outbound one. For every
request it resolves the name, vets every address with the same rules as
`guard`, and connects to the address it vetted. If the sandbox is ever
compromised, the worst it can do is fetch public web pages.

Supports CONNECT (HTTPS) and plain GET/HEAD in absolute form. Nothing else.
"""

import argparse
import asyncio
import logging
from urllib.parse import urlsplit

from . import guard
from .config import Config

log = logging.getLogger("unhook.proxy")

CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 30.0
MAX_HEAD = 16 * 1024
MAX_BYTES = 8 * 1024 * 1024  # per connection, either direction
HOP_BY_HOP = {"connection", "proxy-connection", "keep-alive", "proxy-authorization", "te", "trailer", "upgrade"}


class Proxy:
    def __init__(self, cfg: Config | None = None, max_connections: int = 64):
        self.cfg = cfg or Config()
        self._slots = asyncio.Semaphore(max_connections)

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with self._slots:
            try:
                await self._serve(reader, writer)
            except (TimeoutError, ConnectionError, asyncio.IncompleteReadError):
                pass
            except Exception:  # one bad client must not take the proxy down
                log.exception("unexpected error")
            finally:
                writer.close()

    async def _serve(self, reader, writer) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), IDLE_TIMEOUT)
        except asyncio.LimitOverrunError:
            return await _reply(writer, 431, "request head too large")
        lines = head.decode("latin-1").split("\r\n")
        try:
            method, target, _ = lines[0].split(" ", 2)
        except ValueError:
            return await _reply(writer, 400, "bad request line")

        if method == "CONNECT":
            host, _, port = target.rpartition(":")
            if not port.isdigit():
                return await _reply(writer, 400, "CONNECT needs host:port")
            return await self._tunnel(reader, writer, host.strip("[]"), int(port))

        if method not in ("GET", "HEAD"):
            return await _reply(writer, 405, "only GET, HEAD and CONNECT are allowed")
        await self._forward(reader, writer, method, target, lines[1:])

    async def _open(self, writer, host: str, port: int):
        """Vet the name, then connect to an address we vetted. None if we replied with an error."""
        try:
            if port not in self.cfg.ports:
                raise guard.Blocked(f"port {port} is not on the allow list")
            guard.check_literal(host, self.cfg.allow_private)
            loop = asyncio.get_running_loop()
            addrs = await loop.run_in_executor(None, guard.resolve, host, port, self.cfg.allow_private)
        except guard.Blocked as exc:
            log.info("deny %s:%s (%s)", host, port, exc)
            await _reply(writer, 403, str(exc), blocked=True)
            return None
        except guard.Unresolvable as exc:
            await _reply(writer, 502, str(exc))
            return None
        for addr in addrs:
            try:
                conn = await asyncio.wait_for(asyncio.open_connection(addr, port), CONNECT_TIMEOUT)
                log.info("allow %s:%s", host, port)
                return conn
            except (TimeoutError, OSError):
                continue
        await _reply(writer, 502, f"could not connect to {host}")
        return None

    async def _tunnel(self, reader, writer, host: str, port: int) -> None:
        conn = await self._open(writer, host, port)
        if conn is None:
            return
        up_reader, up_writer = conn
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        await _relay(reader, writer, up_reader, up_writer)

    async def _forward(self, reader, writer, method: str, target: str, header_lines: list[str]) -> None:
        parts = urlsplit(target)
        if parts.scheme != "http" or not parts.hostname:
            return await _reply(writer, 400, "plain requests must use an absolute http:// URL")
        conn = await self._open(writer, parts.hostname, parts.port or 80)
        if conn is None:
            return
        up_reader, up_writer = conn
        kept = []
        for line in header_lines:
            name = line.split(":", 1)[0].strip().lower()
            if line and name not in HOP_BY_HOP and name != "host":
                kept.append(line)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        netloc = parts.netloc.rpartition("@")[2]
        request = [f"{method} {path} HTTP/1.1", f"Host: {netloc}", "Connection: close", *kept]
        up_writer.write(("\r\n".join(request) + "\r\n\r\n").encode("latin-1"))
        await up_writer.drain()
        await _relay(reader, writer, up_reader, up_writer)


async def _relay(client_r, client_w, up_r, up_w) -> None:
    budget = [MAX_BYTES]

    async def pipe(src, dst, eof_ends_all: bool) -> bool:
        """Copy until EOF. Returns True when the whole exchange is over."""
        try:
            while True:
                chunk = await asyncio.wait_for(src.read(65536), IDLE_TIMEOUT)
                if not chunk:
                    if eof_ends_all or not dst.can_write_eof():
                        return True
                    dst.write_eof()  # the client is done sending; keep reading the answer
                    return False
                budget[0] -= len(chunk)
                if budget[0] < 0:
                    return True
                dst.write(chunk)
                await dst.drain()
        except (TimeoutError, ConnectionError):
            return True

    pending = {asyncio.ensure_future(pipe(client_r, up_w, False)), asyncio.ensure_future(pipe(up_r, client_w, True))}
    try:
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            if any(task.result() for task in done):
                break
    finally:
        for task in pending:
            task.cancel()
        up_w.close()


async def _reply(writer, status: int, reason: str, blocked: bool = False) -> None:
    phrase = {400: "Bad Request", 403: "Forbidden", 405: "Method Not Allowed", 431: "Request Header Fields Too Large",
              502: "Bad Gateway"}[status]
    body = f"{reason}\n".encode()
    extra = f"X-Unhook-Blocked: {reason}\r\n" if blocked else ""
    writer.write(f"HTTP/1.1 {status} {phrase}\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                 f"{extra}Connection: close\r\n\r\n".encode("latin-1", "replace") + body)
    try:
        await writer.drain()
    except ConnectionError:
        pass


async def serve(host: str, port: int, cfg: Config | None = None) -> None:
    cfg = cfg or Config.from_env()
    server = await asyncio.start_server(Proxy(cfg).handle, host, port, limit=MAX_HEAD)
    log.info("egress proxy listening on %s:%s%s", host, port, " (private addresses ALLOWED, tests only)" if cfg.allow_private else "")
    async with server:
        await server.serve_forever()


def main() -> None:
    ap = argparse.ArgumentParser(description="Unhook egress proxy")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=3128)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(serve(args.host, args.port))


if __name__ == "__main__":
    main()
