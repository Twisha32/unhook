import os
from dataclasses import dataclass

from .guard import ALLOWED_PORTS


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class Config:
    # Where outbound traffic goes. In the compose setup this is the egress proxy,
    # which owns DNS and the IP policy. Empty means "resolve and connect ourselves".
    proxy: str = ""
    # Tests only: lets the tracer talk to 127.0.0.1. Never set this in a deployment.
    allow_private: bool = False
    ports: frozenset[int] = ALLOWED_PORTS
    default_mode: str = "http"  # "http" or "browser"
    max_hops: int = 10
    hop_timeout: float = 8.0
    deadline: float = 25.0
    max_body: int = 512 * 1024
    concurrency: int = 4

    @classmethod
    def from_env(cls) -> "Config":
        env = os.environ.get
        return cls(
            proxy=env("UNHOOK_SANDBOX_PROXY", ""),
            allow_private=_flag("UNHOOK_SANDBOX_ALLOW_PRIVATE"),
            ports=frozenset(int(p) for p in env("UNHOOK_SANDBOX_PORTS", "").replace(",", " ").split()) or ALLOWED_PORTS,
            default_mode=env("UNHOOK_SANDBOX_MODE", "http"),
            max_hops=int(env("UNHOOK_SANDBOX_MAX_HOPS", "10")),
            hop_timeout=float(env("UNHOOK_SANDBOX_HOP_TIMEOUT", "8")),
            deadline=float(env("UNHOOK_SANDBOX_DEADLINE", "25")),
            max_body=int(env("UNHOOK_SANDBOX_MAX_BODY", str(512 * 1024))),
            concurrency=int(env("UNHOOK_SANDBOX_CONCURRENCY", "4")),
        )
