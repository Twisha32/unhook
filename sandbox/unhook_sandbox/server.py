"""HTTP API the analysis pipeline talks to. One endpoint that matters: POST /trace."""

import threading
from typing import Literal

import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel, Field

from . import browser, tracer
from .config import Config


class TraceRequest(BaseModel):
    url: str = Field(max_length=2048)
    mode: Literal["http", "browser"] | None = None


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or Config.from_env()
    app = FastAPI(title="Unhook sandbox", docs_url=None, redoc_url=None)
    slots = threading.BoundedSemaphore(cfg.concurrency)

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "default_mode": cfg.default_mode, "browser": browser.available(),
                "proxy": bool(cfg.proxy)}

    # A plain `def` so FastAPI runs it in a worker thread; tracing blocks on the network.
    @app.post("/trace")
    def trace(req: TraceRequest):
        mode = req.mode or cfg.default_mode
        with slots:
            if mode == "browser" and browser.available():
                return browser.trace(req.url, cfg)
            result = tracer.trace(req.url, cfg)
            if mode == "browser":
                result["error"] = result["error"] or "browser mode is not installed here; used plain http"
            return result

    return app


def main() -> None:
    uvicorn.run(create_app(), host="0.0.0.0", port=8080, log_level="info")


if __name__ == "__main__":
    main()
