"""Olfa redirect-tracer HTTP service.

    uvicorn app:app --app-dir features/redirect-tracer --port 8788
    -> open http://127.0.0.1:8788/

POST /trace  {"url": "https://..."}  -> shared risk schema + hops + flags
GET  /        -> the timeline demo UI
GET  /health

Run it directly with `python features/redirect-tracer/app.py` if you prefer.
"""

from __future__ import annotations

import pathlib
import sys

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
# The shared schema lives one level up; the repo root must be importable too.
sys.path.insert(0, str(HERE.parent.parent))

from tracer import compute_flags, risk_score, trace  # noqa: E402

try:  # shared helpers are optional at runtime, so import defensively
    from features.shared.risk_schema import make_result, reason  # type: ignore
except Exception:  # pragma: no cover
    def reason(code, message, severity="medium", details=None):  # type: ignore
        entry = {"code": code, "message": message, "severity": severity}
        if details:
            entry["details"] = details
        return entry

    def make_result(url, score, reasons=None, **extra):  # type: ignore
        return {"url": url, "score": score, "level": "safe" if score < 0.4 else "suspicious" if score < 0.75 else "dangerous", "reasons": reasons or [], **extra}

app = FastAPI(title="Olfa redirect-tracer", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

FLAG_MESSAGES = {
    "too_many_hops": ("Too many redirects", "The address bounces more than 10 times, a common way to hide the destination.", "medium"),
    "shortener_used": ("Shortened link", "A link shortener hides the real destination until you click.", "low"),
    "domain_hopping": ("Hops between domains", "The chain passes through several different domains.", "medium"),
    "final_domain_differs_from_origin": ("Ends somewhere else", "The final page is on a different domain from the link you started with.", "medium"),
    "https_downgrade": ("Encryption downgrade", "The chain switches from https to plain http, so the rest is readable in transit.", "high"),
    "redirect_loop": ("Redirect loop", "The chain loops back to a page it already visited.", "high"),
    "blocked_private_address": ("Blocked private address", "A hop pointed at a private or local address. Olfa refuses to follow it.", "high"),
    "fetch_failed": ("A hop failed", "One of the addresses could not be fetched.", "low"),
}


class TraceRequest(BaseModel):
    url: str = Field(..., description="Absolute http(s) URL to trace")
    max_hops: int = Field(10, ge=1, le=25)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "redirect-tracer"}


@app.post("/trace")
def post_trace(request: TraceRequest) -> dict:
    result = trace(request.url, max_hops=request.max_hops)
    score = risk_score([hop.as_dict() for hop in result.hops], result.flags)
    reasons = [
        reason(code, FLAG_MESSAGES.get(code, ("Notice", code, "low"))[1], FLAG_MESSAGES.get(code, ("", "", "low"))[2])
        for code in result.flags
    ]
    payload = result.as_dict()
    payload.update(make_result(request.url, score, reasons, hops=payload["hops"], flags=result.flags, final_url=payload["final_url"]))
    return payload


@app.get("/")
def index() -> FileResponse:
    return FileResponse(str(HERE / "static" / "index.html"))


if __name__ == "__main__":  # pragma: no cover
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8788)
