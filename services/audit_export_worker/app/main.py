from __future__ import annotations

import threading
import time

from fastapi import Depends, FastAPI, Header, HTTPException, Response

from .config import settings
from .db import ensure_schema, get_conn
from .exporter import metrics_snapshot, pipeline_health, run_forever

app = FastAPI(
    title="Audit Export Worker",
    version="1.0.0",
    description="SIEM export pipeline for immutable backoffice audit logs.",
)

APP_START_MONOTONIC = time.monotonic()
_stop_event = threading.Event()
_worker_thread: threading.Thread | None = None


def _require_metrics_token(
    x_metrics_token: str | None = Header(default=None, alias="X-Metrics-Token"),
):
    if settings.metrics_token and x_metrics_token != settings.metrics_token:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.on_event("startup")
def startup() -> None:
    ensure_schema()
    global _worker_thread
    if _worker_thread is None or not _worker_thread.is_alive():
        _worker_thread = threading.Thread(
            target=run_forever,
            args=(_stop_event,),
            daemon=True,
            name="audit-export-loop",
        )
        _worker_thread.start()


@app.on_event("shutdown")
def shutdown() -> None:
    _stop_event.set()


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": settings.service_name}


@app.get("/readyz")
def readyz():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
    return {"status": "ready"}


@app.get("/metrics")
def metrics(_: None = Depends(_require_metrics_token)):
    uptime_seconds = int(time.monotonic() - APP_START_MONOTONIC)
    counters = metrics_snapshot()
    health = pipeline_health()
    lines = [
        "# HELP audit_export_worker_uptime_seconds Process uptime in seconds.",
        "# TYPE audit_export_worker_uptime_seconds gauge",
        f"audit_export_worker_uptime_seconds {uptime_seconds}",
        "# HELP audit_export_batches_success_total Successful export batches.",
        "# TYPE audit_export_batches_success_total counter",
        f"audit_export_batches_success_total {counters['batches_success_total']}",
        "# HELP audit_export_batches_failed_total Failed export batches.",
        "# TYPE audit_export_batches_failed_total counter",
        f"audit_export_batches_failed_total {counters['batches_failed_total']}",
        "# HELP audit_export_logs_exported_total Total audit logs exported.",
        "# TYPE audit_export_logs_exported_total counter",
        f"audit_export_logs_exported_total {counters['logs_exported_total']}",
        "# HELP audit_export_replay_success_total Successful dead-letter replays.",
        "# TYPE audit_export_replay_success_total counter",
        f"audit_export_replay_success_total {counters['replay_success_total']}",
        "# HELP audit_export_replay_failed_total Failed dead-letter replay attempts.",
        "# TYPE audit_export_replay_failed_total counter",
        f"audit_export_replay_failed_total {counters['replay_failed_total']}",
        "# HELP audit_export_last_log_id Last successfully exported audit log ID.",
        "# TYPE audit_export_last_log_id gauge",
        f"audit_export_last_log_id {health['last_log_id']}",
        "# HELP audit_export_lag_logs Unexported audit logs count.",
        "# TYPE audit_export_lag_logs gauge",
        f"audit_export_lag_logs {health['lag_logs']}",
        "# HELP audit_export_pending_dead_letters Pending dead letters waiting replay.",
        "# TYPE audit_export_pending_dead_letters gauge",
        f"audit_export_pending_dead_letters {health['pending_dead_letters']}",
        "# HELP audit_export_dead_letter_total Exhausted dead letters requiring operator action.",
        "# TYPE audit_export_dead_letter_total gauge",
        f"audit_export_dead_letter_total {health['dead_letter_total']}",
    ]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
