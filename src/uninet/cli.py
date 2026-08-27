"""Single-command launcher.

    uninet                 # train (if needed) -> run pipeline -> serve dashboard -> open browser
    python -m uninet       # same

Flags:
    --pcap PATH       ingest a capture instead of synthetic traffic
    --seed N          synthetic sample seed
    --port N          dashboard port (default 8000 / config)
    --host H          bind host (use 0.0.0.0 in containers)
    --no-open         do not open a browser
    --no-auth         disable the login screen for this run
    --retrain         force-retrain the anomaly model before starting
    --workers N       Phase 5: host-partitioned parallel pipeline across N workers
    --executor MODE   process | thread   (default: process)
    --no-live         disable the live refresh loop (live console is ON by default)
    --interval S      seconds between live refreshes (default 5)
"""
from __future__ import annotations

import argparse
import sys

from uninet.config import load_settings


def _ensure_anomaly_model(settings, *, force: bool) -> None:
    path = settings.model_path_anomaly
    if path.is_file() and not force:
        return
    print("· training anomaly model (one-time) …", flush=True)
    from uninet.training.train_anomaly import main as train_main

    train_main([])
    print(f"· anomaly model ready -> {path}", flush=True)


def _make_source(pcap: str | None, seed: int):
    if pcap:
        from uninet.ingestion.sources.pcap import PcapSource

        return PcapSource(pcap)
    from uninet.ingestion.sources.synthetic import SyntheticSource

    return SyntheticSource(seed=seed)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="uninet", description="UniNet threat console")
    p.add_argument("--pcap", metavar="PATH")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--port", type=int)
    p.add_argument("--host")
    p.add_argument("--no-open", action="store_true")
    p.add_argument("--no-auth", action="store_true")
    p.add_argument("--retrain", action="store_true")
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--executor", choices=["process", "thread"], default="process")
    p.add_argument("--no-live", action="store_true")
    p.add_argument("--interval", type=float, default=5.0)
    args = p.parse_args(argv)
    args.live = not args.no_live

    settings = load_settings()
    if args.port:
        settings.api_port = args.port
    if args.host:
        settings.api_host = args.host
    if args.no_auth:
        settings.auth_disabled = True

    _ensure_anomaly_model(settings, force=args.retrain)

    from uninet.api.app import create_app, serve, set_result

    # ---- initial detection pass ------------------------------------
    if args.workers > 1:
        from uninet.streaming.service import run_sharded

        print(f"· Phase 5: sharded pipeline across {args.workers} {args.executor} workers …",
              flush=True)
        result = run_sharded(
            _make_source(args.pcap, args.seed), settings,
            workers=args.workers, executor=args.executor,
        )
    else:
        from uninet.detection.detector import Detector
        from uninet.streaming.worker import run_pipeline

        print("· running detection pipeline …", flush=True)
        result = run_pipeline(
            _make_source(args.pcap, args.seed), settings,
            detector=Detector.from_settings(settings),
        )
    print(
        f"· {result.flow_count} flows -> {len(result.alerts)} alerts "
        f"(graph {result.graph.stats()['nodes']} nodes)",
        flush=True,
    )

    app = create_app(result, settings=settings)

    # ---- live refresh loop --------------------------------------
    live = None
    if args.live:
        from uninet.ingestion.sources.synthetic import SyntheticSource
        from uninet.streaming.service import LiveService

        app.config["LIVE"] = True
        counter = {"n": 0}

        def _factory():
            counter["n"] += 1
            return SyntheticSource(seed=args.seed + counter["n"])

        live = LiveService(
            _factory, settings, interval=args.interval,
            on_update=lambda res: set_result(app, res),
        )
        print(f"· live mode: refreshing every {args.interval:g}s", flush=True)
        live.start()

    try:
        serve(app, settings, open_browser=not args.no_open)
    finally:
        if live:
            live.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
