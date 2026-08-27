"""Single-command launcher.

    uninet                 # train (if needed) -> run pipeline -> serve dashboard -> open browser
    python -m uninet       # same

Flags:
    --pcap PATH   ingest a capture instead of synthetic traffic
    --seed N      synthetic sample seed
    --port N      dashboard port (default 8000 / config)
    --host H      bind host (use 0.0.0.0 in containers)
    --no-open     do not open a browser
    --no-auth     disable the login screen for this run
    --retrain     force-retrain the anomaly model before starting
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

    train_main([])  # synthetic benign
    print(f"· anomaly model ready -> {path}", flush=True)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="uninet", description="UniNet threat console")
    p.add_argument("--pcap", metavar="PATH")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--port", type=int)
    p.add_argument("--host")
    p.add_argument("--no-open", action="store_true")
    p.add_argument("--no-auth", action="store_true")
    p.add_argument("--retrain", action="store_true")
    args = p.parse_args(argv)

    settings = load_settings()
    if args.port:
        settings.api_port = args.port
    if args.host:
        settings.api_host = args.host
    if args.no_auth:
        settings.auth_disabled = True

    _ensure_anomaly_model(settings, force=args.retrain)

    # ---- ingest + detect --------------------------------------------
    if args.pcap:
        from uninet.ingestion.sources.pcap import PcapSource

        source = PcapSource(args.pcap)
    else:
        from uninet.ingestion.sources.synthetic import SyntheticSource

        source = SyntheticSource(seed=args.seed)

    from uninet.detection.detector import Detector
    from uninet.streaming.worker import run_pipeline

    print("· running detection pipeline …", flush=True)
    result = run_pipeline(source, settings, detector=Detector.from_settings(settings))
    print(
        f"· {result.flow_count} flows -> {len(result.alerts)} alerts "
        f"(graph {result.graph.stats()['nodes']} nodes)",
        flush=True,
    )

    # ---- serve ------------------------------------------------------
    from uninet.api.app import create_app, serve

    app = create_app(result, settings=settings)
    serve(app, settings, open_browser=not args.no_open)
    return 0


if __name__ == "__main__":
    sys.exit(main())
