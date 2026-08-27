"""Streaming throughput benchmark.

    python -m uninet.eval.throughput_bench --flows 200000
    python -m uninet.eval.throughput_bench --flows 400000 --workers 4      # Phase 5 scale-out

Generates a large synthetic flow log and measures end-to-end
(ingest -> bus -> features -> TB-Graph -> detection) flows/sec. This is the
number behind any "N flows/sec on commodity hardware" claim.
"""
from __future__ import annotations

import argparse
import time

from uninet.config import load_settings
from uninet.detection.detector import Detector
from uninet.ingestion.sources.base import FlowSource
from uninet.ingestion.sources.synthetic import SyntheticSource
from uninet.schemas.flow import FlowRecord
from uninet.streaming.service import run_sharded
from uninet.streaming.worker import run_pipeline


class _Replicated(FlowSource):
    """Repeat a base scenario, time-shifted, to reach a target flow count."""

    name = "bench"

    def __init__(self, target: int) -> None:
        base = SyntheticSource().collect()
        span = (base[-1].start_ts - base[0].start_ts) or 1.0
        self._records: list[FlowRecord] = []
        reps = max(1, target // max(len(base), 1) + 1)
        for k in range(reps):
            shift = k * (span + 5.0)
            for r in base:
                self._records.append(r.model_copy(update={
                    "src_ip": r.src_ip if k == 0 else f"{r.src_ip}/{k}",
                    "start_ts": r.start_ts + shift,
                    "end_ts": r.end_ts + shift,
                }))
        self._records = self._records[:target]

    def stream(self):
        yield from self._records


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--flows", type=int, default=100_000)
    p.add_argument("--workers", type=int, default=1, help="Phase 5: parallel shards")
    p.add_argument("--executor", choices=["process", "thread"], default="process")
    args = p.parse_args(argv)

    settings = load_settings()
    source = _Replicated(args.flows)
    n = len(source._records)

    t0 = time.perf_counter()
    if args.workers > 1:
        result = run_sharded(source, settings, workers=args.workers, executor=args.executor)
        mode = f"{args.workers}x {args.executor}"
    else:
        result = run_pipeline(source, settings, detector=Detector.from_settings(settings))
        mode = "single"
    dt = time.perf_counter() - t0

    print(
        f"flows={n}  mode={mode}  windows={result.window_count}  "
        f"alerts={len(result.alerts)}  time={dt:.2f}s  ->  {n / dt:,.0f} flows/sec"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
