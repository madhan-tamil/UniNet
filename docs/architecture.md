# UniNet architecture (Phases 1, 2, 5)

```
 one-way tap / data diode
          │
          ▼
   ingestion/sources         PCAP · NetFlow · IPFIX · sFlow · synthetic
          │   FlowRecord (normalized, unidirectional)
          ▼
   streaming/bus             InProcBus (default) │ KafkaBus (one-way topic)
          │
          ▼
   features/extractor        flow · DNS · TLS/JA3 · temporal  ──►  fixed vector
          │                                                   +  behavioural fingerprint
          ▼
   tb_graph/                 burst_builder → graph_builder → graph_store
     ⭐ Traffic-Burst graph   nodes: host, burst, domain
                             edges: emits, burst_in/out, direction_change, periodic, resolves
          │
          ▼
   detection/                rules (statistical)                       ┐
                             anomaly_model (IsoForest / baseline)      ├─ evidence
                             rgat_model (RGAT │ heuristic graph)       │   fusion ─► Alert
                             sequence_model (GRU │ heuristic temporal) ┘
          │
          ▼
   api/app.py                Flask: /api/alerts /api/graph /api/explain /api/ask
          │                        + /api/stream (SSE) + dashboard
          ▼
   explainability/  narrative · key factors · burst timeline · fusion bars
   assistant/       offline read-only Q&A over the alert + explanation + subgraph
```

Sequence model is **additive evidence only** — it never changes the fused
confidence or the chosen threat class.

## Windowing

`run_pipeline` processes flows in fixed `window_seconds` slices. Within a window,
flows are grouped by local host; each host yields one feature vector, a set of
bursts, a merged TB-Graph subgraph, and (if fused confidence ≥ threshold) one
`Alert`.

## Evidence fusion

```
confidence = w_rule·rule_score + w_anom·anomaly_score + w_graph·graph_score
             + corroboration_bonus     # when rule class == graph hint
```

Weights come from `config/config.yaml` (`fusion_weights`, renormalized to sum 1).
Threat class is taken from the most interpretable signal that fired: rules →
graph structure → `UNKNOWN` for a pure anomaly (the zero-day path).

## Phase 5 — scale-out (`streaming/service.py`)

```
        flows ──► partition by hash(local_host) % N ──► shard 0 … shard N-1
                                                          │        │
                              each shard: full Phase 1/2 pipeline (own Detector)
                                                          │        │
                                                          └── merge_results ──► one PipelineResult
```

* **`run_sharded(source, workers, executor)`** — `executor="process"` gives real
  parallelism (each worker rebuilds its own `Detector` + models); `"thread"` is
  used in tests. Every shard receives a **shared window anchor** (global earliest
  flow), so partitioning changes wall-clock time only, not detections — verified
  by `tests/test_service.py`.
* Partitioning on the local host keeps a host's entire TB-Graph on one worker
  (no cross-shard graph merges for the same host).
* **`LiveService`** — background thread that re-runs the pipeline every
  `--interval` seconds and hot-swaps the dashboard's `PipelineResult`
  (`uninet --live`). The console polls every 5 s and updates in place.
* Bench: `python -m uninet.eval.throughput_bench --flows 400000 --workers 4`.

Kafka path: `KafkaBus` is the one-way topic; N `run_sharded` workers map onto N
consumer-group members in a real deployment.

## "Read-only" — architecture, not the UI

"Read-only" describes the **sensor architecture**: passive tap / data diode, no
return path, no probing, no payload decryption, no mitigation commands. The
*console* is fully interactive (filtering, drill-down, live client view).

Enforced: `src/uninet/assistant/` must not import `socket`, `subprocess`,
`requests`, `scapy`, … (`tests/test_assistant_readonly.py`). The HTTP API exposes
no mutating routes; `POST /api/ask` is the offline templated assistant (no LLM,
no network) so the read-only guarantee holds by construction.
