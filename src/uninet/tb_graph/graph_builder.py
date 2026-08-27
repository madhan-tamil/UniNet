"""Traffic Bursts -> TB-Graph (``networkx.MultiDiGraph``).

Node types:  HOST, BURST, DOMAIN
Edge (relation) types:
    EMITS             host  -> each of its bursts
    BURST_OUT/IN      burst -> chronologically next burst with same peer
    DIRECTION_CHANGE  same, but the traffic direction flipped between them
    PERIODIC          burst -> burst when that host<->peer chain is regular
    RESOLVES          burst -> domain it looked up

Burst node attributes are the RGAT input features.
"""
from __future__ import annotations

import networkx as nx

from uninet.schemas.burst import Direction, TrafficBurst
from uninet.schemas.graph import NodeType, RelationType
from uninet.utils import coefficient_of_variation

_DIR_CODE = {Direction.OUTBOUND: 1.0, Direction.INBOUND: -1.0, Direction.UNKNOWN: 0.0}


class GraphBuilder:
    def __init__(self, periodicity_cov_threshold: float = 0.35, min_chain: int = 3) -> None:
        self.cov_threshold = periodicity_cov_threshold
        self.min_chain = min_chain

    def build(self, bursts: list[TrafficBurst], graph: nx.MultiDiGraph | None = None) -> nx.MultiDiGraph:
        g = graph if graph is not None else nx.MultiDiGraph()
        if not bursts:
            return g

        for b in bursts:
            self._add_burst(g, b)

        # chain bursts per (host, peer)
        chains: dict[tuple[str, str], list[TrafficBurst]] = {}
        for b in bursts:
            chains.setdefault((b.host, b.peer), []).append(b)

        for (host, _peer), chain in chains.items():
            chain.sort(key=lambda b: b.start_ts)
            self._link_chain(g, chain)

        return g

    # ------------------------------------------------------------------ #
    def _add_burst(self, g: nx.MultiDiGraph, b: TrafficBurst) -> None:
        host_id = f"host:{b.host}"
        burst_id = f"burst:{b.burst_id}"

        if not g.has_node(host_id):
            g.add_node(host_id, ntype=NodeType.HOST.value, ip=b.host)
        g.add_node(
            burst_id,
            ntype=NodeType.BURST.value,
            host=b.host,
            peer=b.peer,
            direction=b.direction.value,
            start_ts=b.start_ts,
            duration=b.duration,
            flow_count=float(b.flow_count),
            packet_count=float(b.packet_count),
            byte_count=float(b.byte_count),
            mean_flow_bytes=b.mean_flow_bytes,
            unique_dst_ports=float(b.unique_dst_ports),
            dst_ports=list(b.dst_ports[:12]),
            domains=list(b.domains[:8]),
            protocols=list(b.protocols),
            intra_periodicity=b.intra_periodicity,
            dir_code=_DIR_CODE[b.direction],
        )
        g.add_edge(host_id, burst_id, key=RelationType.EMITS.value, rel=RelationType.EMITS.value)

        for dom in b.domains:
            dom_id = f"domain:{dom}"
            if not g.has_node(dom_id):
                g.add_node(dom_id, ntype=NodeType.DOMAIN.value, name=dom)
            g.add_edge(
                burst_id, dom_id, key=RelationType.RESOLVES.value,
                rel=RelationType.RESOLVES.value,
            )

    def _link_chain(self, g: nx.MultiDiGraph, chain: list[TrafficBurst]) -> None:
        if len(chain) < 2:
            return

        for prev, nxt in zip(chain, chain[1:]):
            a, b = f"burst:{prev.burst_id}", f"burst:{nxt.burst_id}"
            if prev.direction != nxt.direction and Direction.UNKNOWN not in (
                prev.direction, nxt.direction
            ):
                rel = RelationType.DIRECTION_CHANGE
            elif nxt.direction == Direction.INBOUND:
                rel = RelationType.BURST_IN
            else:
                rel = RelationType.BURST_OUT
            g.add_edge(a, b, key=rel.value, rel=rel.value, gap=nxt.start_ts - prev.start_ts)

        # periodic overlay across the whole chain
        if len(chain) >= self.min_chain:
            starts = [b.start_ts for b in chain]
            gaps = [j - i for i, j in zip(starts, starts[1:])]
            cov = coefficient_of_variation(gaps)
            if cov <= self.cov_threshold:
                for prev, nxt in zip(chain, chain[1:]):
                    g.add_edge(
                        f"burst:{prev.burst_id}", f"burst:{nxt.burst_id}",
                        key=RelationType.PERIODIC.value, rel=RelationType.PERIODIC.value,
                        interval_cov=cov,
                    )
