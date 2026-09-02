"""Temporal sequence scoring over a host's burst timeline (NetMamba-inspired).

The TB-Graph captures *structure*; this model captures *order and rhythm* - it
reads the sequence of Traffic Bursts a host produced in the window and looks for
temporal signatures: clock-regular check-ins (C2 beacon), a sudden volume regime
shift (exfil onset), a monotone ramp (flood / scan build-up).

Two implementations behind :class:`SequenceThreatScorer`:

* ``SequenceModel`` - a GRU/SSM sequence classifier (PyTorch, ``[ml]`` extra),
  the lightweight cousin of NetMamba's unidirectional Mamba encoder. Trained by
  ``training/train_sequence.py``.
* ``HeuristicSequenceScorer`` - dependency-free: autocorrelation of inter-burst
  gaps + regime-shift + escalation. Runs when torch is absent so the fourth
  signal is always available.

Contribution is **additive evidence only** - it never changes the fused
confidence or the threat class chosen by the detector.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from uninet.detection.threat_types import ThreatType
from uninet.schemas.burst import Direction, TrafficBurst
from uninet.utils import clamp01, coefficient_of_variation, periodicity_score

try:  # optional heavy stack
    import torch  # type: ignore

    _TORCH = True
except ImportError:  # pragma: no cover - env dependent
    _TORCH = False

_SEQ_FEATURES = ["log_bytes", "log_flows", "log_gap", "dir_code", "intra_periodicity"]
_DIR_CODE = {Direction.OUTBOUND: 1.0, Direction.INBOUND: -1.0, Direction.UNKNOWN: 0.0}
_MIN_BURSTS = 3


@dataclass
class SequenceScore:
    score: float
    threat_hint: ThreatType
    rationale: str = ""
    features: dict[str, float] = field(default_factory=dict)


def sequence_matrix(bursts: list[TrafficBurst]) -> np.ndarray:
    """[n_bursts, len(_SEQ_FEATURES)] ordered by start time."""
    bs = sorted(bursts, key=lambda b: b.start_ts)
    starts = [b.start_ts for b in bs]
    gaps = [0.0] + [b - a for a, b in zip(starts, starts[1:])]
    rows = [
        [
            np.log1p(b.byte_count),
            np.log1p(b.flow_count),
            np.log1p(max(g, 0.0)),
            _DIR_CODE.get(b.direction, 0.0),
            float(b.intra_periodicity),
        ]
        for b, g in zip(bs, gaps)
    ]
    return np.asarray(rows, dtype=float) if rows else np.zeros((0, len(_SEQ_FEATURES)))


class SequenceThreatScorer:
    def __init__(self, model_path: str | Path | None = None) -> None:
        self._model: SequenceModel | None = None
        if model_path and _TORCH and Path(model_path).is_file():
            try:
                self._model = SequenceModel.load(model_path)
            except Exception:  # pragma: no cover - incompatible checkpoint
                self._model = None
        self._heuristic = HeuristicSequenceScorer()

    @property
    def backend(self) -> str:
        return "gru" if self._model is not None else "heuristic"

    def score(self, bursts: list[TrafficBurst], host_ip: str = "") -> SequenceScore:
        if self._model is not None:
            try:
                return self._model.score(bursts)
            except Exception:  # pragma: no cover
                pass
        return self._heuristic.score(bursts)


class HeuristicSequenceScorer:
    def score(self, bursts: list[TrafficBurst]) -> SequenceScore:
        if len(bursts) < _MIN_BURSTS:
            return SequenceScore(0.0, ThreatType.BENIGN, "too few bursts for a temporal read")

        bs = sorted(bursts, key=lambda b: b.start_ts)
        starts = [b.start_ts for b in bs]
        vols = np.array([float(b.byte_count) for b in bs])
        gaps = np.diff(starts)

        regularity = periodicity_score(starts)                       # 1.0 == perfect beacon
        gap_cov = coefficient_of_variation(gaps) if gaps.size else 0.0
        rising = float(np.mean(np.diff(vols) > 0)) if vols.size > 1 else 0.0
        vmax = float(vols.max()) or 1.0
        regime_shift = float(np.max(np.abs(np.diff(vols))) / vmax) if vols.size > 1 else 0.0
        flips = sum(
            1 for a, b in zip(bs, bs[1:])
            if a.direction != b.direction and Direction.UNKNOWN not in (a.direction, b.direction)
        ) / max(len(bs) - 1, 1)
        mean_bytes = float(vols.mean())
        max_ports = max((b.unique_dst_ports for b in bs), default=0)

        score = clamp01(
            0.65 * regularity
            + 0.20 * regime_shift
            + 0.10 * rising
            + 0.05 * flips
        )

        if regularity >= 0.75 and mean_bytes < 8000:
            hint = ThreatType.C2_BEACON
            why = f"clock-regular burst cadence (periodicity {regularity:.2f}, gap CoV {gap_cov:.2f})"
        elif rising >= 0.7 and max_ports >= 20:
            hint = ThreatType.PORT_SCAN
            why = f"monotone burst escalation across {max_ports} ports"
        elif rising >= 0.7 and len(bs) >= 5:
            hint = ThreatType.DDOS
            why = f"monotone volume ramp over {len(bs)} bursts"
        elif regime_shift >= 0.6 and vmax > 5e6:
            hint = ThreatType.DATA_EXFIL
            why = f"abrupt egress regime shift ({regime_shift:.2f} of peak in one step)"
        elif score >= 0.5:
            hint = ThreatType.UNKNOWN
            why = "irregular but structured burst sequence"
        else:
            hint = ThreatType.BENIGN
            why = "burst timeline within normal temporal bounds"

        return SequenceScore(
            score, hint, why,
            features={
                "regularity": round(regularity, 3),
                "gap_cov": round(float(gap_cov), 3),
                "regime_shift": round(regime_shift, 3),
                "rising_fraction": round(rising, 3),
                "direction_flip_rate": round(flips, 3),
            },
        )


# ====================================================================== #
#  GRU sequence classifier (optional - requires torch)
# ====================================================================== #
if _TORCH:  # pragma: no cover - exercised only with the ml extra
    import torch
    import torch.nn.functional as F
    from torch import nn

    _THREATS = list(ThreatType)

    class _SeqNet(nn.Module):
        def __init__(self, in_dim: int = len(_SEQ_FEATURES), hidden: int = 48):
            super().__init__()
            self.gru = nn.GRU(in_dim, hidden, batch_first=True, bidirectional=False)
            self.head = nn.Linear(hidden, len(_THREATS))

        def forward(self, x):  # x: [B, T, F]
            _, h = self.gru(x)
            return self.head(h.squeeze(0))

    class SequenceModel:
        def __init__(self, net: _SeqNet | None = None, in_dim: int = len(_SEQ_FEATURES)):
            self.in_dim = in_dim
            self.net = net or _SeqNet(in_dim)
            self.net.eval()

        @staticmethod
        def to_tensor(bursts: list[TrafficBurst]):
            m = sequence_matrix(bursts)
            if m.shape[0] < _MIN_BURSTS:
                return None
            return torch.tensor(m, dtype=torch.float32).unsqueeze(0)

        def score(self, bursts: list[TrafficBurst]) -> SequenceScore:
            x = self.to_tensor(bursts)
            if x is None:
                return SequenceScore(0.0, ThreatType.BENIGN, "too few bursts")
            with torch.no_grad():
                probs = F.softmax(self.net(x), dim=-1).squeeze(0)
            k = int(torch.argmax(probs))
            benign_i = _THREATS.index(ThreatType.BENIGN)
            return SequenceScore(
                float(1.0 - probs[benign_i]), _THREATS[k],
                f"GRU sequence p={float(probs[k]):.2f} for {_THREATS[k].value}",
            )

        def save(self, path: str | Path) -> None:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            torch.save({"state_dict": self.net.state_dict(), "in_dim": self.in_dim}, path)

        @classmethod
        def load(cls, path: str | Path) -> SequenceModel:
            blob = torch.load(path, map_location="cpu")
            m = cls(in_dim=blob.get("in_dim", len(_SEQ_FEATURES)))
            m.net.load_state_dict(blob["state_dict"])
            m.net.eval()
            return m

else:  # torch not installed - keep the name importable

    class SequenceModel:  # type: ignore
        def __init__(self, *_, **__):
            raise RuntimeError('SequenceModel needs the ml extra: pip install -e ".[ml]"')

        @classmethod
        def load(cls, *_a, **_k):
            raise RuntimeError('SequenceModel needs the ml extra: pip install -e ".[ml]"')
