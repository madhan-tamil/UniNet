"""Train the GRU burst-sequence classifier (Phase 2 · 4th signal).

Requires the ``ml`` extra (torch). Without it this prints a skip notice and
exits 0 - the detector then uses ``HeuristicSequenceScorer``, so the signal is
still produced.

    python -m uninet.training.train_sequence --epochs 40
    python -m uninet.training.train_sequence --dataset tii --limit 100000
"""
from __future__ import annotations

import argparse

from uninet.config import load_settings
from uninet.detection.threat_types import ThreatType
from uninet.ingestion.sources.synthetic import SyntheticSource
from uninet.training._samples import Sample, build_samples

try:
    import torch  # type: ignore

    _TORCH = True
except ImportError:
    _TORCH = False


def _collect(dataset: str, limit: int) -> list[Sample]:
    if dataset == "tii":
        from uninet.datasets.tii_ssrc23 import load_tii_ssrc23

        recs, labels = load_tii_ssrc23(limit=limit)
        return build_samples(recs, flow_labels=labels)
    out: list[Sample] = []
    for seed in range(16):
        src = SyntheticSource(seed=seed)
        out += build_samples(src.collect(), host_labels=src.labels)
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dataset", choices=["synthetic", "tii"], default="synthetic")
    p.add_argument("--limit", type=int, default=100_000)
    p.add_argument("--epochs", type=int, default=40)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--out", default=None)
    args = p.parse_args(argv)

    if not _TORCH:
        print('torch not installed - skipping. Install: pip install -e ".[ml]"')
        return 0

    import torch.nn.functional as F
    from torch.nn.utils.rnn import pad_sequence
    from torch.utils.data import DataLoader

    from uninet.detection.sequence_model import SequenceModel, sequence_matrix

    settings = load_settings()
    threats = list(ThreatType)
    label_idx = {t: i for i, t in enumerate(threats)}

    seqs, ys = [], []
    for s in _collect(args.dataset, args.limit):
        m = sequence_matrix(s.features.bursts)
        if m.shape[0] < 3:
            continue
        seqs.append(torch.tensor(m, dtype=torch.float32))
        ys.append(label_idx[s.label])
    if len(seqs) < 8:
        print(f"not enough sequences ({len(seqs)})")
        return 1

    idx = list(range(len(seqs)))
    split = max(1, int(0.8 * len(idx)))

    def collate(batch):
        xs, ls = zip(*batch)
        return pad_sequence(xs, batch_first=True), torch.tensor(ls)

    train = DataLoader([(seqs[i], ys[i]) for i in idx[:split]], batch_size=16,
                       shuffle=True, collate_fn=collate)
    val = [(seqs[i], ys[i]) for i in idx[split:]]

    model = SequenceModel()
    opt = torch.optim.Adam(model.net.parameters(), lr=args.lr, weight_decay=5e-4)
    for epoch in range(1, args.epochs + 1):
        model.net.train()
        tot = 0.0
        for xb, yb in train:
            opt.zero_grad()
            loss = F.cross_entropy(model.net(xb), yb)
            loss.backward()
            opt.step()
            tot += float(loss)
        if epoch % 10 == 0 or epoch == args.epochs:
            model.net.eval()
            with torch.no_grad():
                acc = (
                    sum(int(model.net(x.unsqueeze(0)).argmax() == t) for x, t in val)
                    / max(len(val), 1)
                )
            print(f"epoch {epoch:3d}  loss {tot / max(split, 1):.4f}  val_acc {acc:.3f}")

    out = args.out or settings.model_path_sequence
    model.save(out)
    print(f"saved sequence model -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
