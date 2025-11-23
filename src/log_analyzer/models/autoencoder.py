"""PyTorch tabular autoencoder for unsupervised anomaly detection.

Trained on the assumption that the bulk of training data is benign;
reconstruction error of unseen inputs serves as the anomaly score.
"""

from __future__ import annotations

import numpy as np
import torch
from torch import nn
from torch.utils.data import DataLoader, TensorDataset

from .base import AnomalyModel


class _Net(nn.Module):
    def __init__(self, n_features: int, hidden: int = 32, latent: int = 8):
        super().__init__()
        self.enc = nn.Sequential(
            nn.Linear(n_features, hidden),
            nn.ReLU(),
            nn.Linear(hidden, latent),
            nn.ReLU(),
        )
        self.dec = nn.Sequential(
            nn.Linear(latent, hidden),
            nn.ReLU(),
            nn.Linear(hidden, n_features),
        )

    def forward(self, x):
        return self.dec(self.enc(x))


class AutoencoderModel(AnomalyModel):
    name = "autoencoder"

    def __init__(
        self,
        hidden: int = 32,
        latent: int = 8,
        epochs: int = 30,
        lr: float = 1e-3,
        batch_size: int = 256,
        device: str | None = None,
    ):
        self.hidden = hidden
        self.latent = latent
        self.epochs = epochs
        self.lr = lr
        self.batch_size = batch_size
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self._net: _Net | None = None
        self._err_lo: float | None = None
        self._err_hi: float | None = None

    def _build(self, n_features: int) -> None:
        self._net = _Net(n_features, self.hidden, self.latent).to(self.device)

    def fit(self, X: np.ndarray) -> "AutoencoderModel":
        self._build(X.shape[1])
        assert self._net is not None
        ds = TensorDataset(torch.from_numpy(X.astype(np.float32)))
        dl = DataLoader(ds, batch_size=self.batch_size, shuffle=True)
        opt = torch.optim.Adam(self._net.parameters(), lr=self.lr)
        loss_fn = nn.MSELoss()
        self._net.train()
        for _ in range(self.epochs):
            for (batch,) in dl:
                batch = batch.to(self.device)
                opt.zero_grad()
                recon = self._net(batch)
                loss = loss_fn(recon, batch)
                loss.backward()
                opt.step()
        # calibrate
        err = self._reconstruction_error(X)
        self._err_lo = float(err.min())
        self._err_hi = float(np.quantile(err, 0.99))
        return self

    def _reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        assert self._net is not None
        self._net.eval()
        with torch.no_grad():
            x = torch.from_numpy(X.astype(np.float32)).to(self.device)
            recon = self._net(x)
            err = ((recon - x) ** 2).mean(dim=1).cpu().numpy()
        return err

    def score(self, X: np.ndarray) -> np.ndarray:
        err = self._reconstruction_error(X)
        if self._err_lo is None or self._err_hi is None:
            return err
        denom = max(self._err_hi - self._err_lo, 1e-9)
        return np.clip((err - self._err_lo) / denom, 0.0, 1.0)
