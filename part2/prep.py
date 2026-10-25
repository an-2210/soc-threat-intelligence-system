"""Shared code for Part 2. Training and detection both import this, so the preprocessing cannot drift apart."""
import numpy as np
import pandas as pd
import torch

LABEL = "Label"
BENIGN = "BENIGN"
DUPLICATE_COLUMN = "Fwd Header Length.1"  # identical copy of "Fwd Header Length" in the CIC-IDS2017 CSVs
CHUNK = 100_000


class Autoencoder(torch.nn.Module):
    """Learns to rebuild normal flows. Attacks rebuild badly, so their reconstruction error is high."""

    def __init__(self, n_features):
        super().__init__()
        self.net = torch.nn.Sequential(
            torch.nn.Linear(n_features, 64), torch.nn.ReLU(),
            torch.nn.Linear(64, 32), torch.nn.ReLU(),
            torch.nn.Linear(32, 12), torch.nn.ReLU(),  # bottleneck
            torch.nn.Linear(12, 32), torch.nn.ReLU(),
            torch.nn.Linear(32, 64), torch.nn.ReLU(),
            torch.nn.Linear(64, n_features),
        )

    def forward(self, x):
        return self.net(x)


def load_csv(path):
    """Read one CIC-IDS2017 CSV: strip the padded column names and repair the mangled dash in attack labels."""
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    df = df.drop(columns=[DUPLICATE_COLUMN], errors="ignore")
    df[LABEL] = df[LABEL].astype(str).str.strip().str.replace("�", "-", regex=False)
    return df


def feature_columns(df):
    return [c for c in df.columns if c != LABEL]


def drop_bad_rows(df, features):
    """Infinity and NaN cannot be scaled or scored. Drop those rows and return how many were dropped."""
    values = df[features].to_numpy(np.float64)
    bad = ~np.isfinite(values).all(axis=1)
    return df.loc[~bad].reset_index(drop=True), int(bad.sum())


def signed_log(x):
    """Flow counts and durations are heavy-tailed. A signed log keeps negative values and compresses the tail."""
    return np.sign(x) * np.log1p(np.abs(x))


def fit_scaler(raw_values, features):
    """Fit on training benign rows only. Features that are constant in training are dropped."""
    x = signed_log(raw_values.astype(np.float64))
    mean, std = x.mean(axis=0), x.std(axis=0)
    keep = std > 0
    return {"features": [f for f, k in zip(features, keep) if k], "mean": mean[keep], "std": std[keep]}


def transform(df, bundle):
    """Raw flow columns -> standardised float32 matrix, using the scaler and feature list saved at training time."""
    out = np.empty((len(df), len(bundle["features"])), np.float32)
    for start in range(0, len(df), CHUNK):
        raw = df[bundle["features"]].iloc[start:start + CHUNK].to_numpy(np.float64)
        out[start:start + CHUNK] = (signed_log(raw) - bundle["mean"]) / bundle["std"]
    return out


def ae_squared_error(model, x):
    """Per-feature squared reconstruction error, shape (rows, features)."""
    out = np.empty(x.shape, np.float32)
    with torch.no_grad():
        for start in range(0, len(x), CHUNK):
            xb = torch.from_numpy(x[start:start + CHUNK])
            out[start:start + CHUNK] = ((model(xb) - xb) ** 2).numpy()
    return out


def percentile_grid(val_scores, points=10001):
    """Maps a raw anomaly score to a confidence: the share of validation normal flows it scores above."""
    return np.quantile(val_scores, np.linspace(0, 1, points)), np.linspace(0, 1, points)


def confidence(score, grid):
    grid_scores, grid_probs = grid
    return float(np.interp(score, grid_scores, grid_probs))
