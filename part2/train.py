"""Part 2 training. The models see only BENIGN traffic. Every attack row is held out and used only for testing."""
import argparse
import glob
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import joblib
import numpy as np
import pandas as pd
import torch
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score, roc_curve

import prep

HERE = os.path.dirname(os.path.abspath(__file__))
SEED = 42
TARGET_FPR = 0.01  # threshold = 99th percentile of validation normal scores, so about 1% of normal flows alert
MAX_EPOCHS, PATIENCE, BATCH = 60, 3, 1024
SCALER_ROWS = 300_000
DEMO_PER_CLASS = 20
DEMO_ATTACKS = ["DDoS", "PortScan", "DoS Hulk"]


def load_all(folder):
    benign, attacks, features = [], [], None
    for path in sorted(glob.glob(os.path.join(folder, "*.csv"))):
        df = prep.load_csv(path)
        cols = prep.feature_columns(df)
        assert features is None or features == cols, f"{path} has different columns"
        features = cols
        df, bad = prep.drop_bad_rows(df, features)
        df[features] = df[features].astype(np.float32)
        print(f"{os.path.basename(path)}: {len(df):,} rows kept, {bad:,} dropped (NaN/Inf)")
        benign.append(df[df[prep.LABEL] == prep.BENIGN])
        attacks.append(df[df[prep.LABEL] != prep.BENIGN])
    return pd.concat(benign, ignore_index=True), pd.concat(attacks, ignore_index=True), features


def train_autoencoder(x_train, x_val, n_features):
    model = prep.Autoencoder(n_features)
    opt = torch.optim.Adam(model.parameters(), lr=1e-3)
    loss_fn = torch.nn.MSELoss()
    xt, xv = torch.from_numpy(x_train), torch.from_numpy(x_val)
    best, best_state, bad = float("inf"), None, 0
    start = time.time()
    for epoch in range(1, MAX_EPOCHS + 1):
        model.train()
        perm = torch.randperm(len(xt))
        for i in range(0, len(xt), BATCH):
            xb = xt[perm[i:i + BATCH]]
            opt.zero_grad()
            loss = loss_fn(model(xb), xb)
            loss.backward()
            opt.step()
        model.eval()
        with torch.no_grad():
            val = loss_fn(model(xv), xv).item()  # early stopping uses normal validation traffic only
        print(f"  epoch {epoch:2d}  validation normal MSE {val:.5f}")
        if val < best - 1e-5:
            best, bad = val, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            bad += 1
            if bad >= PATIENCE:
                break
    model.load_state_dict(best_state)
    model.eval()
    return model, time.time() - start


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(HERE, "data"), help="folder with the CIC-IDS2017 MachineLearningCVE CSVs")
    a = ap.parse_args()
    torch.manual_seed(SEED)
    rng = np.random.default_rng(SEED)

    benign, attacks, features = load_all(a.data)
    print(f"\nBENIGN {len(benign):,} rows, attack rows {len(attacks):,}")

    # 70 / 15 / 15 random split of normal traffic. Attacks are never split into training data.
    order = rng.permutation(len(benign))
    n_tr, n_va = int(0.70 * len(benign)), int(0.15 * len(benign))
    tr, va, te = benign.iloc[order[:n_tr]], benign.iloc[order[n_tr:n_tr + n_va]], benign.iloc[order[n_tr + n_va:]]

    scaler_rows = tr[features].iloc[rng.choice(len(tr), SCALER_ROWS, replace=False)].to_numpy(np.float64)
    bundle = prep.fit_scaler(scaler_rows, features)
    n_features = len(bundle["features"])
    print(f"features used: {n_features} (constant-in-training features dropped: {len(features) - n_features})")

    x_tr, x_va, x_te = (prep.transform(d, bundle) for d in (tr, va, te))
    x_att = prep.transform(attacks, bundle)

    print("\nTraining Isolation Forest on BENIGN train rows")
    start = time.time()
    iforest = IsolationForest(n_estimators=200, max_samples=256, random_state=SEED, n_jobs=-1).fit(x_tr)
    if_time = time.time() - start

    print("\nTraining autoencoder on BENIGN train rows")
    ae, ae_time = train_autoencoder(x_tr, x_va, n_features)

    scorers = {
        "iforest": lambda x: -iforest.score_samples(x),  # higher = more anomalous
        "autoencoder": lambda x: prep.ae_squared_error(ae, x).mean(axis=1),
    }
    train_seconds = {"iforest": if_time, "autoencoder": ae_time}

    val_scores = {m: f(x_va) for m, f in scorers.items()}
    test_benign = {m: f(x_te) for m, f in scorers.items()}
    test_attack = {m: f(x_att) for m, f in scorers.items()}

    thresholds = {m: float(np.quantile(val_scores[m], 1 - TARGET_FPR)) for m in scorers}
    grids = {m: prep.percentile_grid(val_scores[m]) for m in scorers}

    labels = attacks[prep.LABEL].to_numpy()
    comparison, per_attack = [], {lab: {"attack": lab, "test_rows": int((labels == lab).sum())} for lab in sorted(set(labels))}
    roc = {}
    for m in scorers:
        thr, sb, sa = thresholds[m], test_benign[m], test_attack[m]
        y = np.r_[np.zeros(len(sb)), np.ones(len(sa))]
        s = np.r_[sb, sa]
        fpr, tpr, _ = roc_curve(y, s)
        roc[m] = (fpr, tpr)
        comparison.append({
            "model": m,
            "threshold": round(thr, 6),
            "validation_fpr": round(float((val_scores[m] > thr).mean()), 4),
            "test_fpr": round(float((sb > thr).mean()), 4),
            "roc_auc": round(roc_auc_score(y, s), 4),
            "attack_detection_rate": round(float((sa > thr).mean()), 4),
            "train_seconds": round(train_seconds[m], 1),
        })
        for lab in per_attack:
            sl = test_attack[m][labels == lab]
            per_attack[lab][f"{m}_detection_rate"] = round(float((sl > thr).mean()), 4)
            per_attack[lab][f"{m}_roc_auc"] = round(roc_auc_score(np.r_[np.zeros(len(sb)), np.ones(len(sl))], np.r_[sb, sl]), 4) if len(sl) else np.nan

    results = os.path.join(HERE, "results")
    models = os.path.join(HERE, "models")
    os.makedirs(results, exist_ok=True)
    os.makedirs(models, exist_ok=True)

    comparison = pd.DataFrame(comparison)
    per_attack = pd.DataFrame(sorted(per_attack.values(), key=lambda r: -r["test_rows"]))
    comparison.to_csv(os.path.join(results, "model_comparison.csv"), index=False)
    per_attack.to_csv(os.path.join(results, "per_attack_detection.csv"), index=False)
    pd.DataFrame({"split": ["benign_train", "benign_validation", "benign_test", "attacks_test_only"],
                  "rows": [len(tr), len(va), len(te), len(attacks)]}).to_csv(os.path.join(results, "data_split.csv"), index=False)

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(5, 5))
    for m, (fpr, tpr) in roc.items():
        ax.plot(fpr, tpr, label=m)
    ax.plot([0, 1], [0, 1], "k--", linewidth=0.8)
    ax.set_xlabel("False positive rate (normal test flows)")
    ax.set_ylabel("Detection rate (attack test flows)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(results, "roc_curves.png"), dpi=150)

    joblib.dump({"features": bundle["features"], "mean": bundle["mean"], "std": bundle["std"],
                 "iforest": iforest, "thresholds": thresholds, "grids": grids,
                 "target_fpr": TARGET_FPR, "seed": SEED}, os.path.join(models, "anomaly_bundle.joblib"))
    torch.save(ae.state_dict(), os.path.join(models, "autoencoder.pt"))

    # Demo flows: a small raw-format sample of held-out rows, like Part 1's demo_flows.csv. Used only for the demo.
    demo = [te.sample(DEMO_PER_CLASS, random_state=SEED).assign(true_label=prep.BENIGN)]
    for lab in DEMO_ATTACKS:
        demo.append(attacks[labels == lab].sample(DEMO_PER_CLASS, random_state=SEED).assign(true_label=lab))
    pd.concat(demo, ignore_index=True).to_csv(os.path.join(HERE, "demo_flows.csv"), index=False)

    print("\n=== Model comparison (test: held-out normal flows + all attack rows) ===")
    print(comparison.to_string(index=False))
    print("\n=== Per attack type (never seen in training) ===")
    print(per_attack.to_string(index=False))


if __name__ == "__main__":
    main()
