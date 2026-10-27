"""Part 2: zero-day anomaly detector. Flags flows that look unlike normal traffic and emits alert JSON.

The models were trained on BENIGN traffic only, so they never learned any attack. Nothing here uses the true label."""
import argparse
import datetime as dt
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import joblib
import numpy as np
import pandas as pd
import requests
import torch

import prep

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- the one thing to change at final hookup: Part 3's address ----
URL = "http://<dell-ip>:8000/alert"
# --------------------------------------------------------------------

DST_IP = "192.168.10.5"
# CIC-IDS2017 MachineLearningCVE has no IP columns, so demo sources are placeholders chosen at random.
# Real flows with a "Source IP" column use that column instead.
SIMULATED_SOURCES = ["203.0.113.10", "203.0.113.11", "198.51.100.7", "192.0.2.55", "10.0.0.5", "10.0.0.23"]
TOP_K = 3


class Detector:
    def __init__(self, name):
        self.name = name
        bundle = joblib.load(os.path.join(HERE, "models", "anomaly_bundle.joblib"))
        self.bundle = bundle
        self.threshold = bundle["thresholds"][name]
        self.grid = bundle["grids"][name]
        if name == "iforest":
            self.model = bundle["iforest"]
        else:
            self.model = prep.Autoencoder(len(bundle["features"]))
            self.model.load_state_dict(torch.load(os.path.join(HERE, "models", "autoencoder.pt"), weights_only=True))
            self.model.eval()

    def score(self, x):
        """Higher = more unlike normal traffic. Same scale as the threshold."""
        if self.name == "iforest":
            return -self.model.score_samples(x)
        return prep.ae_squared_error(self.model, x).mean(axis=1)

    def abnormality(self, x):
        """Per-feature abnormality, used to pick the features shown in each alert."""
        if self.name == "iforest":
            return np.abs(x)
        return prep.ae_squared_error(self.model, x)


def load_flows(path):
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    return df


def build_alert(row, score, conf, src_ip, top):
    return {
        "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "part2",
        "src_ip": src_ip,
        "dst_ip": DST_IP,
        "dst_port": int(row["Destination Port"]),
        "label": "Anomaly",
        "confidence": round(conf, 4),
        "top_features": {f: round(float(row[f]), 2) for f in top},
    }


def send(alert, url, post):
    if not post:
        print(json.dumps(alert))
        return
    try:
        r = requests.post(url, json=alert, timeout=3)
        print(r.status_code, alert["label"], alert["src_ip"], alert["confidence"])
    except requests.RequestException as e:
        print("Could not reach dashboard:", e)


def detect(flows, det, url=URL, post=False, delay=0.0, custom_src=None, custom_dst=None):
    x = prep.transform(flows, det.bundle)
    scores = det.score(x)
    abnormal = det.abnormality(x)
    features = det.bundle["features"]
    n = 0
    for i in range(len(flows)):
        if scores[i] <= det.threshold:
            continue
        row = flows.iloc[i]
        top = [features[j] for j in np.argsort(-abnormal[i])[:TOP_K]]
        src = custom_src or (row["Source IP"] if "Source IP" in row else random.choice(SIMULATED_SOURCES))
        conf = prep.confidence(scores[i], det.grid)
        alert = build_alert(row, scores[i], conf, src, top)
        if custom_dst:
            alert["dst_ip"] = custom_dst
        send(alert, url, post)
        n += 1
        if delay:
            time.sleep(delay)
    print(f"{n} alerts from {len(flows)} flows (model: {det.name}, threshold {det.threshold:.4f})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", default=os.path.join(HERE, "demo_flows.csv"))
    ap.add_argument("--model", choices=["autoencoder", "iforest"], default="autoencoder")
    ap.add_argument("--url", default=URL)
    ap.add_argument("--src-ip", default=None, help="Custom source IP to assign to alerts (default: simulated)")
    ap.add_argument("--dst-ip", default=None, help="Custom destination IP (default: 192.168.10.5)")
    ap.add_argument("--send", action="store_true", help="POST alerts to the URL (default: just print them)")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between alerts, for a live-looking demo")
    a = ap.parse_args()

    detect(load_flows(a.flows), Detector(a.model), url=a.url, post=a.send, delay=a.delay, custom_src=a.src_ip, custom_dst=a.dst_ip)
