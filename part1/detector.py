"""Part 1: supervised classifier that turns network flows into alert JSON."""
import argparse, json, random, time
import datetime as dt
import joblib, requests
import pandas as pd

# ---- the one thing to change at final hookup: Part 3's address ----
URL = "http://<dell-ip>:8000/alert"
# --------------------------------------------------------------------

bundle = joblib.load("models/rf_detector.joblib")
model, FEATURES = bundle["model"], bundle["features"]
MEAN, STD = bundle["mean"], bundle["std"]
IMPORTANCE = dict(zip(FEATURES, model.feature_importances_))

# Demo only: the dataset has no IPs, so we simulate them.
ATTACKERS = {"BruteForce": ["203.0.113.10", "203.0.113.11"],
             "DoS": ["198.51.100.7"],
             "PortScan": ["192.0.2.55"]}


def explain(row, k=3):
    """Top-k features that look most abnormal vs normal traffic, weighted by model importance."""
    score = {f: IMPORTANCE[f] * abs((row[f] - MEAN[f]) / STD[f]) for f in FEATURES}
    top = sorted(score, key=score.get, reverse=True)[:k]
    return {f: round(float(row[f]), 2) for f in top}


def build_alert(row, probs, meta):
    idx = int(probs.argmax())
    label = str(model.classes_[idx])
    if label == "Benign":
        return None
    return {
        "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "part1",
        "src_ip": meta["src_ip"],
        "dst_ip": meta["dst_ip"],
        "dst_port": meta["dst_port"],
        "label": label,                      # BruteForce | DoS | PortScan
        "confidence": round(float(probs[idx]), 2),
        "top_features": explain(row),
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


def make_meta(row, true_label):
    if true_label in ATTACKERS:
        src = random.choice(ATTACKERS[true_label])
    else:
        src = f"10.0.0.{random.randint(2, 50)}"
    return {"src_ip": src, "dst_ip": "192.168.10.5", "dst_port": int(row["Destination Port"])}


def detect(flows, metas, url=URL, post=False, delay=0.0):
    """flows: DataFrame with the FEATURES columns; metas: one dict (src_ip, dst_ip, dst_port) per flow."""
    X = flows[FEATURES]
    probs = model.predict_proba(X)
    n = 0
    for i in range(len(X)):
        alert = build_alert(X.iloc[i], probs[i], metas[i])
        if alert:
            send(alert, url, post)
            n += 1
            if delay:
                time.sleep(delay)
    print(f"{n} alerts from {len(X)} flows")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", default="demo_flows.csv")
    ap.add_argument("--url", default=URL)
    ap.add_argument("--send", action="store_true", help="POST alerts to the URL (default: just print them)")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between alerts, for a live-looking demo")
    a = ap.parse_args()

    df = pd.read_csv(a.flows)
    true = df["true_label"] if "true_label" in df else pd.Series([None] * len(df))
    metas = [make_meta(df.iloc[i], true.iloc[i]) for i in range(len(df))]
    detect(df, metas, url=a.url, post=a.send, delay=a.delay)
