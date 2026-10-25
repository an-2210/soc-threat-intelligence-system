# Part 2: Zero-Day Anomaly Detector (CIC-IDS2017)

Learns only what normal traffic looks like, then flags flows that look unlike it. Attacks are never shown to the models during training, so the detector does not need to know an attack type to raise an alert. Output is alert JSON for the SOC dashboard (Part 3).

This version uses CIC-IDS2017 (MachineLearningCVE) instead of UNSW-NB15.

## Contents
- prep.py : shared preprocessing and the autoencoder class (used by both training and detection)
- train.py : trains Isolation Forest and an autoencoder on BENIGN rows, sets thresholds, evaluates, saves models
- anomaly.py : loads the models and emits alert JSON (label "Anomaly")
- test_receiver.py : local stand-in for Part 3's POST /alert endpoint (same as Part 1)
- demo_flows.csv : 80 held-out flows (20 BENIGN, 20 each of DDoS, PortScan, DoS Hulk) for demos
- models/ : anomaly_bundle.joblib (scaler, feature list, Isolation Forest, thresholds), autoencoder.pt
- results/ : model_comparison.csv, per_attack_detection.csv, data_split.csv, roc_curves.png

## Setup
    python3 -m venv venv && source venv/bin/activate
    pip install -r requirements.txt

## Data (not included in the repo)
Put the eight MachineLearningCVE CSVs in data/ (or make a symlink named data pointing to them).
The training script reads every *.csv in that folder.

    Monday, Tuesday, Wednesday, Thursday-Morning-WebAttacks, Thursday-Afternoon-Infilteration,
    Friday-Morning, Friday-Afternoon-PortScan, Friday-Afternoon-DDos

## Train
    python3 train.py --data data

Rewrites models/, results/ and demo_flows.csv. The autoencoder alone took about 100 seconds in the last run.

## Run the detector
Print alerts only (autoencoder is the default model):

    python3 anomaly.py

Choose the Isolation Forest instead:

    python3 anomaly.py --model iforest

Send alerts to a dashboard (change the URL to Part 3's address):

    python3 anomaly.py --send --url http://<dell-ip>:8000/alert --delay 0.5

Local test without Part 3 (use test_receiver.py on port 8000, or change the port in both files if something else already uses it):

    python3 test_receiver.py                                        (terminal 1)
    python3 anomaly.py --send --url http://127.0.0.1:8000/alert     (terminal 2)

## How it works
1. Normal traffic only: BENIGN rows are split 70 / 15 / 15 (train / validation / test). Attack rows are never used for fitting, early stopping or thresholds.
2. Preprocessing: drop rows with NaN or Infinity (about 0.1% of rows), drop the duplicate column "Fwd Header Length.1", signed-log the heavy-tailed features, standardise with statistics from the training rows, and drop features that are constant in training (8 dropped, 69 kept).
3. Isolation Forest (200 trees) and an autoencoder (69 to 64 to 32 to 12 to 32 to 64 to 69, MSE loss, Adam, early stopping on validation normal MSE). The autoencoder stopped at epoch 55 of 60.
4. Threshold: the 99th percentile of validation normal scores, so about 1% of normal flows alert.
5. Confidence in an alert = share of validation normal flows that this flow scores above. An alert at 0.99 means it is more unusual than 99% of normal traffic.

## Alert format
    {"timestamp": "2026-10-25T16:23:30Z", "source": "part2", "src_ip": "...", "dst_ip": "192.168.10.5",
     "dst_port": 443, "label": "Anomaly", "confidence": 0.9974,
     "top_features": {"Bwd IAT Std": 7235135.5, "Fwd IAT Std": 0.0, "Init_Win_bytes_forward": 256.0}}

CIC-IDS2017 MachineLearningCVE has no IP columns, so source addresses are chosen at random from a list of placeholders in anomaly.py. If a flow file has a "Source IP" column, that value is used. The detector never looks at the true label.

`top_features` lists the three features the chosen model finds most abnormal: reconstruction error per feature for the autoencoder, and the absolute standardised value for Isolation Forest.

## Results (test set: 15% of normal flows plus every attack row, 556,556 attack flows)

| Model | ROC-AUC | Normal flows alerted (test) | Attack flows detected |
|---|---|---|---|
| Isolation Forest | 0.818 | 1.04% | 0.9% |
| Autoencoder (default) | 0.936 | 1.00% | 52.9% |

Per attack type, detection rate at the same threshold (never seen in training):

| Attack | Test rows | Isolation Forest | Autoencoder | Autoencoder ROC-AUC |
|---|---|---|---|---|
| DDoS | 128,025 | 0.0% | 85.0% | 0.994 |
| DoS slowloris | 5,796 | 25.1% | 68.8% | 0.993 |
| DoS Slowhttptest | 5,499 | 55.0% | 41.6% | 0.990 |
| DoS Hulk | 230,124 | 0.2% | 61.7% | 0.901 |
| DoS GoldenEye | 10,293 | 0.1% | 27.4% | 0.957 |
| PortScan | 158,804 | 0.1% | 21.7% | 0.945 |
| FTP-Patator | 7,935 | 0.0% | 0.6% | 0.919 |
| SSH-Patator | 5,897 | 0.0% | 0.2% | 0.748 |
| Bot | 1,956 | 0.0% | 1.6% | 0.714 |
| Web Attack - Brute Force | 1,507 | 0.0% | 0.0% | 0.876 |
| Web Attack - XSS | 652 | 0.0% | 0.0% | 0.899 |
| Infiltration | 36 | 63.9% | 86.1% | 0.977 |
| Web Attack - Sql Injection | 21 | 0.0% | 0.0% | 0.771 |
| Heartbleed | 11 | 100% | 100% | 0.998 |

Full numbers are in results/. Infiltration, SQL Injection and Heartbleed have very few rows, so their rates are not reliable.

## Limitations
- Detection is low for most attacks at a 1% false-positive budget. Patator, Web Attacks and Bot look almost like normal flows in these features, so this detector does not catch them. A supervised model (Part 1) or a lower threshold would be needed, with more false alarms.
- The benign split is random across all days, so the normal test flows come from the same days as training. The false-positive rate on a new day could be higher.
- The autoencoder was chosen as the default after both models were tested. Both configurations were fixed before the test run, but the choice itself used the test numbers, so treat the autoencoder's results as slightly optimistic.
- Source IP addresses are simulated.
- Tested on this one dataset only. Part 1's cross-dataset test on CSE-CIC-IDS2018 has not been run for this model.
