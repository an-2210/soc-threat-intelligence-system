# Part 1: Supervised Classifier (CIC-IDS2017)

Classifies network flows as Benign / DoS / PortScan / BruteForce using Random Forest and
HistGradientBoosting, and emits alert JSON to the SOC dashboard (Part 3).

## Contents
- part1_classifier.ipynb : full pipeline (cleaning, feature selection, training, evaluation, ablation, cross-dataset test)
- detector.py : loads the trained Random Forest and emits alert JSON
- test_receiver.py : tiny local stand-in for Part 3's POST /alert endpoint
- demo_flows.csv : 80 real test flows (20 per class) for demos
- alert_example.json : one sample alert in the agreed format
- models/ : trained models
- figures/ : confusion matrices, feature importances, result tables

## Setup
    python3.11 -m venv venv && source venv/bin/activate
    pip install -r requirements.txt

## Data (not included in the repo)
- CIC-IDS2017 MachineLearningCSV (UNB): put the Monday, Tuesday, Wednesday and Friday-Afternoon-PortScan CSVs in data/
- CSE-CIC-IDS2018 (Wednesday-14-02-2018 and Friday-16-02-2018, "Processed Traffic Data for ML Algorithms") in data2018/

## Run the detector
Print alerts only:

    python detector.py

Send alerts to a dashboard (change the URL to Part 3's address):

    python detector.py --send --url http://<dell-ip>:8000/alert --delay 0.5

Local test without Part 3:

    python test_receiver.py                    (terminal 1)
    python detector.py --send --url http://127.0.0.1:8000/alert   (terminal 2)

## Alert format
    POST /alert
    {"timestamp": "2026-10-21T05:52:22Z", "source": "part1", "src_ip": "...", "dst_ip": "...",
     "dst_port": 21, "label": "BruteForce", "confidence": 1.0,
     "top_features": {"Destination Port": 21.0, "...": 0.0}}
Labels from this part: BruteForce, DoS, PortScan. IP addresses are simulated in demo mode because the dataset contains none. They are random placeholders and never depend on the true label.

## Results (CIC-IDS2017, 80/20 stratified split, 25 features)
- Accuracy on the 20% held-out test split (116,485 flows): Random Forest 0.9994, HistGradientBoosting 0.9994
- Random Forest macro F1 0.9994, HistGradientBoosting macro F1 0.9993 (train 78s vs 15s)
- Without Destination Port: macro F1 0.9985 (BruteForce 0.9995 -> 0.9970)

## CSE-CIC-IDS2018 (Wednesday-14-02-2018 and Friday-16-02-2018, official processed files)

Results on a 30% holdout of 2018 flows (60,033 flows; 200,108 flows sampled from the two days, 50,000 cap per attack type):

| Model | Benign | DoS Hulk | SSH brute force | FTP brute force (16 flows) | SlowHTTPTest (17 flows) | 2017 test accuracy |
|---|---|---|---|---|---|---|
| Trained on 2017 only (previous model) | 98.14% | 2.95% | 0.02% | 0% | 0% | 0.9994 |
| Trained on 2017 + 2018 training part (current) | 99.98% | 100.00% | 99.99% | 37.5% | 5.9% | 0.9994 |

- The current model is `models/rf_detector.joblib`. The previous one is kept as `models/rf_detector_2017_only.joblib`.
- Results are in `figures/cross_2018_retrain.csv`.
- **This is not a test on unseen attacks.** The 2018 holdout is a random 30% of the same two days, so the same attack tools and time periods appear in training. The 100% and 99.99% show the model learned 2018 traffic. They do not show it would detect a new attack family.
- The 2017-only row is the real cross-dataset test: a model that never saw 2018 misses DoS Hulk and SSH brute force almost entirely.
- FTP brute force and SlowHTTPTest have too few flows here (16 and 17) for a reliable rate.
- PortScan does not exist in 2018, so it is not part of this table.
