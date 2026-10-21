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
Labels from this part: BruteForce, DoS, PortScan. IP addresses are simulated in demo mode because the dataset contains none.

## Results (CIC-IDS2017, 80/20 stratified split, 25 features)
- Random Forest macro F1 0.9994, HistGradientBoosting macro F1 0.9993 (train 82s vs 20s)
- Without Destination Port: macro F1 0.9985 (BruteForce 0.9995 -> 0.9970)

## Limitation: cross-dataset generalisation
Tested on CSE-CIC-IDS2018 without retraining: Benign correctly handled (98.1%), but DoS Hulk detected only 3% (RF) / 10% (boosting)
and SSH brute force about 0.01%. Feature distributions differ strongly between the two datasets, so the models
should be retrained on local traffic before any real use. PortScan does not exist in 2018, and FTP-BruteForce and
SlowHTTPTest had too few unique flows to evaluate.
