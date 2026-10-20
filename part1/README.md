# Part 1: Supervised Classifier (CIC-IDS2017)

Classifies network flows as Benign / DoS / PortScan / BruteForce with Random Forest and a gradient boosting model,
and emits alert JSON to the SOC dashboard (Part 3).

## Setup
python3.11 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

## Data (not included in the repo)
- CIC-IDS2017 MachineLearningCSV (UNB): put the Monday, Tuesday, Wednesday and Friday-Afternoon-PortScan CSVs in `data/`
- CSE-CIC-IDS2018 (Wed-14-02 and Fri-16-02 files) in `data2018/` for the cross-dataset test

## Run
- `part1_classifier.ipynb`: preprocessing, feature selection, training, evaluation, cross-dataset test
- `python detector.py`: replays `demo_flows.csv` and prints alert JSON
