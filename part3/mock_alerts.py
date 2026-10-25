"""Mock alert generator for testing the SOC Dashboard and FastAPI ingestion endpoint.

Generates realistic simulated security events:
- PortScan reconnaissance
- SSH / FTP BruteForce attempts
- DoS floods
- Zero-day Autoencoder anomalies
"""
import argparse
import datetime as dt
import json
import random
import time
import requests

ATTACKERS = [
    {"ip": "198.51.100.45", "name": "External Recon Bot", "role": "scanner"},
    {"ip": "203.0.113.88", "name": "Brute Force Worker", "role": "credential_stuffer"},
    {"ip": "192.0.2.140", "name": "DoS Botnet Node", "role": "flooder"},
    {"ip": "10.0.0.99", "name": "Compromised Internal Host", "role": "lateral_mover"},
    {"ip": "203.0.113.11", "name": "Persistent Threat Actor", "role": "multi_stage"},
]

TARGET_HOSTS = ["192.168.10.5", "192.168.10.15", "192.168.10.25"]
COMMON_PORTS = [21, 22, 80, 443, 3306, 8080, 8443]


def generate_portscan_alert(attacker_ip: str) -> dict:
    dst_port = random.choice([21, 22, 80, 135, 443, 445, 1433, 3306, 3389, 5000, 8080])
    return {
        "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "mock_part1",
        "src_ip": attacker_ip,
        "dst_ip": random.choice(TARGET_HOSTS),
        "dst_port": dst_port,
        "label": "PortScan",
        "confidence": round(random.uniform(0.96, 1.0), 2),
        "top_features": {
            "Destination Port": float(dst_port),
            "PSH Flag Count": 1.0,
            "Bwd Packets/s": round(random.uniform(15000, 250000), 1),
        },
        "is_synthetic": True,
    }


def generate_bruteforce_alert(attacker_ip: str) -> dict:
    port = random.choice([21, 22])
    return {
        "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "mock_part1",
        "src_ip": attacker_ip,
        "dst_ip": random.choice(TARGET_HOSTS),
        "dst_port": port,
        "label": "BruteForce",
        "confidence": round(random.uniform(0.97, 1.0), 2),
        "top_features": {
            "Destination Port": float(port),
            "Init_Win_bytes_forward": 29200.0,
            "PSH Flag Count": 1.0,
        },
        "is_synthetic": True,
    }


def generate_dos_alert(attacker_ip: str) -> dict:
    return {
        "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "mock_part1",
        "src_ip": attacker_ip,
        "dst_ip": random.choice(TARGET_HOSTS),
        "dst_port": 80,
        "label": "DoS",
        "confidence": round(random.uniform(0.98, 1.0), 2),
        "top_features": {
            "Packet Length Variance": round(random.uniform(2000000, 12000000), 1),
            "Bwd Packet Length Std": round(random.uniform(1800, 6000), 2),
            "Avg Bwd Segment Size": round(random.uniform(1500, 3000), 2),
        },
        "is_synthetic": True,
    }


def generate_anomaly_alert(attacker_ip: str) -> dict:
    return {
        "timestamp": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "mock_part2",
        "src_ip": attacker_ip,
        "dst_ip": random.choice(TARGET_HOSTS),
        "dst_port": random.choice([80, 443, 8080]),
        "label": "Anomaly",
        "confidence": round(random.uniform(0.990, 0.999), 4),
        "top_features": {
            "Init_Win_bytes_forward": float(random.choice([256, 1024, 0])),
            "Bwd IAT Std": round(random.uniform(100000, 8000000), 1),
            "Fwd IAT Std": round(random.uniform(50000, 4000000), 1),
        },
        "is_synthetic": True,
    }


def generate_alert(scenario: str = "random", attacker_ip: str = None) -> dict:
    ip = attacker_ip or random.choice(ATTACKERS)["ip"]
    if scenario == "portscan":
        return generate_portscan_alert(ip)
    elif scenario == "bruteforce":
        return generate_bruteforce_alert(ip)
    elif scenario == "dos":
        return generate_dos_alert(ip)
    elif scenario == "anomaly":
        return generate_anomaly_alert(ip)
    else:
        choice = random.choices(
            ["portscan", "bruteforce", "dos", "anomaly"],
            weights=[35, 25, 20, 20],
            k=1,
        )[0]
        return generate_alert(choice, ip)


def run_campaign(url: str, delay: float = 0.5, dry_run: bool = False):
    """Simulates an APT kill-chain campaign: PortScan -> BruteForce -> Anomaly / DoS."""
    campaign_ip = "203.0.113.11"
    print(f"\n[+] Launching coordinated attack campaign simulation from {campaign_ip} ...")
    
    stages = [
        ("Phase 1: Reconnaissance (Port Scanning)", ["portscan"] * 6),
        ("Phase 2: Weaponization & Access (Brute Force on Port 22/21)", ["bruteforce"] * 5),
        ("Phase 3: Evasion & Unknown Payload (Zero-Day Anomaly)", ["anomaly"] * 3),
        ("Phase 4: Impact (DoS Disruption)", ["dos"] * 4),
    ]

    total_sent = 0
    for phase_name, alerts in stages:
        print(f"\n---> {phase_name}")
        for scenario in alerts:
            alert = generate_alert(scenario, attacker_ip=campaign_ip)
            dispatch(alert, url, dry_run)
            total_sent += 1
            if delay > 0:
                time.sleep(delay)
    print(f"\n[OK] Campaign simulation complete ({total_sent} alerts dispatched).")


def dispatch(alert: dict, url: str, dry_run: bool):
    if dry_run:
        print("[DRY-RUN]", json.dumps(alert))
        return
    try:
        resp = requests.post(url, json=alert, timeout=3)
        if resp.status_code == 200:
            print(f"[SENT 200] {alert['source'].upper():<6} | {alert['label']:<11} | {alert['src_ip']} -> {alert['dst_ip']}:{alert['dst_port']} (Conf: {alert['confidence']})")
        else:
            print(f"[ERR {resp.status_code}]", resp.text)
    except requests.RequestException as e:
        print(f"[FAILED] Could not connect to {url}: {e}")


def main():
    parser = argparse.ArgumentParser(description="Generate mock IDS alerts and send to Part 3 SOC Receiver.")
    parser.add_argument("--url", default="http://127.0.0.1:8000/alert", help="Receiver POST endpoint")
    parser.add_argument("--count", type=int, default=15, help="Number of random alerts to send (0 to disable)")
    parser.add_argument("--delay", type=float, default=0.2, help="Delay between alerts in seconds")
    parser.add_argument("--campaign", action="store_true", help="Run a realistic multi-stage kill-chain campaign")
    parser.add_argument("--loop", action="store_true", help="Send alerts continuously until interrupted")
    parser.add_argument("--dry-run", action="store_true", help="Print alerts to console without sending HTTP requests")
    args = parser.parse_args()

    if args.campaign:
        run_campaign(args.url, args.delay, args.dry_run)
        return

    print(f"[+] Generating alerts to {args.url} (delay={args.delay}s, dry_run={args.dry_run}) ...")
    sent = 0
    try:
        while True:
            alert = generate_alert()
            dispatch(alert, args.url, args.dry_run)
            sent += 1
            if not args.loop and sent >= args.count:
                break
            if args.delay > 0:
                time.sleep(args.delay)
    except KeyboardInterrupt:
        print(f"\n[!] Stopped by user. Sent {sent} alerts.")

    print(f"[OK] Done. Dispatched {sent} alerts.")


if __name__ == "__main__":
    main()
