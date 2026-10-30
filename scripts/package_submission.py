"""Packaging utility for Assignment 10 VTOP project submission.

Automatically creates and packages all required project deliverables according
to the prescribed naming convention: <Slot>_<Team>_*

Examples:
    python scripts/package_submission.py --slot F1 --team Team1
"""
import argparse
import os
import shutil
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def package(slot: str, team: str, out_dir: str = None):
    prefix = f"{slot}_{team}"
    target_dir = out_dir or os.path.join(ROOT, "submission", prefix)
    os.makedirs(target_dir, exist_ok=True)
    print(f"\n[+] Packaging submission for: {prefix}")
    print(f"[*] Target Directory: {target_dir}\n")

    # 1. Report PDF
    report_src = os.path.join(ROOT, "docs", "ML_Powered_Intrusion_Detector_Report.pdf")
    if os.path.exists(report_src):
        dst = os.path.join(target_dir, f"{prefix}_Report.pdf")
        shutil.copy2(report_src, dst)
        print(f"  [OK] {os.path.basename(dst)} (Project Report)")

    # 2. Presentation PPT
    ppt_src = os.path.join(ROOT, "docs", "Project_Presentation.pptx")
    if os.path.exists(ppt_src):
        dst = os.path.join(target_dir, f"{prefix}_PPT.pptx")
        shutil.copy2(ppt_src, dst)
        print(f"  [OK] {os.path.basename(dst)} (Presentation Slides)")

    # 3. Cisco Packet Tracer Simulation (.pkt)
    pkt_src = os.path.join(ROOT, "simulation", "network_topology.pkt")
    if os.path.exists(pkt_src):
        dst = os.path.join(target_dir, f"{prefix}_Simulation.pkt")
        shutil.copy2(pkt_src, dst)
        print(f"  [OK] {os.path.basename(dst)} (Network Simulation)")

    # 4. Screenshots Zip
    screenshots_dir = os.path.join(ROOT, "screenshots")
    if os.path.exists(screenshots_dir):
        zip_path = os.path.join(target_dir, f"{prefix}_Screenshots.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
            for f in os.listdir(screenshots_dir):
                full_p = os.path.join(screenshots_dir, f)
                if os.path.isfile(full_p):
                    z.write(full_p, arcname=f)
        print(f"  [OK] {os.path.basename(zip_path)} (Dashboard & ML Evaluation Screenshots)")

    # 5. Clean Source Code Zip (omitting node_modules, .git, and __pycache__)
    src_zip_path = os.path.join(target_dir, f"{prefix}_SourceCode.zip")
    exclude_dirs = {".git", "node_modules", "__pycache__", ".vscode", "dist", "submission"}
    with zipfile.ZipFile(src_zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                if file.endswith((".pyc", ".pyo")):
                    continue
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, ROOT)
                if rel_path.startswith("submission"):
                    continue
                z.write(full_path, arcname=os.path.join(prefix, rel_path))
    print(f"  [OK] {os.path.basename(src_zip_path)} (Clean Complete Source Code Package)")

    print(f"\n[DONE] All deliverables successfully packaged in: {target_dir}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Package VTOP project deliverables")
    parser.add_argument("--slot", default="F1", help="Slot Number (e.g. F1, F2, L31)")
    parser.add_argument("--team", default="Team1", help="Team Number (e.g. Team1, Team2)")
    parser.add_argument("--out", default=None, help="Custom output directory")
    args = parser.parse_args()
    package(args.slot, args.team, args.out)
