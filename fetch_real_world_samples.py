"""
fetch_real_world_samples.py
----------------------------
Pulls a fresh batch of real, publicly-shared phishing emails from
"Phishing Pot" (https://github.com/rf-peixoto/phishing_pot) - a
research corpus of real phishing samples collected via honeypots,
licensed CC BY-NC 4.0 (non-commercial use with attribution - see
NOTICE.md in this folder before using this for anything commercial).

Why this exists: campaign_correlation.py's whole job is finding
similarities across REAL emails. The hand-built demo emails in
../sample_email.eml and ../campaign_batch/ prove the logic works, but
they're synthetic - this script gets you actual captured phishing mail
to run the pipeline against instead.

This does NOT bulk-mirror the repository (it has 8,600+ files, ~400MB -
too big to bundle and disrespectful to re-scrape repeatedly per the
maintainer's own request). It does a throwaway shallow clone, copies out
a small random sample, and deletes the clone.

Usage:
    python fetch_real_world_samples.py                  # 30 random samples, <=150KB each
    python fetch_real_world_samples.py --count 50
    python fetch_real_world_samples.py --max-size 300000 --out ./my_batch
"""

import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile

REPO_URL = "https://github.com/rf-peixoto/phishing_pot.git"


def fetch(count: int, max_size: int, out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        clone_path = os.path.join(tmp, "phishing_pot")
        print(f"Cloning {REPO_URL} (shallow) ...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", REPO_URL, clone_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print("git clone failed:", result.stderr, file=sys.stderr)
            print(
                "This needs network access to github.com and a working `git` "
                "install. If your environment blocks outbound git access, "
                "download a sample manually from the repo's `email/` folder "
                "and drop the .eml files into this directory instead.",
                file=sys.stderr,
            )
            sys.exit(1)

        email_dir = os.path.join(clone_path, "email")
        candidates = [
            f for f in os.listdir(email_dir)
            if f.endswith(".eml") and os.path.getsize(os.path.join(email_dir, f)) <= max_size
        ]

        if not candidates:
            print(f"No .eml files under {max_size} bytes found.", file=sys.stderr)
            sys.exit(1)

        chosen = random.sample(candidates, min(count, len(candidates)))
        for fname in chosen:
            shutil.copy(os.path.join(email_dir, fname), os.path.join(out_dir, fname))

        print(f"Copied {len(chosen)} real phishing samples into {out_dir}/")
        print("Remember: CC BY-NC 4.0 - non-commercial use with attribution. See NOTICE.md.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=30, help="Number of samples to pull (default: 30)")
    parser.add_argument("--max-size", type=int, default=150_000, help="Skip files larger than this many bytes (default: 150000)")
    parser.add_argument("--out", default=os.path.dirname(os.path.abspath(__file__)), help="Output directory (default: this folder)")
    args = parser.parse_args()

    fetch(args.count, args.max_size, args.out)


if __name__ == "__main__":
    main()
