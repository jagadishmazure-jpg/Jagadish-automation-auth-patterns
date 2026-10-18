"""Print the real test total (collected, then passed). CI and the README use this."""
import subprocess
import sys

collect = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "--collect-only", "-q"],
    capture_output=True, text=True, cwd=".")
for line in collect.stdout.splitlines():
    if "test collected" in line or "tests collected" in line:
        print("collected:", line.strip())

run = subprocess.run(
    [sys.executable, "-m", "pytest", "tests/", "-q"],
    capture_output=True, text=True, cwd=".")
for line in run.stdout.splitlines():
    if "passed" in line or "failed" in line or "error" in line:
        print("result:", line.strip())
sys.exit(run.returncode)
