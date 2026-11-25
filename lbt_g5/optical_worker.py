"""Subprocess entry point for the explicit DVD imaging workload."""
import json
from pathlib import Path
import sys

# The bounded process wrapper uses the scratch directory as its cwd.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lbt_g5.optical_workload import DVD, _worker
from lbt_g5.workload_runtime import Unavailable


if __name__ == "__main__":
    if len(sys.argv) != 6 or sys.argv[5] != "--confirmed-unencrypted-dvd":
        raise SystemExit(64)
    config = DVD(sys.argv[1], int(sys.argv[2]), True, int(sys.argv[3]))
    try:
        print(json.dumps(_worker(config, Path(sys.argv[4])), allow_nan=False))
    except Unavailable as error:
        print(json.dumps({"reason": str(error)}))
        raise SystemExit(3)
