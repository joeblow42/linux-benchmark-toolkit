"""Select a G5 development workload mode through Dialog."""
import argparse
from pathlib import Path
import shutil
import subprocess
import sys

from .core_workloads import ShortParameters, short_workloads
from .sustained_workloads import SustainedParameters, sustained_workloads
from .workload_cli import main as run
from .workload_runtime import Mode


def choose(dialog, *args):
    response = subprocess.run((dialog, "--stdout", "--clear", "--title",
                               "Linux Benchmark Toolkit development workloads", *args),
                              stdout=subprocess.PIPE, text=True)
    if response.returncode in (1, 255):
        return None
    if response.returncode:
        raise RuntimeError("Dialog failed")
    return response.stdout.strip()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args(argv)
    dialog = shutil.which("dialog")
    if dialog is None or not sys.stdin.isatty() or not sys.stderr.isatty():
        parser.error("Dialog and an interactive terminal are required")
    choices = ("discovery", "Read-only inventory",
               "standard", "Short CPU, memory, and storage workloads",
               "extended", "Short and sustained workloads",
               "interactive", "Select local workloads")
    try:
        mode = choose(dialog, "--menu", "Select a mode", "16", "76", "6", *choices)
        if mode is None:
            return 0
        dispatch = ["--mode", mode, "--output-root", str(args.output_root)]
        if mode == Mode.INTERACTIVE.value:
            cases = short_workloads(ShortParameters()) + sustained_workloads(SustainedParameters())
            items = [part for case in cases for part in (case.id, case.group, "off")]
            selected = choose(dialog, "--separate-output", "--checklist",
                              "Select local workloads", "18", "76", "8", *items)
            if not selected:
                return 0
            for item in selected.splitlines():
                dispatch.extend(("--select", item))
        if mode != Mode.DISCOVERY.value:
            confirmation = choose(dialog, "--yesno",
                                  "This run can generate CPU load and write temporary scratch data. Continue?",
                                  "10", "68")
            if confirmation is None:
                return 0
        return run(dispatch)
    except RuntimeError as error:
        parser.exit(2, f"Development menu: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
