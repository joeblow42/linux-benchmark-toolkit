"""Select a Linux Benchmark Toolkit workload mode through Dialog."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

from .publication_policy import OUTPUTS, editable_settings, load_policy, save_settings
from .core_workloads import ShortParameters, short_workloads
from .sustained_workloads import SustainedParameters, sustained_workloads
from .workload_cli import main as run
from .workload_runtime import Mode


def choose(dialog, *args):
    response = subprocess.run((dialog, "--stdout", "--clear", "--title",
                               "Linux Benchmark Toolkit", *args),
                              stdout=subprocess.PIPE, text=True)
    if response.returncode in (1, 255):
        return None
    if response.returncode:
        raise RuntimeError("Dialog failed")
    return response.stdout.strip()


def edit(dialog, config, filename):
    from copy import deepcopy

    existing = editable_settings(load_policy(config))
    proposed = deepcopy(existing)
    document = proposed[filename]
    privacy = filename == "privacy.yaml"
    flags = document["mask" if privacy else "exports"]
    choices = {key: (key if privacy else OUTPUTS[key]) for key in flags}
    if privacy:
        choices = {"global_privacy_enabled": "Enable privacy", **choices}
        flags["global_privacy_enabled"] = document["global_privacy_enabled"]
    items = [part for key, label in choices.items()
             for part in (key, label, "on" if flags[key] else "off")]
    selected = choose(dialog, "--separate-output", "--checklist",
                      "Privacy Options" if privacy else "Output Options", "21", "88", "13", *items)
    if selected is None:
        return
    enabled = set(selected.splitlines())
    for key in flags:
        flags[key] = key in enabled
    if privacy:
        document["global_privacy_enabled"] = flags.pop("global_privacy_enabled")
    save_settings(config, filename, existing, proposed)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", "--results-dir", type=Path,
                        default=Path(os.environ.get("LBT_RESULTS_DIR", Path(__file__).resolve().parents[1] / "results")))
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "config")
    args = parser.parse_args(argv)
    dialog = shutil.which("dialog")
    if dialog is None or not sys.stdin.isatty() or not sys.stderr.isatty():
        parser.error("Dialog and an interactive terminal are required")
    choices = ("discovery", "Read-only inventory",
               "standard", "Short CPU, memory, and storage workloads",
               "extended", "Short and sustained workloads",
               "interactive", "Select local workloads",
               "privacy", "Privacy Options",
               "outputs", "Output Options")
    try:
        mode = choose(dialog, "--menu", "Select a mode", "16", "76", "6", *choices)
        if mode is None:
            return 0
        if mode in ("privacy", "outputs"):
            edit(dialog, args.config, mode + ".yaml")
            return 0
        dispatch = ["--publish", "--mode", mode, "--output-root", str(args.output_root),
                    "--config", str(args.config)]
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
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(2, f"Workload menu: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
