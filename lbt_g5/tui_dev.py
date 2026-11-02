"""G5-03 development Dialog TUI for the unified IC-02 collector engine.

Not the production launcher, report viewer or diagnostics control.
One unprivileged TUI process owns at most one helper; multiple acquisitions
within that process reuse it. Every acquisition creates a new run directory,
one engine and one O1 consent snapshot, with an independent D0 validation.
"""
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from .engine import UnifiedCollectorEngine
from .privileged_session import PrivilegedHealthSession, PrivilegedSessionError
from .safety import SourceConsent, SourceRequest

_MENU = (
    ("os", "Acquire OS and firmware metadata"),
    ("memory", "Acquire memory and pressure metadata"),
    ("block", "Acquire block-device inventory"),
    ("all", "Acquire all registered sources (O1 requires consent)"),
    ("enable", "Enable privileged health helper for this TUI session"),
    ("health", "Query an explicitly authorized disk's health"),
    ("exit", "Exit LBT development TUI"),
)
_DEVICE_RE = re.compile(r"/dev/(?:sd[a-z]+|nvme[0-9]+(?:n[0-9]+)?)\Z")
_SELECTED = {
    "os": ("COL-OS",),
    "memory": ("COL-MEM",),
    "block": ("COL-BLOCK",),
    "all": None,
}
_MAX_TEXT = 384


class TuiRuntimeError(RuntimeError):
    pass


class Dialog:
    """Fixed argument vectors, never shell or user-constructed command text."""

    def __init__(self, binary="/usr/bin/dialog"):
        if binary != "/usr/bin/dialog" or not os.path.isfile(binary):
            raise TuiRuntimeError("system Dialog (/usr/bin/dialog) is required")
        self.binary = binary

    def _call(self, *argv):
        proc = subprocess.run((self.binary, "--stdout", "--clear",
                               "--backtitle", "Linux Benchmark Toolkit — G5-03",
                               *argv),
                              stdin=None, stdout=subprocess.PIPE, check=False)
        return proc.returncode, proc.stdout.decode("utf-8", "replace").strip()

    def menu(self, privileged):
        caption=("Privileged helper: active" if privileged
                 else "Privileged helper: inactive")
        args = tuple(v for pair in _MENU for v in pair)
        code, result = self._call("--title", "IC-02 Development",
                                  "--menu", caption, "20", "84", "7", *args)
        if code != 0:
            return "exit"
        if result not in {item[0] for item in _MENU}:
            raise TuiRuntimeError("invalid TUI selection")
        return result

    def device(self):
        code, result = self._call(
            "--title", "Drive-health selection", "--inputbox",
            "Enter one local SATA/NVMe device (example: /dev/sda). "
            "This value is revalidated against this run's sealed D0 inventory.",
            "11", "90", "/dev/sda")
        if code != 0:
            return None
        if len(result) > _MAX_TEXT or not _DEVICE_RE.fullmatch(result):
            raise TuiRuntimeError("invalid device path")
        return result

    def consent(self, device):
        code, _ = self._call(
            "--title", "Explicit per-device consent", "--yesno",
            "SRC-13 DEVICE_HEALTH\n\nSelected: "+device+
            "\n\nThis read-only health query may wake or spin up the selected "
            "storage device. Approve this operation for the NEXT run only?",
            "12", "88")
        return code == 0

    def notice(self, message, *, title="LBT acquisition"):
        value = str(message)[:4096]
        self._call("--title", title, "--msgbox", value, "13", "88")


def _private_output_root(directory: Path):
    if not directory.is_absolute() or directory.is_symlink():
        raise TuiRuntimeError("output root must be absolute and not a symlink")
    if not directory.exists():
        # No recursive mkdir: parent directory must already exist.
        directory.mkdir(mode=0o700)
    meta = directory.stat()
    if (not directory.is_dir() or meta.st_uid != os.geteuid()
            or meta.st_mode & 0o077):
        raise TuiRuntimeError("output root must be owner-owned and mode 0700")
    return directory


def _run_id():
    return datetime.now(timezone.utc).strftime("run-%Y%j%H%M%S")


def verify_acquisition(run, folder):
    """Verify committed original bytes and their attempt receipts, not reports."""
    families = set()
    artifacts = 0
    total_bytes = 0
    partials = 0
    for collector in run.collectors:
        for entry in collector.source_attempts:
            path = folder / entry.receipt_private_path
            meta = json.loads(path.read_text())
            if meta["run_id"] != run.run_id or meta["collector_id"] != collector.collector_id:
                raise TuiRuntimeError("attempt receipt ownership mismatch")
            if meta["source_id"] not in {f"SRC-{i:02d}" for i in range(1,29)}:
                raise TuiRuntimeError("unregistered source receipt")
            observed = entry.outcome
            if isinstance(observed, dict):
                originals = tuple(observed.get("receipts", ()))
                status = observed["disposition"]
            else:
                originals = tuple(getattr(observed, "artifacts", ()) or ())
                if hasattr(observed, "stdout"):
                    originals = tuple(x for x in (observed.stdout,observed.stderr)
                                      if x is not None)
                status = observed.disposition
            if meta["evidence_ids"] != [r.evidence_id for r in originals]:
                raise TuiRuntimeError("attempt/evidence reference mismatch")
            for item in originals:
                # EvidenceWriter always generates these under private/evidence.
                rel = Path(item.private_relative_path)
                if (len(rel.parts) != 3 or rel.parts[:2] != ("private","evidence")
                        or any(x in (".","..") for x in rel.parts)):
                    raise TuiRuntimeError("unsafe evidence location")
                data = (folder / rel).read_bytes()
                if (len(data) != item.byte_count
                        or hashlib.sha256(data).hexdigest() != item.sha256):
                    raise TuiRuntimeError("immutable original evidence mismatch")
                artifacts += 1
                total_bytes += len(data)
            if status != "CAPTURED":
                partials += 1
            families.add(meta["source_id"])
    return len(families), run.source_attempt_count, artifacts, total_bytes, partials


class OperatorTui:
    """Keeps authenticated helper alive while the Dialog menu remains open."""

    def __init__(self, output_root, *, dialog=None, helper_factory=None,
                 engine_factory=UnifiedCollectorEngine):
        self.output_root = Path(output_root)
        self.dialog = dialog
        self.helper_factory = helper_factory or PrivilegedHealthSession
        self.engine_factory = engine_factory
        self._helper = None
        self._sessions = 0

    def _acquire(self, choice, device=None):
        run_id = _run_id()
        folder = self.output_root / run_id
        folder.mkdir(mode=0o700, exist_ok=False)
        engine = self.engine_factory(str(folder), run_id)
        consent = None
        if choice == "health":
            approved = SourceConsent(run_id, "SRC-13", "DEVICE_HEALTH",
                                     device, datetime.now(timezone.utc), True)
            consent = {"SRC-13":SourceRequest(
                run_id,"SRC-13","DEVICE_HEALTH",
                target=device,consent=approved)}
        selected = ("COL-BLOCK",) if choice == "health" else _SELECTED[choice]
        # Only one permitted acquisition engine and evidence dispatcher.
        outcome = engine.run(selected,o1_requests=consent,
                             privileged_session=self._helper)
        totals = verify_acquisition(outcome,folder)
        self._sessions += 1
        # The TUI displays operational completion only, no report viewer/links.
        return ("Run "+run_id+"\nSources: "+str(totals[0])+
                " | Attempts: "+str(totals[1])+
                "\nVerified artifacts: "+str(totals[2])+
                " | Bytes: "+str(totals[3])+
                "\nNon-CAPTURED transport attempts: "+str(totals[4])+
                "\nEvidence integrity: PASS")

    def run(self, *, sudo=False):
        if os.geteuid() == 0:
            raise TuiRuntimeError("main LBT TUI must not run as root")
        if not (sys.stdin.isatty() and sys.stderr.isatty()):
            raise TuiRuntimeError("interactive terminal required for Dialog and sudo")
        _private_output_root(self.output_root)
        if self.dialog is None:
            self.dialog = Dialog()
        # The helper context spans the complete menu lifetime.
        with ExitStack() as stack:
            if sudo:
                self._helper = stack.enter_context(self.helper_factory())
            while True:
                choice = self.dialog.menu(self._helper is not None)
                if choice == "exit":
                    break
                if choice == "enable":
                    if self._helper is None:
                        try:
                            self._helper = stack.enter_context(self.helper_factory())
                            self.dialog.notice(
                                "Privileged helper active for this TUI session. "
                                "Device health still requires separate consent.")
                        except PrivilegedSessionError:
                            self.dialog.notice("Administrator authentication failed. "
                                               "Unprivileged collection remains available.")
                    else:
                        self.dialog.notice("Privileged helper already active. "
                                           "No second password prompt is needed.")
                    continue
                if choice == "health":
                    device = self.dialog.device()
                    if device is None:
                        continue
                    if not self.dialog.consent(device):
                        self.dialog.notice("Device health request declined.")
                        continue
                    if self._helper is None:
                        self.dialog.notice("Enable privileged helper from the main menu "
                                           "before consenting to a drive-health query.")
                        continue
                try:
                    summary = self._acquire(choice,
                                             device=device if choice == "health" else None)
                    self.dialog.notice(summary)
                except Exception as exc:
                    # No raw source paths, device output or tracebacks in TUI.
                    self.dialog.notice("Acquisition interrupted: "+type(exc).__name__+
                                       ". Private evidence is retained.")
        self._helper = None
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sudo", action="store_true",
                        help="authenticate once when the TUI opens")
    parser.add_argument("--output-root", default=None,
                        help="existing or new owner-restricted evidence root")
    args = parser.parse_args(argv)
    root = args.output_root or str(Path.home() / "lbt-g5-03-tui-evidence")
    try:
        return OperatorTui(root).run(sudo=args.sudo)
    except (TuiRuntimeError, PrivilegedSessionError, OSError) as exc:
        print("G5-03 TUI error: "+str(exc),file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
