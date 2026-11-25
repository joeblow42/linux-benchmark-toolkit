"""Run the G5 development workload registry with owner-only output."""
import argparse
from pathlib import Path

from .core_workloads import MIB, ShortParameters, short_workloads
from .workload_runtime import Mode, Resources, Runtime


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("discovery", "standard", "interactive"))
    parser.add_argument("--output-root", required=True, type=Path,
                        help="existing owner-only directory for inventory and benchmark data")
    parser.add_argument("--select", action="append", default=[],
                        help="interactive workload ID or group:NAME, repeatable")
    parser.add_argument("--cpu-workers", type=int, default=ShortParameters.cpu_workers)
    parser.add_argument("--disk-reserve-mib", type=int, default=1024)
    args = parser.parse_args(argv)
    try:
        parameters = ShortParameters(cpu_workers=args.cpu_workers)
        runtime = Runtime(short_workloads(parameters),
                          limits=Resources(parameters.cpu_workers, 128 * MIB, 128 * MIB),
                          disk_reserve_bytes=args.disk_reserve_mib * MIB)
        session = runtime.execute(args.output_root, Mode(args.mode), selections=args.select)
    except (OSError, ValueError) as error:
        parser.exit(2, f"Workload runtime: {error}\n")
    print(f"{session.state} {session.directory}")
    return {"COMPLETE": 0, "PARTIAL": 3, "FAILED": 1, "INTERRUPTED": 130}[session.state]


if __name__ == "__main__":
    raise SystemExit(main())
