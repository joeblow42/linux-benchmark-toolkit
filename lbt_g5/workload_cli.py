"""Run the G5 development workload registry with owner-only output."""
import argparse
from pathlib import Path

from .core_workloads import MIB, ShortParameters, short_workloads
from .peer_workload import Peer, peer_workload
from .sustained_workloads import SustainedParameters, sustained_workloads
from .workload_runtime import Mode, Resources, Runtime


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=tuple(mode.value for mode in Mode))
    parser.add_argument("--output-root", required=True, type=Path,
                        help="existing owner-only directory for inventory and benchmark data")
    parser.add_argument("--select", action="append", default=[],
                        help="interactive workload ID or group:NAME, repeatable")
    parser.add_argument("--cpu-workers", type=int, default=ShortParameters.cpu_workers)
    parser.add_argument("--disk-reserve-mib", type=int, default=1024)
    parser.add_argument("--sustained-seconds", type=int, default=SustainedParameters.seconds)
    parser.add_argument("--max-celsius", type=int, default=SustainedParameters.max_celsius)
    parser.add_argument("--network-peer", help="literal address of a consenting iperf3 peer")
    parser.add_argument("--authorize-peer", action="store_true")
    args = parser.parse_args(argv)
    if bool(args.network_peer) != args.authorize_peer:
        parser.error("provide both --network-peer and --authorize-peer")
    try:
        parameters = ShortParameters(cpu_workers=args.cpu_workers)
        sustained = SustainedParameters(seconds=args.sustained_seconds,
                                        cpu_workers=min(2, args.cpu_workers),
                                        max_celsius=args.max_celsius)
        workloads = short_workloads(parameters) + sustained_workloads(sustained)
        if args.network_peer:
            workloads += (peer_workload(Peer(args.network_peer, args.authorize_peer)),)
        runtime = Runtime(workloads,
                          limits=Resources(parameters.cpu_workers, 128 * MIB, 128 * MIB),
                          disk_reserve_bytes=args.disk_reserve_mib * MIB)
        session = runtime.execute(args.output_root, Mode(args.mode), selections=args.select)
    except (OSError, ValueError) as error:
        parser.exit(2, f"Workload runtime: {error}\n")
    print(f"{session.state} {session.directory}")
    return {"COMPLETE": 0, "PARTIAL": 3, "FAILED": 1, "INTERRUPTED": 130}[session.state]


if __name__ == "__main__":
    raise SystemExit(main())
