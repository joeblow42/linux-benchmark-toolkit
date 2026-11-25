"""Optional bounded bidirectional iperf3 workload for an authorized literal peer."""
from dataclasses import dataclass
import ipaddress
import json

from .workload_process import capture, tool_path
from .workload_runtime import Mode, Resources, Workload


@dataclass(frozen=True)
class Peer:
    address: str
    authorized: bool
    port: int = 5201
    seconds: int = 30
    megabits_per_second: int = 25

    def __post_init__(self):
        address = ipaddress.ip_address(self.address)
        if self.authorized is not True or address.is_multicast or address.is_unspecified:
            raise ValueError("network tests require an explicitly authorized unicast peer")
        for name, minimum, maximum in (("port", 1, 65535), ("seconds", 1, 30),
                                       ("megabits_per_second", 1, 100)):
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"{name} outside peer workload limits")


def run_peer(context, peer):
    iperf = tool_path("iperf3")
    measurements = {}
    for label, direction in (("upload", ()), ("download", ("--reverse",))):
        result = capture(context, (iperf, "--client", str(ipaddress.ip_address(peer.address)),
                                   "--port", str(peer.port), "--json", "--parallel", "1",
                                   "--time", str(peer.seconds), "--bitrate",
                                   f"{peer.megabits_per_second}M", *direction),
                         seconds=peer.seconds + 12)
        payload = json.loads(result.stdout)
        if result.returncode or payload.get("error"):
            raise RuntimeError("peer measurement failed")
        end = payload["end"]
        measurements[label] = {"sent_bits_per_second": end["sum_sent"]["bits_per_second"],
                               "received_bits_per_second": end["sum_received"]["bits_per_second"],
                               "retransmits": end["sum_sent"].get("retransmits")}
    return {"requested_seconds_per_direction": peer.seconds,
            "bitrate_limit_mbps": peer.megabits_per_second, "directions": measurements}


def peer_workload(peer):
    return Workload("network-peer", "network", Mode.STANDARD, Resources(cpu_workers=1),
                    lambda context: run_peer(context, peer), requires_selection=True)
