"""Run the G5 development workload registry with owner-only output."""
import argparse
import json
import os
from pathlib import Path

from .backup_workload import CASES as BACKUP_CASES, Backup, backup_workloads
from .core_workloads import MIB, ShortParameters, short_workloads
from .jellyfin_workloads import (
    ClientProfile, CONCURRENT, JELLYFIN_CASES, direct_play, import_session_evidence, jellyfin_workloads,
)
from .optical_workload import DVD, dvd_workload
from .peer_workload import Peer, peer_workload
from .smb_workload import smb_target, smb_workload
from .sustained_workloads import SustainedParameters, sustained_workloads
from .video_workload import Video, VideoCase, video_workloads
from .workload_runtime import Mode, Resources, Runtime, Workload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=tuple(mode.value for mode in Mode))
    parser.add_argument("--output-root", "--results-dir", type=Path,
                        default=Path(os.environ.get("LBT_RESULTS_DIR", Path(__file__).resolve().parents[1] / "results")),
                        help="owner-only directory for inventory and benchmark data")
    parser.add_argument("--no-tui", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--publish", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "config")
    parser.add_argument("--list-tests", action="store_true", help="list built-in workload IDs")
    parser.add_argument("--select", action="append", default=[],
                        help="interactive workload ID or group:NAME, repeatable")
    parser.add_argument("--smb-target", help="override the local //host/share default")
    parser.add_argument("--authorize-smb", action="store_true")
    parser.add_argument("--smb-mib", type=int, default=16)
    parser.add_argument("--backup-destination", type=Path,
                        help="existing local directory for temporary generated backup copies")
    parser.add_argument("--backup-large-mib", type=int, default=64)
    parser.add_argument("--backup-small-files", type=int, default=2048)
    parser.add_argument("--cpu-workers", type=int, default=ShortParameters.cpu_workers)
    parser.add_argument("--disk-reserve-mib", type=int, default=1024)
    parser.add_argument("--sustained-seconds", type=int, default=SustainedParameters.seconds)
    parser.add_argument("--max-celsius", type=int, default=SustainedParameters.max_celsius)
    parser.add_argument("--network-peer", help="literal address of a consenting iperf3 peer")
    parser.add_argument("--authorize-peer", action="store_true")
    parser.add_argument("--dvd-device", help="selected /dev/srN drive")
    parser.add_argument("--dvd-bytes", type=int, help="expected capacity of the selected disc")
    parser.add_argument("--confirm-unencrypted-dvd", action="store_true")
    parser.add_argument("--video-source", type=Path, help="owned local DVD video fixture")
    parser.add_argument("--video-seconds", type=int)
    parser.add_argument("--video-deadline", type=int)
    parser.add_argument("--vaapi-render-device", help="explicit render node for comparison")
    parser.add_argument("--jellyfin-fixture", action="append", default=[], metavar="CASE=FILE")
    parser.add_argument("--jellyfin-streams", type=int, choices=(1, 2, 4), default=2)
    parser.add_argument("--direct-play-fixture", type=Path)
    parser.add_argument("--direct-play-profile", type=Path,
                        help="JSON with container, video_codecs, audio_codecs and subtitle_codecs")
    parser.add_argument("--jellyfin-session-export", type=Path)
    parser.add_argument("--jellyfin-transcode-log", type=Path)
    args = parser.parse_args(argv)
    if args.list_tests:
        if args.mode or args.select:
            parser.error("--list-tests cannot be combined with workload execution")
        for item in short_workloads(ShortParameters()) + sustained_workloads(SustainedParameters()):
            print(item.id)
        return 0
    if not args.mode:
        parser.error("select --mode or launch the Dialog menu")
    if bool(args.direct_play_fixture) != bool(args.direct_play_profile):
        parser.error("provide both --direct-play-fixture and --direct-play-profile")
    if args.jellyfin_transcode_log and not args.jellyfin_session_export:
        parser.error("--jellyfin-transcode-log requires --jellyfin-session-export")
    if args.vaapi_render_device and args.video_source is None:
        parser.error("--vaapi-render-device requires --video-source")
    dvd_flags = (bool(args.dvd_device), args.dvd_bytes is not None, args.confirm_unencrypted_dvd)
    if any(dvd_flags) and not all(dvd_flags):
        parser.error("provide --dvd-device, --dvd-bytes and --confirm-unencrypted-dvd together")
    if bool(args.network_peer) != args.authorize_peer:
        parser.error("provide both --network-peer and --authorize-peer")
    backup_selected = any(item in (*BACKUP_CASES, "group:backup") for item in args.select)
    if backup_selected != bool(args.backup_destination) or (backup_selected and args.mode != "interactive"):
        parser.error("backup requires interactive selection and --backup-destination")
    smb_selected = "backup-smb" in args.select
    if (smb_selected != args.authorize_smb or (smb_selected and args.mode != "interactive")
            or (args.smb_target and not smb_selected)):
        parser.error("SMB requires interactive selection of backup-smb and --authorize-smb")
    if "group:backup" in args.select:
        args.select = [item for item in args.select if item != "group:backup"] + list(BACKUP_CASES)
    try:
        parameters = ShortParameters(cpu_workers=args.cpu_workers)
        sustained = SustainedParameters(seconds=args.sustained_seconds,
                                        cpu_workers=min(2, args.cpu_workers),
                                        max_celsius=args.max_celsius)
        workloads = short_workloads(parameters) + sustained_workloads(sustained)
        if smb_selected:
            workloads += (smb_workload(smb_target(args.smb_target), args.smb_mib),)
        if backup_selected:
            workloads += backup_workloads(Backup(args.backup_destination, args.disk_reserve_mib * MIB,
                                                  args.backup_large_mib, args.backup_small_files))
        if args.network_peer:
            workloads += (peer_workload(Peer(args.network_peer, args.authorize_peer)),)
        disk_bytes = 128 * MIB
        if all(dvd_flags):
            if args.mode != "interactive" or "dvd-image" not in args.select:
                raise ValueError("select dvd-image in interactive mode to authorize imaging")
            dvd = dvd_workload(DVD(args.dvd_device, args.dvd_bytes, args.confirm_unencrypted_dvd))
            workloads += (dvd,)
            disk_bytes = max(disk_bytes, dvd.resources.disk_bytes)
        memory_bytes = 128 * MIB
        short_seconds = 120 if args.video_seconds is None else args.video_seconds
        extended_seconds = 300 if args.video_seconds is None else args.video_seconds
        short_deadline = 180 if args.video_deadline is None else args.video_deadline
        extended_deadline = 600 if args.video_deadline is None else args.video_deadline
        if args.video_source:
            short_video = Video(args.video_source, short_seconds, short_deadline,
                                max_celsius=args.max_celsius)
            video = Video(args.video_source, extended_seconds, extended_deadline,
                          max_celsius=args.max_celsius)
            short_case = VideoCase("video-short", ("mpeg2video",), output_height=480)
            workloads += video_workloads(short_video, (short_case,), tier=Mode.STANDARD,
                                         requires_selection=False)
            workloads += video_workloads(video)
            if args.vaapi_render_device:
                hardware = Video(args.video_source, extended_seconds, extended_deadline,
                                 max_celsius=args.max_celsius, render_device=args.vaapi_render_device)
                workloads += video_workloads(hardware)
            memory_bytes = 512 * MIB
        videos = {}
        valid_cases = {case.id for case in (*JELLYFIN_CASES, CONCURRENT)}
        if args.jellyfin_fixture:
            for selection in args.jellyfin_fixture:
                case, equal, file = selection.partition("=")
                if not equal or not file or case not in valid_cases or case in videos:
                    raise ValueError("provide one CASE=FILE per registered Jellyfin case")
                videos[case] = Video(Path(file), extended_seconds, extended_deadline,
                                     max_celsius=args.max_celsius)
        workloads += jellyfin_workloads(videos, args.jellyfin_streams)
        if any(selection in valid_cases for selection in args.select):
            selected_streams = args.jellyfin_streams if CONCURRENT.id in args.select else 1
            memory_bytes = max(memory_bytes, selected_streams * 512 * MIB)
        if args.direct_play_fixture:
            with args.direct_play_profile.open(encoding="utf-8") as stream:
                data = stream.read(16385)
            if len(data) > 16384:
                raise ValueError("Direct Play profile exceeds the size limit")
            profile = ClientProfile(**json.loads(data))
            workloads += (Workload("jf-direct-play", "jellyfin", Mode.EXTENDED,
                                   Resources(cpu_workers=1, memory_bytes=128 * MIB),
                                   lambda context: direct_play(context, Video(args.direct_play_fixture), profile),
                                   requires_selection=True),)
        if args.jellyfin_session_export:
            workloads += (Workload("jf-session-evidence", "jellyfin", Mode.EXTENDED,
                                   Resources(memory_bytes=8 * MIB),
                                   lambda context: import_session_evidence(
                                       context, args.jellyfin_session_export, args.jellyfin_transcode_log),
                                   requires_selection=True),)
        runtime = Runtime(workloads,
                          limits=Resources(parameters.cpu_workers, memory_bytes, disk_bytes),
                          disk_reserve_bytes=args.disk_reserve_mib * MIB)
        if args.publish:
            args.output_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        session = runtime.execute(args.output_root, Mode(args.mode), selections=args.select)
    except (OSError, TypeError, ValueError) as error:
        parser.exit(2, f"Workload runtime: {error}\n")
    print(f"{session.state} {session.directory}")
    if args.publish and session.state in ("COMPLETE", "PARTIAL"):
        from .workload_report import publish
        try:
            print(f"Report {publish(session.directory, args.config, initial=True)}")
        except (OSError, KeyError, ValueError) as error:
            parser.exit(2, f"Workload publication: {error}\n")
    return {"COMPLETE": 0, "PARTIAL": 3, "FAILED": 1, "INTERRUPTED": 130}[session.state]


if __name__ == "__main__":
    raise SystemExit(main())
