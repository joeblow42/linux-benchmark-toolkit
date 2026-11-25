"""B/C owner-approved read-only DVD-Video decode verification."""
import argparse
import os
from pathlib import Path
import re
import stat

from lbt_g5.core_workloads import IOPressureGuard, MIB, check_pressure
from lbt_g5.sustained_workloads import Monitor
from lbt_g5.video_workload import Video, _digest, _keep, _progress, probe
from lbt_g5.workload_process import ProcessLimit, capture, tool_path
from lbt_g5.workload_runtime import Context, Mode, Resources, Runtime, Unavailable, Workload


def encryption_observation(stderr):
    log = stderr.lower()
    if re.search(rb"(disc is scrambled|dvd is encrypted|disc is encrypted)", log):
        return "ENCRYPTED_REPORTED"
    if re.search(rb"(disc is not scrambled|dvd is not encrypted|disc is not encrypted)", log):
        return "UNENCRYPTED_REPORTED"
    return "UNVERIFIED"


MAX_FIXTURE_BYTES = 256 * MIB


def decode_dvd(context, *, device, library_dir, title, seconds, keep_fixture=False):
    if not os.access(device, os.R_OK):
        raise Unavailable("OPTICAL_DEVICE_NOT_READABLE")
    dev = os.stat(device, follow_symlinks=False)
    if not stat.S_ISBLK(dev.st_mode) or os.major(dev.st_rdev) != 11:
        raise Unavailable("OPTICAL_DEVICE_TYPE_UNSUPPORTED")
    if not (library_dir / "libdvdcss.so.2").is_file():
        raise Unavailable("DVD_DECRYPTION_LIBRARY_MISSING")
    io_guard = IOPressureGuard(context.check_stop)
    context = Context(context.scratch, io_guard.poll, context.inventory, context.evidence)
    check_pressure("cpu", 15)
    monitor = Monitor(context, 80)
    guarded = Context(context.scratch, monitor.poll, context.inventory, context.evidence)
    ffmpeg = tool_path("ffmpeg")
    partial = None
    pace = ()
    output = ("-f", "null", "-")
    if keep_fixture:
        context.evidence.mkdir(mode=0o700)
        partial = context.evidence / "dvd-encoding-fixture.partial.mkv"
        pace = ("-readrate", "1")
        output = ("-c:v", "copy", "-fs", str(MAX_FIXTURE_BYTES), "-f", "matroska",
                  "-n", str(partial))
    command = (
        "/usr/bin/env", f"LD_LIBRARY_PATH={library_dir}", "DVDCSS_CACHE=off", "DVDCSS_VERBOSE=2",
        ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "info", "-xerror",
        "-nostats", "-progress", "pipe:1", "-threads", "1", "-f", "dvdvideo",
        "-title", str(title), "-preindex", "0", *pace, "-i", device,
        "-map", "0:v:0", "-an", "-sn", "-dn", "-t", str(seconds), *output,
    )
    try:
        result = capture(guarded, command, seconds=180 if keep_fixture else 90,
                         output_bytes=512 * 1024)
    except ProcessLimit as error:
        _keep(context, "dvd.partial.stdout", error.stdout)
        _keep(context, "dvd.partial.stderr", error.stderr)
        raise
    _keep(context, "dvd.stdout", result.stdout)
    _keep(context, "dvd.stderr", result.stderr)
    if result.returncode:
        raise RuntimeError("DVD decoding command failed")
    frames, media_seconds = _progress(result.stdout)
    fixture = {}
    if partial is not None:
        size = partial.stat().st_size
        if not 0 < size <= MAX_FIXTURE_BYTES or media_seconds < min(seconds, 30):
            raise RuntimeError("DVD fixture did not meet the requested size and duration bounds")
        _, _, metadata = probe(guarded, Video(partial))
        stream = next((value for value in metadata.get("streams", [])
                       if value.get("codec_type") == "video"), {})
        if stream.get("codec_name") != "mpeg2video":
            raise RuntimeError("DVD fixture is not an MPEG-2 video stream")
        checked = capture(guarded, (ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error",
            "-xerror", "-nostats", "-progress", "pipe:1", "-threads", "1", "-i", str(partial),
            "-map", "0:v:0", "-an", "-f", "null", "-"), seconds=120, output_bytes=512 * 1024)
        _keep(context, "fixture-decode.stdout", checked.stdout)
        _keep(context, "fixture-decode.stderr", checked.stderr)
        if checked.returncode:
            raise RuntimeError("retained DVD fixture could not be decoded")
        verified_frames, verified_seconds = _progress(checked.stdout)
        if verified_frames != frames or abs(verified_seconds - media_seconds) > 1:
            raise RuntimeError("retained DVD fixture does not match the extracted stream")
        checksum = _digest(guarded, partial)
        with partial.open("rb") as stream_file:
            os.fsync(stream_file.fileno())
        final = partial.with_name("dvd-encoding-fixture.mkv")
        partial.rename(final)
        fixture = {"fixture_file": final.name, "fixture_bytes": size, "fixture_sha256": checksum,
                   "fixture_codec": "mpeg2video", "fixture_width": stream.get("width"),
                   "fixture_height": stream.get("height"), "decoded_fixture_frames": verified_frames,
                   "decoded_fixture_seconds": verified_seconds}
    monitor.poll(force=True)
    io_guard.poll(force=True)
    return {"title_number": title, "frames": frames, "media_seconds": media_seconds,
            "elapsed_seconds": result.seconds, "realtime_factor": media_seconds / result.seconds,
            "encryption_observation": encryption_observation(result.stderr),
            "libdvdcss_diagnostic_present": b"libdvdcss" in result.stderr.lower(),
            "peak_io_pressure_percent": io_guard.peak, **fixture, **monitor.result()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", required=True)
    parser.add_argument("--title", type=int, default=1)
    parser.add_argument("--seconds", type=int, default=5)
    parser.add_argument("--keep-fixture", action="store_true")
    parser.add_argument("--library-dir", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--authorize-owned-dvd-decode", action="store_true", required=True)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"/dev/sr[0-9]+", args.device):
        parser.error("select a local /dev/srN optical drive")
    seconds_limit = 120 if args.keep_fixture else 15
    if not 1 <= args.title <= 99 or not 1 <= args.seconds <= seconds_limit:
        parser.error(f"select title 1 through 99 and a duration of 1 through {seconds_limit} seconds")
    workload = Workload("dvd-video-decode", "optical", Mode.EXTENDED,
                        Resources(cpu_workers=1, memory_bytes=256*MIB,
                                  disk_bytes=(MAX_FIXTURE_BYTES + 4*MIB) if args.keep_fixture else 0),
                        lambda context: decode_dvd(context, device=args.device,
                                                   library_dir=args.library_dir.resolve(),
                                                   title=args.title, seconds=args.seconds,
                                                   keep_fixture=args.keep_fixture))
    session = Runtime((workload,), limits=workload.resources,
                      disk_reserve_bytes=1024*MIB).execute(
        args.output_root, Mode.INTERACTIVE, selections=(workload.id,), collectors=("COL-OPTICAL",))
    row, = session.results
    print(session.directory, row["status"], row["reason"], flush=True)
    if row["status"] == "COMPLETE":
        values = row["measurements"]
        print(values["frames"], "frames", values["media_seconds"], "seconds",
              values["encryption_observation"], "libdvdcss diagnostic",
              values["libdvdcss_diagnostic_present"], flush=True)
        if args.keep_fixture:
            print(session.directory / "dvd-video-decode-evidence" / values["fixture_file"],
                  values["fixture_bytes"], "bytes", values["decoded_fixture_frames"],
                  "verified decoded frames", flush=True)
    return {"COMPLETE": 0, "UNAVAILABLE": 3, "SKIPPED": 130, "FAILED": 1}[row["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
