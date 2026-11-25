"""RP-08 synthetic Jellyfin transcode cases and separate Direct Play evidence."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
from pathlib import Path
import threading
import time

from .core_workloads import MIB, _fields, check_pressure
from .video_workload import Video, VideoCase, _keep, probe, transcode, video_workloads
from .workload_runtime import Cancelled, Context, Mode, Resources, Unavailable, Unsafe, Workload


JELLYFIN_CASES = (
    VideoCase("jf-01", ("h264",), 1080, 720),
    VideoCase("jf-02", ("h264",), 1080, 1080),
    VideoCase("jf-03", ("mpeg4",)),
    VideoCase("jf-04", ("wmv3",)),
    VideoCase("jf-05", ("mpeg2video",)),
    VideoCase("jf-06", ("hevc",), 1080, 1080),
    VideoCase("jf-07", ("hevc",), 2160, 1080),
    VideoCase("jf-08", ("hevc",), 2160, 1080, tone_map=True),
    VideoCase("jf-09", ("h264",), image_subtitles=True),
)
CONCURRENT = VideoCase("jf-10", ("h264",), 1080, 1080)


def run_concurrent(context, video, count):
    if count not in (1, 2, 4):
        raise ValueError("choose 1, 2, or 4 simultaneous encodes")
    if video.path is None:
        raise Unavailable("VIDEO_FIXTURE_MISSING")
    check_pressure("memory", 10)
    try:
        free = int(dict(_fields("/proc/meminfo"))["MemAvailable"]) * 1024
    except (OSError, KeyError, ValueError):
        raise Unavailable("MEMORY_CAPACITY_UNAVAILABLE") from None
    if free < count * 768 * MIB:
        raise Unavailable("CONCURRENT_MEMORY_HEADROOM")
    halt = threading.Event()
    barrier = threading.Barrier(count)
    cancellation_lock = threading.Lock()

    def stop():
        if halt.is_set():
            raise Cancelled()
        with cancellation_lock:
            context.check_stop()

    def stream(index):
        scratch = context.scratch / f"stream-{index}"
        scratch.mkdir(mode=0o700)
        private = context.evidence / f"stream-{index}" if context.evidence is not None else None
        if private is not None:
            context.evidence.mkdir(mode=0o700, exist_ok=True)

        def launch():
            barrier.wait(timeout=min(video.wall_seconds, 20))

        try:
            return transcode(Context(scratch, stop, context.inventory, private), CONCURRENT,
                             video, synchronize=launch)
        except BaseException:
            halt.set()
            barrier.abort()
            raise

    failures = []
    results = []
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=count) as workers:
        futures = [workers.submit(stream, n + 1) for n in range(count)]
        try:
            for future in futures:
                try:
                    results.append(future.result())
                except Exception as error:
                    failures.append(error)
        except BaseException:
            halt.set()
            barrier.abort()
            raise
    if failures:
        original = next((error for error in failures if isinstance(error, Unsafe)), None)
        if original is None:
            original = next((error for error in failures
                             if not isinstance(error, (Cancelled, threading.BrokenBarrierError))), failures[0])
        raise original
    overlap = min(row["capture_end_monotonic"] for row in results) - max(
        row["capture_start_monotonic"] for row in results)
    if overlap <= 0:
        raise RuntimeError("FFmpeg capture intervals did not overlap")
    for row in results:
        del row["capture_end_monotonic"], row["capture_start_monotonic"]
    return {"laboratory_streams": count, "capture_overlap_seconds": overlap,
            "elapsed_seconds": time.monotonic() - started, "streams": results}


@dataclass(frozen=True)
class ClientProfile:
    container: str
    video_codecs: tuple
    audio_codecs: tuple
    subtitle_codecs: tuple
    streams: int = 1
    storage_bits_per_second: int | None = None
    network_bits_per_second: int | None = None

    def __post_init__(self):
        if not isinstance(self.container, str) or not self.container:
            raise ValueError("Direct Play profile requires a container name")
        for list_value in (self.video_codecs, self.audio_codecs, self.subtitle_codecs):
            if not isinstance(list_value, (list, tuple)) or not all(
                    isinstance(value, str) and value for value in list_value):
                raise ValueError("Direct Play codecs must be lists of names")
        if type(self.streams) is not int or not 1 <= self.streams <= 64:
            raise ValueError("Direct Play profile must select between 1 and 64 streams")
        for value in (self.storage_bits_per_second, self.network_bits_per_second):
            if value is not None and (type(value) is not int or value <= 0):
                raise ValueError("Direct Play throughput evidence must be positive bits per second")


def direct_play(context, video, profile):
    _, demuxer, metadata = probe(context, video)
    streams = metadata.get("streams", [])
    if not any(row.get("codec_type") == "video" for row in streams):
        raise Unavailable("DIRECT_PLAY_VIDEO_STREAM_MISSING")
    allowed = {"video": profile.video_codecs, "audio": profile.audio_codecs,
               "subtitle": profile.subtitle_codecs}
    constraints = []
    if profile.container != demuxer:
        constraints.append("CONTAINER")
    for kind, codecs in allowed.items():
        if any(row["codec_type"] == kind and row.get("codec_name") not in codecs for row in streams):
            constraints.append(kind.upper())
    try:
        required = int(metadata["format"]["bit_rate"]) * profile.streams
        if required <= 0:
            raise ValueError
    except (KeyError, ValueError, TypeError):
        required = None
    observations = {"aggregate_required_bits_per_second": required,
                    "storage_bits_per_second": profile.storage_bits_per_second,
                    "network_bits_per_second": profile.network_bits_per_second}
    available = [value for value in (profile.storage_bits_per_second,
                                     profile.network_bits_per_second) if value is not None]
    return {"compatibility_constraints": constraints,
            "compatibility": "CLIENT_INCOMPATIBLE" if constraints else "SUPPORTED_IN_PROFILE",
            "throughput": "INSUFFICIENT" if required and any(value < required for value in available)
            else "MEETS_OBSERVED_REQUIREMENT" if required and len(available) == 2 else "UNVERIFIED",
            "actual_client_session": "NOT_TESTED", **observations}


def _server_export(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 2 * MIB:
        raise Unavailable("JELLYFIN_SESSION_EVIDENCE_UNAVAILABLE")
    with path.open("rb") as stream:
        data = stream.read(2 * MIB + 1)
    if len(data) > 2 * MIB:
        raise Unavailable("JELLYFIN_SESSION_EVIDENCE_UNAVAILABLE")
    return data


def import_session_evidence(context, session_export, transcode_log=None):
    """Retain evidence exported by an operator from a controlled real server session."""
    session_bytes = _server_export(session_export)
    record = json.loads(session_bytes)
    if not isinstance(record, dict):
        raise Unavailable("JELLYFIN_PLAY_METHOD_UNAVAILABLE")
    state = record.get("PlayState")
    play = state.get("PlayMethod") if isinstance(state, dict) else record.get("PlayMethod")
    if play not in ("DirectPlay", "DirectStream", "Transcode"):
        raise Unavailable("JELLYFIN_PLAY_METHOD_UNAVAILABLE")
    if play == "Transcode" and transcode_log is None:
        raise Unavailable("JELLYFIN_TRANSCODE_LOG_REQUIRED")
    log_bytes = _server_export(transcode_log) if transcode_log is not None else b""
    context.check_stop()
    _keep(context, "jellyfin-session.json", session_bytes)
    if log_bytes:
        _keep(context, "jellyfin-transcode.log", log_bytes)
    return {"play_method": play, "evidence_origin": "OPERATOR_SERVER_EXPORT",
            "transcode_log_bytes": len(log_bytes)}


def jellyfin_workloads(videos, count=2):
    if count not in (1, 2, 4):
        raise ValueError("choose 1, 2, or 4 simultaneous encodes")
    registrations = []
    for case in JELLYFIN_CASES:
        video = videos.get(case.id, Video(None))
        registrations.extend(video_workloads(video, (case,), group="jellyfin"))
    video = videos.get(CONCURRENT.id, Video(None))
    registrations.append(Workload(CONCURRENT.id, "jellyfin", Mode.EXTENDED,
                                  Resources(cpu_workers=count * video.threads,
                                            memory_bytes=count * 512 * MIB),
                                  lambda context: run_concurrent(context, video, count),
                                  requires_selection=True))
    return tuple(registrations)
