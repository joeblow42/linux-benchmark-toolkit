"""Bounded FFmpeg transcoding with explicit local media fixtures."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

from .core_workloads import MIB, check_pressure
from .sustained_workloads import Monitor
from .workload_process import ProcessLimit, capture, tool_path
from .workload_runtime import Context, Mode, Resources, Unavailable, Workload

FORMATS = {".vob": "mpeg", ".mpg": "mpeg", ".mpeg": "mpeg", ".mp4": "mov",
           ".mkv": "matroska", ".ts": "mpegts", ".wmv": "asf", ".avi": "avi"}
SOFTWARE = {"h264": "libx264", "hevc": "libx265"}
MAX_FIXTURE_BYTES = 2 * 1024 * MIB
RENDER = re.compile(r"/dev/dri/renderD[0-9]+\Z")


@dataclass(frozen=True)
class VideoCase:
    id: str
    input_codecs: tuple
    input_height: int | None = None
    output_height: int | None = None
    codec: str = "h264"
    deinterlace: bool = False
    tone_map: bool = False
    image_subtitles: bool = False


@dataclass(frozen=True)
class Video:
    path: Path | None
    seconds: int = 120
    wall_seconds: int = 180
    threads: int = 1
    max_celsius: int = 80
    render_device: str | None = None

    def __post_init__(self):
        for name, low, high in (("seconds", 1, 600), ("wall_seconds", 1, 900),
                                ("threads", 1, 4), ("max_celsius", 45, 90)):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"{name} outside video workload bounds")
        if self.render_device is not None and not RENDER.fullmatch(self.render_device):
            raise ValueError("invalid VA-API render device")


def _local_fixture(path):
    if path is None:
        raise Unavailable("VIDEO_FIXTURE_MISSING")
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise Unavailable("VIDEO_FIXTURE_MISSING")
    try:
        demuxer = FORMATS[path.suffix.lower()]
    except KeyError:
        raise Unavailable("VIDEO_CONTAINER_UNSUPPORTED") from None
    if not 0 < path.stat().st_size <= MAX_FIXTURE_BYTES:
        raise Unavailable("VIDEO_FIXTURE_SIZE_OUTSIDE_LIMIT")
    return path.resolve(), demuxer


def _keep(context, label, data):
    if context.evidence is not None:
        context.evidence.mkdir(mode=0o700, exist_ok=True)
        with (context.evidence / label).open("xb") as stream:
            stream.write(data)


def probe(context, video):
    path, demuxer = _local_fixture(video.path)
    result = capture(context, (tool_path("ffprobe"), "-v", "error", "-max_alloc", "268435456",
                               "-protocol_whitelist", "file", "-format_whitelist", demuxer,
                               "-show_entries",
                               "stream=index,codec_name,codec_type,width,height,color_transfer:format=duration,bit_rate",
                               "-of", "json", str(path)), seconds=15)
    _keep(context, "ffprobe.stdout", result.stdout)
    _keep(context, "ffprobe.stderr", result.stderr)
    if result.returncode:
        raise Unavailable("VIDEO_FIXTURE_FORMAT_UNAVAILABLE")
    return path, demuxer, json.loads(result.stdout)


def _digest(context, path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            context.check_stop()
            digest.update(chunk)
    return digest.hexdigest()


def _progress(stdout):
    final = {}
    current = {}
    for line in stdout.decode("ascii", errors="replace").splitlines():
        key, found, value = line.partition("=")
        if found:
            current[key] = value
        if key == "progress":
            final = current
            current = {}
    try:
        frames = int(final["frame"])
        media_time = int(final["out_time_us"]) / 1e6
    except (ValueError, KeyError):
        raise RuntimeError("FFmpeg did not report measured output") from None
    if final["progress"] != "end" or frames <= 0 or media_time <= 0:
        raise RuntimeError("FFmpeg output duration is incomplete")
    return frames, media_time


def video_command(ffmpeg, path, demuxer, case, video, *, subtitle_index=None):
    filters = []
    if case.deinterlace:
        filters.append("bwdif=mode=send_frame")
    if case.tone_map:
        filters.extend(("zscale=transfer=linear:npl=100", "format=gbrpf32le", "tonemap=hable",
                        "zscale=primaries=bt709:transfer=bt709:matrix=bt709"))
    if case.output_height:
        filters.append(f"scale=-2:{case.output_height}")
    common = (ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-xerror", "-nostats",
              "-max_alloc", "268435456", "-filter_threads", "1", "-filter_complex_threads", "1",
              "-progress", "pipe:1")
    if video.render_device:
        common += ("-vaapi_device", video.render_device)
        encoder = case.codec + "_vaapi"
        filters.extend(("format=nv12", "hwupload"))
        settings = ("-qp", "23")
    else:
        encoder = SOFTWARE[case.codec]
        filters.append("format=yuv420p")
        settings = ("-preset", "veryfast", "-crf", "23")
        if case.codec == "hevc":
            settings += ("-x265-params", "pools=none:frame-threads=1")
    filters = ",".join(filters)
    if case.image_subtitles:
        mapping = ("-filter_complex", f"[0:v:0][0:{subtitle_index}]overlay,{filters}[video]", "-map", "[video]")
    else:
        mapping = ("-map", "0:v:0", "-vf", filters)
    return (*common, "-threads", str(video.threads), "-protocol_whitelist", "file",
            "-format_whitelist", demuxer, "-i", str(path), *mapping, "-an", "-sn", "-dn",
            "-t", str(video.seconds), "-c:v", encoder, "-threads", str(video.threads),
            *settings, "-f", "null", "-"), encoder


def _first_video(metadata):
    return next((row for row in metadata.get("streams", []) if row.get("codec_type") == "video"), {})


def transcode(context, case, video, *, synchronize=None):
    if video.path is None or not Path(video.path).is_file():
        raise Unavailable("VIDEO_FIXTURE_MISSING")
    check_pressure("cpu", 15)
    check_pressure("io", 25)
    if video.render_device:
        try:
            device = os.stat(video.render_device, follow_symlinks=False)
            if (not stat.S_ISCHR(device.st_mode) or os.major(device.st_rdev) != 226
                    or not os.access(video.render_device, os.R_OK | os.W_OK)):
                raise OSError
        except OSError:
            raise Unavailable("VAAPI_RENDER_DEVICE_UNAVAILABLE") from None
    path, demuxer, metadata = probe(context, video)
    stream = _first_video(metadata)
    if stream.get("codec_name") not in case.input_codecs:
        raise Unavailable("VIDEO_FIXTURE_CODEC_MISMATCH")
    if any(type(stream.get(dimension)) is not int or not 1 <= stream[dimension] <= bound
           for dimension, bound in (("width", 4096), ("height", 2160))):
        raise Unavailable("VIDEO_FIXTURE_DIMENSIONS_OUTSIDE_LIMIT")
    if case.input_height and stream.get("height") != case.input_height:
        raise Unavailable("VIDEO_FIXTURE_HEIGHT_MISMATCH")
    if case.tone_map and stream.get("color_transfer") not in ("smpte2084", "arib-std-b67"):
        raise Unavailable("HDR_FIXTURE_REQUIRED")
    subtitle = next((row["index"] for row in metadata.get("streams", [])
                     if row.get("codec_type") == "subtitle" and row.get("codec_name") in
                     ("dvd_subtitle", "hdmv_pgs_subtitle", "dvb_subtitle")), None)
    if case.image_subtitles and subtitle is None:
        raise Unavailable("IMAGE_SUBTITLE_FIXTURE_REQUIRED")
    ffmpeg = tool_path("ffmpeg")
    argv, encoder = video_command(ffmpeg, path, demuxer, case, video, subtitle_index=subtitle)
    for flag, codec, missing in (("-decoders", stream["codec_name"], "VIDEO_DECODER_UNAVAILABLE"),
                                  ("-encoders", encoder, "VIDEO_ENCODER_UNAVAILABLE")):
        available = capture(context, (ffmpeg, "-hide_banner", flag), seconds=10)
        if available.returncode or not any(line.split()[1:2] == [codec.encode()]
                                           for line in available.stdout.splitlines()):
            raise Unavailable(missing)
    version = capture(context, (ffmpeg, "-version"), seconds=10)
    _keep(context, "ffmpeg.version", version.stdout)
    digest = _digest(context, path)
    monitor = Monitor(context, video.max_celsius)
    guarded = Context(context.scratch, monitor.poll, context.inventory, context.evidence)
    if synchronize is not None:
        synchronize()
    capture_start = time.monotonic()
    try:
        result = capture(guarded, argv, seconds=video.wall_seconds, output_bytes=512 * 1024)
    except ProcessLimit as error:
        _keep(context, "ffmpeg.partial.stdout", error.stdout)
        _keep(context, "ffmpeg.partial.stderr", error.stderr)
        raise
    capture_end = time.monotonic()
    _keep(context, "ffmpeg.stdout", result.stdout)
    _keep(context, "ffmpeg.stderr", result.stderr)
    if result.returncode:
        raise RuntimeError("FFmpeg transcode failed")
    frames, seconds = _progress(result.stdout)
    monitor.poll(force=True)
    interval = {"capture_start_monotonic": capture_start,
                "capture_end_monotonic": capture_end} if synchronize is not None else {}
    return {**interval, "fixture_sha256": digest, "encoder": encoder, "threads": video.threads,
            "tool_version": version.stdout.splitlines()[0].decode(errors="replace") if version.stdout else None,
            "input_codec": stream["codec_name"], "input_height": stream.get("height"),
            "output_height": case.output_height or stream.get("height"),
            "frames": frames, "media_seconds": seconds, "elapsed_seconds": result.seconds,
            "realtime_factor": seconds / result.seconds, **monitor.result()}


DVD_CASES = (
    VideoCase("dvd-h264", ("mpeg2video",), output_height=480),
    VideoCase("dvd-hevc", ("mpeg2video",), output_height=480, codec="hevc", deinterlace=True),
)


def video_workloads(video, cases=DVD_CASES, *, group="video", tier=Mode.EXTENDED,
                    requires_selection=True):
    return tuple(Workload(case.id + ("-vaapi" if video.render_device else ""),
                          group, tier,
                          Resources(cpu_workers=video.threads, memory_bytes=512 * MIB),
                          lambda context, scenario=case: transcode(context, scenario, video),
                          requires_selection=requires_selection) for case in cases)
