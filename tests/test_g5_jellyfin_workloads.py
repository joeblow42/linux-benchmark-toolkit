import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lbt_g5.jellyfin_workloads import (
    ClientProfile, JELLYFIN_CASES, direct_play, import_session_evidence, jellyfin_workloads,
    run_concurrent,
)
from lbt_g5.video_workload import Video, transcode, video_command
from lbt_g5.workload_runtime import Context, Unavailable


class JellyfinWorkloadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.context = Context(self.root, lambda: None, {}, self.root / "evidence")

    def test_registry_covers_all_cases_and_absent_fixture_is_unavailable(self):
        registry = jellyfin_workloads({})
        self.assertEqual([item.id for item in registry], [f"jf-{number:02}" for number in range(1, 11)])
        with self.assertRaisesRegex(Unavailable, "VIDEO_FIXTURE_MISSING"):
            registry[-1].run(self.context)
        with self.assertRaises(ValueError):
            jellyfin_workloads({}, count=3)

    def test_hdr_and_image_subtitle_recipes(self):
        source = self.root / "sample.mkv"
        video = Video(source)
        hdr, subtitles = JELLYFIN_CASES[-2:]
        argv, _ = video_command("ffmpeg", source, "matroska", hdr, video)
        self.assertIn("tonemap=hable", " ".join(argv))
        argv, _ = video_command("ffmpeg", source, "matroska", subtitles, video, subtitle_index=3)
        self.assertIn("[0:v:0][0:3]overlay", " ".join(argv))

    @patch("lbt_g5.jellyfin_workloads.probe")
    def test_direct_play_separates_client_compatibility_and_observed_throughput(self, probe):
        source = self.root / "sample.mp4"
        probe.return_value = source, "mov", {
            "streams": [{"codec_type": "video", "codec_name": "h264"},
                        {"codec_type": "audio", "codec_name": "aac"}],
            "format": {"bit_rate": "10000"}}
        compatible = ClientProfile("mov", ("h264",), ("aac",), (), streams=2,
                                   storage_bits_per_second=100000, network_bits_per_second=19000)
        result = direct_play(self.context, Video(source), compatible)
        self.assertEqual(result["compatibility"], "SUPPORTED_IN_PROFILE")
        self.assertEqual(result["throughput"], "INSUFFICIENT")
        self.assertEqual(result["aggregate_required_bits_per_second"], 20000)
        self.assertEqual(result["actual_client_session"], "NOT_TESTED")
        incompatible = ClientProfile("mov", ("hevc",), ("aac",), ())
        result = direct_play(self.context, Video(source), incompatible)
        self.assertEqual(result["compatibility_constraints"], ["VIDEO"])
        self.assertEqual(result["throughput"], "UNVERIFIED")

    def test_server_exports_remain_separate_and_private(self):
        session = self.root / "session.json"
        session.write_text(json.dumps({"PlayMethod": "Transcode", "Client": "fixture"}))
        log = self.root / "transcode.log"
        log.write_bytes(b"FICTIONAL TEST LOG")
        outcome = import_session_evidence(self.context, session, log)
        self.assertEqual(outcome["play_method"], "Transcode")
        self.assertEqual((self.context.evidence / "jellyfin-transcode.log").read_bytes(), log.read_bytes())
        self.assertNotIn("Client", outcome)

    @unittest.skipUnless(os.getenv("LBT_RUN_VIDEO_SMOKE") == "1", "dedicated FFmpeg smoke only")
    @patch("lbt_g5.core_workloads.pressure", return_value={"avg10_percent": 0})
    @patch("lbt_g5.jellyfin_workloads.check_pressure")
    @patch("lbt_g5.video_workload.check_pressure")
    @patch("lbt_g5.video_workload.Monitor")
    def test_real_simultaneous_h264_transcode(self, monitor, *_):
        tool = shutil.which("ffmpeg")
        self.assertIsNotNone(tool)
        source = self.root / "sample.mp4"
        subprocess.run((tool, "-nostdin", "-loglevel", "error", "-f", "lavfi",
                        "-i", "testsrc2=size=1920x1080:rate=12", "-t", "1", "-threads", "1",
                        "-c:v", "libx264", "-preset", "ultrafast", str(source)),
                       timeout=25, check=True)
        monitor.return_value.result.return_value = {}
        observations = {}
        for case in JELLYFIN_CASES[:2]:
            context = Context(self.root, lambda: None, {}, self.root / case.id)
            result = transcode(context, case, Video(source, seconds=1, wall_seconds=25))
            self.assertEqual(result["output_height"], case.output_height)
            self.assertGreater(result["frames"], 0)
            observations[case.id] = result
        with patch("lbt_g5.jellyfin_workloads._fields", return_value=[("MemAvailable", "4194304")]):
            result = run_concurrent(self.context, Video(source, seconds=1, wall_seconds=25), 2)
        self.assertEqual(result["laboratory_streams"], 2)
        self.assertGreater(result["capture_overlap_seconds"], 0)
        self.assertEqual(len(result["streams"]), 2)
        self.assertTrue(all(row["realtime_factor"] > 0 for row in result["streams"]))
        observations["jf-10"] = result
        if destination := os.getenv("LBT_JELLYFIN_EVIDENCE"):
            output = Path(destination)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps({"context": "SYNTHETIC_CI", "observations": observations},
                                         indent=2, allow_nan=False) + "\n")
