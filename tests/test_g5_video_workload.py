import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from lbt_g5.video_workload import DVD_CASES, Video, _progress, transcode, video_command
from lbt_g5.workload_runtime import Context, Unavailable


class VideoWorkloadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.context = Context(self.root, lambda: None, {}, self.root / "evidence")

    def test_progress_requires_completed_measured_frames(self):
        self.assertEqual(_progress(b"frame=1\nout_time_us=80000\nprogress=continue\n"
                                   b"frame=7\nout_time_us=280000\nprogress=end\n"), (7, .28))
        with self.assertRaises(RuntimeError):
            _progress(b"frame=1\nout_time_us=80000\nprogress=continue\n")

    def test_fixed_software_and_hardware_plans(self):
        video = Video(self.root / "sample.vob")
        argv, encoder = video_command("/usr/bin/ffmpeg", video.path, "mpeg", DVD_CASES[1], video)
        self.assertEqual(encoder, "libx265")
        self.assertIn("bwdif", " ".join(argv))
        self.assertIn("pools=none:frame-threads=1", argv)
        self.assertEqual(argv[-3:], ("-f", "null", "-"))
        hardware = Video(video.path, render_device="/dev/dri/renderD128")
        argv, encoder = video_command("/usr/bin/ffmpeg", video.path, "mpeg", DVD_CASES[0], hardware)
        self.assertEqual(encoder, "h264_vaapi")
        self.assertIn("hwupload", " ".join(argv))
        self.assertIn("/dev/dri/renderD128", argv)

    @patch("lbt_g5.video_workload.check_pressure")
    def test_missing_input_does_not_run_ffmpeg(self, _):
        with patch("lbt_g5.video_workload.capture") as runner:
            with self.assertRaisesRegex(Unavailable, "VIDEO_FIXTURE_MISSING"):
                transcode(self.context, DVD_CASES[0], Video(self.root / "missing.vob"))
            runner.assert_not_called()

    @unittest.skipUnless(os.getenv("LBT_RUN_VIDEO_SMOKE") == "1", "dedicated FFmpeg smoke only")
    @patch("lbt_g5.core_workloads.pressure", return_value={"avg10_percent": 0})
    @patch("lbt_g5.video_workload.check_pressure")
    @patch("lbt_g5.video_workload.Monitor")
    def test_real_ffmpeg_h264_and_hevc_on_synthetic_vob(self, monitor, *_):
        tool = shutil.which("ffmpeg")
        self.assertIsNotNone(tool)
        source = self.root / "sample.mpg"
        subprocess.run((tool, "-nostdin", "-loglevel", "error", "-f", "lavfi",
                        "-i", "testsrc2=size=720x480:rate=25", "-t", "1",
                        "-threads", "1", "-c:v", "mpeg2video", "-f", "mpeg", str(source)),
                       timeout=20, check=True)
        monitor.return_value.result.return_value = {}
        for case, encoder in zip(DVD_CASES, ("libx264", "libx265")):
            with self.subTest(case=case.id):
                context = Context(self.root, lambda: None, {}, self.root / case.id)
                result = transcode(context, case, Video(source, seconds=1, wall_seconds=20))
                self.assertEqual(result["input_codec"], "mpeg2video")
                self.assertEqual(result["encoder"], encoder)
                self.assertGreater(result["frames"], 0)
                self.assertGreater(result["realtime_factor"], 0)
                self.assertTrue((context.evidence / "ffmpeg.stdout").is_file())
