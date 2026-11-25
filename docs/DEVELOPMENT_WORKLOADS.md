# G5 development workloads

The development entry point is `python3 -m lbt_g5.workload_cli`. Run it from the repository as an ordinary user. The output root must be an existing owner-only directory. Each run creates a new private directory containing the original G5 inventory, a separate `workloads.json`, and any retained workload evidence. Release launcher integration is planned for Slice F.

- **Discovery** runs inventory only.
- **Standard** includes short CPU, memory, and file-backed storage workloads. An owned MPEG-2 fixture supplied with `--video-source` also enables the short video workload.
- **Extended** adds sustained CPU and file-backed storage. Supply `--sustained-seconds` and `--max-celsius` to change the development bounds.
- **Interactive** selects workloads with repeatable `--select ID`. `--select group:cpu` and similar groups select ordinary members. Explicit-impact or fixture-driven workloads use individual IDs.

Storage tests write only toolkit-created scratch files in the chosen output tree. Use a supported local filesystem with sufficient free space. The I/O-pressure guard applies across the host. Reported read and random I/O performance can include filesystem caching. A live overlay measures the overlay path. An operator-designated second drive can provide a distinct storage path.

## Optical and video

Select `dvd-image` with the confirmed `--dvd-device`, `--dvd-bytes`, and `--confirm-unencrypted-dvd` options. Use authorized, known-good unencrypted media and ordinary-user read permission. The private output keeps a verified ISO or a partial copy with retry evidence. Automated physical media-profile verification and a separate ddrescue recovery mode remain open.

For an owned MPEG-2 fixture, `--video-source FILE --mode interactive --select dvd-h264 --select dvd-hevc` compares software H.264 and HEVC, with deinterlacing on the HEVC scenario. Available VA-API comparisons use an explicitly supplied render device and the `dvd-h264-vaapi` or `dvd-hevc-vaapi` selections. The development defaults target 120 seconds of media for short video and 300 seconds for extended cases, subject to the actual fixture duration and wall time limits. FFmpeg and FFprobe must already be installed.

## Jellyfin scenarios

Use `--jellyfin-fixture jf-01=FILE --mode interactive --select jf-01` for the 1080p H.264 to 720p scenario. The registry offers `jf-01` through `jf-10`. Use `--jellyfin-streams 1|2|4` with `jf-10` to choose simultaneous encodes. Results cover local FFmpeg workloads and preserve per-stream measurements.

Select `jf-direct-play` with an owned fixture and a `--direct-play-profile` JSON file. The profile contains `container`, `video_codecs`, `audio_codecs`, and `subtitle_codecs`. The codec fields are lists. For MP4, use the FFmpeg demuxer label `mov`. Optional fields are `streams`, `storage_bits_per_second`, and `network_bits_per_second`. Supply separately measured rates to assess aggregate delivery. The result reports codec compatibility and throughput evidence independently.

Select `jf-session-evidence` with an operator-exported Jellyfin session JSON object and, for a transcode, the corresponding `--jellyfin-transcode-log`. This imports a real session's local evidence under the operator's control. The import does not initiate a server or client session.
