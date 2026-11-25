# Increment 71 FFmpeg handoff

RP-08 C2 uses an explicit owned local fixture and a constrained demuxer. It probes the video stream, hashes the fixture, and encodes MPEG-2 to H.264 or HEVC with deinterlacing. The preview CLI can add a separately selected VA-API encoding variant on an allowed readable render device. The VA-API configuration uses software decode and hardware encode. Results report frames, measured media time, wall time, real-time factor, encoder and version, and thermal observations. Raw tool outputs stay private. Default source durations are 120 seconds for the configured short workload and 300 for an extended encode.

Three local focused tests passed. The FFmpeg smoke ran in both GitHub Actions events with an actual synthetic MPEG-2 file and both software encoders. Unified Full passed 21/21. Physical-disc content and VA-API measurement remain open. Bodhi had no FFmpeg tools during setup, so no tool was installed on the laptop by the toolkit.

Draft #97 is stacked on draft #96. Both implementation Actions events passed. Verify the documentation head independently. Formal CP-02 remains 0/39. Continue with the C3 Jellyfin format and overlap scenarios, keeping stand-alone transcodes, Direct Play compatibility evidence, and actual server session evidence separate.
