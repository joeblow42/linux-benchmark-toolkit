# Increment 72 and slices B and C handoff

## Development result

The RP-08 C3 registry covers JF-01 through JF-10. Individual fixtures are explicit. The workload checks stream codec, dimensions, HDR transfer or image-subtitle requirements as applicable. Concurrent H.264 launches 1, 2 or 4 separate FFmpeg encoders, measures overlap and records each stream. The default CLI selects two streams when JF-10 is requested. Direct Play evaluates selected client profile constraints and separately supplied storage/network evidence. An optional import retains an operator-exported session and corresponding transcode log. Client capacity requires a measured client session.

Four local focused checks and the Interactive routing fixture passed. Unified Full passed 21/21. The dedicated real FFmpeg check ran in CI. Both implementation artifacts were downloaded and checked for actual 720p and 1080p output scenarios, two overlapping processes and positive per-stream frame and rate results. The other fixture recipes remain unmeasured until matching media is supplied. See the checkpoint for CI run and artifact IDs. Verify final documentation CI separately.

## Exact reviewed branch stack

| Increment | Scope | Draft PR | Verified documentation commit |
|---|---|---|---|
| 67 | RP-06 B1 workload runtime | #93 | d347297 |
| 68 | RP-07 B2 short measurements | #94 | 80fbb85 |
| 69 | RP-07 B3 sustained loads and thermal guard | #95 | 33829cf |
| 70 | RP-08 C1 DVD imaging | #96 | 5af4b7e |
| 71 | RP-08 C2 DVD video encoding | #97 | cccf2ff |
| 72 | RP-08 C3 Jellyfin and Direct Play | #98 | Verify the published documentation commit |

Both push and PR implementation and documentation checks passed for Increments 67–71. The draft stack starts on #92. The installation and production launcher cutover remain separate. Formal CP-02 stays at 0/39 executed and accepted.

## Physical verification still open

The Bodhi short CPU and memory measurements completed. A two-second CPU smoke exercised the thermal sensor path. Buffered short and sustained storage positive paths were verified on isolated fixtures. The Bodhi storage write guard stopped the hardware run because of pre-existing host I/O pressure. A second drive is suitable only after the owner designates an owner-only directory on a supported local filesystem and host conditions allow the test.

Optical imaging passed on a generated ISO fixture. A physical test needs ordinary read access to the selected optical device, known-good permitted unencrypted media with a confirmed capacity, and a private local output destination with space and reserve. The preview uses the native bounded read and retry map. A physical media-profile check and a separate ddrescue mode remain open. VA-API, a live Jellyfin client/server session, remaining matching transcode fixtures and any configured network peer are also pending their inputs and applicable authorization.

Slice D RP-09 is the next roadmap work after this requested scope. The B/C engineering and software verification here leave CP-07, production cutover and FAT acceptance separate.
