# Linux Benchmark Toolkit — FAT Roadmap Rev 0.2 (CANDIDATE)
**Date:** 2026-11-15 | **Change authority:** Owner-approved Alternative B scope; revised planning and requirements disposition remain CANDIDATE pending separate approval. **Planning only; no production implementation authorization, merge, formal CP-02 acceptance or release.**

## 1. Goal and factual operating model
One trusted operator runs a portable **offline Linux live USB** to inspect a computer, collect factual hardware inventory and run safe benchmarks. The result helps decide whether the hardware should be kept, repaired, upgraded, repurposed or retired. The same first article retains **core CPU/memory/storage/thermal work** and **DVD/optical, FFmpeg/Jellyfin and backup/rsync/SMB workloads** as approved by the owner's Alternative B decision.

**Threat boundary correction:** No second local operator, malicious record editor, hostile co-tenant or attacker is assumed. The inspected machine and removable media may nevertheless have corrupt, incomplete or unexpectedly formatted data. Keep safeguards against **accidental writes to existing files, wrong drives, excessive thermal/load stress, incomplete benchmarks, misleading measurements and dropped results**. Do not create further adversarial forged-record/rehashed-manifest campaigns absent an actual product requirement. Public reports still require practical operator-controlled privacy handling because they may be shared later.

The live Linux USB is isolated/offline; explicitly authorized optional network/SMB/Jellyfin tests may require temporary peer connectivity **only when the operator chooses that test**. Do not claim that those tests ran in a disconnected environment.

## 2. Authority, history and non-automatic changes
- Governing process: AI-Assisted Software Engineering Governance Standard v1.0, applied proportionately to user/physical safety and correct functionality.
- Requirements Rev 1.6: **283** (209 FR, 74 NFR); owner-approved RP-01 FAT applicability totals **210 mandatory / 65 conditional / 8 explicit later release** remain in force. Original baseline SHA256: `04849cd13ecc75c803839ab7c59a1015c5b92d1f05bf31422b54406c188e2702`.
- Approved exceptions retained: FR-134 later-release TUI report viewing, FR-177 FAT mandatory execution selection, FR-186 FAT mandatory interactive test-group/individual selection where practical.
- Frozen canonical schema 1.0.0, status-record schema 1.0/41 combinations and G5-03 source/privilege/consent/capture boundaries are not silently amended.
- Current engineering anchor: draft PR #72, head `16a50ba2dbe570f4790ac7d0cfcd8d63601d6b49`, verified PR CI 43764211945 and push CI 43764206376, both SUCCESS. Draft PRs stay unmerged.
- Baseline applicability **per ID** and original 20-column controlled requirement CSV are not in the identified GitHub current tree; only their hashes, aggregate classifications and 283-ID CP-02 trace are available. This candidate cannot legitimately amend per-ID dispositions without recovering those source bytes.

## 3. Priority order and execution slices
The 13 owner-approved RP identifiers are retained. The proposed work is scheduled in six **functional slices**, not an artificial new numbered stage model. Each increment is bounded, follows a real functional dependency, and ends with code/test/output/host evidence where applicable.

### Slice A — Finish functional G5-04 integration (RP-03 / RP-04)
**A1**: Close RP-03.2 by checking representative *actual* capture → typed/lossless record → honest parser-error/unavailable state using original sealed bytes. Use normal, missing, malformed and partial acquisition fixtures only; no more deliberate falsified hashes or attacker-replay matrices.
**A2**: RP-03.3: zero-observation session, partial/interrupted session, limitations and truthful completion state. Test normal workflow interruption/cleanup.
**A3**: RP-04: reconcile the original 39 CP-02 cases, retain operational correctness and malformed/incomplete data tests, propose removal or replacement of adversary-only methods as **test-scope changes**, and record remaining unexecuted cases without claiming acceptance. Validate the real Bodhi 7 AMD64 acquisition path.
**Exit:** One validated inventory session is available to benchmark and report consumers; no invented hardware facts; no silent evidence loss. CP-07 owner review remains an explicit gate, with candidate dispositions reviewed rather than inferred.

### Slice B — Benchmark runtime and core measurements (RP-06 / RP-07)
**B1**: One execution path and one session model for Discovery / Standard / Extended / Interactive selection; honor cancellation and resource reservations. No competing final launcher.
**B2**: Real short CPU single/all-thread, memory bandwidth/pressure, temporary-file storage throughput/latency/IOPS; hardware availability and repeatability controls.
**B3**: Extended sustained CPU/disk and thermal/throttling sampling with bounded time and load, temperature stop criteria, no raw-device writes. Network measurement only with user-authorized peer.
**Exit:** Runs report actual measured values with units/parameters or clear NOT_TESTED/UNAVAILABLE; inspected user data is not overwritten.

### Slice C — Optical/DVD and FFmpeg/Jellyfin (RP-08)
**C1**: Optical presence and known-good permitted DVD media, bounded read reliability, imaging to safe chosen destination, verification and honest unsupported/failed outcomes.
**C2**: DVD encode/deinterlace H.264/H.265 and CPU-vs-VA-API capability where available; compare consistent fixtures.
**C3**: JF-01..JF-10 representative format/transcode/concurrency matrix and optional actual Jellyfin test; distinguish FFmpeg ability, real server behavior, and Direct Play.
**Exit:** Selected cases return reproducible elapsed/throughput/realtime factor/errors; absent media/GPU/server is reported as inapplicable or not tested, not passed.

### Slice D — Backup and data movement (RP-09)
**D1**: Large/small-file and initial/incremental rsync with generated test content; require designated writable destination, capacity reserve and cleanup.
**D2**: USB/local and operator-authorized SMB path throughput, concurrency where useful; checksum verification of **test data**, interrupted-transfer/error reporting.
**Exit:** Throughput and integrity/reliability are distinct; never modify pre-existing user files.

### Slice E — Assessments, privacy and publication (RP-05 / RP-10 / RP-11)
**E1**: Per-workload capability, performance, reliability and coverage classifications with transparent thresholds; explicit Unknown/Not Tested.
**E2**: One self-contained offline HTML report with inventory, measurements, specialized results, limitations, and keep/repair/upgrade/repurpose/retire evidence. Avoid unsupported unconditional hardware-wide scores.
**E3**: Implement approved privacy.yaml and outputs.yaml behavior proportionately for local operator usage and later report sharing; satisfy approved conditional outputs as applicable, but prioritize working HTML. No silent amendment of previously approved nine conditional outputs.
**Exit:** An actual run produces a readable report; optional formats only where selected/applicable; no source re-execution for report-only regeneration.

### Slice F — Product cutover and FAT (RP-12 / RP-13)
**F1**: Integrate CLI and Dialog TUI with the unified engine, the four modes, optional selection, progress and understandable errors. Preserve no-TUI-report-viewer approval.
**F2**: Relocatable offline AMD64 package with clear required dependencies, checksums, notices and operator guidance. Approve actual launcher cutover before switching.
**F3**: Execute real Bodhi Linux 7 live-USB first article and representative second computer tests: inventory accuracy, core/specialized measurements on applicable fixtures, safety cleanup, reboot/relocation, offline reporting and limited selected peer-connected trials.
**Exit:** A frozen candidate runs start-to-finish on physical machines; user reviews documented exceptions and explicitly authorizes FAT entry. Passing CI is not a substitute for actual FAT.

## 4. Original roadmap package reconciliation
| RP | Keep or change | Reason |
|---|---|---|
| RP-01 | APPROVED scope; reopen only its test-method/operating-assumption overlay | Alternative B retains all three workload classes; per-ID disposition changes require source authority |
| RP-02 | Preserve demonstrated limits; no new speculative limit campaign | Prevent actual overload/truncation, not hostile action |
| RP-03 | Complete truthful record generation; stop forged-canonical defense expansion | Consumer needs accurate, usable inventory |
| RP-04 | Keep functional/error/integration tests; reclassify adversarial-only cases for owner review | Tests should be relevant to operation |
| RP-05 | Keep practical mask/config behavior; avoid attacker story | Outputs may be shared outside the isolated machine |
| RP-06 | Essential | Safe run modes and cancellation |
| RP-07 | Essential | Actual core benchmarks |
| RP-08 | Essential | DVD and Jellyfin explicitly retained |
| RP-09 | Essential | Backup/rsync/SMB explicitly retained |
| RP-10 | Essential | Practical reuse/suitability judgment |
| RP-11 | Essential; preserve approved output contract until owner amendment | One combined HTML report first |
| RP-12 | Essential | Working offline TUI/CLI/package |
| RP-13 | Essential with real host evidence | Actual FAT functionality |

## 5. Prohibited complexity growth and required practical safeguards
**Do not initiate** new rehashed-manifest, invented-attacker, forged-observation, malicious-second-party, exploit or unrelated security-hardening work solely to protect the toolkit from an owner outside the model. Existing tests/code are not automatically deleted; deletion requires impact review, especially if they also catch ordinary corruption.

**Do retain** strict non-destructive disk behavior, clear drive/path choice, temporary-file cleanup, capacity reserves, source privilege consent for SMART/NVMe, bounded CPU and thermal loads, correct timing/units, handling of absent/failed devices, truthful test status, accurate report fields and reasonable sharing privacy.

## 6. Owner review gates before implementation resumes
1. Approve or amend this Rev 0.2 **candidate** roadmap and its threat-assumption corrective overlay. Alternative B scope itself is already approved.
2. Recover the original 20-column Rev 1.6 CSV and the owner-approved per-ID RP-01 applicability crosswalk (source hashes above); do not invent missing requirement wording/dispositions. Reconcile all 283 IDs against the linked worksheet.
3. Approve any requirement modification, relaxation of a frozen D-02/status contract, source/privilege change, output-count change, or removal of original CP-02 test cases that materially changes acceptance.
4. Later: CP-07 stage decision, launcher cutover, and FAT entry remain separate authorization checkpoints.

**Proposed immediate Increment 48:** planning/requirements gate first; after approval, begin Slice A1 *functional end-to-end source-to-consumer verification*. Do not resume synthetic forgery tests. No source code is modified by this planning proposal.

## 7. Source pointers
- FAT Rev 0.1 original ODT: `LBT_First_Article_Test_Readiness_Roadmap_Rev0_1_20261109(2).odt` (Project attachment).
- Current repository baseline: https://github.com/joeblow42/linux-benchmark-toolkit/tree/16a50ba2dbe570f4790ac7d0cfcd8d63601d6b49
- Approved RP-01 aggregate: `verification/fat/rp01_owner_scope_approval_20261113.json`.
- Current trace: `verification/g5_04/requirements_traceability_rev1_6.csv` (283 IDs; 12 appended trace fields, **not original 20-column source**).
- Functional proposals: `docs/ROADMAP.md` and `docs/TEST_SPECIFICATION.md` (context; neither supersedes owner approval).
