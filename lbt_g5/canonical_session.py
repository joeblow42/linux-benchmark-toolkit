"""G5-04 private canonical-session materialization from ONE completed IC-02 run.

No host probing, CLI report generation, source re-execution, or privacy policy
evaluation occurs here. This deliberately conservative first normalizer
preserves each acquired artifact as a raw original observation. UTF-8 is
preserved as typed literal text when reasonably bounded; all other values use
a lossless sealed-byte reference and explicitly record the absence of parsing.
It never infers a semantic datum or benchmark result from raw inventory bytes.

The manifest is committed last. Without an independently verified manifest,
a run is not a validated canonical session, even if some private files exist.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat

from .canonical_contract import (
    CANONICAL_SCHEMA_VERSION, CanonicalContractError,
    new_status, validate_status_record,
)
from .catalog import initial_catalog
from .local_space import LOCAL_TYPES
from .normalization import (normalize_sealed_source, parser_available,
                            SourceParseError, dmi_field_from_source_path,
                            cpu_sysfs_path_identity, block_sysfs_path_identity,
                            optical_sysfs_path_identity,
                            drm_sysfs_path_identity, net_sysfs_path_identity,
                            thermal_sysfs_path_identity,
                            hwmon_sysfs_path_identity, power_sysfs_path_identity)
from .safety import initial_source_policies, valid_run_id

PRIVATE_FILES = ("system.json", "source_attempts.json", "status_records.json")
MANIFEST_NAME = "session_manifest.json"
MAX_LITERAL_TEXT = 262144  # larger text remains a byte-exact sealed reference
MAX_RECEIPT_BYTES = 256 * 1024


def _check_private_dir(path):
    st = os.lstat(path)
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid()
            or st.st_mode & 0o077):
        raise CanonicalContractError("private directory unsafe")
    return path


def _check_run(path, run_id):
    if not valid_run_id(run_id) or path.name != run_id:
        raise CanonicalContractError("invalid acquisition run identity")
    if not path.is_absolute() or os.path.realpath(path) != str(path):
        raise CanonicalContractError("run location must be absolute and non-symlink")
    _check_private_dir(path)
    _check_private_dir(path / "private")
    _check_private_dir(path / "private" / "source_attempt_records")
    # Denied-only and zero-observation runs need not have an evidence folder.
    if os.path.lexists(path / "private" / "evidence"):
        _check_private_dir(path / "private" / "evidence")


def _read_restricted(path, ceiling):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                or st.st_mode & 0o077 or st.st_size > ceiling):
            raise CanonicalContractError("unsafe or oversize private file")
        blocks = []
        remaining = ceiling + 1
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                break
            blocks.append(part)
            remaining -= len(part)
        raw = b"".join(blocks)
        if len(raw) > ceiling or len(raw) != st.st_size:
            raise CanonicalContractError("invalid private file size")
        return raw
    finally:
        os.close(fd)


def _json_load(raw):
    def strict_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise CanonicalContractError("duplicate JSON field")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=strict_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              CanonicalContractError("non-finite JSON number")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CanonicalContractError("malformed private JSON") from exc


def _render(obj):
    return (json.dumps(obj, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def _atomic_new_private(private, name, raw):
    if name not in PRIVATE_FILES + (MANIFEST_NAME,):
        raise CanonicalContractError("unexpected canonical filename")
    directory = os.open(private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    staging = ".pending-" + secrets.token_hex(12)
    fd = None
    try:
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short canonical write")
            view = view[count:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        # EXCL hard-link publish cannot replace another committed record.
        os.link(staging, name, src_dir_fd=directory, dst_dir_fd=directory,
                follow_symlinks=False)
        os.fsync(directory)
        os.unlink(staging, dir_fd=directory)
        os.fsync(directory)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def _artifacts(recorded):
    outcome = recorded.outcome
    if isinstance(outcome, dict):
        return tuple(outcome.get("receipts", ()))
    if hasattr(outcome, "stdout"):
        return tuple(x for x in (outcome.stdout, outcome.stderr) if x is not None)
    return tuple(getattr(outcome, "artifacts", ()) or ())


def _verified_mountinfo_paths(metadata, artifacts, policy):
    """Bind SRC-14 to the one fixed G5-03 D0 proc worker file.

    G5-03 emits /proc/self/mountinfo once and seals its original bytes as
    item0001; no shell invocation, custom path, target or second artifact is
    authorized. Unavailable/failed attempts may have no captured original.
    """
    paths = metadata.get("source_paths")
    if type(paths) is not list:
        raise CanonicalContractError("mountinfo source path record missing")
    if (metadata.get("invocation") != policy.operation_id
            or metadata.get("target") is not None):
        raise CanonicalContractError("mountinfo fixed operation or target mismatch")
    if not artifacts:
        if paths:
            raise CanonicalContractError("mountinfo claimed path without original")
        return ()
    if (len(artifacts) != 1 or paths != ["/proc/self/mountinfo"]
            or artifacts[0].artifact != "item0001"
            or metadata.get("unavailable_fields") != []
            or metadata.get("outcome") not in ("CAPTURED","PARTIAL")):
        raise CanonicalContractError(
            "mountinfo sealed item/fixed worker source provenance mismatch")
    return ("/proc/self/mountinfo",)


def _verified_dmi_paths(metadata, artifacts, policy):
    """Bind each sealed SRC-04 item to the *recorded* worker source-path slot.

    G5-03 stores successful worker source_paths in receipt order, while the
    evidence writer seals successful items as item0001..itemNNNN. Missing
    optional attributes do not create evidence items. Fail closed if the
    receipt cannot prove an unambiguous monotonic mapping. No host probing.
    """
    paths = metadata.get("source_paths")
    if type(paths) is not list or len(paths) != len(artifacts):
        raise CanonicalContractError("DMI path and artifact counts disagree")
    if len(paths) > policy.max_entries:
        raise CanonicalContractError("DMI source path count exceeds approved bound")
    fields = []
    for index, (path, artifact) in enumerate(zip(paths, artifacts), 1):
        if artifact.artifact != "item" + format(index, "04d"):
            raise CanonicalContractError("DMI sealed artifact ordinal mismatch")
        field = dmi_field_from_source_path(path)
        if field is None:
            raise CanonicalContractError("DMI source path not approved")
        fields.append(field)
    if fields != sorted(set(fields)):
        raise CanonicalContractError("DMI source path duplicate or ambiguous order")
    return tuple(paths)



def _verified_cpu_sysfs_paths(metadata, artifacts, policy):
    """One-to-one attribution in the G5-03 SRC-07 worker's actual order.

    The worker emits root CPU sets in sorted-name order, CPU directory names
    lexically, and each CPU's attributes in its fixed worker tuple order.
    Optional unavailable files create no sealed item or successful path.
    Never infer a path from a value or read the host during normalization.
    """
    paths = metadata.get("source_paths")
    if type(paths) is not list or len(paths) != len(artifacts):
        raise CanonicalContractError("CPU sysfs path and artifact counts disagree")
    if len(paths) > policy.max_entries:
        raise CanonicalContractError("CPU sysfs source path count exceeds approved bound")
    previous_order = None
    for index, (path, artifact) in enumerate(zip(paths, artifacts), 1):
        if artifact.artifact != "item" + format(index, "04d"):
            raise CanonicalContractError("CPU sysfs sealed artifact ordinal mismatch")
        identity = cpu_sysfs_path_identity(path)
        if identity is None:
            raise CanonicalContractError("CPU sysfs source path not approved")
        order = identity[1]
        if previous_order is not None and order <= previous_order:
            raise CanonicalContractError("CPU sysfs source path order or identity ambiguous")
        previous_order = order
    return tuple(paths)



def _verified_block_sysfs_paths(metadata, artifacts, policy):
    """Bind SRC-12 original byte item ordinals to exact G5-03 worker paths.

    Device directory entries are visited lexically and each device's attribute
    tuple in a fixed *nonalphabetical* sequence. Optional unavailability yields
    no source-path or evidence item. Reject mismatched/ambiguous provenance
    before emitting any canonical session manifest.
    """
    paths = metadata.get("source_paths")
    if type(paths) is not list or len(paths) != len(artifacts):
        raise CanonicalContractError("block sysfs path/artifact counts disagree")
    if len(paths) > policy.max_entries:
        raise CanonicalContractError("block sysfs source entry bound exceeded")
    previous_order = None
    for index, (path, artifact) in enumerate(zip(paths, artifacts), 1):
        if artifact.artifact != "item" + format(index, "04d"):
            raise CanonicalContractError("block sysfs evidence item ordinal mismatch")
        identity = block_sysfs_path_identity(path)
        if identity is None:
            raise CanonicalContractError("block sysfs path is not registered")
        order = identity[1]
        if previous_order is not None and order <= previous_order:
            raise CanonicalContractError("block sysfs duplicate or wrong worker order")
        previous_order = order
    return tuple(paths)



def _verified_optical_sysfs_paths(metadata, artifacts, policy):
    """Source SRC-17 read-only optical paths in original G5 worker sequence.

    Only successful reads produce source_paths and itemNNNN originals. Worker
    sorts srN names lexically (sr10 before sr2) and visits the fixed attribute
    order. This verifies item-to-receipt binding, not media insertion.
    """
    paths = metadata.get("source_paths")
    if type(paths) is not list or len(paths) != len(artifacts):
        raise CanonicalContractError("optical sysfs path/artifact count mismatch")
    if len(paths) > policy.max_entries:
        raise CanonicalContractError("optical sysfs entry bound exceeded")
    previous_order = None
    for index, (path, artifact) in enumerate(zip(paths, artifacts), 1):
        if artifact.artifact != "item" + format(index, "04d"):
            raise CanonicalContractError("optical sysfs artifact ordinal mismatch")
        identity = optical_sysfs_path_identity(path)
        if identity is None:
            raise CanonicalContractError("optical sysfs path not registered")
        if previous_order is not None and identity[1] <= previous_order:
            raise CanonicalContractError("optical sysfs order or identity ambiguous")
        previous_order = identity[1]
    return tuple(paths)



def _verified_lexical_sysfs_paths(metadata, artifacts, policy, *, identity_fn,
                                   label):
    """Validate G5-03 sorted entry/fixed-attribute order and sealed item slots.

    The source-specific identity function is constrained to approved paths,
    with sort keys constructed from the worker's registered tuple order.
    """
    paths = metadata.get("source_paths")
    if type(paths) is not list or len(paths) != len(artifacts):
        raise CanonicalContractError(label + " path/artifact count mismatch")
    if len(paths) > policy.max_entries:
        raise CanonicalContractError(label + " source entry bound exceeded")
    previous_order = None
    for number, (path, artifact) in enumerate(zip(paths, artifacts), 1):
        if artifact.artifact != "item" + format(number, "04d"):
            raise CanonicalContractError(label + " item ordinal mismatch")
        identity = identity_fn(path)
        if identity is None:
            raise CanonicalContractError(label + " unapproved source path")
        if previous_order is not None and identity[1] <= previous_order:
            raise CanonicalContractError(label + " duplicate/nonworker order")
        previous_order = identity[1]
    return tuple(paths)



def _verified_d1_single_call_streams(metadata, artifacts, *, invocation, label):
    """Strict G5-03 one-subcall D1 source-stream original and receipt binding.

    G5-03 seals only nonempty stdout/stderr as call0001-* in that order.
    The invocation is exactly the approved fixed command, never operator argv.
    """
    if metadata.get("source_paths") != []:
        raise CanonicalContractError(label + " cannot have sysfs source paths")
    if artifacts and metadata.get("invocation") != invocation:
        raise CanonicalContractError(label + " invocation mismatch")
    names = [a.artifact for a in artifacts]
    expected = ["call0001-stdout", "call0001-stderr"]
    if len(names) != len(set(names)) or len(names) > 2:
        raise CanonicalContractError(label + " duplicate/too many originals")
    if any(n not in expected for n in names):
        raise CanonicalContractError(label + " unapproved subcall/stream original")
    if names != sorted(names, key=expected.index):
        raise CanonicalContractError(label + " original stream order mismatch")
    return tuple(n.split("-")[-1] for n in names)


def _verified_lscpu_streams(metadata, artifacts):
    return _verified_d1_single_call_streams(
        metadata, artifacts, invocation="lscpu", label="lscpu")


def _verified_lsblk_streams(metadata, artifacts):
    return _verified_d1_single_call_streams(
        metadata, artifacts, invocation=(
            "lsblk --bytes --json --output "
            "NAME,KNAME,TYPE,SIZE,RO,RM,MODEL,SERIAL,TRAN"), label="lsblk")


def _verified_lspci_streams(metadata, artifacts):
    """Exact single-subcall D1 PCI original stream; never an operator target."""
    if metadata.get("target") is not None:
        raise CanonicalContractError("lspci target not approved")
    return _verified_d1_single_call_streams(
        metadata, artifacts, invocation="lspci -nn", label="lspci")


def _verified_fsstat_streams(metadata, artifacts, local_mounts, policy):
    """Bind each D1 FS_STAT stream to an ordered, approved same-run local mount.

    The G5-03 adapter seals nonempty stdout/stderr as callNNNN-* and stores
    mount:stream in source_paths. Only a fully parsed same-run SRC-14 D0
    mountinfo original may supply local_mounts. No host probing occurs here.
    """
    paths = metadata.get("source_paths")
    if (type(paths) is not list or len(paths) != len(artifacts)
            or metadata.get("invocation") != "FS_STAT"
            or metadata.get("target") is not None):
        raise CanonicalContractError("FS_STAT worker receipt identity mismatch")
    if not artifacts:
        return (), ()
    if local_mounts is None:
        raise CanonicalContractError("FS_STAT lacks verified same-run mountinfo")
    mounts, streams = [], []
    last_call = 0
    last_stream = None
    seen_mounts = set()
    last_mount = None
    for artifact, label in zip(artifacts, paths):
        matched = re.fullmatch(r"call([0-9]{4})-(stdout|stderr)", artifact.artifact)
        if matched is None or type(label) is not str:
            raise CanonicalContractError("FS_STAT unapproved original stream slot")
        call = int(matched.group(1))
        stream = matched.group(2)
        mount, sep, recorded_stream = label.rpartition(":")
        if (not sep or recorded_stream != stream or mount not in local_mounts
                or call < 1 or call > policy.max_entries):
            raise CanonicalContractError("FS_STAT mount/stream not approved by source")
        if call == last_call:
            if stream != "stderr" or last_stream != "stdout" or mount != last_mount:
                raise CanonicalContractError("FS_STAT duplicate/reordered stream")
        elif call == last_call + 1:
            if mount in seen_mounts:
                raise CanonicalContractError("FS_STAT repeated mount acquisition")
            seen_mounts.add(mount)
        else:
            raise CanonicalContractError("FS_STAT skipped or reversed worker call")
        last_call, last_stream, last_mount = call, stream, mount
        mounts.append(mount)
        streams.append(stream)
    return tuple(mounts), tuple(streams)


def _o1_expected_argv(source_id, target):
    """Pure approved G5-03 O1 command identity; never touches a device."""
    if type(target) is not str:
        return None
    if source_id == "SRC-13":
        if re.fullmatch(r"/dev/sd[a-z]+", target):
            return ["smartctl", "-i", "-H", target]
        if re.fullmatch(r"/dev/nvme[0-9]+(?:n[0-9]+)?", target):
            return ["nvme", "smart-log", target]
    elif source_id == "SRC-18" and re.fullmatch(r"/dev/sr[0-9]+", target):
        return ["sg_get_config", "--readonly", "--current", target]
    elif source_id == "SRC-21" and re.fullmatch(r"/dev/dri/renderD[0-9]+", target):
        return ["vainfo", "--display", "drm", "--device", target]
    return None


def _verified_o1_provenance(folder, run_id, receipt, recorded, all_attempts,
                            artifacts):
    """Match G5-03 runtime witness to its durable consent and sealed D0 slot.

    A receipt's ALLOW field alone is not authorization. The originating
    RecordedOutcome and same-run inventory must independently agree. This is
    an operational chain of custody, not a cryptographic operator signature.
    """
    p = receipt.get("authorization_provenance")
    fields = {"run_id", "source_id", "operation_id", "target",
              "consent_run_id", "consent_source_id", "consent_operation_id",
              "consent_target", "consent_issued_utc", "impact_acknowledged",
              "inventory_source_id", "inventory_source_path",
              "inventory_evidence_id", "approved_argv"}
    sid = receipt.get("source_id")
    upstream = {"SRC-13":"SRC-12", "SRC-18":"SRC-17",
                "SRC-21":"SRC-19"}.get(sid)
    if (upstream is None or receipt.get("authorization_class") != "O1"
            or receipt.get("schema_version") != "g5-02-attempt-0.2"
            or receipt.get("decision") != "ALLOW"
            or type(p) is not dict or set(p) != fields
            or recorded.authorization_provenance != p
            or receipt.get("source_paths") != []):
        raise CanonicalContractError("O1 operational authorization witness absent or forged")
    target = receipt.get("target")
    argv = _o1_expected_argv(sid, target)
    if (argv is None or p["approved_argv"] != argv
            or receipt.get("invocation") != " ".join(argv)
            or any(p[key] != receipt[key] for key in (
                "run_id","source_id","operation_id","target"))
            or p["consent_run_id"] != run_id
            or p["consent_source_id"] != sid
            or p["consent_operation_id"] != receipt["operation_id"]
            or p["consent_target"] != target
            or p["impact_acknowledged"] is not True
            or p["inventory_source_id"] != upstream):
        raise CanonicalContractError("O1 consent, source or fixed command mismatch")
    try:
        timestamp = datetime.fromisoformat(p["consent_issued_utc"].replace("Z","+00:00"))
        observed = datetime.fromisoformat(receipt["observed_utc"].replace("Z","+00:00"))
        run_start = datetime.strptime(run_id[4:], "%Y%j%H%M%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, AttributeError) as exc:
        raise CanonicalContractError("invalid O1 consent timestamps") from exc
    if (timestamp.tzinfo is None or timestamp.utcoffset().total_seconds()!=0
            or not p["consent_issued_utc"].endswith("Z")
            or observed.tzinfo is None or observed.utcoffset().total_seconds()!=0
            # The immutable G5-02 receipt timestamps are truncated to
            # milliseconds; the validated G5-03 consent ticket carries
            # microseconds. Compare at the *recorded* precision only.
            or not run_start <= timestamp
            or timestamp.replace(
                microsecond=(timestamp.microsecond // 1000) * 1000) > observed):
        raise CanonicalContractError("O1 consent outside source run")
    slot = receipt["attempt_id"].rsplit("-",1)[-1]
    expected = ["call" + format(int(slot),"04d") + "-" + stream
                for stream in ("stdout","stderr")]
    names=[a.artifact for a in artifacts]
    if (not names or len(names)>2 or len(set(names))!=len(names)
            or any(n not in expected for n in names)
            or names != sorted(names,key=expected.index)):
        raise CanonicalContractError("O1 source stream ordinal/order mismatch")
    inv_path=p["inventory_source_path"]
    if type(inv_path) is not str or type(p["inventory_evidence_id"]) is not str:
        raise CanonicalContractError("invalid O1 inventory evidence identity")
    if sid == "SRC-13":
        m=re.match(r"^/sys/class/block/(sd[a-z]+|nvme[0-9]+n[0-9]+)/",inv_path)
        name=target.rsplit("/",1)[-1]
        matches=bool(m and (m.group(1)==name or (
            re.fullmatch(r"nvme[0-9]+",name) and
            re.fullmatch(re.escape(name)+r"n[0-9]+",m.group(1)))))
    elif sid == "SRC-18":
        m=re.match(r"^/sys/class/block/(sr[0-9]+)/",inv_path)
        matches=bool(m and target=="/dev/"+m.group(1))
    else:
        matches=bool(re.match(r"^/sys/class/drm/card[0-9]+/",inv_path))
        # Render-node->card identity was checked using the real device at
        # G5-03 execution, not re-probed while normalizing sealed evidence.
    if not matches:
        raise CanonicalContractError("O1 inventory path and target do not match")
    for previous in all_attempts:
        prior_path=previous.receipt_private_path
        if (type(prior_path) is not str or not re.fullmatch(
                r"private/source_attempt_records/SRC-[0-9]{2,}-[0-9]{2,}\.json",
                prior_path)):
            continue
        prior=_json_load(_read_restricted(folder/prior_path,MAX_RECEIPT_BYTES))
        if (prior.get("run_id") != run_id or prior.get("source_id") != upstream
                or prior.get("authorization_class") != "D0"
                or prior.get("outcome") not in ("CAPTURED","PARTIAL")):
            continue
        evidence=_artifacts(previous)
        paths=prior.get("source_paths")
        if (type(paths) is not list or len(paths) != len(evidence)
                or prior.get("evidence_ids") != [a.evidence_id for a in evidence]):
            continue
        for path, item in zip(paths,evidence):
            if (path==inv_path and item.evidence_id==p["inventory_evidence_id"]
                    and item.run_id==run_id and item.source_id==upstream):
                raw=_read_restricted(folder/item.private_relative_path,item.byte_count)
                if (len(raw)==item.byte_count and
                        hashlib.sha256(raw).hexdigest()==item.sha256):
                    return True
    raise CanonicalContractError("O1 inventory witness not bound to sealed same-run D0")


def _status_for(receipt, artifacts, *, parser_state="NOT_RUN",
                o1_provenance_verified=False):
    """A status needs actual factual source and parser evidence.

    A captured source without a parser cannot be finalized as acquisition
    COMPLETE, PARTIAL/PARSE_FAILED or SOURCE_INCOMPLETE. Fail closed.
    """
    if parser_state not in ("NOT_RUN", "OK", "FAILED"):
        raise CanonicalContractError("invalid parser disposition")
    state, reason = receipt["outcome"], receipt["reason"]
    if state == "CAPTURED":
        if reason != "BYTES_PRESERVED":
            raise CanonicalContractError("captured source has unapproved reason")
        if not artifacts or parser_state == "NOT_RUN":
            raise CanonicalContractError("captured source has no supported parser result")
        if parser_state == "FAILED":
            return "PARTIAL", "PARSE_FAILED"
        return "COMPLETE", "OK"
    if state == "PARTIAL":
        if receipt["capture_limited"] or reason in ("CAPTURE_LIMIT", "TIME_BUDGET_EXCEEDED"):
            return "PARTIAL", "CAPTURE_LIMIT"
        if reason == "EVIDENCE_PERSIST_FAILED":
            return "PARTIAL", "EVIDENCE_INCOMPLETE"
        if reason == "SOURCE_INCOMPLETE":
            return "PARTIAL", "SOURCE_INCOMPLETE"
        # Owner approved Alternative A, 2026-11-04. A nonzero D1 exit is
        # acquisition incompleteness, not proof of a parser failure. Require
        # the actual recorded exit and at least one preserved original.
        if reason == "EXIT_NONZERO":
            code = receipt.get("exit_code")
            if (receipt.get("authorization_class") != "D1"
                    or not artifacts or type(code) is not int
                    or code == 0 or abs(code) > 65535
                    or receipt.get("timed_out") or receipt.get("capture_limited")):
                raise CanonicalContractError("unsubstantiated D1 nonzero exit")
            return "PARTIAL", "SOURCE_INCOMPLETE"
        # Separate owner-approved O1 Alternative A. The G5-03 recorded
        # consent/inventory/command witness MUST be independently checked
        # above; a self-asserted ALLOW receipt is insufficient.
        if reason == "ACQUISITION_ERROR":
            code = receipt.get("exit_code")
            if (receipt.get("authorization_class") != "O1"
                    or receipt.get("source_id") not in ("SRC-13","SRC-18","SRC-21")
                    or receipt.get("decision") != "ALLOW"
                    or o1_provenance_verified is not True
                    or not artifacts or type(code) is not int
                    or code == 0 or abs(code) > 65535
                    or receipt.get("timed_out") or receipt.get("capture_limited")):
                raise CanonicalContractError("unsubstantiated O1 nonzero acquisition")
            return "PARTIAL", "SOURCE_INCOMPLETE"
        raise CanonicalContractError("unclassified partial-source reason")
    if state == "DENIED" and reason == "OPERATOR_AUTH_REQUIRED":
        return "UNAUTHORIZED", "OPERATOR_AUTH_REQUIRED"
    if state == "DENIED" and reason == "ACCESS_DENIED":
        return "PERMISSION_DENIED", "ACCESS_DENIED"
    if state == "UNAVAILABLE":
        if reason in ("TOOL_MISSING", "EXECUTABLE_NOT_FOUND",
                      "PYTHON3_NOT_FOUND"):
            return "TOOL_MISSING", "EXECUTABLE_NOT_FOUND"
        if reason in ("NO_RELEVANT_DEVICE", "NOT_APPLICABLE"):
            return "NOT_APPLICABLE", "NO_RELEVANT_DEVICE"
        if reason == "SOURCE_ABSENT":
            return "UNAVAILABLE", "SOURCE_ABSENT"
        raise CanonicalContractError("unclassified unavailable-source reason")
    if state == "FAILED":
        if reason == "EVIDENCE_PERSIST_FAILED":
            return "FAILED", "EVIDENCE_PERSIST_FAILED"
        if reason == "TIME_BUDGET_EXCEEDED":
            return "FAILED", "TIME_BUDGET_EXCEEDED"
        if reason == "ACQUISITION_ERROR":
            return "FAILED", "ACQUISITION_ERROR"
    # Unknown source transport reasons do not prove a failure category.
    raise CanonicalContractError("unclassified source outcome/reason; refuse final status")


def _observation(artifact, raw, attempt_id, *, status_record_id,
                 parser_findings=None, limitations=None):
    try:
        if len(raw) > MAX_LITERAL_TEXT:
            raise UnicodeDecodeError("utf-8", raw, 0, 1, "literal size bound")
        literal = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        literal = None
    return {
        "observation_id": "obs:" + artifact.evidence_id,
        "collector_id": artifact.collector_id,
        "status_record_id": status_record_id,
        "datum_path": "unclassified.source." + artifact.source_id + "." + artifact.artifact,
        "instance_key": artifact.evidence_id,
        "ordinal": 0,
        "observed_value": literal if literal is not None else {"sealed_bytes_ref": artifact.evidence_id},
        "normalized_value": None,
        "value_type": "STRING" if literal is not None else "BYTES_REF",
        "unit": None,
        "evidence_refs": [artifact.evidence_id],
        "source_attempt_ids": [attempt_id],
        "transformation_ids": [],
        "acquired_utc": None,
        "capture_limit_ids": [],
        "parser_findings": list(parser_findings if parser_findings is not None
                                else ("UNPARSED_SOURCE_ARTIFACT",)),
        "limitations": list(limitations if limitations is not None
                            else ("Source-specific semantic normalization not yet implemented",)),
    }


def _semantic_observation(artifact, attempt_id, datum, index, parser_id):
    """One typed observation derived from a precisely identified sealed original."""
    return {
        "observation_id": "obs:" + artifact.evidence_id + ":sem:" + str(index),
        "collector_id": artifact.collector_id,
        "status_record_id": "st:" + attempt_id,
        "datum_path": datum.datum_path,
        "instance_key": artifact.evidence_id,
        "ordinal": index,
        "observed_value": datum.observed_value,
        "normalized_value": datum.normalized_value,
        "value_type": datum.value_type,
        "unit": datum.unit,
        "evidence_refs": [artifact.evidence_id],
        "source_attempt_ids": [attempt_id],
        "transformation_ids": [parser_id],
        "acquired_utc": None,
        "capture_limit_ids": [],
        "parser_findings": ["SOURCE_PARSER_SUCCEEDED"],
        "limitations": [],
    }


def build_canonical(run_directory, engine_run):
    """Commit private G5-04 records from a completed G5-03 EngineRun.

    Returns a restricted manifest after verifying all files and same-run
    provenance. Never calls an adapter, executable, or legacy collector.
    """
    folder = Path(run_directory)
    run_id = engine_run.run_id
    _check_run(folder, run_id)
    if engine_run.canonical_status_pending is not True:
        raise CanonicalContractError("unexpected engine canonical state")
    if (folder / "private" / MANIFEST_NAME).exists():
        raise FileExistsError("canonical session already finalized")
    private = folder / "private"
    policies = {p.source_id: p for p in initial_source_policies()}
    attempted = set()
    evidence = {}
    observations = []
    attempts = []
    statuses = []
    limits = []
    all_attempt_ids = set()
    source_ids = set()
    all_original_bytes = 0
    semantic_field_count = 0
    verified_local_mounts = None
    all_attempts = [item for collector in engine_run.collectors
                    for item in collector.source_attempts]
    for item in all_attempts:
        receipt_path = item.receipt_private_path
        if (type(receipt_path) is not str or not re.fullmatch(
                r"private/source_attempt_records/SRC-[0-9]{2,}-[0-9]{2,}\.json",
                receipt_path)):
            raise CanonicalContractError("invalid receipt location")
        receipt_raw = _read_restricted(folder / receipt_path, MAX_RECEIPT_BYTES)
        metadata = _json_load(receipt_raw)
        source_id = metadata.get("source_id")
        policy = policies.get(source_id)
        attempt_id = metadata.get("attempt_id")
        if (policy is None or metadata.get("run_id") != run_id
                or metadata.get("collector_id") != policy.collector_id
                or metadata.get("operation_id") != policy.operation_id
                or metadata.get("authorization_class") != policy.authorization_class
                or receipt_path != "private/source_attempt_records/" + attempt_id + ".json"
                or attempt_id in attempted):
            raise CanonicalContractError("invalid/duplicate source receipt")
        attempted.add(attempt_id)
        all_attempt_ids.add(attempt_id)
        source_ids.add(source_id)
        artifacts = _artifacts(item)
        if metadata.get("evidence_ids") != [x.evidence_id for x in artifacts]:
            raise CanonicalContractError("receipt and engine evidence disagree")
        if metadata.get("acquired_bytes") != sum(x.byte_count for x in artifacts):
            raise CanonicalContractError("receipt byte count mismatch")
        sysfs_paths = (_verified_mountinfo_paths(metadata, artifacts, policy)
                       if source_id == "SRC-14" else
                       _verified_dmi_paths(metadata, artifacts, policy)
                       if source_id == "SRC-04" else
                       _verified_cpu_sysfs_paths(metadata, artifacts, policy)
                       if source_id == "SRC-07" else
                       _verified_block_sysfs_paths(metadata, artifacts, policy)
                       if source_id == "SRC-12" else
                       _verified_optical_sysfs_paths(metadata, artifacts, policy)
                       if source_id == "SRC-17" else
                       _verified_lexical_sysfs_paths(metadata, artifacts, policy,
                           identity_fn=drm_sysfs_path_identity, label="DRM")
                       if source_id == "SRC-19" else
                       _verified_lexical_sysfs_paths(metadata, artifacts, policy,
                           identity_fn=net_sysfs_path_identity, label="NET")
                       if source_id == "SRC-22" else
                       _verified_lexical_sysfs_paths(metadata, artifacts, policy,
                           identity_fn=thermal_sysfs_path_identity, label="THERM")
                       if source_id == "SRC-24" else
                       _verified_lexical_sysfs_paths(metadata, artifacts, policy,
                           identity_fn=hwmon_sysfs_path_identity, label="HWMON")
                       if source_id == "SRC-25" else
                       _verified_lexical_sysfs_paths(metadata, artifacts, policy,
                           identity_fn=power_sysfs_path_identity, label="POWER")
                       if source_id == "SRC-26" else ())
        # SRC-13/SRC-18 O1 may be normalized only after verifying same-run
        # consent, approved device/argv and D0 original evidence.
        o1_verified = False
        if (source_id in ("SRC-13", "SRC-18")
                and metadata["outcome"] in ("CAPTURED","PARTIAL")
                and metadata["reason"] in ("BYTES_PRESERVED","ACQUISITION_ERROR")):
            o1_verified = _verified_o1_provenance(
                folder, run_id, metadata, item, all_attempts, artifacts)
        # G5-03 O1 transport cannot claim captured success with a nonzero
        # return, timeout, truncation, or non-complete preserved stream.
        # Never promote such a contradictory receipt to COMPLETE/OK.
        if source_id in ("SRC-13", "SRC-18") and metadata["outcome"] == "CAPTURED":
            if (type(metadata.get("exit_code")) is not int
                    or metadata["exit_code"] != 0
                    or metadata.get("timed_out") is not False
                    or metadata.get("capture_limited") is not False
                    or any(a.limit_applied or not a.complete for a in artifacts)):
                raise CanonicalContractError(
                    "O1 captured transport contradicts original/exit evidence")
        if source_id == "SRC-20" and metadata["outcome"] == "CAPTURED":
            if (type(metadata.get("exit_code")) is not int
                    or metadata["exit_code"] != 0
                    or metadata.get("timed_out") is not False
                    or metadata.get("capture_limited") is not False
                    or not artifacts
                    or any(a.limit_applied or not a.complete for a in artifacts)):
                raise CanonicalContractError(
                    "lspci captured transport contradicts original/exit evidence")
        command_streams = (_verified_lscpu_streams(metadata, artifacts)
                           if source_id == "SRC-05" else
                           _verified_lsblk_streams(metadata, artifacts)
                           if source_id == "SRC-11" else
                           _verified_lspci_streams(metadata, artifacts)
                           if source_id == "SRC-20" else
                           tuple(a.artifact.rsplit("-", 1)[-1] for a in artifacts)
                           if source_id in ("SRC-13", "SRC-18") and o1_verified else ())
        fsstat_mounts, fsstat_streams = (
            _verified_fsstat_streams(metadata, artifacts, verified_local_mounts, policy)
            if source_id == "SRC-15" else ((), ()))
        linked = []
        parser_executions = 0
        parser_failures = []
        for artifact_index, artifact in enumerate(artifacts, 1):
            eid = artifact.evidence_id
            if (eid in evidence or artifact.run_id != run_id
                    or artifact.source_id != source_id
                    or artifact.collector_id != policy.collector_id
                    or artifact.attempt != attempt_id.rsplit("-", 1)[-1]
                    or eid != (run_id + "_" + policy.collector_id + "_" +
                               source_id + "_" + artifact.attempt + ":" +
                               artifact.artifact)
                    or artifact.private_relative_path != "private/evidence/" + eid
                    or not re.fullmatch(r"[a-f0-9]{64}", artifact.sha256)
                    or type(artifact.byte_count) is not int
                    or artifact.byte_count < 0 or artifact.byte_count > policy.max_bytes):
                raise CanonicalContractError("invalid/duplicate sealed artifact reference")
            raw = _read_restricted(folder / artifact.private_relative_path,
                                   artifact.byte_count)
            if (len(raw) != artifact.byte_count or
                    hashlib.sha256(raw).hexdigest() != artifact.sha256):
                raise CanonicalContractError("original evidence integrity failure")
            all_original_bytes += artifact.byte_count
            evidence[eid] = {
                "evidence_id": eid, "source_attempt_id": attempt_id,
                "private_relative_path": artifact.private_relative_path,
                "sha256": artifact.sha256, "byte_count": artifact.byte_count,
                "complete": artifact.complete,
                "limit_applied": artifact.limit_applied,
                "omitted_at_least": artifact.omitted_at_least,
            }
            # Invoke a registered parser ONLY on already sealed, hash-checked bytes.
            # Unknown families remain original evidence, but their captured data
            # cannot masquerade as a finalized canonical acquisition status.
            parsed = None
            error = None
            source_stream = (fsstat_streams[artifact_index - 1]
                             if source_id == "SRC-15" else
                             command_streams[artifact_index - 1]
                             if source_id in ("SRC-05", "SRC-11", "SRC-20")
                             or (source_id in ("SRC-13", "SRC-18") and o1_verified)
                             else None)
            diagnostic_only = (source_id in ("SRC-05", "SRC-11", "SRC-13", "SRC-15", "SRC-18", "SRC-20")
                               and source_stream == "stderr")
            if (metadata["outcome"] in ("CAPTURED", "PARTIAL")
                    and parser_available(source_id) and not diagnostic_only
                    and (source_id not in ("SRC-13", "SRC-18") or o1_verified)):
                parser_executions += 1
                try:
                    parsed = normalize_sealed_source(
                        source_id, raw,
                        source_path=(fsstat_mounts[artifact_index - 1]
                                     if source_id == "SRC-15" else
                                     sysfs_paths[artifact_index - 1]
                                     if source_id in ("SRC-04", "SRC-07", "SRC-12", "SRC-14", "SRC-17", "SRC-19", "SRC-22", "SRC-24", "SRC-25", "SRC-26") else None),
                        source_stream=source_stream,
                        source_command=(metadata["authorization_provenance"]
                                        ["approved_argv"][0]
                                        if source_id in ("SRC-13", "SRC-18") else None),
                        source_target=(metadata["target"]
                                       if source_id in ("SRC-13", "SRC-18") else None))
                except SourceParseError as exc:
                    error = str(exc)[:128]
                    parser_failures.append(error)
            if parsed is not None:
                if source_id == "SRC-14" and metadata["outcome"] == "CAPTURED":
                    # Registered original grammar, not a new live mount read.
                    ordered = (rec["mount_point"] for rec in
                               parsed.values[0].normalized_value
                               if rec["filesystem_type"] in LOCAL_TYPES)
                    verified_local_mounts = tuple(dict.fromkeys(ordered))
                observations.append(_observation(
                    artifact, raw, attempt_id, status_record_id="st:" + attempt_id,
                    parser_findings=("ORIGINAL_PRESERVED", "SOURCE_PARSER_SUCCEEDED"),
                    limitations=()))
                for index, datum in enumerate(parsed.values):
                    observations.append(_semantic_observation(
                        artifact, attempt_id, datum, index, parsed.parser_id))
                    semantic_field_count += 1
            else:
                observations.append(_observation(
                    artifact, raw, attempt_id, status_record_id="st:" + attempt_id,
                    parser_findings=(("PARSER_FAILED:" + error,) if error else
                                     ("DIAGNOSTIC_ORIGINAL_PRESERVED",)
                                     if diagnostic_only else
                                     ("PARSER_NOT_AVAILABLE",)),
                    limitations=(("SOURCE_PARSER_ERROR:" + error,) if error else
                                 ("STDERR_NOT_SEMANTIC_DATA",)
                                 if diagnostic_only else
                                 ("Semantic parser not implemented for source",))))
            linked.append(eid)
        if parser_executions:
            parser_state = "FAILED" if parser_failures else "OK"
        else:
            parser_state = "NOT_RUN"
        if (source_id not in ("SRC-13", "SRC-18") and metadata["outcome"] == "PARTIAL"
                and metadata["reason"] == "ACQUISITION_ERROR"):
            o1_verified = _verified_o1_provenance(
                folder, run_id, metadata, item, all_attempts, artifacts)
        status, reason = _status_for(
            metadata, artifacts, parser_state=parser_state,
            o1_provenance_verified=o1_verified)
        status_id = "st:" + attempt_id
        if (metadata.get("capture_limited") or any(x.limit_applied for x in artifacts)):
            limit_id = "limit:" + attempt_id
            limits.append({
                "limit_id": limit_id, "source_attempt_id": attempt_id,
                "approved_rule_id": "G4-07:" + source_id,
                "threshold": policy.max_bytes, "unit": "bytes",
                "observed_extent": metadata["acquired_bytes"],
                "missing_extent": metadata.get("missing_extent_known_at_least"),
                "affected_scope": source_id,
                "reason": metadata["reason"],
            })
        else:
            limit_id = None
        statuses.append(new_status(
            record_id=status_id, domain="acquisition",
            component_id=policy.collector_id, subject_id=source_id,
            status=status, reason_code=reason,
            detail=("transport=" + str(metadata["outcome"]) +
                    "/" + str(metadata["reason"]) +
                    (("; exit_code=" + str(metadata["exit_code"])) +
                     ("; target=" + metadata["target"]
                      if metadata["reason"] == "ACQUISITION_ERROR" else "")
                     if metadata["outcome"] == "PARTIAL" and
                        metadata["reason"] in ("EXIT_NONZERO","ACQUISITION_ERROR")
                     else "") +
                    (("; parser_errors=" + ",".join(parser_failures))
                     if parser_failures else ("; parser=verified" if parser_executions else
                                              "; parser=not-run")))[:1024],
            evidence_refs=linked, source_attempt_ids=[attempt_id],
            limit_record_ids=([limit_id] if limit_id else [])))
        attempts.append({
            "attempt_id": attempt_id, "receipt_private_path": receipt_path,
            "receipt_sha256": hashlib.sha256(receipt_raw).hexdigest(),
            "receipt_byte_count": len(receipt_raw),
            "source_id": source_id, "collector_id": policy.collector_id,
            "source_disposition": metadata["outcome"],
            "source_reason": metadata["reason"],
            "evidence_ids": linked, "status_record_id": status_id,
            "authorization_class": policy.authorization_class,
            "capture_bytes": metadata["acquired_bytes"],
            "capture_limited": metadata.get("capture_limited", False),
            "errors": metadata.get("errors", []),
            "unavailable_fields": metadata.get("unavailable_fields", []),
        })
    if engine_run.source_attempt_count != len(attempts):
        raise CanonicalContractError("engine attempt count mismatch")
    if any(a["source_id"] not in source_ids for a in attempts):
        raise CanonicalContractError("invalid source allocation")
    orchestrated_state = "PARTIAL"
    orchestrated_reason = "MINIMUM_WITH_GAPS"
    statuses.append(new_status(
        record_id="st:session", domain="orchestration",
        component_id="SES-CANONICAL", subject_id=run_id,
        status=orchestrated_state, reason_code=orchestrated_reason,
        detail=("Raw originals validated; semantic normalization incomplete; " +
                str(len(observations)) + " original/semantic observation records; " +
                str(len(attempts)) + " source attempts")[:1024],
        evidence_refs=[], source_attempt_ids=sorted(all_attempt_ids)))
    system = {
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "run_id": run_id,
        "platform_scope": "Linux-AMD64",
        "normalization_state": ("PARTIAL_SEMANTIC_NORMALIZATION"
                                if semantic_field_count else "RAW_FALLBACK_ONLY"),
        "observations": observations,
        "capture_limits": limits,
        "limitations": ["Canonical schema/integrity completion pending CP-04",
                        ("Registered semantic parsers: " +
                         str(sum(1 for source in policies if parser_available(source))) +
                         " of " + str(len(policies)) + " source families; " +
                         "this is not complete acquisition or validation"),
                        "Zero observations permitted; no benchmark measurements inferred"],
    }
    outputs = {
        "system.json": system,
        "source_attempts.json": {
            "schema_version": CANONICAL_SCHEMA_VERSION,
            "run_id": run_id, "attempts": attempts,
        },
        "status_records.json": {
            "schema_version": CANONICAL_SCHEMA_VERSION,
            "run_id": run_id, "status_records": statuses,
        },
    }
    # Validate before any file is written.
    for status in statuses:
        validate_status_record(status, evidence_ids=evidence,
                               attempt_ids=all_attempt_ids,
                               limit_ids={x["limit_id"] for x in limits})
    serialized = {name: _render(payload) for name, payload in outputs.items()}
    manifest = {
        "schema_version": CANONICAL_SCHEMA_VERSION,
        "run_id": run_id,
        "completion_state": "INCOMPLETE",
        "integrity_verified": True,
        "semantic_normalization_complete": False,
        "observation_count": len(observations),
        "attempt_count": len(attempts),
        "source_count": len(source_ids),
        "original_byte_count": all_original_bytes,
        "files": {name: {"sha256": hashlib.sha256(raw).hexdigest(),
                         "byte_count": len(raw)}
                  for name, raw in serialized.items()},
        "evidence": evidence,
        "status_record_ids": [x["record_id"] for x in statuses],
        "limitations": system["limitations"],
    }
    for name in PRIVATE_FILES:
        _atomic_new_private(private, name, serialized[name])
    _atomic_new_private(private, MANIFEST_NAME, _render(manifest))
    validate_canonical(folder)
    return manifest


def validate_canonical(run_directory):
    """Read-only verification of private files, references and sealed bytes."""
    folder = Path(run_directory)
    run_id = folder.name
    _check_run(folder, run_id)
    private = folder / "private"
    manifest = _json_load(_read_restricted(private / MANIFEST_NAME, 8 * 1024 * 1024))
    if (manifest.get("schema_version") != CANONICAL_SCHEMA_VERSION
            or manifest.get("run_id") != run_id
            or manifest.get("integrity_verified") is not True
            or set(manifest.get("files", {})) != set(PRIVATE_FILES)):
        raise CanonicalContractError("invalid session manifest")
    records = {}
    for name in PRIVATE_FILES:
        file_info = manifest["files"][name]
        raw = _read_restricted(private / name, 64 * 1024 * 1024)
        if (len(raw) != file_info.get("byte_count")
                or hashlib.sha256(raw).hexdigest() != file_info.get("sha256")):
            raise CanonicalContractError("canonical file integrity failure")
        records[name] = _json_load(raw)
        if (records[name].get("run_id") != run_id
                or records[name].get("schema_version") != CANONICAL_SCHEMA_VERSION):
            raise CanonicalContractError("canonical file identity mismatch")
    attempts = records["source_attempts.json"]["attempts"]
    statuses = records["status_records.json"]["status_records"]
    observations = records["system.json"]["observations"]
    evidence = manifest["evidence"]
    if (len(attempts) != manifest["attempt_count"]
            or len(observations) != manifest["observation_count"]
            or len({a["attempt_id"] for a in attempts}) != len(attempts)
            or len({s["record_id"] for s in statuses}) != len(statuses)):
        raise CanonicalContractError("invalid canonical entity counts")
    attempt_ids = {a["attempt_id"] for a in attempts}
    for eid, record in evidence.items():
        if (record["evidence_id"] != eid or
                record["source_attempt_id"] not in attempt_ids
                or record["private_relative_path"] != "private/evidence/" + eid):
            raise CanonicalContractError("manifest evidence binding invalid")
        raw = _read_restricted(folder / record["private_relative_path"],
                               record["byte_count"])
        if (hashlib.sha256(raw).hexdigest() != record["sha256"] or
                len(raw) != record["byte_count"]):
            raise CanonicalContractError("sealed original altered")
    limits = {x["limit_id"] for x in records["system.json"]["capture_limits"]}
    for status in statuses:
        validate_status_record(status, evidence_ids=evidence,
                               attempt_ids=attempt_ids, limit_ids=limits)
    for a in attempts:
        receipt_path = a.get("receipt_private_path")
        if receipt_path != ("private/source_attempt_records/" + a["attempt_id"] + ".json"):
            raise CanonicalContractError("attempt receipt path invalid")
        receipt_raw = _read_restricted(folder / receipt_path,
                                       a["receipt_byte_count"])
        if (len(receipt_raw) != a["receipt_byte_count"]
                or hashlib.sha256(receipt_raw).hexdigest() != a["receipt_sha256"]):
            raise CanonicalContractError("original source attempt receipt altered")
        receipt_record = _json_load(receipt_raw)
        if (receipt_record.get("run_id") != run_id
                or receipt_record.get("attempt_id") != a["attempt_id"]
                or receipt_record.get("source_id") != a["source_id"]
                or receipt_record.get("evidence_ids") != a["evidence_ids"]
                or receipt_record.get("acquired_bytes") != a["capture_bytes"]):
            raise CanonicalContractError("source receipt/canonical disagreement")
        if a["status_record_id"] not in {x["record_id"] for x in statuses}:
            raise CanonicalContractError("dangling status reference")
        if any(e not in evidence or evidence[e]["source_attempt_id"] != a["attempt_id"]
               for e in a["evidence_ids"]):
            raise CanonicalContractError("attempt evidence provenance failure")
    for observation in observations:
        if (not observation["evidence_refs"]
                or not observation["source_attempt_ids"]
                or any(e not in evidence for e in observation["evidence_refs"])
                or any(a not in attempt_ids for a in observation["source_attempt_ids"])
                or any(evidence[e]["source_attempt_id"] not in
                       observation["source_attempt_ids"] for e in observation["evidence_refs"])):
            raise CanonicalContractError("observation provenance failure")
    return manifest
