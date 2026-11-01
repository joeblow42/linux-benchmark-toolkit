"""G5-02 O1 vetted plans, nonexecuting until explicit run/device consent.

This module never probes devices. G5-03 must derive trusted_targets from sealed
D0 inventory, present impacts/bounds to the operator, and pass a one-run ticket.
"""
from dataclasses import dataclass
import os
import re
import stat
from .safety import SourceRequest,decide_source,initial_source_policies

@dataclass(frozen=True)
class OptionalSourcePlan:
    source_id: str
    operation_id: str
    target: str
    argv: tuple[str,...]
    max_bytes: int
    max_seconds: int
    impact: str

def plan_optional(request:SourceRequest, *,validate_real_device:bool=True):
    """Refuse if any policy, target identity, or one-run consent check fails.

    A returned command plan is NOT permission to run arbitrary paths or to skip
    the normal bounded executable writer/worker. No command is invoked here.
    """
    policy={p.source_id:p for p in initial_source_policies()}.get(request.source_id)
    if policy is None or policy.authorization_class!="O1":
        raise PermissionError("unregistered or not O1")
    decision=decide_source(request)
    if not decision.allowed:
        raise PermissionError(decision.reason)
    target=request.target
    if target is None or not isinstance(target,str):
        raise PermissionError("selected device required")
    if request.source_id=="SRC-13":
        if re.fullmatch(r"/dev/sd[a-z]+",target):
            argv=("smartctl","-i","-H",target)
            device_class="block"
        elif re.fullmatch(r"/dev/nvme[0-9]+(?:n[0-9]+)?",target):
            argv=("nvme","smart-log",target)
            device_class="block_or_char"
        else:
            raise PermissionError("unregistered health device")
        impact="Drive health query may wake or spin up selected storage device"
    elif request.source_id=="SRC-18":
        if re.fullmatch(r"/dev/sr[0-9]+",target) is None:
            raise PermissionError("unregistered optical device")
        argv=("sg_get_config","--readonly","--current",target)
        device_class="block"
        impact="Selected optical drive GET CONFIGURATION may spin up media"
    elif request.source_id=="SRC-21":
        if re.fullmatch(r"/dev/dri/renderD[0-9]+",target) is None:
            raise PermissionError("unregistered render node")
        argv=("vainfo","--display","drm","--device",target)
        device_class="char"
        impact="Local VA-API driver initialization; not a benchmark"
    else:
        raise PermissionError("no O1 plan")
    if validate_real_device:
        # Only installed genuine device nodes; no symlink escapes.
        if os.path.islink(target):raise PermissionError("symlink device prohibited")
        try: mode=os.lstat(target).st_mode
        except OSError: raise PermissionError("selected device not present")
        if device_class=="block" and not stat.S_ISBLK(mode):
            raise PermissionError("not a block device")
        if device_class=="char" and not stat.S_ISCHR(mode):
            raise PermissionError("not a render character device")
        if device_class=="block_or_char" and not (
            stat.S_ISBLK(mode) or stat.S_ISCHR(mode)):
            raise PermissionError("not a storage device")
    return OptionalSourcePlan(policy.source_id,policy.operation_id,target,argv,
                              policy.per_target_bytes or policy.max_bytes,
                              policy.per_target_seconds or policy.max_seconds,impact)
