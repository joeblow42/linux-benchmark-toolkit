"""Classify saved workload evidence without reacquiring host data."""
from math import isfinite


def rate(value):
    return type(value) in (int, float) and isfinite(value) and value >= 0


def assess(row):
    status = row["status"]
    measurements = row["measurements"]
    result = {"id": row["id"], "capability": "UNKNOWN", "performance": "UNKNOWN",
              "reliability": "UNKNOWN", "coverage": "NOT_TESTED",
              "reason": row["reason"], "performance_basis": None}
    if status == "SKIPPED":
        return result
    if status == "FAILED":
        result["coverage"] = "ATTEMPT_FAILED"
        return result
    if status != "COMPLETE":
        return result
    result.update(capability="DEMONSTRATED", coverage="TESTED_IN_RECORDED_CASE")
    if measurements.get("actual_client_session") == "NOT_TESTED":
        result["coverage"] = "PROFILE_ONLY"
        if measurements.get("compatibility") == "CLIENT_INCOMPATIBLE":
            result["capability"] = "PROFILE_INCOMPATIBLE"
    if row["id"] == "jf-session-evidence":
        result.update(capability="RECORDED", coverage="IMPORTED_SESSION")
    if row["id"] == "backup-large":
        initial = measurements.get("initial", {})
        throughput = initial.get("mib_per_second")
        if rate(throughput):
            result["performance"] = "GOOD" if throughput >= 80 else "MARGINAL" if throughput >= 30 else "POOR"
            result["performance_basis"] = "Generated sequential copy: Good ≥80 MiB/s, Marginal ≥30 MiB/s"
    realtime = measurements.get("realtime_factor")
    if rate(realtime):
        result["performance"] = "MEETS_REALTIME" if realtime >= 1 else "BELOW_REALTIME"
        result["performance_basis"] = "Measured transcode reaches real time at ≥1×"
    verification = measurements.get("integrity", {}).get("verified", measurements.get("verified"))
    if verification is True:
        result["reliability"] = "VERIFIED_FOR_TEST_DATA"
    elif verification is False:
        result["reliability"] = "INTEGRITY_FAILED"
    return result
