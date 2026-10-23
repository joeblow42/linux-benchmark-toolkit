"""Approved Revision 1.2 requirement identity and conservative validation links.

The 2026-10-22 authoritative CSV defines contiguous FR-001..190 and
NFR-001..066. This is an ID register, NOT copied or altered requirement text.
Evidence from a linked check is always partial until independently reviewed.
"""
import re

BASELINE = "Approved Requirements Baseline Revision 1.2"
APPROVED_IDS = frozenset(
    [f"LBT-FR-{i:03d}" for i in range(1, 191)] +
    [f"LBT-NFR-{i:03d}" for i in range(1, 67)]
)
DEFERRED_IDS = frozenset(
    ["LBT-FR-001", "LBT-FR-002", "LBT-FR-003", "LBT-FR-004",
     "LBT-FR-008", "LBT-FR-009", "LBT-FR-010"]
)

# These links mean only that the test contributes evidence relevant to an
# approved requirement. They do not establish complete verification.
LINKS = {
    "VAL-P1-CLI-001": ("LBT-FR-128", "LBT-NFR-041"),
    "VAL-P1-LAUNCH-001": ("LBT-FR-136",),
    "VAL-P1-OUTPUT-001": ("LBT-FR-138",),
    "VAL-P1-REPORT-001": ("LBT-FR-127", "LBT-NFR-040"),
    "VAL-P1-ACCEPT-001": ("LBT-FR-136",),
    "VAL-P1-ACCEPT-003": ("LBT-FR-124", "LBT-FR-128"),
    "VAL-P1-ACCEPT-004": ("LBT-FR-124",),
    "VAL-P1-ACCEPT-006": ("LBT-FR-138",),
    "VAL-P1-ACCEPT-008": ("LBT-NFR-047",),
    "VAL-P1-ACCEPT-010": ("LBT-FR-127", "LBT-NFR-040"),
    "VAL-P1-ACCEPT-012": ("LBT-FR-139",),
    "VAL-P1-ACCEPT-013": ("LBT-FR-136", "LBT-FR-138"),
    "VAL-P1-ACCEPT-014": ("LBT-FR-139", "LBT-FR-136"),
    "VAL-P1-ACCEPT-015": ("LBT-FR-138",),
    "VAL-P1-ACCEPT-016": ("LBT-FR-132",),
}


def links_for(validation_id: str) -> tuple[str, ...]:
    links = LINKS.get(validation_id, ())
    if any(i not in APPROVED_IDS for i in links):
        raise ValueError("validation links include unknown approved requirement")
    return links


def coverage(rows: list[dict]) -> dict:
    """Report partial evidence and every uncovered ID; never infer VERIFIED."""
    links: dict[str, list[str]] = {}
    for row in rows:
        for rid in row["requirement_ids"]:
            if rid not in APPROVED_IDS:
                raise ValueError("unrecognized approved requirement")
            links.setdefault(rid, []).append(row["validation_id"])
    return {
        "baseline": BASELINE,
        "total": len(APPROVED_IDS),
        "linked": len(links),
        "unlinked": sorted(APPROVED_IDS - links.keys()),
        "linked_tests": {key: sorted(value) for key, value in sorted(links.items())},
        "verification_policy": "LINKED_EVIDENCE_ONLY_NOT_REQUIREMENT_VERIFICATION",
        "fully_verified": [],
        "deferred": sorted(DEFERRED_IDS),
    }
