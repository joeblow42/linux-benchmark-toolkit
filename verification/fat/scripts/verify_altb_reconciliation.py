#!/usr/bin/env python3
"""Verify byte-exact authority and complete Alternative B per-ID derived matrices."""
import argparse, csv, hashlib, json
from collections import Counter
from pathlib import Path
ORIG={"Requirements_Rev1_6.csv":"04849cd13ecc75c803839ab7c59a1015c5b92d1f05bf31422b54406c188e2702","LBT_RP01_283_Requirement_FAT_Applicability_Approved_20261113.csv":"deb4ea158491d980e7ff57d6ac9bc58560316edf3adfb8d3e9c37c59f9266092"}
PAIRS={"Type":"Controlled_Type","Category":"Controlled_Category","Requirement":"Exact_Requirement_Text","Recommended_Criticality":"Controlled_Criticality","Disposition":"Controlled_Disposition","Release_Target":"Controlled_Release_Target","Initial_Platform_Applicability":"Controlled_Platform_Applicability"}
COUNTS={"FAT_MANDATORY":210,"CONDITIONALLY_APPLICABLE":65,"EXPLICIT_LATER_RELEASE":8}
DOWN={"CT-08-N2","CT-11-N2","CT-11-N3"}
def load(p):
    with p.open(encoding="utf-8-sig",newline="") as fh: rows=list(csv.reader(fh))
    assert all(len(r)==len(rows[0]) for r in rows),str(p)+" width"
    return rows[0], [dict(zip(rows[0],r)) for r in rows[1:]]
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--source-root",type=Path,default=Path("."));args=ap.parse_args()
    fat=args.source_root/"verification"/"fat"
    for name,d in ORIG.items():
        assert hashlib.sha256((fat/"authority"/name).read_bytes()).hexdigest()==d,name+" SHA256"
    rh,rr=load(fat/"authority"/"Requirements_Rev1_6.csv")
    ah,ar=load(fat/"authority"/"LBT_RP01_283_Requirement_FAT_Applicability_Approved_20261113.csv")
    th,tr=load(args.source_root/"verification"/"g5_04"/"requirements_traceability_rev1_6.csv")
    ch,cr=load(args.source_root/"verification"/"g5_04"/"cp02_39case_coverage_review_25.csv")
    oh,orr=load(fat/"altb_candidate_requirement_reconciliation_283_20261115.csv")
    vh,vr=load(fat/"altb_cp02_39case_method_review_20261116.csv")
    assert (len(rr),len(ar),len(tr),len(cr),len(orr),len(vr))==(283,283,283,39,283,39)
    assert (len(rh),len(ah),len(th),len(ch),len(oh),len(vh))==(20,17,12,12,53,16)
    assert oh[:47]==rh+["RP01_"+x for x in ah[1:]]+["CP02_"+x for x in th[1:]]
    assert vh[:12]==ch
    assert len({x["Requirement_ID"] for x in rr})==len({x["Requirement_ID"] for x in ar})==len({x["Requirement_ID"] for x in tr})==283
    assert Counter(x["Proposed_FAT_Disposition"] for x in ar)==COUNTS
    scopes={x["Requirement_ID"]:x for x in ar};traces={x["Requirement_ID"]:x for x in tr}
    links={}
    for c in cr:
        for k in (x.strip() for x in c["Requirement_IDs"].split(";")):
            if k: links.setdefault(k,[]).append(c["Case_ID"])
    wrong_order=0
    for i,(r,o) in enumerate(zip(rr,orr)):
        k=r["Requirement_ID"];a=scopes[k];t=traces[k]
        assert ar[i]["Requirement_ID"]==k
        wrong_order+=int(tr[i]["Requirement_ID"]!=k)
        assert all(r[p]==a[q] for p,q in PAIRS.items()),k+" controlled overlap"
        assert a["FAT_Approval_State"]=="OWNER_APPROVED_2026-11-13"
        assert a["Current_Verification_State"]==t["Verification_State"]=="NOT_VERIFIED"
        assert all(o[x]==r[x] for x in rh),k+" original field"
        assert all(o["RP01_"+x]==a[x] for x in ah[1:]),k+" RP01 field"
        assert all(o["CP02_"+x]==t[x] for x in th[1:]),k+" CP02 field"
        assert o["CP02_Original_Case_IDs"]==";".join(links.get(k,[])),k+" cases"
        assert o["Proposed_Requirement_Text_Change"]=="NONE" and o["Approved_FAT_Disposition_Changed"]=="NO"
    assert wrong_order==141
    counts=Counter()
    for c,v in zip(cr,vr):
        assert all(c[k]==v[k] for k in ch),c["Case_ID"]+" original case field"
        target="DOWNSTREAM_NOT_EXECUTED" if c["Case_ID"] in DOWN else "REPLACE_WITH_ORDINARY_FAILURE" if c["Case_ID"]=="CT-07-N1" else "KEEP_FUNCTIONAL"
        assert v["Alternative_B_Method_Disposition"]==target and v["Acceptance_Criterion_Changed"]=="NO",c["Case_ID"]
        counts[target]+=1
    assert counts=={"KEEP_FUNCTIONAL":35,"REPLACE_WITH_ORDINARY_FAILURE":1,"DOWNSTREAM_NOT_EXECUTED":3}
    print(json.dumps({"status":"PASS","source_ids":283,"source_columns":20,"approved_columns":17,"derived_columns":53,"controlled_overlap_checks":1981,"mismatches":0,"cp02_trace_order_mismatch_positions":wrong_order,"fat_counts":COUNTS,"original_cp02_cases":39,"formal_accepted_cp02":0,"cp02_method_counts":dict(counts),"verification":"283_NOT_VERIFIED","increment48":"PAUSED"},indent=2))
if __name__=="__main__":main()
