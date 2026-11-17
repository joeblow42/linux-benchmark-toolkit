#!/usr/bin/env python3
"""Build LBT Alternative B ODT/ZIP from byte-exact GitHub recovery sources."""
import argparse,csv,hashlib,html,json,re,shutil,tempfile,zipfile
from pathlib import Path
SHA={"Requirements_Rev1_6.csv":"04849cd13ecc75c803839ab7c59a1015c5b92d1f05bf31422b54406c188e2702","LBT_RP01_283_Requirement_FAT_Applicability_Approved_20261113.csv":"deb4ea158491d980e7ff57d6ac9bc58560316edf3adfb8d3e9c37c59f9266092"}
ODT="LBT_FAT_Alternative_B_GitHub_Recovery_Handoff_20261116.odt"
ZIP="LBT_FAT_Alternative_B_GitHub_Recovery_20261116.zip"
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def make_odt(markdown,out):
    def paragraph(s,style="Text_20_body"):
        s=re.sub(r"\*\*([^*]+)\*\*",r"\1",s)
        s=s.replace(chr(96),"")
        return '<text:p text:style-name="'+style+'">'+html.escape(s)+'</text:p>'
    paragraphs=[]
    for line in markdown.splitlines():
        t=line.strip()
        if not t:continue
        if t.startswith("# "):paragraphs.append('<text:h text:style-name="Heading_20_1" text:outline-level="1">'+html.escape(t[2:])+'</text:h>')
        elif t.startswith("## "):paragraphs.append('<text:h text:style-name="Heading_20_2" text:outline-level="2">'+html.escape(t[3:])+'</text:h>')
        elif t.startswith("### "):paragraphs.append('<text:h text:style-name="Heading_20_3" text:outline-level="3">'+html.escape(t[4:])+'</text:h>')
        elif t.startswith("|---") or t.startswith("|:"):continue
        elif t.startswith("|"):paragraphs.append(paragraph(" | ".join(x.strip() for x in t.strip("|").split("|"))))
        elif t.startswith("- "):paragraphs.append(paragraph("• "+t[2:]))
        else:paragraphs.append(paragraph(t))
    h='<?xml version="1.0" encoding="UTF-8"?>'
    ns='xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" xmlns:fo="urn:oasis:names:tc:opendocument:xmlns:xsl-fo-compatible:1.0"'
    c=h+'<office:document-content '+ns+' office:version="1.2"><office:body><office:text>'+''.join(paragraphs)+'</office:text></office:body></office:document-content>'
    st=h+'<office:document-styles '+ns+' office:version="1.2"><office:styles><style:style style:name="Standard" style:family="paragraph"><style:text-properties fo:font-family="Liberation Sans" fo:font-size="9pt"/></style:style><style:style style:name="Text_20_body" style:family="paragraph" style:parent-style-name="Standard"><style:paragraph-properties fo:margin-bottom="0.09in"/></style:style><style:style style:name="Heading_20_1" style:family="paragraph"><style:text-properties fo:font-size="17pt" fo:font-weight="bold"/></style:style><style:style style:name="Heading_20_2" style:family="paragraph"><style:paragraph-properties fo:margin-top="0.18in"/><style:text-properties fo:font-size="12pt" fo:font-weight="bold"/></style:style><style:style style:name="Heading_20_3" style:family="paragraph"><style:text-properties fo:font-size="10pt" fo:font-weight="bold"/></style:style></office:styles></office:document-styles>'
    meta=h+'<office:document-meta '+ns+' office:version="1.2"><office:meta/></office:document-meta>'
    m=h+'<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2"><manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/><manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="styles.xml" manifest:media-type="text/xml"/><manifest:file-entry manifest:full-path="meta.xml" manifest:media-type="text/xml"/></manifest:manifest>'
    with zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED,compresslevel=8) as z:
        z.writestr("mimetype","application/vnd.oasis.opendocument.text",compress_type=zipfile.ZIP_STORED)
        for path,value in (("content.xml",c),("styles.xml",st),("meta.xml",meta),("META-INF/manifest.xml",m)):z.writestr(path,value)
def main():
    p=argparse.ArgumentParser();p.add_argument("--source-root",type=Path,default=Path("."));p.add_argument("--outdir",type=Path,required=True);a=p.parse_args()
    fat=(a.source_root/"verification"/"fat").resolve();a.outdir.mkdir(parents=True,exist_ok=True)
    for n,d in SHA.items():
        if digest(fat/"authority"/n)!=d:raise SystemExit("Source SHA-256 mismatch: "+n)
    with (fat/"authority"/"Requirements_Rev1_6.csv").open(encoding="utf-8-sig",newline="") as f:req=list(csv.DictReader(f))
    with (fat/"authority"/"LBT_RP01_283_Requirement_FAT_Applicability_Approved_20261113.csv").open(encoding="utf-8-sig",newline="") as f:mat=list(csv.DictReader(f))
    assert len(req)==len(mat)==283 and [x["Requirement_ID"] for x in req]==[x["Requirement_ID"] for x in mat]
    assert all(x["FAT_Approval_State"]=="OWNER_APPROVED_2026-11-13" for x in mat)
    assert {k:sum(x["Proposed_FAT_Disposition"]==k for x in mat) for k in ("FAT_MANDATORY","CONDITIONALLY_APPLICABLE","EXPLICIT_LATER_RELEASE")}=={"FAT_MANDATORY":210,"CONDITIONALLY_APPLICABLE":65,"EXPLICIT_LATER_RELEASE":8}
    handoff=fat/"altb_source_recovery_handoff_20261116.md";make_odt(handoff.read_text(encoding="utf-8"),a.outdir/ODT)
    with tempfile.TemporaryDirectory() as tmp:
        stage=Path(tmp)
        for n in ("authority","handoff","planning","validation"):(stage/n).mkdir()
        for n in SHA:shutil.copyfile(fat/"authority"/n,stage/"authority"/n)
        shutil.copyfile(handoff,stage/"handoff"/handoff.name);shutil.copyfile(a.outdir/ODT,stage/"handoff"/ODT)
        for n in ("altb_candidate_fat_roadmap_rev0_2_20261115.md","altb_candidate_requirement_reconciliation_rev0_2_20261115.md","altb_candidate_requirement_reconciliation_283_20261115.csv"):shutil.copyfile(fat/n,stage/"planning"/n)
        shutil.copyfile(fat/"altb_source_recovery_verification_20261116.json",stage/"validation"/"altb_source_recovery_verification_20261116.json")
        (stage/"README_RECOVERY.md").write_text("LBT Alternative B recovery. Read handoff/altb_source_recovery_handoff_20261116.md first.\nAll source CSVs are byte-exact and SHA-256 checked. Rev 0.2 planning is CANDIDATE. Increment 48 remains PAUSED.\n",encoding="utf-8")
        items=sorted(x for x in stage.rglob("*") if x.is_file())
        (stage/"SHA256SUMS.txt").write_text("".join(digest(x)+"  "+x.relative_to(stage).as_posix()+"\n" for x in items),encoding="utf-8")
        with zipfile.ZipFile(a.outdir/ZIP,"w",zipfile.ZIP_DEFLATED,compresslevel=9) as z:
            for x in sorted(y for y in stage.rglob("*") if y.is_file()):z.write(x,x.relative_to(stage).as_posix())
    with zipfile.ZipFile(a.outdir/ZIP) as z:assert z.testzip() is None
    print(json.dumps({"result":"PASS","odt":ODT,"odt_sha256":digest(a.outdir/ODT),"zip":ZIP,"zip_sha256":digest(a.outdir/ZIP)},indent=2))
if __name__=="__main__":main()
