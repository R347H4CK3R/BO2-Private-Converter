import argparse, hashlib, json, os
from pathlib import Path
from collections import Counter

def sha256(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--source",required=True)
    ap.add_argument("--output",required=True)
    a=ap.parse_args()
    root=Path(a.source)
    if not root.is_dir(): raise SystemExit(f"Source folder not found: {root}")
    out=Path(a.output); out.mkdir(parents=True,exist_ok=True)
    rows=[]; exts=Counter(); total=0
    for p in root.rglob("*"):
        if not p.is_file(): continue
        try:
            size=p.stat().st_size
            with open(p,"rb") as f: magic=f.read(16)
            ext=p.suffix.lower() or "<none>"; exts[ext]+=1; total+=size
            kind="file"
            if magic.startswith(b"TAff0100"): kind="bo2_fastfile_taff0100"
            elif magic.startswith(b"\x7fELF"): kind="elf"
            elif magic.startswith(b"SCE\x00"): kind="sce_self"
            rows.append({"path":str(p.relative_to(root)),"size":size,"extension":ext,"kind":kind,"sha256":sha256(p)})
        except (OSError,PermissionError) as e:
            rows.append({"path":str(p.relative_to(root)),"error":str(e)})
    report={"source":str(root),"file_count":len(rows),"total_bytes":total,"extensions":dict(exts.most_common()),"files":rows}
    (out/"bo2_inventory.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    summary={"source":str(root),"file_count":len(rows),"total_bytes":total,"extensions":dict(exts.most_common(50)),
             "taff0100_count":sum(r.get("kind")=="bo2_fastfile_taff0100" for r in rows),
             "elf_count":sum(r.get("kind")=="elf" for r in rows),
             "sce_self_count":sum(r.get("kind")=="sce_self" for r in rows)}
    (out/"bo2_summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    print(json.dumps(summary,indent=2))
if __name__=="__main__": main()
