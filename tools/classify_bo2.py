import argparse, json
from pathlib import Path
from collections import Counter, defaultdict

def classify(path, magic):
    ext=path.suffix.lower()
    if magic.startswith(b"TAff0100"): return "encrypted_fastfile"
    if magic.startswith(b"\x7fELF"): return "decrypted_elf_analysis"
    if magic.startswith(b"SCE\x00"): return "sce_self_wrapper"
    if ext==".ipak": return "ipak_candidate"
    if ext in {".png",".jpg",".jpeg",".dds",".tga",".json",".cfg",".txt",".gsc",".wav",".ogg",".obj"}: return "readable_candidate"
    if ext in {".webm",".bik"}: return "video_candidate"
    if ext==".sabs": return "audio_bank_candidate"
    return "unsupported_or_needs_parser"

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--source",required=True); ap.add_argument("--output",required=True)
    a=ap.parse_args(); root=Path(a.source); out=Path(a.output); out.mkdir(parents=True,exist_ok=True)
    if not root.is_dir(): raise SystemExit("Source folder not found: "+str(root))
    counts=Counter(); exts=defaultdict(Counter); samples=defaultdict(list); rows=[]
    for p in root.rglob("*"):
        if not p.is_file(): continue
        try:
            with p.open("rb") as fh: magic=fh.read(16)
            category=classify(p,magic); ext=p.suffix.lower() or "<none>"
            counts[category]+=1; exts[category][ext]+=1
            rel=str(p.relative_to(root))
            if len(samples[category])<25: samples[category].append(rel)
            rows.append({"path":rel,"size":p.stat().st_size,"extension":ext,"category":category})
        except (OSError,PermissionError) as e:
            rows.append({"path":str(p.relative_to(root)),"category":"read_error","error":str(e)}); counts["read_error"]+=1
    report={"source":str(root),"counts":dict(counts),"extensions_by_category":{k:dict(v) for k,v in exts.items()},"samples":dict(samples),"files":rows}
    (out/"bo2_classification.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
    summary={"source":str(root),"file_count":len(rows),"counts":dict(counts),"extensions_by_category":{k:dict(v) for k,v in exts.items()}}
    (out/"bo2_classification_summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    print(json.dumps(summary,indent=2))
if __name__=="__main__": main()
