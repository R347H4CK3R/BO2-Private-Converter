import argparse,json,hashlib
from pathlib import Path
from collections import Counter

def sha256(p):
    h=hashlib.sha256()
    with p.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""):
            h.update(b)
    return h.hexdigest()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--source",required=True)
    ap.add_argument("--output",required=True)
    ap.add_argument("--reports",required=True)
    a=ap.parse_args()
    root=Path(a.source); out=Path(a.output); rep=Path(a.reports)
    out.mkdir(parents=True,exist_ok=True); rep.mkdir(parents=True,exist_ok=True)
    allowed={".json",".png"}; manifest=[]; blocked=Counter(); errors=[]
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        rel=str(p.relative_to(root)); ext=p.suffix.lower()
        try:
            with p.open("rb") as f:
                head=f.read(16)
            if head.startswith(b"TAff0100"):
                blocked["encrypted_fastfile"]+=1; continue
            if head.startswith(b"SCE\x00"):
                blocked["sce_self"]+=1; continue
            if head.startswith(b"\x7fELF"):
                blocked["elf_analysis_only"]+=1; continue
            if ext in allowed:
                if ext==".json":
                    try:
                        json.loads(p.read_text(encoding="utf-8"))
                    except Exception:
                        blocked["invalid_json"]+=1; continue
                if ext==".png" and not head.startswith(b"\x89PNG\r\n\x1a\n"):
                    blocked["invalid_png"]+=1; continue
                manifest.append({"source_relative_path":rel,"type":ext[1:],"size":p.stat().st_size,"sha256":sha256(p)})
            elif ext==".ipak":
                blocked["ipak_pending_conversion"]+=1
            elif ext==".sabs":
                blocked["sabs_pending_conversion"]+=1
            elif ext in {".webm",".bik"}:
                blocked["video_pending_runtime_conversion"]+=1
            else:
                blocked["unsupported_pending_parser"]+=1
        except Exception as e:
            blocked["read_error"]+=1
            errors.append({"path":rel,"error":str(e)})
    result={"schema":1,"source_root":str(root),"generated_root":str(out),"runtime_ready":manifest,"runtime_ready_count":len(manifest),"deferred":dict(blocked),"errors":errors}
    (out/"BUILD_MANIFEST.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    summary={"runtime_ready_count":len(manifest),"deferred":dict(blocked),"error_count":len(errors)}
    (rep/"stage4_gamedata_summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    print(json.dumps(summary,indent=2))

if __name__=="__main__":
    main()
