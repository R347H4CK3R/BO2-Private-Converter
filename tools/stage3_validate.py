import argparse,json,struct
from pathlib import Path
from collections import Counter,defaultdict

READABLE={".json",".png"}
def main():
 p=argparse.ArgumentParser(); p.add_argument("--source",required=True); p.add_argument("--output",required=True); a=p.parse_args()
 root=Path(a.source); out=Path(a.output); out.mkdir(parents=True,exist_ok=True)
 counts=Counter(); issues=[]; samples=defaultdict(list)
 for f in root.rglob("*"):
  if not f.is_file(): continue
  ext=f.suffix.lower()
  try:
   with f.open("rb") as h: head=h.read(32)
   if head.startswith(b"TAff0100"): cat="blocked_encrypted_fastfile"
   elif head.startswith(b"\x7fELF"): cat="elf_analysis_ready"
   elif head.startswith(b"SCE\x00"): cat="sce_wrapper_skip_when_elf_exists"
   elif ext==".json":
    try: json.loads(f.read_text(encoding="utf-8")); cat="json_valid"
    except Exception as e: cat="json_invalid"; issues.append({"path":str(f.relative_to(root)),"error":str(e)})
   elif ext==".png":
    cat="png_valid" if head.startswith(b"\x89PNG\r\n\x1a\n") else "png_invalid"
   elif ext==".ipak": cat="ipak_requires_parser_validation"
   elif ext==".sabs": cat="sabs_requires_parser"
   elif ext in {".webm",".bik"}: cat="video_passthrough_or_transcode"
   else: cat="unsupported_or_metadata"
   counts[cat]+=1
   if len(samples[cat])<20: samples[cat].append(str(f.relative_to(root)))
  except Exception as e:
   counts["read_error"]+=1; issues.append({"path":str(f.relative_to(root)),"error":str(e)})
 report={"source":str(root),"counts":dict(counts),"issues":issues,"samples":dict(samples),
 "stage3_decisions":{"fastfiles":"blocked unless legally decrypted/normalized","elf":"analysis input only; never executed on ARM64 iOS","json_png":"validated readable inputs","ipak":"next converter target","sabs":"parser required","video":"runtime compatibility/transcode validation required"}}
 (out/"stage3_validation.json").write_text(json.dumps(report,indent=2),encoding="utf-8")
 (out/"stage3_summary.json").write_text(json.dumps({"counts":dict(counts),"issue_count":len(issues),"decisions":report["stage3_decisions"]},indent=2),encoding="utf-8")
 print(json.dumps(report["stage3_decisions"],indent=2)); print(json.dumps(dict(counts),indent=2))
if __name__=="__main__": main()
