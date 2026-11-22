import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.chdir(os.path.dirname(os.path.abspath(__file__)))
from mcp_toolscan import scan_tool
rows = json.load(open("corpus.json")); out = {}
for split in ("dev","held","v2_capability","all"):
    rs = [r for r in rows if split=="all" or r["split"]==split]
    tp=fp=fn=tn=0; misses=[]
    for r in rs:
        f = scan_tool(r["tool"])["flagged"]; y = r["label"]
        tp+=f and y; fp+=f and not y; fn+=(not f) and y; tn+=(not f) and not y
        if f!=bool(y): misses.append((r["tool"]["name"], "FN" if y else "FP"))
    out[split]=dict(n=len(rs),tp=tp,fp=fp,fn=fn,tn=tn,precision=round(tp/max(tp+fp,1),3),recall=round(tp/max(tp+fn,1),3),fpr=round(fp/max(fp+tn,1),3),errors=misses)
print(json.dumps(out, indent=1)); json.dump(out, open("results.json","w"), indent=1)
