#!/usr/bin/env python3
"""
列出当前缓存的 sampled_entry_guards，看看哪些字段让它们
不能通过 is_usable_filtered_guard。
在任何 Tor 节点的 DataDirectory 下运行：
    python inspect_guards.py /path/to/data
"""
import sys, pickle, pprint, os, json

data_dir = sys.argv[1] if len(sys.argv) > 1 else "."
state = os.path.join(data_dir, "state")
if not os.path.exists(state):
    print("找不到 Tor state 文件")
    sys.exit(1)

def read_kv(path):
    kv = {}
    key = None
    for ln in open(path, encoding="utf-8"):
        if ln.startswith(" "):
            kv[key] += ln.strip()
        else:
            key, val = ln.split(None, 1)
            kv[key] = val.strip()
    return kv

st = read_kv(state)
guards = [json.loads(s) for s in st.get("EntryGuard", "").split("|") if s]
print(f"{len(guards)} guards cached\n")
for g in guards:
    tags = []
    if g.get("is_usable_filtered_guard"):
        tags.append("USABLE")
    if g.get("is_pending"):
        tags.append("PENDING")
    if g.get("reachable_since"):
        tags.append("REACHABLE")
    if g.get("unreachable_since"):
        tags.append("UNREACHABLE")
    print(f"{g['nickname']:<10}  {','.join(tags) or '---'}")
