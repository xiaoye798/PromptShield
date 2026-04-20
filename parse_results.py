import json

with open("memgpt_benchmark_report_20260415_192511.json", encoding="utf-8") as f:
    data = json.load(f)

print(f"System: {data['system']}, Model: {data['model']}, Noise: {data['noise_level']}, Reps: {data['n_reps']}")
print(f"Total scenarios: {len(data['results'])}")
print()
print(f"{'Row':<5} {'Label':<35} {'KR':<7} {'StrictKR':<10} {'SFS':<7} {'SPR':<7}")
print("-" * 75)
for r in data["results"]:
    print(f"{r['row']:<5} {r['label'][:34]:<35} {r['avg_kr']:<7.2f} {r['avg_strict_kr']:<10.2f} {r['avg_sfs']:<7.3f} {r['avg_spr']:<7.2f}")

print()
krs = [r["avg_kr"] for r in data["results"]]
sfs_vals = [r["avg_sfs"] for r in data["results"]]
sprs = [r["avg_spr"] for r in data["results"]]
skrs = [r["avg_strict_kr"] for r in data["results"]]
print(f"Overall Avg KR={sum(krs)/len(krs):.3f}, StrictKR={sum(skrs)/len(skrs):.3f}, SFS={sum(sfs_vals)/len(sfs_vals):.3f}, SPR={sum(sprs)/len(sprs):.3f}")

# Also compute avg latency
all_lats = []
for r in data["results"]:
    for rep in r["reps"]:
        if "latency_ms" in rep:
            all_lats.append(rep["latency_ms"])
        elif "latency_s" in rep:
            all_lats.append(rep["latency_s"] * 1000)
print(f"Overall Avg Latency={sum(all_lats)/len(all_lats):.0f} ms ({sum(all_lats)/len(all_lats)/1000:.1f} s)")
