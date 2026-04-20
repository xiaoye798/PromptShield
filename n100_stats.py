import json

# Load N100 results
data_s = json.load(open("appendix_benchmark_report_noise100_20260412_202755.json"))
data_p = json.load(open("appendix_benchmark_report_noise100_20260412_202822.json"))

shelLM = data_s["results"]["shelLM"]
ps = data_p["results"]["PromptShield"]

for name, results in [("shelLM", shelLM), ("PromptShield", ps)]:
    kr_vals = [r["avg_kr"] for r in results]
    sfs_vals = [r["avg_sfs"] for r in results]
    tok_vals = [r["reps"][0]["tokens"] for r in results]
    lat_vals = [r["reps"][0]["latency_ms"] for r in results]
    
    avg_kr = sum(kr_vals) / len(kr_vals)
    avg_sfs = sum(sfs_vals) / len(sfs_vals)
    total_tok = sum(tok_vals)
    avg_lat = sum(lat_vals) / len(lat_vals) / 1000  # seconds
    spr = sum(1 for k in kr_vals if k > 0) / len(kr_vals)
    
    print("=== %s N100 ===" % name)
    print("  Macro KR  = %.4f" % avg_kr)
    print("  Macro SFS = %.4f" % avg_sfs)
    print("  SPR       = %.2f (%d/%d)" % (spr, sum(1 for k in kr_vals if k > 0), len(kr_vals)))
    print("  Avg Token = %dK" % (total_tok // len(lat_vals) // 1000))
    print("  Avg Lat   = %.1fs" % avg_lat)
    print()

# Comparison: show scenarios where N100 KR differs from each other
print("\n=== Scenario Mapping (N100 row -> label -> shelLM KR -> PS KR) ===")
for s, p in zip(shelLM, ps):
    marker = ""
    print("Row %2d %-30s  sLM=%.2f  PS=%.2f %s" % (s["row"], s["label"], s["avg_kr"], p["avg_kr"], marker))
