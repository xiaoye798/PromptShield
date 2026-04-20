import json

for fn, sys_name in [
    ("appendix_benchmark_report_noise100_20260412_202755.json", "shelLM"),
    ("appendix_benchmark_report_noise100_20260412_202822.json", "PromptShield"),
]:
    with open(fn) as f:
        data = json.load(f)
    results = data["results"][sys_name]
    print("\n=== %s N100 (%d rows) ===" % (sys_name, len(results)))
    kr_sum = 0
    for r in results:
        kr = r["avg_kr"]
        lat_ms = r["reps"][0].get("latency_ms", 0)
        tok = r["reps"][0].get("tokens", 0)
        kr_sum += kr
        print("Row %2d %-30s KR=%.2f  Lat=%.1fs  Tok=%d" % (r["row"], r["label"], kr, lat_ms / 1000, tok))
    print("Macro-avg KR = %.4f" % (kr_sum / len(results)))
