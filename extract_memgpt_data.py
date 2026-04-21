import json

data = json.load(open('memgpt_benchmark_report_20260415_192511.json', encoding='utf-8'))

print("Row | Label                     | KR     | SFS    | SPR  | Lat(s) | Tokens")
print("----|---------------------------|--------|--------|------|--------|-------")
total_lat = 0
total_tok = 0
total_kr = 0
total_sfs = 0
total_spr = 0

for r in data['results']:
    lats = [rep.get('latency_ms', 0) for rep in r['reps']]
    toks = [rep.get('tokens', 0) for rep in r['reps']]
    avg_lat = sum(lats) / len(lats) / 1000
    avg_tok = sum(toks) / len(toks)
    total_lat += avg_lat
    total_tok += avg_tok
    total_kr += r['avg_kr']
    total_sfs += r['avg_sfs']
    total_spr += r['avg_spr']
    print(f"{r['row']:2d}  | {r['label'][:25]:25s} | {r['avg_kr']:.4f} | {r['avg_sfs']:.4f} | {r['avg_spr']:.2f} | {avg_lat:6.1f} | {avg_tok:.0f}")

n = len(data['results'])
print(f"\nOverall averages:")
print(f"  KR  = {total_kr/n:.4f}")
print(f"  SFS = {total_sfs/n:.4f}")
print(f"  SPR = {total_spr/n:.4f}")
print(f"  Lat = {total_lat/n:.1f}s")
print(f"  Tok = {total_tok/n:.0f}")
