import json

files = {
    'shelLM': 'real_baseline_benchmark_report_20260414_195010.json',
    'Beelzebub': 'real_baseline_benchmark_report_20260414_195040.json',
    'Beelzebub-R': 'real_baseline_benchmark_report_20260414_195109.json',
    'PromptShield': 'real_baseline_benchmark_report_20260414_195137.json',
}

for name, fname in files.items():
    with open(fname, encoding='utf-8') as f:
        data = json.load(f)
    meta = data.get('meta', {})
    sys_name = meta.get('system', '?')
    sc_count = meta.get('scenarios_count', '?')
    reps = meta.get('reps', '?')
    print(f'=== {name} ({fname}) ===')
    print(f'  System: {sys_name} | Scenarios: {sc_count} | Reps: {reps}')
    raw_results = data.get('results', {})
    # results is a dict keyed by system name, with a list of scenario dicts
    if isinstance(raw_results, dict):
        # Get the first (and only) system's results
        results = list(raw_results.values())[0]
    else:
        results = raw_results
    krs = [r['avg_kr'] for r in results]
    skrs = [r['avg_strict_kr'] for r in results]
    sfss = [r['avg_sfs'] for r in results]
    ssfss = [r['avg_strict_sfs'] for r in results]
    sprs = [r.get('avg_spr', None) for r in results]
    n = len(krs)
    implant = sum(1 for k in krs if k > 0)
    simplant = sum(1 for k in skrs if k > 0)
    print(f'  N={n}')
    print(f'  Mean KR={sum(krs)/n:.4f}  Mean StrictKR={sum(skrs)/n:.4f}')
    print(f'  Mean SFS={sum(sfss)/n:.4f}  Mean StrictSFS={sum(ssfss)/n:.4f}')
    if any(s is not None for s in sprs):
        valid_sprs = [s for s in sprs if s is not None]
        print(f'  Mean SPR={sum(valid_sprs)/len(valid_sprs):.4f}')
    print(f'  Implant Viable (KR>0): {implant}/{n} ({100*implant/n:.1f}%)')
    print(f'  Strict Implant (StrictKR>0): {simplant}/{n} ({100*simplant/n:.1f}%)')
    
    # Per-row breakdown
    print(f'  --- Per-Row KR / StrictKR ---')
    for r in results:
        row = r['row']
        tid = r.get('label', r.get('technique_id', '?'))
        kr = r['avg_kr']
        skr = r['avg_strict_kr']
        spr_val = r.get('avg_spr', '')
        spr_str = f' SPR={spr_val:.2f}' if isinstance(spr_val, (int, float)) else ''
        print(f'    Row {row:2d} {tid:30s} KR={kr:.2f} StrictKR={skr:.2f}{spr_str}')
    print()
