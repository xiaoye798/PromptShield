import json

with open('mutated_replay_report_20260410_171602.json', encoding='utf-8') as f:
    report = json.load(f)

CLASS_MAP = {
    'ATK-02': 'standard', 'ATK-03': 'standard', 'ATK-04': 'advanced',
    'ATK-05': 'advanced', 'ATK-06': 'standard', 'ATK-07': 'advanced',
    'ATK-09': 'advanced', 'ATK-10': 'advanced', 'ATK-11': 'standard',
    'ATK-12': 'standard', 'ATK-13': 'standard', 'ATK-14': 'standard',
    'ATK-15': 'standard', 'ATK-16': 'simple', 'ATK-17': 'simple',
    'ATK-18': 'advanced', 'ATK-19': 'standard', 'ATK-20': 'simple',
    'ATK-24': 'simple', 'ATK-25': 'simple', 'ATK-26': 'standard',
    'ATK-27': 'advanced', 'ATK-28': 'obfuscated', 'ATK-29': 'standard',
    'ATK-30': 'advanced',
}

classes = {c: {'scen': 0, 'var': 0, 'kw': 0, 'sem': 0}
           for c in ['simple', 'standard', 'advanced', 'obfuscated']}

for sid, data in report['per_scenario_summary'].items():
    cls = CLASS_MAP.get(sid, 'standard')
    classes[cls]['scen'] += 1
    classes[cls]['var'] += data['total_variants']
    classes[cls]['kw'] += data['keyword_pass']
    classes[cls]['sem'] += data['semantic_pass']

print("CLASS         | Scen | Var | KW Pass         | Sem Pass")
print("-" * 65)
ts = tv = tk = tsem = 0
for cls in ['simple', 'standard', 'advanced', 'obfuscated']:
    d = classes[cls]
    kwr = d['kw'] / d['var'] * 100
    semr = d['sem'] / d['var'] * 100
    print("{:13s} | {:4d} | {:3d} | {:2d}/{:2d} ({:5.1f}%) | {:2d}/{:2d} ({:5.1f}%)".format(
        cls, d['scen'], d['var'], d['kw'], d['var'], kwr, d['sem'], d['var'], semr))
    ts += d['scen']; tv += d['var']; tk += d['kw']; tsem += d['sem']
print("-" * 65)
print("{:13s} | {:4d} | {:3d} | {:2d}/{:2d} ({:5.1f}%) | {:2d}/{:2d} ({:5.1f}%)".format(
    "TOTAL", ts, tv, tk, tv, tk/tv*100, tsem, tv, tsem/tv*100))
