import re

with open(r'xx.tex', 'r', encoding='utf-8') as f:
    content = f.read()

# Validate Table 5: 13 columns
t5_start = content.find(r'\label{tab:comprehensive-results}')
t5_end = content.find(r'\end{table*}', t5_start)
t5 = content[t5_start:t5_end]

spec = re.search(r'\\begin\{tabular\}\{(c+)\}', t5)
ncols = len(spec.group(1)) if spec else 0
print(f"Table 5 column spec: {ncols} columns")

for line in t5.split('\n'):
    line = line.strip()
    if line.startswith('%') or '&' not in line or '\\\\' not in line:
        continue
    amps = line.count('&')
    if amps != ncols - 1:
        print(f"  MISMATCH: {amps} & (expected {ncols-1}) in: {line[:70]}...")

# Validate appendix table: 10 columns
ap_start = content.find(r'\label{tab:per-scenario}')
ap_end = content.find(r'\end{tabular}', ap_start)
ap = content[ap_start:ap_end]

spec2 = re.search(r'\\begin\{tabular\}\{(c+)\}', ap)
ncols2 = len(spec2.group(1)) if spec2 else 0
print(f"Appendix table column spec: {ncols2} columns")

errs = 0
for line in ap.split('\n'):
    line = line.strip()
    if (line.startswith('%') or line.startswith('\\rowcolor') or
        line.startswith('\\midrule') or line.startswith('\\toprule') or
        line.startswith('\\cmidrule') or line.startswith('\\multirow') or
        line.startswith('\\begin') or '&' not in line):
        continue
    amps = line.count('&')
    if amps != ncols2 - 1:
        errs += 1
        print(f"  MISMATCH: {amps} & (expected {ncols2-1}) in: {line[:80]}...")
if errs == 0:
    print("  All appendix data rows have correct column count")

print("Validation complete.")
