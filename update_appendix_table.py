"""
Modify the appendix per-scenario table in samplepaper.tex to add MemGPT columns.
Inserts MemGPT KR_I and Lat columns between Beelzebub and PromptShield.
"""
import re

# MemGPT per-scenario data (position-indexed, matching appendix table row order)
# Format: (KR_I, Latency_s)
memgpt_data = [
    (1.00, 60.7),   # 1  T1098.004
    (0.33, 60.0),   # 2  T1136.001
    (1.00, 40.8),   # 3  T1053.003
    (1.00, 48.2),   # 4  T1543.002
    (1.00, 65.9),   # 5  T1546.004
    (1.00, 48.0),   # 6  T1037.004
    (0.56, 43.0),   # 7  T1078.003
    (1.00, 38.9),   # 8  T1505.003
    (0.67, 43.4),   # 9  T1574.006
    (0.67, 47.6),   # 10 T1556.003
    (1.00, 47.5),   # 11 T1105 (Gafgyt Dropper)
    (1.00, 57.4),   # 12 T1071 (IRC Botnet)
    (1.00, 62.4),   # 13 T1499
    (1.00, 52.2),   # 14 T1021.004
    (0.67, 28.9),   # 15 T1574.006 variant
    (1.00, 47.5),   # 16 T1037.004 variant
    (1.00, 37.2),   # 17 T1505.003 variant
    (1.00, 49.0),   # 18 T1548.001
    (1.00, 318.7),  # 19 T1552.004 (SSH Key Theft - long due to agent loop)
    (1.00, 38.2),   # 20 T1552.001
    (1.00, 44.8),   # 21 T1560
    (1.00, 45.9),   # 22 T1071.004
    (0.67, 42.7),   # 23 T1036.004 (Process Hiding)
    (0.50, 56.8),   # 24 T1059
]

tex_path = r"xx.tex"

with open(tex_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Find the appendix per-scenario table
# Replace header
old_header = r"""\begin{tabular}{cccccccc}
\toprule
\multirow{2}{*}{\textbf{MITRE ID}} & \multicolumn{3}{c}{\textbf{shelLM}} & \textbf{Beelz.} & \multicolumn{3}{c}{\textbf{PromptShield}} \\
\cmidrule(lr){2-4} \cmidrule(lr){5-5} \cmidrule(lr){6-8}
 & KR$_I$ & KR$_N$ & Lat.\,(s) & KR$_I$ & KR$_I$ & KR$_N$ & Lat.\,(s) \\"""

new_header = r"""\begin{tabular}{cccccccccc}
\toprule
\multirow{2}{*}{\textbf{MITRE ID}} & \multicolumn{3}{c}{\textbf{shelLM}} & \textbf{Beelz.} & \multicolumn{2}{c}{\textbf{MemGPT}} & \multicolumn{3}{c}{\textbf{PromptShield}} \\
\cmidrule(lr){2-4} \cmidrule(lr){5-5} \cmidrule(lr){6-7} \cmidrule(lr){8-10}
 & KR$_I$ & KR$_N$ & Lat.\,(s) & KR$_I$ & KR$_I$ & Lat.\,(s) & KR$_I$ & KR$_N$ & Lat.\,(s) \\"""

assert old_header in content, "Could not find appendix table header!"
content = content.replace(old_header, new_header, 1)

# Now modify each data row: insert MemGPT values between Beelzebub (col 5) and PromptShield (col 6)
# Pattern: active data row has format:
#   MITRE_ID  & val & val & val & val & val & val & val \\
# We need to insert 2 values after the 4th & (Beelzebub column)

# Match active (non-commented) data rows with exactly 7 & separators
data_row_pattern = re.compile(
    r'^((?:T\d|\\multicolumn).*?)$',
    re.MULTILINE
)

row_idx = 0
def replace_data_row(match):
    global row_idx
    line = match.group(1)
    
    # Skip commented lines
    if line.strip().startswith('%'):
        return line
    
    # Check if this is a data row (has & separators and \\)
    if '&' not in line or '\\\\' not in line:
        return line
    
    # Split by &
    parts = line.split('&')
    
    # For the average row, handle separately
    if '\\textbf{Average}' in line or 'Average' in line:
        # Average row: insert MemGPT averages
        # Current: Average & 0.87 & 0.87 & 9.0 & 0.26 & 0.98 & 0.98 & 9.7 \\
        # New: Average & 0.87 & 0.87 & 9.0 & 0.26 & 0.88 & 59.4 & 0.98 & 0.98 & 9.7 \\
        if len(parts) == 8:
            new_parts = parts[:5] + [' \\textbf{0.88}', ' \\textbf{59.4}'] + parts[5:]
            return '&'.join(new_parts)
        return line
    
    # Regular data row: 8 parts (MITRE + 7 values)
    if len(parts) == 8 and row_idx < len(memgpt_data):
        kr, lat = memgpt_data[row_idx]
        kr_str = f'{kr:.2f}'
        lat_str = f'{lat:.1f}'
        # Insert after part[4] (Beelzebub KR_I)
        new_parts = parts[:5] + [f' {kr_str}', f' {lat_str}'] + parts[5:]
        row_idx += 1
        return '&'.join(new_parts)
    
    return line

# Find the section between \midrule and \bottomrule in the appendix table
# We need to be in the right table (the appendix one, not the main one)
appendix_marker = r'\label{tab:per-scenario}'
appendix_pos = content.find(appendix_marker)
assert appendix_pos > 0, "Could not find appendix table marker!"

# Find \midrule after the appendix marker
midrule_pos = content.find('\\midrule', appendix_pos)
bottomrule_pos = content.find('\\bottomrule', midrule_pos)

table_body = content[midrule_pos:bottomrule_pos]

# Process line by line
lines = table_body.split('\n')
new_lines = []
for line in lines:
    stripped = line.strip()
    # Skip empty, comment-only, rowcolor-only, midrule lines
    if (not stripped or 
        stripped.startswith('%') or 
        stripped.startswith('\\rowcolor') or
        stripped == '\\midrule'):
        new_lines.append(line)
        continue
    
    # Check if it's a data row (starts with T or \multicolumn)
    if (stripped.startswith('T') or stripped.startswith('\\multicolumn')) and '&' in stripped and '\\\\' in stripped:
        parts = stripped.split('&')
        
        if '\\textbf{Average}' in stripped or 'Average' in stripped:
            # Average row
            if len(parts) == 8:
                new_parts = parts[:5] + [' \\textbf{0.88}', ' \\textbf{59.4}'] + parts[5:]
                new_lines.append('&'.join(new_parts))
            else:
                new_lines.append(line)
        elif len(parts) == 8 and row_idx < len(memgpt_data):
            kr, lat = memgpt_data[row_idx]
            kr_str = f'{kr:.2f}'
            lat_str = f'{lat:.1f}'
            new_parts = parts[:5] + [f' {kr_str}', f' {lat_str}'] + parts[5:]
            row_idx += 1
            new_lines.append('&'.join(new_parts))
        else:
            new_lines.append(line)
    else:
        new_lines.append(line)

new_table_body = '\n'.join(new_lines)
content = content[:midrule_pos] + new_table_body + content[bottomrule_pos:]

# Update the table description text
old_desc = "Table~\\ref{tab:per-scenario} reports KR under both the Ideal condition and Noise-100 conditions."
new_desc = "Table~\\ref{tab:per-scenario} reports KR under both the Ideal condition and Noise-100 conditions, with MemGPT results included for the Ideal condition."
content = content.replace(old_desc, new_desc, 1)

with open(tex_path, 'w', encoding='utf-8') as f:
    f.write(content)

print(f"Done! Processed {row_idx} data rows.")
print("MemGPT columns added to appendix per-scenario table.")
