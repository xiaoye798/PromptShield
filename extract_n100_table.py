"""Extract Noise-100 per-scenario KR from benchmark JSON and merge with Ideal data."""
import json, sys, os

# Ideal-condition data (from appendix table)
IDEAL_DATA = [
    # (row, label, shelLM_KR, shelLM_Lat, Beelz_KR, PS_KR, PS_Lat)
    (1, "T1098.004 SSH Keys", 1.00, 7.6, 0.50, 1.00, 11.6),
    (2, "T1136.001 Local Acct", 1.00, 12.1, 1.00, 0.50, 11.5),
    (3, "T1053.003 Cron", 1.00, 5.1, 0.00, 1.00, 5.7),
    (4, "T1543.002 Systemd", 0.67, 7.6, 0.50, 1.00, 13.4),
    (5, "T1546.004 Shell Cfg", 1.00, 16.1, 0.33, 1.00, 6.6),
    (6, "T1037.004 RC Scripts", 1.00, 6.8, 0.00, 1.00, 8.5),
    (7, "T1078.003 Valid Acct", 0.33, 6.3, 0.33, 1.00, 8.4),
    (8, "T1574.006 Linker Hijack", 1.00, 5.7, 1.00, 1.00, 6.5),
    (9, "T1556.003 PAM Backdoor", 1.00, 6.2, 0.00, 0.00, 7.3),
    (10, "T1059.004 Gafgyt Dropper", 1.00, 8.6, 0.00, 1.00, 8.5),
    (11, "T1071.001 IRC Botnet", 0.33, 8.7, 0.00, 1.00, 13.9),
    (12, "T1499 DDoS Tool", 1.00, 10.6, 0.00, 1.00, 12.4),
    (13, "T1021.004 SSH Worm", 1.00, 11.7, 0.00, 1.00, 11.6),
    (14, "T1574.006 LD_PRELOAD Var.", 1.00, 5.2, 1.00, 1.00, 6.5),
    (15, "T1037.004 RC Local Var.", 1.00, 8.7, 0.00, 1.00, 8.5),
    (16, "T1505.003 Web Shell Var.", 1.00, 5.3, 0.00, 1.00, 5.6),
    (17, "T1548.001 SUID Backdoor", 1.00, 5.6, 1.00, 1.00, 7.1),
    (18, "T1552.004 SSH Key Theft", 1.00, 24.9, 0.00, 1.00, 24.9),
    (19, "T1552.001 Env Var Exfil", 1.00, 5.4, 0.00, 1.00, 5.3),
    (20, "T1560 Data Archive", 1.00, 7.0, 0.00, 1.00, 10.0),
    (21, "T1071.004 DNS Tunneling", 1.00, 12.0, 0.00, 1.00, 12.0),
    (22, "T1564.001 Process Hiding", 0.00, 9.4, 0.00, 1.00, 11.2),
    (23, "T1059 Reverse Shell", 0.50, 14.0, 0.00, 0.50, 15.5),
    (24, "T1059 Multi-stage", 0.00, 0.0, 0.00, 0.00, 0.0),  # placeholder if exists
]

def load_n100(json_path, system_name):
    """Load N100 KR per row from a benchmark JSON."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    results = data["results"].get(system_name, [])
    return {r["row"]: r["avg_kr"] for r in results}

def main():
    repo = os.path.dirname(os.path.abspath(__file__))
    
    # Find N100 JSON files
    shellm_json = None
    ps_json = None
    for fn in sorted(os.listdir(repo)):
        if fn.startswith("appendix_benchmark_report_noise100_") and fn.endswith(".json"):
            with open(os.path.join(repo, fn), "r") as f:
                meta = json.load(f)["meta"]
            if "shelLM" in meta["systems"]:
                shellm_json = os.path.join(repo, fn)
            if "PromptShield" in meta["systems"]:
                ps_json = os.path.join(repo, fn)
    
    if not shellm_json and not ps_json:
        print("No N100 JSON files found yet. Experiments still running.")
        sys.exit(1)
    
    shellm_n100 = load_n100(shellm_json, "shelLM") if shellm_json else {}
    ps_n100 = load_n100(ps_json, "PromptShield") if ps_json else {}
    
    print("shelLM N100 file:", shellm_json)
    print("PS N100 file:", ps_json)
    print("shelLM rows:", len(shellm_n100), "PS rows:", len(ps_n100))
    
    # Print merged data
    print("\n%-35s  sLM_I sLM_N  Beelz  PS_I  PS_N" % "Scenario")
    print("-" * 75)
    
    shellm_ideal_sum = 0
    shellm_n100_sum = 0
    beelz_sum = 0
    ps_ideal_sum = 0
    ps_n100_sum = 0
    count = 0
    
    for row, label, s_kr, s_lat, b_kr, p_kr, p_lat in IDEAL_DATA[:23]:
        s_n = shellm_n100.get(row, None)
        p_n = ps_n100.get(row, None)
        s_n_str = "%.2f" % s_n if s_n is not None else " -- "
        p_n_str = "%.2f" % p_n if p_n is not None else " -- "
        
        # Highlight drops
        s_drop = "*" if s_n is not None and s_n < s_kr else " "
        p_drop = "*" if p_n is not None and p_n < p_kr else " "
        
        print("%-35s  %.2f  %s%s  %.2f  %.2f  %s%s" % (
            label, s_kr, s_n_str, s_drop, b_kr, p_kr, p_n_str, p_drop
        ))
        
        shellm_ideal_sum += s_kr
        if s_n is not None:
            shellm_n100_sum += s_n
        beelz_sum += b_kr
        ps_ideal_sum += p_kr
        if p_n is not None:
            ps_n100_sum += p_n
        count += 1
    
    n_s = len(shellm_n100)
    n_p = len(ps_n100)
    print("-" * 75)
    print("Macro-avg (Ideal, %d scenarios):" % count)
    print("  shelLM KR=%.2f  Beelz KR=%.2f  PS KR=%.2f" % (
        shellm_ideal_sum / count, beelz_sum / count, ps_ideal_sum / count
    ))
    if n_s > 0:
        print("  shelLM N100 KR=%.2f (%d scenarios)" % (shellm_n100_sum / n_s, n_s))
    if n_p > 0:
        print("  PS N100 KR=%.2f (%d scenarios)" % (ps_n100_sum / n_p, n_p))
    
    # Show scenarios with KR degradation under N100
    print("\n=== Scenarios with KR drop under N100 ===")
    for row, label, s_kr, s_lat, b_kr, p_kr, p_lat in IDEAL_DATA[:23]:
        s_n = shellm_n100.get(row)
        p_n = ps_n100.get(row)
        if s_n is not None and s_n < s_kr:
            print("  shelLM Row %d (%s): %.2f -> %.2f (delta=%.2f)" % (row, label, s_kr, s_n, s_n - s_kr))
        if p_n is not None and p_n < p_kr:
            print("  PS Row %d (%s): %.2f -> %.2f (delta=%.2f)" % (row, label, p_kr, p_n, p_n - p_kr))

if __name__ == "__main__":
    main()
