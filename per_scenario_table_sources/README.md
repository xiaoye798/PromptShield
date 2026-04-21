## Per-Scenario Table Source Files

This folder contains the five JSON reports used by the appendix table "Per-Scenario Keyword Recall" in paper/samplepaper.tex.

Column-to-file mapping:

- shelLM KR_I and Lat.(s): appendix_benchmark_report_20260410_202802.json
- shelLM KR_N: appendix_benchmark_report_noise100_20260412_202755.json
- Beelz. KR_I: appendix_benchmark_report_20260410_204319.json
- PromptShield KR_I and Lat.(s): appendix_benchmark_report_20260410_205739.json
- PromptShield KR_N: appendix_benchmark_report_noise100_20260412_202822.json

Row mapping rule:

- Table row n maps to the JSON object with "row": n in each source file.
- The 24 scenario labels are aligned across all five files.


