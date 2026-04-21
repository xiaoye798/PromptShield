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

Average row mapping:

- shelLM KR_I: 0.8681 -> 0.87
- shelLM KR_N: 0.8681 -> 0.87
- shelLM Lat.(s): 9.0
- Beelz. KR_I: 0.2569 -> 0.26
- PromptShield KR_I: 0.9167 -> 0.92
- PromptShield KR_N: 0.9167 -> 0.92
- PromptShield Lat.(s): 9.9

