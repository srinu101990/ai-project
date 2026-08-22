# Training dataset (CYBER_SENTINEL.AI)

Two different sizes. Do not mix them up.

| File | Row count | What it is |
|---|---|---|
| `threat_corpus_sample.csv` | **2,200 data + 1 header = 2,201 lines** | Small Excel sample for viva |
| `templates_by_class.csv` | one row per wording template | Train vs holdout templates |
| `corpus_counts.csv` | count table | Official numbers |
| `threat_corpus_full.csv` | **450,000 data + 1 header = 450,001 lines** | Full generated train+test. **Not in git** — you build it with the command below |

The screenshots say **400,000** because that is the **train** size used by the model
(20,000 rows × 20 classes). The full CSV also has **50,000** holdout test rows,
so the file you count will be **450,001 lines**.

## Build the 400,000-train file on your laptop

```bat
cd %USERPROFILE%\Desktop\CYBER_SENTINEL
git pull origin cursor/laptop-phishing-mail-cd50
cd backend
py -3 -m scripts.export_full_corpus
find /c /v "" ..\docs\dataset\threat_corpus_full.csv
explorer ..\docs\dataset
```

`find /c /v ""` prints the line count. Expect **450001**.

That command generates the same SOC-style text the trainer used. It is **not** a
public 1-billion-row internet download.

## Honesty for viva

- `2201` in the sample file is correct. That file was always a sample.
- `400000` in the screenshots is the in-memory train size, not the sample CSV.
- Holdout text still uses the same family names. 100% is not perfect real-world detection.
