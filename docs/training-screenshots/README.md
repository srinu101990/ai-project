# Training screenshots

These stills were generated from the **real v4 metrics** and a sample of the
generated corpus (`python -m scripts.export_dataset_and_shots`).

`01_dataset_preview.png` is the **2,200-row sample CSV**. The **400,000** number
is the in-memory train size. Build the full file with
`python -m scripts.export_full_corpus` (450,001 lines including the header).

sklearn has no neural-net epoch bar. The “training in progress” frame shows the
actual four steps: build corpus → TF-IDF → Logistic Regression → holdout score.

| File | What to show in the report |
|---|---|
| `01_dataset_preview.png` | Sample labeled events |
| `02_class_balance.png` | 20,000 train rows per class |
| `03_training_console.png` | Trainer command and sklearn report |
| `04_training_metrics.png` | 400,000 / 50,000 / 100% holdout |
| `05_training_progress.png` | Steps while the local trainer runs |
| `training_console.log` | Plain-text copy of the console |

Honesty: generated SOC text. 100% holdout is not perfect real-world detection.
