# Training dataset (CYBER_SENTINEL.AI)

This is the **generated** SOC-style corpus used to train the local v4 classifier
(TF-IDF + Logistic Regression). It is **not** a public 1-billion-row download.

## Files

| File | What it is |
|---|---|
| `threat_corpus_sample.csv` | 2,200 labeled events: 100 train + 10 holdout rows per class. Open in Excel. |
| `templates_by_class.csv` | Every wording template. Last two templates per class are holdout. |

The production model was trained on **400,000** generated train events
(20,000 per class) and scored on **50,000** held-out-template events.

Regenerate the sample and screenshots from `backend/`:

```bat
python -m scripts.export_dataset_and_shots
```

Regenerate the full model:

```bat
python -m scripts.train_threat_model 20000
```

## Columns

`threat_corpus_sample.csv`

- `split` — `train` or `test` (test = held-out last-two templates)
- `threat_type` — one of the 20 project classes
- `event_text` — generated alert / mail / host text

## Honesty for viva

Holdout wordings still use the same family names (LockBit, Emotet, WannaCry).
A high score here is not a claim of perfect real-world detection.
The live dashboard still uses regex rules plus this local model.
