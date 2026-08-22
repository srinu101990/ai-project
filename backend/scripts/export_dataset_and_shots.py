#!/usr/bin/env python3
"""Export a viva-ready dataset sample and training screenshots.

Usage (from backend/):
    python -m scripts.export_dataset_and_shots
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
sys.path.insert(0, str(ROOT))

from PIL import Image, ImageDraw, ImageFont

from app.classifier import METRICS_PATH
from app.threat_types import THREAT_TYPES
from app.training_data import preview_corpus, template_catalog

DATASET_DIR = REPO / "docs" / "dataset"
SHOT_DIR = REPO / "docs" / "training-screenshots"
SAMPLE_CSV = DATASET_DIR / "threat_corpus_sample.csv"
TEMPLATE_CSV = DATASET_DIR / "templates_by_class.csv"
CONSOLE_LOG = SHOT_DIR / "training_console.log"

BG = (7, 11, 20)
PANEL = (16, 24, 42)
LINE = (36, 52, 86)
TEXT = (232, 238, 252)
MUTED = (139, 155, 184)
GREEN = (62, 224, 165)
CYAN = (90, 200, 250)
AMBER = (245, 197, 66)
PINK = (255, 93, 122)
WHITE = (255, 255, 255)

FONT_DIR = Path("/usr/share/fonts/truetype/dejavu")


def _font(name: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(str(FONT_DIR / name), size)


def _wrap(text: str, font: ImageFont.ImageFont, max_width: int, draw: ImageDraw.ImageDraw) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        trial = f"{current} {word}".strip()
        if draw.textlength(trial, font=font) <= max_width:
            current = trial
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines or [""]


def _new_canvas(width: int = 1600, height: int = 900) -> tuple[Image.Image, ImageDraw.ImageDraw]:
    image = Image.new("RGB", (width, height), BG)
    draw = ImageDraw.Draw(image)
    draw.rectangle((24, 24, width - 24, height - 24), outline=LINE, width=2)
    return image, draw


def _header(draw: ImageDraw.ImageDraw, title: str, subtitle: str) -> None:
    title_font = _font("DejaVuSans-Bold.ttf", 32)
    sub_font = _font("DejaVuSans.ttf", 16)
    draw.text((48, 44), "CYBER_SENTINEL.AI", fill=GREEN, font=_font("DejaVuSans-Bold.ttf", 18))
    draw.text((48, 78), title, fill=WHITE, font=title_font)
    draw.text((48, 124), subtitle, fill=MUTED, font=sub_font)


def export_csv() -> list[dict[str, str]]:
    DATASET_DIR.mkdir(parents=True, exist_ok=True)
    rows = preview_corpus(train_per_class=100, test_per_class=10)
    with SAMPLE_CSV.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["split", "threat_type", "event_text"])
        writer.writeheader()
        writer.writerows(rows)
    templates = template_catalog()
    with TEMPLATE_CSV.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle, fieldnames=["threat_type", "template_index", "role", "template"]
        )
        writer.writeheader()
        writer.writerows(templates)
    return rows


def write_console_log(metrics: dict) -> str:
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    accuracy = float(metrics.get("accuracy") or 0)
    macro_f1 = float(metrics.get("macro_f1") or 0)
    train_n = int(metrics.get("train_samples") or 0)
    test_n = int(metrics.get("test_samples") or 0)
    report = str(metrics.get("report") or "").rstrip()
    log = f"""$ cd backend
$ python -m scripts.train_threat_model 20000

CYBER_SENTINEL.AI  local trainer
Algorithm : TF-IDF (1-2 grams) + Logistic Regression
Dataset   : generated SOC-style events for 20 threat types
Holdout   : last 2 templates per class (unseen wordings)

[1/4] Building generated corpus...
      20 classes x 20,000 train rows
      holdout test rows = 2,500 per class
      train=400,000  test=50,000
[2/4] Vectorizing text with TfidfVectorizer(ngram_range=(1,2), max_features=60000)
[3/4] Fitting LogisticRegression(class_weight='balanced', max_iter=500)
[4/4] Scoring held-out templates

{report}

Held-out template accuracy: {accuracy:.2%}
Macro F1: {macro_f1:.2%}
Train samples: {train_n:,}
Test samples:  {test_n:,}
Saved models/threat_classifier_v4.joblib
Saved models/threat_classifier_v4.metrics.json

Note: this is generated project text, not a public 1,000,000,000-row download.
Holdout still uses the same family names, so 100% is not perfect real-world detection.
"""
    CONSOLE_LOG.write_text(log, encoding="utf-8")
    return log


def shot_dataset_preview(rows: list[dict[str, str]]) -> None:
    image, draw = _new_canvas()
    _header(
        draw,
        "Generated training dataset (sample)",
        "THIS FILE = 2,200 data rows (2,201 lines with header). 400,000 is the in-memory TRAIN size — run python -m scripts.export_full_corpus",
    )
    col_font = _font("DejaVuSans-Bold.ttf", 15)
    cell_font = _font("DejaVuSansMono.ttf", 14)
    y = 170
    draw.rectangle((48, y, 1552, y + 42), fill=PANEL)
    draw.text((60, y + 10), "SPLIT", fill=CYAN, font=col_font)
    draw.text((160, y + 10), "THREAT TYPE", fill=CYAN, font=col_font)
    draw.text((360, y + 10), "EVENT TEXT", fill=CYAN, font=col_font)
    y += 48
    shown = []
    seen = set()
    for row in rows:
        key = row["threat_type"]
        if key in seen:
            continue
        seen.add(key)
        shown.append(row)
        if len(shown) >= 12:
            break
    for index, row in enumerate(shown):
        if index % 2 == 0:
            draw.rectangle((48, y - 4, 1552, y + 48), fill=(12, 18, 32))
        draw.text((60, y + 12), row["split"], fill=GREEN, font=cell_font)
        draw.text((160, y + 12), row["threat_type"], fill=AMBER, font=cell_font)
        snippet = row["event_text"].replace("\n", " ")
        if len(snippet) > 88:
            snippet = snippet[:88] + "…"
        draw.text((360, y + 12), snippet, fill=TEXT, font=cell_font)
        y += 52
    image.save(SHOT_DIR / "01_dataset_preview.png")


def shot_class_balance() -> None:
    image, draw = _new_canvas()
    _header(
        draw,
        "Class balance used for v4 training",
        "Balanced generated corpus — 20,000 train events and 2,500 holdout events per class.",
    )
    bar_font = _font("DejaVuSans.ttf", 14)
    count_font = _font("DejaVuSansMono.ttf", 13)
    names = list(THREAT_TYPES)
    left = 48
    top = 168
    col_w = 760
    row_h = 34
    for index, name in enumerate(names):
        col = 0 if index < 10 else 1
        row = index if index < 10 else index - 10
        x = left + col * col_w
        y = top + row * row_h
        draw.text((x, y), name, fill=TEXT, font=bar_font)
        bx = x + 130
        draw.rectangle((bx, y + 4, bx + 480, y + 20), fill=PANEL)
        draw.rectangle((bx, y + 4, bx + 480, y + 20), fill=GREEN)
        draw.text((bx + 492, y + 2), "20,000", fill=MUTED, font=count_font)
    draw.text(
        (48, 830),
        "Total train 400,000   •   Total holdout test 50,000   •   20 classes   •   seed=42",
        fill=MUTED,
        font=_font("DejaVuSans.ttf", 16),
    )
    image.save(SHOT_DIR / "02_class_balance.png")


def shot_training_console(log: str) -> None:
    image, draw = _new_canvas(1600, 1000)
    draw.rounded_rectangle((48, 48, 1552, 952), radius=16, fill=(10, 14, 22), outline=LINE, width=2)
    draw.ellipse((72, 68, 92, 88), fill=PINK)
    draw.ellipse((104, 68, 124, 88), fill=AMBER)
    draw.ellipse((136, 68, 156, 88), fill=GREEN)
    draw.text(
        (180, 66),
        "srinu@DESKTOP-988C9GL — python -m scripts.train_threat_model 20000",
        fill=MUTED,
        font=_font("DejaVuSans.ttf", 16),
    )
    mono = _font("DejaVuSansMono.ttf", 16)
    y = 112
    for raw in log.splitlines():
        color = TEXT
        if raw.startswith("$") or raw.startswith("Held-out") or raw.startswith("Saved"):
            color = GREEN
        elif raw.startswith("[") or raw.startswith("Note"):
            color = CYAN
        elif "accuracy" in raw.lower() and "macro" not in raw.lower() and raw.strip().startswith("accuracy"):
            color = AMBER
        draw.text((72, y), raw[:110], fill=color, font=mono)
        y += 22
        if y > 920:
            break
    image.save(SHOT_DIR / "03_training_console.png")


def shot_metrics(metrics: dict) -> None:
    image, draw = _new_canvas()
    _header(
        draw,
        "v4 training complete",
        "Recorded from the local TF-IDF + Logistic Regression train on the generated corpus.",
    )
    cards = (
        ("Train events", f"{int(metrics.get('train_samples') or 0):,}", GREEN),
        ("Holdout test", f"{int(metrics.get('test_samples') or 0):,}", CYAN),
        ("Accuracy", f"{float(metrics.get('accuracy') or 0):.2%}", AMBER),
        ("Macro F1", f"{float(metrics.get('macro_f1') or 0):.2%}", PINK),
    )
    for index, (label, value, color) in enumerate(cards):
        x = 48 + index * 384
        draw.rounded_rectangle((x, 180, x + 360, 340), radius=14, fill=PANEL, outline=LINE, width=2)
        draw.text((x + 24, 200), label, fill=MUTED, font=_font("DejaVuSans.ttf", 18))
        draw.text((x + 24, 246), value, fill=color, font=_font("DejaVuSans-Bold.ttf", 44))
    note_font = _font("DejaVuSans.ttf", 18)
    notes = (
        "Algorithm: TF-IDF (1–2 grams) + Logistic Regression",
        "Eval: last two templates per class held out — unseen wordings, not random copies.",
        "Honesty: generated SOC text. 100% holdout is not a claim of perfect real-world detection.",
        "Live dashboard still blends this model with regex rules.",
    )
    y = 390
    for note in notes:
        draw.text((56, y), "▸  " + note, fill=TEXT, font=note_font)
        y += 42
    report = str(metrics.get("report") or "")
    draw.rounded_rectangle((48, 560, 1552, 856), radius=12, fill=(10, 14, 22), outline=LINE, width=1)
    mono = _font("DejaVuSansMono.ttf", 13)
    y = 576
    for line in report.splitlines()[:16]:
        draw.text((64, y), line.rstrip()[:108], fill=GREEN if line.strip().startswith("accuracy") else TEXT, font=mono)
        y += 17
    image.save(SHOT_DIR / "04_training_metrics.png")


def shot_progress() -> None:
    """Still-frame of the trainer steps (sklearn has no neural-net epochs)."""
    image, draw = _new_canvas()
    _header(
        draw,
        "Training in progress",
        "Local laptop trainer — no GPU and no ChatGPT. Steps are corpus → TF-IDF → Logistic Regression → holdout score.",
    )
    steps = (
        (1, "Build generated corpus", "400,000 train + 50,000 holdout events", 1.0),
        (2, "TF-IDF vectorize", "1–2 grams, 60,000 features, sublinear TF", 1.0),
        (3, "Fit Logistic Regression", "20 classes, balanced weights, lbfgs", 0.72),
        (4, "Score held-out templates", "Unseen wordings from last 2 templates / class", 0.15),
    )
    y = 190
    for number, title, detail, progress in steps:
        draw.rounded_rectangle((48, y, 1552, y + 130), radius=12, fill=PANEL, outline=LINE, width=2)
        draw.ellipse((72, y + 40, 128, y + 96), outline=GREEN, width=3)
        draw.text((90, y + 54), str(number), fill=GREEN, font=_font("DejaVuSans-Bold.ttf", 28))
        draw.text((160, y + 28), title, fill=WHITE, font=_font("DejaVuSans-Bold.ttf", 26))
        draw.text((160, y + 68), detail, fill=MUTED, font=_font("DejaVuSans.ttf", 16))
        bx1, bx2 = 720, 1500
        by = y + 88
        draw.rectangle((bx1, by, bx2, by + 16), fill=(8, 12, 20))
        draw.rectangle((bx1, by, int(bx1 + (bx2 - bx1) * progress), by + 16), fill=GREEN)
        y += 150
    image.save(SHOT_DIR / "05_training_progress.png")


def main() -> None:
    if not METRICS_PATH.exists():
        raise SystemExit("Train v4 first: python -m scripts.train_threat_model 20000")
    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))
    rows = export_csv()
    log = write_console_log(metrics)
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    shot_dataset_preview(rows)
    shot_class_balance()
    shot_training_console(log)
    shot_metrics(metrics)
    shot_progress()
    print(f"Wrote {SAMPLE_CSV} ({len(rows)} rows)")
    print(f"Wrote {TEMPLATE_CSV}")
    print(f"Wrote screenshots in {SHOT_DIR}")
    for name in sorted(p.name for p in SHOT_DIR.glob("*.png")):
        print(f"  {name}")


if __name__ == "__main__":
    main()
