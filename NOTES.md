# NOTES.md — Live Build Log

This file is maintained from hour zero. Every meaningful event — breakage, fix, design decision — is logged here with a timestamp.
This is a required deliverable, not an afterthought.

---

## 2024-08-20 — Initial Build

### Architecture Decision: Statistical layer has no LLM
- **Decision**: Rolling z-scores and Isolation Forest run with zero LLM involvement.
- **Reason**: Velocity/decline-rate spikes are deterministic arithmetic. An LLM adds latency and non-determinism to a problem that doesn't need language reasoning. Speed is the constraint here — the statistical layer must respond in milliseconds.

### Architecture Decision: LLM has no write access
- **Decision**: `ActionLayer` contains no function that writes to a block list, card list, or merchant suspension list. The capability does not exist in the codebase.
- **Reason**: A non-deterministic system (LLM) must not hold authority over fraud enforcement decisions. The LLM recommends; a human decides.

### Architecture Decision: Google Gemini (gemini-2.5-flash) for LLM Reasoning
- **Decision**: Using Google Gemini (`gemini-2.5-flash` / `gemini-2.0-flash` via official `google-genai` SDK).
- **Reason**: Single-digit second latency, structured JSON response mode (`response_mime_type="application/json"`), and seamless integration. Runs exclusively on flagged candidate anomaly windows to classify attack patterns.

### Architecture Decision: Fallback is a named deliverable
- **Decision**: `reasoning/fallback.py` is a first-class module, not an emergency patch.
- **Reason**: The judging criteria explicitly names failure recovery. The fallback path is demonstrated live in the demo, not hidden.

---

## Known Issues / Resolved

### Issue: Isolation Forest contamination & baseline contamination
- **Symptom**: Initial evaluation on held-out set suffered either low recall or high false-positives when trained on uncurated mixed data.
- **Fix**: Trained baseline Isolation Forest on verified normal traffic from the train split (`is_attack=0`). In online detection, anomalous windows are flagged without polluting rolling baseline statistics.
- **Resolved**: Yes.

### Issue: Sequential BIN score false-trigger on normal traffic
- **Symptom**: In `_sequential_bin_score`, repeated transactions with the same popular card BIN produced differences of `0 <= d <= 5`, falsely giving normal traffic a ~0.65 sequential score.
- **Fix**: Checked for sequential increments across *distinct* unique BINs (`1 <= d <= 3`, `unique_bins >= 4`), returning 0.0 for normal repeated BINs and ~1.0 for sequential enumeration attacks.
- **Resolved**: Yes.

### Issue: Windows console Unicode encoding (cp1252)
- **Symptom**: Unicode symbols (`\u2500`, `₹`, checkmarks) caused `UnicodeEncodeError` on Windows default codepages.
- **Fix**: Replaced with clean ASCII formatting (`INR`, `[OK]`, `[ALERT]`, `-`).
- **Resolved**: Yes.

---

## Held-Out Test Evaluation Results (Final)

- **Test Windows**: 142 windows (5-minute sliding window, 1-minute step)
- **True Positives (TP)**: 28
- **False Positives (FP)**: 7
- **False Negatives (FN)**: 2
- **True Negatives (TN)**: 105
- **Precision**: 80.0%
- **Recall**: 93.3%
- **F1 Score**: 0.8615
- **₹ False-Positive Cost**: INR 1,400.00 (7 FP events × INR 200 / 15-min risk review)
- **Test Suite**: 39/39 passing (`pytest tests/ -v`)

---

*Kept live throughout build. Pull straight from here for the "What Broke & Fixed" demo slide.*
