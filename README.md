# 🛡️ Razorpay Aegis — Autonomous Two-Tier Fraud Defense Engine

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Tests](https://img.shields.io/badge/Tests-39%2F39%20Passing-brightgreen.svg)]()
[![Precision](https://img.shields.io/badge/Precision-100%25%20(Stream)-success.svg)]()
[![Recall](https://img.shields.io/badge/Recall-93.3%25%20(Held--out)-blue.svg)]()

> **Razorpay Aegis** is an enterprise-grade, two-tier autonomous risk detection engine designed to catch coordinated card-testing micro-bursts and sequential BIN enumeration attacks in real-time with **< 1ms gateway latency**, **zero single-point-of-failure**, and **₹0.00 operational false-positive cost**.

---

## 🚀 The Core Problem: The False-Positive Paradox

In modern payment gateways processing lakhs of transactions per minute:
1. **Traditional Rule Engines** are fast, but opaque. They generate thousands of false alarms on legitimate flash sales, costing merchants lost GMV and **₹50+ Lakhs/month in human analyst review costs** (15 min @ ₹800/hr = ₹200 per investigation).
2. **Naive AI Gateways** that call an LLM on every transaction introduce **1,500ms checkout latency** and cost **₹200+ Crore/month** in API compute.

### The Aegis Solution: Two-Tier Hybrid Funnel

```
               100,000+ Transactions / Minute
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │  TIER 1: In-Memory Statistical ML Engine               │
  │  • Welford Online Variance + Isolation Forest          │
  │  • Sub-millisecond latency (< 0.8ms) | Marginal Cost: ₹0│
  │  • Automatically filters 99.9% of normal traffic       │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼ (Only ~0.1% flagged as unusual)
                  ~100 Incident Windows / Day
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │  TIER 2: Asynchronous Cognitive LLM Layer              │
  │  • Groq LPU (GPT-OSS 120B / Llama 3.3 70B) or Gemini   │
  │  • Asynchronous (Zero impact on checkout latency)      │
  │  • Distinguishes real attacks from flash sales         │
  │  • Plain-English incident reports + Action recommendations│
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │  Gated Action Layer & Append-Only Audit Trail (SQLite) │
  │  • Zero write-access to blocklists (Defense-in-depth)  │
  │  • Automatic Deterministic Fallback on API timeout     │
  └────────────────────────────────────────────────────────┘
```

---

## 📊 Benchmark & Evaluation Results

Evaluated against an 8-hour held-out test dataset (942 transactions across 142 rolling sliding windows):

| Metric | Result | Benchmark Target | Status |
|---|---|---|---|
| **Attack Recall** | **93.3%** (28/30 attack windows) | > 85.0% | ✅ Exceeded |
| **Precision** | **80.0%** (Held-out) / **100%** (Stream) | > 75.0% | ✅ Exceeded |
| **F1 Score** | **0.8615** | > 0.8000 | ✅ Exceeded |
| **Gateway Latency** | **< 0.8 ms** (Tier-1 in-memory) | < 10 ms | ✅ Real-time |
| **False-Positive Review Cost** | **INR 1,400.00** (₹0.00 on live stream) | Minimize | ✅ Optimized |
| **Test Suite Coverage** | **39 / 39 Unit & Pipeline Tests Passing** | 100% | ✅ 100% Passed |

---

## 🖥️ Live Dashboards

### 1. Interactive Web Dashboard (`/dashboard`)
Open `http://localhost:8000/dashboard` for a modern, dark-themed real-time visual interface:
- **Live Attack Feed**: Displays real-time incident cards with confidence, attack signature, trigger features, and full AI diagnosis.
- **Dynamic Engine Pill**: Shows active reasoning provider (`Groq LPU 120B` / `Google Gemini`).
- **Live Ingestion Ticker**: Real-time stream of incoming payments.
- **Key Metrics Panel**: Live TP, FP, Precision, and ₹ FP Cost.

### 2. High-Performance Terminal CLI Monitor
```powershell
# Live interactive dashboard
python -m dashboard.cli

# Continuous incident log stream
python -m dashboard.cli --stream
```

---

## 🛠️ Quickstart & Setup

### 1. Clone & Install Dependencies
```bash
git clone https://github.com/vatsalgargg/Razorpay-Aegis.git
cd Razorpay-Aegis
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy `.env.example` to `.env` and add your free API key:
```bash
cp .env.example .env
```
Inside `.env`:
```env
# Groq Cloud Key (Free: 14,400 requests/day from https://console.groq.com/keys)
GROQ_API_KEY=gsk_your_key_here
GROQ_MODEL=openai/gpt-oss-120b

# Google Gemini Key (Fallback / Alternative from https://aistudio.google.com)
GEMINI_API_KEY=your_gemini_key_here
GEMINI_MODEL=gemini-1.5-flash
```

### 3. Run the Complete System
```powershell
# Windows One-Command Launcher (Seeds DB, starts server, runs evaluation)
.\run.ps1
```

Or manually:
```bash
# Terminal 1: Start API Server
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Open Web UI or CLI Dashboard
# Navigate to http://localhost:8000/dashboard
python -m dashboard.cli

# Terminal 3: Replay Transaction Stream Simulation
python -m api.simulator --mode both --speed 30
```

---

## 🧪 Testing & Verification

Run the full 39-test test suite:
```bash
python -m pytest tests/ -v
```

Run held-out test evaluation:
```bash
python -m evaluation.evaluate
```

---

## 🔒 Enterprise Safety & Compliance

1. **Gated Action Layer**: The AI layer **never** has direct write access to blocklists, merchant configurations, or card registers. It writes structured recommendations to an immutable append-only audit trail for human risk ops.
2. **Deterministic Heuristic Fallback**: If an LLM API experiences rate limits, network timeouts, or cloud outages, the gateway seamlessly shifts to deterministic statistical rules with zero downtime.
3. **Data Protection**: Card numbers are never stored in plain text. Only truncated BINs (6 digits) and last-4 are evaluated.

---

## 📄 License
MIT License. Built for Razorpay Risk Engineering & Hackathon Track.
