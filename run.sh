#!/usr/bin/env bash
# Razorpay AI Risk Manager — Unix one-command launcher
# Usage: ./run.sh [--mode attack|bin|both|normal] [--kill-llm] [--test-only] [--eval-only]

set -e

MODE="both"
KILL_LLM=false
TEST_ONLY=false
EVAL_ONLY=false

for arg in "$@"; do
  case $arg in
    --mode=*) MODE="${arg#*=}" ;;
    --kill-llm) KILL_LLM=true ;;
    --test-only) TEST_ONLY=true ;;
    --eval-only) EVAL_ONLY=true ;;
  esac
done

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║     Razorpay AI Risk Manager — Starting Up          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Load .env
if [ ! -f .env ]; then
  cp .env.example .env
  echo "[setup] Created .env. Set OPENAI_API_KEY before running."
fi
export $(grep -v '^#' .env | xargs)

if [ "$KILL_LLM" = true ]; then
  export FORCE_LLM_TIMEOUT=true
  echo "[demo] FORCE_LLM_TIMEOUT=true — fallback will fire."
fi

if [ "$TEST_ONLY" = true ]; then
  pytest tests/ -v --tb=short
  exit $?
fi

if [ "$EVAL_ONLY" = true ]; then
  python -m evaluation.evaluate
  exit $?
fi

echo "[1/4] Seeding database..."
python -m data.seed_db

echo "[2/4] Starting FastAPI server (port 8000)..."
python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 &
SERVER_PID=$!

# Wait for server
for i in $(seq 1 20); do
  sleep 2
  if curl -sf http://localhost:8000/health > /dev/null 2>&1; then
    echo "[2/4] Server ready ✓"
    break
  fi
  if [ $i -eq 20 ]; then
    echo "[ERROR] Server did not start. Check logs."
    kill $SERVER_PID 2>/dev/null
    exit 1
  fi
done

echo "[3/4] Running transaction stream (mode=$MODE)..."
if [ "$KILL_LLM" = true ]; then
  python -m api.simulator --mode "$MODE" --kill-llm
else
  python -m api.simulator --mode "$MODE"
fi

echo ""
echo "[4/4] Running held-out evaluation..."
python -m evaluation.evaluate

echo ""
echo "✓ Done. Server still running on http://localhost:8000"
echo "  Dashboard: python -m dashboard.cli"
echo "  Audit log: http://localhost:8000/audit"
echo "  Stop:      kill $SERVER_PID"
