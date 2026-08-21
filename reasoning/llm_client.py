"""
LLM reasoning layer — Google Gemini via google-genai SDK.

Only called AFTER the statistical layer has already flagged a window.
Job: classification + explanation. Never detection alone.
Never has write access.

Raises LLMUnavailableError on timeout, network failure, or malformed JSON → fallback.py takes over.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any
from dotenv import load_dotenv

load_dotenv()

from google import genai
from google.genai import types

from data.schemas import AnomalyResult, AttackType, Classification, RecommendedAction
from reasoning.prompts import build_system_prompt, build_user_prompt

logger = logging.getLogger(__name__)

LLM_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "8"))
GEMINI_MODEL        = os.getenv("GEMINI_MODEL", os.getenv("LLM_MODEL", "gemini-2.5-flash"))
FORCE_LLM_TIMEOUT   = os.getenv("FORCE_LLM_TIMEOUT", "false").lower() == "true"


class LLMUnavailableError(Exception):
    """Raised when LLM is unreachable, times out, or returns malformed output."""


# ---------------------------------------------------------------------------
# JSON schema expected from LLM
# ---------------------------------------------------------------------------

EXPECTED_KEYS = {"attack_type", "confidence", "explanation", "recommended_action"}
VALID_ATTACK_TYPES = {e.value for e in AttackType}
VALID_ACTIONS      = {e.value for e in RecommendedAction}


def _validate_llm_response(data: dict[str, Any]) -> None:
    missing = EXPECTED_KEYS - set(data.keys())
    if missing:
        raise ValueError(f"LLM response missing keys: {missing}")
    if data["attack_type"] not in VALID_ATTACK_TYPES:
        raise ValueError(f"Invalid attack_type: {data['attack_type']}")
    if data["recommended_action"] not in VALID_ACTIONS:
        raise ValueError(f"Invalid recommended_action: {data['recommended_action']}")
    conf = data.get("confidence", -1)
    if not (0.0 <= float(conf) <= 1.0):
        raise ValueError(f"confidence out of range: {conf}")


# ---------------------------------------------------------------------------
# LLM Reasoning Client (Groq + Gemini Multi-Provider)
# ---------------------------------------------------------------------------

class LLMReasoningClient:
    def __init__(self) -> None:
        self._groq_key = os.getenv("GROQ_API_KEY")
        self._gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")

        self._groq_client = None
        self._gemini_client = None

        if self._groq_key and self._groq_key != "your-groq-api-key-here":
            try:
                from groq import Groq
                self._groq_client = Groq(api_key=self._groq_key)
                logger.info("[llm] Initialized Groq Cloud client.")
            except Exception as e:
                logger.warning(f"[llm] Failed to initialize Groq client: {e}")

        if self._gemini_key and self._gemini_key != "your-gemini-api-key-here":
            try:
                self._gemini_client = genai.Client(api_key=self._gemini_key)
                logger.info("[llm] Initialized Gemini client.")
            except Exception as e:
                logger.warning(f"[llm] Failed to initialize Gemini client: {e}")

        if not self._groq_client and not self._gemini_client:
            logger.warning("[llm] No LLM API key set — system will use deterministic heuristic fallback.")

    def classify(self, anomaly: AnomalyResult) -> Classification:
        """
        Classify the flagged anomaly window using Groq or Gemini.
        Raises LLMUnavailableError if the call fails for any reason.
        """
        if FORCE_LLM_TIMEOUT:
            raise LLMUnavailableError("LLM timeout forced via FORCE_LLM_TIMEOUT env var.")

        system_prompt = build_system_prompt()
        user_prompt   = build_user_prompt(anomaly)

        # 1. Try Groq Cloud first if configured (Blazing fast & high quota)
        if self._groq_client:
            try:
                t0 = time.monotonic()
                groq_model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
                chat_completion = self._groq_client.chat.completions.create(
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    model=groq_model,
                    response_format={"type": "json_object"},
                    temperature=0.1,
                    max_tokens=1024,
                    timeout=LLM_TIMEOUT_SECONDS,
                )
                elapsed = time.monotonic() - t0
                raw = chat_completion.choices[0].message.content or ""
                logger.info(f"[llm] Groq response received in {elapsed:.2f}s using {groq_model}")

                data = self._parse_json(raw)
                _validate_llm_response(data)

                return Classification(
                    attack_type=AttackType(data["attack_type"]),
                    confidence=float(data["confidence"]),
                    explanation=str(data["explanation"]),
                    recommended_action=RecommendedAction(data["recommended_action"]),
                    llm_used=True,
                    llm_provider="Groq (120B)",
                )
            except Exception as e:
                logger.warning(f"[llm] Groq call failed ({e}) — trying Gemini or fallback.")
                if not self._gemini_client:
                    raise LLMUnavailableError(f"Groq API error: {e}") from e

        # 2. Try Gemini
        if self._gemini_client:
            try:
                t0 = time.monotonic()
                gemini_model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")
                response = self._gemini_client.models.generate_content(
                    model=gemini_model,
                    contents=user_prompt,
                    config=types.GenerateContentConfig(
                        system_instruction=system_prompt,
                        response_mime_type="application/json",
                        temperature=0.1,
                        max_output_tokens=2048,
                    ),
                )
                elapsed = time.monotonic() - t0
                logger.info(f"[llm] Gemini response received in {elapsed:.2f}s using {gemini_model}")

                raw = response.text or ""
                data = self._parse_json(raw)
                _validate_llm_response(data)

                return Classification(
                    attack_type=AttackType(data["attack_type"]),
                    confidence=float(data["confidence"]),
                    explanation=str(data["explanation"]),
                    recommended_action=RecommendedAction(data["recommended_action"]),
                    llm_used=True,
                    llm_provider="Google Gemini",
                )
            except Exception as e:
                raise LLMUnavailableError(f"Gemini API error: {e}") from e

        raise LLMUnavailableError("No LLM client available (set GROQ_API_KEY or GEMINI_API_KEY).")

    @staticmethod
    def _parse_json(raw: str) -> dict[str, Any]:
        cleaned = raw.strip()
        if "```json" in cleaned:
            cleaned = cleaned.split("```json", 1)[1].split("```", 1)[0].strip()
        elif "```" in cleaned:
            cleaned = cleaned.split("```", 1)[1].split("```", 1)[0].strip()
        data = json.loads(cleaned)
        # Normalize all special unicode characters to clean ASCII
        if "explanation" in data and isinstance(data["explanation"], str):
            expl = data["explanation"]
            # Replace dashes / hyphens
            for dash in ("\u2010", "\u2011", "\u2012", "\u2013", "\u2014", "\u2015"):
                expl = expl.replace(dash, "-")
            # Replace quotes
            for q in ("\u2018", "\u2019", "\u201a", "\u201b"):
                expl = expl.replace(q, "'")
            for q in ("\u201c", "\u201d", "\u201e", "\u201f"):
                expl = expl.replace(q, '"')
            # Replace spaces & symbols
            expl = expl.replace("\u202f", " ").replace("\u00a0", " ").replace("\u200b", "")
            expl = expl.replace("\u20b9", "INR ")
            data["explanation"] = expl.encode("ascii", "replace").decode("ascii")
        return data
