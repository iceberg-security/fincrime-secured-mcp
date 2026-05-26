"""LLM-judge interface for the grounding + reasoning scorers (US-028).

A :class:`Judge` is anything callable shaped like
``judge(system: str, user: str) -> JudgeResponse``. Production
implementations call the Anthropic API with prompt caching on the
``system`` prompt (which carries the static rubric); test
implementations inject a deterministic fake so the suite never hits
the network.

Why a Protocol (PEP 544) rather than a direct SDK call:

- The PRD pins LLM-judge scorers as a load-bearing piece of the eval
  loop (US-028). Coupling each scorer to ``anthropic.Anthropic`` would
  require every test to set ``ANTHROPIC_API_KEY`` or skip — both bad
  patterns for the launch-blocker eval gate that US-030 wires into CI.
- Prompt caching is an API-level detail. The Protocol pushes that
  detail into the Anthropic-backed implementation so the scorer code
  only knows about ``(system, user) -> response``.
- Future judges (a local model for offline runs, an OpenAI judge, a
  cached-result replayer) drop in by satisfying the same Protocol.

The PRD specifies prompt caching on the rubric. The Anthropic API
caches a ``system`` block when its ``cache_control`` is set to
``{"type": "ephemeral"}`` — see the Anthropic docs for prompt caching.
We keep the rubric in the ``system`` channel exclusively so the cache
is hit on every subsequent call within the 5-minute TTL window.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:  # pragma: no cover - import guard for the optional SDK
    from anthropic import Anthropic

__all__ = [
    "DEFAULT_MODEL",
    "AnthropicJudge",
    "Judge",
    "JudgeResponse",
]

# The PRD pins Opus 4.7 as the default judge (US-033 ADR + the launch
# blog draft). Stay on the 1M-context variant so the rubric + report +
# audit-log slice fit in one round trip even on the busy datasets.
DEFAULT_MODEL = "claude-opus-4-7"


@dataclass(frozen=True, slots=True)
class JudgeResponse:
    """One round-trip response from an LLM judge.

    The grounding + reasoning scorers parse ``text`` as JSON. The raw
    string is preserved so the scorer's ``details`` can carry it for
    human debugging when JSON parsing fails.
    """

    text: str
    raw: dict[str, Any] | None = None


@runtime_checkable
class Judge(Protocol):
    """Anything callable with ``judge(system, user) -> JudgeResponse``.

    Implementations:

    - :class:`AnthropicJudge` — production, talks to the Anthropic API
      with prompt caching on ``system``.
    - Test fakes — see ``tests/test_scorers_llm.py``. The Protocol
      makes any callable with the right shape a valid Judge.
    """

    def __call__(self, *, system: str, user: str) -> JudgeResponse: ...


# --------------------------------------------------------------------------- #
# Production: Anthropic-backed judge with prompt caching
# --------------------------------------------------------------------------- #


class AnthropicJudge:
    """Production :class:`Judge` backed by the Anthropic Messages API.

    The constructor lazily imports ``anthropic`` so the rest of the
    eval harness keeps working when the SDK isn't installed (tests
    inject a fake judge). The first ``__call__`` per system prompt
    primes the prompt cache; every subsequent call within the
    5-minute TTL window reads the cache and pays only for the user
    prompt.

    Parameters
    ----------
    client:
        Optional preconstructed Anthropic client. If omitted, the
        constructor builds one with the SDK defaults; the API key is
        read from ``ANTHROPIC_API_KEY`` per the SDK contract.
    model:
        Model id. Defaults to :data:`DEFAULT_MODEL`.
    max_tokens:
        Cap on the response length. Default 1024 — judges return JSON,
        not prose.
    """

    def __init__(
        self,
        *,
        client: Anthropic | None = None,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 1024,
    ) -> None:
        if client is None:
            try:
                from anthropic import Anthropic as _Anthropic
            except ImportError as exc:  # pragma: no cover - import-time
                raise RuntimeError(
                    "anthropic SDK not installed; add `anthropic` to your "
                    "deps or inject a Judge fake."
                ) from exc
            client = _Anthropic()
        self._client = client
        self._model = model
        self._max_tokens = max_tokens

    def __call__(self, *, system: str, user: str) -> JudgeResponse:
        response = self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=[
                {
                    "type": "text",
                    "text": system,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user}],
        )
        # The SDK's content blocks are a list of objects; we only care
        # about the text blocks. Concatenate so a model that emits
        # multiple blocks still produces one parseable string.
        parts: list[str] = []
        for block in getattr(response, "content", []) or []:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                parts.append(text)
        return JudgeResponse(
            text="".join(parts),
            raw={"model": getattr(response, "model", self._model)},
        )


def _default_judge_from_env() -> Judge | None:
    """Build the production judge IF an API key is present in env.

    Returns ``None`` otherwise so callers fall back to a fake during
    tests / offline CI. Centralizes the env-driven boot so each scorer
    doesn't have to do it.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return None
    try:
        return AnthropicJudge()
    except RuntimeError:  # pragma: no cover - SDK missing in CI
        return None
