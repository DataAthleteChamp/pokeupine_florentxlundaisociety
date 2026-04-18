"""LLM gateway with diskcache memoization."""

from __future__ import annotations

import hashlib

from pokeupine.config import LLM_CACHE_DIR


def _get_cache():
    """Lazy-init diskcache."""
    import diskcache
    LLM_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return diskcache.Cache(str(LLM_CACHE_DIR))


def llm_complete(prompt: str, model: str = "gpt-4o-mini", temperature: float = 0) -> str:
    """Call an LLM with diskcache memoization.

    Args:
        prompt: The prompt to send
        model: The model to use
        temperature: Sampling temperature

    Returns:
        The LLM response text
    """
    cache = _get_cache()
    key = hashlib.sha256(f"{model}:{temperature}:{prompt}".encode()).hexdigest()

    cached = cache.get(key)
    if cached is not None:
        return cached

    import litellm

    response = litellm.completion(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=temperature,
    )
    result = response.choices[0].message.content
    cache.set(key, result, expire=86400 * 30)  # 30-day TTL
    return result
