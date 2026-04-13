from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from .schemas import LLMConfig


class LLMClient(Protocol):
    def complete(self, *, system: str, user: str) -> str:
        ...


@dataclass(slots=True)
class NullLLMClient:
    reason: str = "LLM disabled"

    def complete(self, *, system: str, user: str) -> str:
        raise RuntimeError(self.reason)


@dataclass(slots=True)
class OpenAICompatibleClient:
    config: LLMConfig

    def complete(self, *, system: str, user: str) -> str:
        api_key = os.environ.get(self.config.api_key_env)
        if not api_key:
            raise RuntimeError(
                f"Missing API key environment variable: {self.config.api_key_env}"
            )

        url = self.config.base_url.rstrip("/") + "/chat/completions"
        payload = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"LLM HTTP error {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"LLM request failed: {exc}") from exc

        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(f"Unexpected LLM response: {data}") from exc


def build_llm_client(config: LLMConfig) -> LLMClient:
    if not config.enabled:
        return NullLLMClient()
    if config.provider != "openai_compatible":
        raise ValueError(f"Unsupported LLM provider: {config.provider}")
    return OpenAICompatibleClient(config=config)
