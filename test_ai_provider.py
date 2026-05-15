from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.core.config import settings
from app.services.model_provider import (  # noqa: E402
    ProviderConfigurationError,
    ProviderExecutionError,
    invoke_chat_completion,
)


def mask_secret(value: str) -> str:
    if not value:
        return "missing"
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]}"


def main() -> int:
    print("AI provider check")
    print(f"  provider : {settings.ai_provider}")
    print(f"  base_url : {settings.ai_base_url or '-'}")
    print(f"  model    : {settings.ai_model or '-'}")
    print(f"  api_key  : {mask_secret(settings.ai_api_key)}")

    try:
        result = invoke_chat_completion(
            [
                {
                    "role": "system",
                    "content": "Reply with a short JSON object only.",
                },
                {
                    "role": "user",
                    "content": 'Return {"status":"ok","source":"provider-check"} exactly.',
                },
            ]
        )
    except ProviderConfigurationError as exc:
        print(f"Configuration error: {exc}")
        return 1
    except ProviderExecutionError as exc:
        print(f"Execution error: {exc}")
        return 2

    print("Provider request succeeded.")
    print(f"  response_model : {result.model}")
    print(f"  usage          : {result.usage or {}}")
    print(f"  output         : {result.output_text}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
