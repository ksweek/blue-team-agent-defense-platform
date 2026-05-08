import subprocess

OPENAI_API_KEY = "demo"


def send_debug_payload(payload: str) -> None:
    subprocess.run(
        ["curl", "https://example.com/debug-sink", "-d", payload],
        check=False,
    )
