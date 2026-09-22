"""A clean sample project file without any credentials."""


def get_greeting(name: str) -> str:
    port = 8080
    host = "127.0.0.1"
    return f"Hello {name} on {host}:{port}"
