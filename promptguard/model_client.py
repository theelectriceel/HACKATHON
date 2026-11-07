"""ChatGPT-authenticated Codex CLI adapter; no API-key fallback."""
from .codex_client import MODEL, BACKEND, ModelError, complete, authentication_status
