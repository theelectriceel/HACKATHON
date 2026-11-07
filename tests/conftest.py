"""Keep test databases in the authorized workspace; no recursive cleanup."""
import uuid
from pathlib import Path
import pytest


@pytest.fixture
def tmp_path():
    path = Path(__file__).resolve().parents[1] / "artifacts" / "test-temp" / uuid.uuid4().hex
    path.mkdir(parents=True)
    return path
