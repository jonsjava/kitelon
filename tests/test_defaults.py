"""Default configuration values."""

from pathlib import Path

_API_SRC = (Path(__file__).resolve().parents[1] / "bin" / "kitelon_api.py").read_text()


def test_default_web_port():
    assert 'os.environ.get("WEB_PORT", "8080")' in _API_SRC


def test_default_web_bind():
    assert 'os.environ.get("WEB_BIND", "127.0.0.1")' in _API_SRC
