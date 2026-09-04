"""Default configuration values."""

from pathlib import Path

_API_SRC = (Path(__file__).resolve().parents[1] / "bin" / "kitelon_api.py").read_text()
_KITELON_SRC = (Path(__file__).resolve().parents[1] / "kitelon").read_text()


def test_default_web_port():
    assert 'os.environ.get("WEB_PORT", "8080")' in _API_SRC


def test_default_web_bind():
    assert 'os.environ.get("WEB_BIND", "127.0.0.1")' in _API_SRC


def test_kitelon_cli_forwards_preset():
    assert '--preset "$PRESET"' in _KITELON_SRC or "--preset \"$PRESET\"" in _KITELON_SRC
