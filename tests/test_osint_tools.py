"""OSINT / recon tool helpers (0.3.5)."""

from pathlib import Path

from kitelon_engine.config import _config_from_merged, load_preset
from kitelon_engine.context import ScanContext
from kitelon_engine.tools import dnsrecon, gau, shodan


def test_config_conservative_defaults(tmp_path: Path):
    merged = {
        "INSTALL_DIR": str(tmp_path),
        "PLUGINS_DIR": str(tmp_path / "plugins"),
        "WORDLIST_DIR": str(tmp_path / "wordlists"),
    }
    cfg = _config_from_merged(merged, tmp_path)
    assert cfg["enable_metagoofil"] is False
    assert cfg["enable_dnsrecon"] is True
    assert cfg["shodan_max_results"] == 25
    assert cfg["gau_max_urls"] == 500
    assert cfg["dnsrecon_axfr"] is False
    assert cfg["censys_mode"] == "hosts"


def test_osint_deep_preset(tmp_path: Path):
    conf_dir = tmp_path / "conf" / "presets"
    conf_dir.mkdir(parents=True)
    (tmp_path / "kitelon.conf").write_text(
        'INSTALL_DIR="{install}"\nPLUGINS_DIR="{install}/plugins"\nWORDLIST_DIR="{install}/wordlists"\n'.format(
            install=tmp_path
        ),
        encoding="utf-8",
    )
    (conf_dir / "osint-deep.conf").write_text(
        "\n".join(
            [
                f'source {tmp_path / "kitelon.conf"}',
                'ENABLE_METAGOOFILE="1"',
                'GAU_MAX_URLS="5000"',
                'DNSRECON_AXFR="1"',
            ]
        ),
        encoding="utf-8",
    )
    overrides = load_preset(tmp_path, "osint-deep")
    assert overrides["enable_metagoofil"] is True
    assert overrides["gau_max_urls"] == 5000
    assert overrides["dnsrecon_axfr"] is True


def test_dnsrecon_types():
    assert "axfr" not in dnsrecon.dnsrecon_types(False)
    assert "axfr" in dnsrecon.dnsrecon_types(True)
    assert "std" in dnsrecon.dnsrecon_types(False)


def test_dnsrecon_args():
    args = dnsrecon.build_dnsrecon_args("/usr/bin/dnsrecon", "example.com", Path("/tmp/out.json"), axfr=True)
    assert args[0] == "/usr/bin/dnsrecon"
    assert "-t" in args
    assert "axfr" in args[args.index("-t") + 1]


def test_gau_args():
    args = gau.build_gau_args("/usr/local/bin/gau", "example.com", providers="wayback", include_subs=True)
    assert args[:2] == ["/usr/local/bin/gau", "--providers"]
    assert "wayback" in args
    assert "--subs" in args
    assert args[-1] == "example.com"


def test_gau_max_urls_cap(tmp_path: Path):
    out = tmp_path / "urls.txt"
    text = "\n".join(f"http://example.com/{i}" for i in range(20))
    count = gau._write_capped_lines(text, out, 5)
    assert count == 5
    assert len(out.read_text(encoding="utf-8").strip().splitlines()) == 5


def test_shodan_skips_without_key(tmp_path: Path):
    ctx = ScanContext(
        install_dir=tmp_path,
        target="example.com",
        mode="osint",
        workspace="lab",
        options={"enable_shodan": True, "shodan_api_key": ""},
    )
    out = tmp_path / "shodan.json"
    assert shodan.run_shodan(ctx, "example.com", out) is False
    assert not out.exists()
