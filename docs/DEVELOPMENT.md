# Development

## Local tests

Install dev dependencies and run parser/fixture tests (no network, no root):

```bash
pip install -r requirements-dev.txt
PYTHONPATH=bin pytest tests/ -q
```

Tests cover ffuf/webtech JSON parsers, findings schema, manifest resume logic, and nmap service import.

## Scan presets

Presets live under `conf/presets/`. Load at scan time:

```bash
sudo kitelon-cli -c 'scan -t example.com -w demo --preset stealth'
sudo kitelon -t example.com -w demo --preset web
```

## Engine toggles

See `examples/kitelon.conf` for `ENABLE_FFUF`, `ENABLE_WEBTECH`, `ENABLE_GOWITNESS`, `ENABLE_NAABU`, `ENABLE_DNSX`, `ENABLE_KATANA`, `ENABLE_TLSX`, and SMB/SSH passes.
