# Development

## Local tests

Install dev dependencies and run parser/fixture tests (no network, no root):

```bash
pip install -r requirements-dev.txt
PYTHONPATH=bin pytest tests/ -q
```

Tests cover ffuf/webtech JSON parsers, findings schema, manifest resume logic, and nmap service import.

## CI

GitHub Actions workflows on every push and pull request to `main`:

- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — **test** (`pytest tests/`)
- [`.github/workflows/vet.yml`](../.github/workflows/vet.yml) — **vet** ([SafeDep vet](https://github.com/safedep/vet/releases) dependency scan; PRs scan changed manifests)
- [`.github/workflows/malware-scan.yml`](../.github/workflows/malware-scan.yml) — **clamav** ([ClamAV](https://www.clamav.net/) file scan on the Ubuntu runner; definitions cached between runs)

To require all three before merging to `main`, enable branch protection on GitHub: **Settings → Branches → Branch protection rules → `main` → Require status checks** and select `test`, `vet`, and `clamav`.

Local ClamAV scan (optional):

```bash
sudo apt install clamav
sudo freshclam
clamscan -r --infected --remove=no --exclude-dir='^\.git' --exclude-dir='^\.venv' .
```

Local vet scan (optional):

```bash
curl -fsSL https://github.com/safedep/vet/releases/download/v1.19.0/vet_Linux_x86_64.tar.gz | tar xz
./vet scan -D .
```

## Scan presets

Presets live under `conf/presets/`. Load at scan time:

```bash
sudo kitelon-cli -c 'scan -t example.com -w demo -pr stealth'
sudo kitelon -t example.com -w demo --preset web
sudo kitelon -t example.com -w demo -o -re --preset osint-deep
```

Presets include `osint-conservative` (default limits) and `osint-deep` (raised OSINT/recon caps).

## Engine toggles

See `examples/kitelon.conf` for `ENABLE_FFUF`, `ENABLE_WEBTECH`, `ENABLE_GOWITNESS`, `ENABLE_NAABU`, `ENABLE_DNSX`, `ENABLE_KATANA`, `ENABLE_TLSX`, and SMB/SSH passes.

## Plugins and modularity

- Vocabulary: [GLOSSARY.md](GLOSSARY.md)
- Architecture: [MODULARITY.md](MODULARITY.md)
- Inventory: [PLUGINS.md](PLUGINS.md)

**Add a plugin:** wrapper in `bin/kitelon_engine/tools/`, `ENABLE_*` in config, entry in `conf/plugins/registry.json`, pipeline hook (see `pipeline_hooks/recon.py` for pattern).

**Ship a pack:** JSON under `conf/packs/<plugin>/`, load with `pack_loader.load_pack()`, reference in registry `packs` list.

Run registry/pack tests:

```bash
PYTHONPATH=bin pytest tests/test_plugin_registry.py tests/test_pack_loader.py -q
```
