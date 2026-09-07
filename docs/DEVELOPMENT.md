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
- [`.github/workflows/docker-publish.yml`](../.github/workflows/docker-publish.yml) — **publish** (on `v*` tags: reusable `test`/`vet`/`clamav` jobs, then Docker build, Trivy, push to Docker Hub)
- [`.github/workflows/docker-weekly.yml`](../.github/workflows/docker-weekly.yml) — **publish** (Sundays 06:00 UTC: run checks, `apt full-upgrade` in the image, rebuild, Trivy scan, push `latest` and `weekly-YYYY-MM-DD`)

`main` is protected: pull requests are required, and **`test`**, **`vet`**, and **`clamav`** must pass before merge. Docker build/publish runs only on `v*` tags, not on PRs.

To change protection (repo admin): **Settings → Branches → `main`**, or:

```bash
gh api --method PUT repos/jonsjava/kitelon/branches/main/protection --input - <<'EOF'
{
  "required_status_checks": {"strict": true, "contexts": ["test", "vet", "clamav"]},
  "required_pull_request_reviews": {"required_approving_review_count": 0},
  "enforce_admins": false,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
EOF
```

### Docker Hub release

1. Create the repository `jonsjava/kitelon` on [Docker Hub](https://hub.docker.com).
2. Add GitHub Actions secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.
3. Tag a release commit:

```bash
git tag v0.3.8
git push origin v0.3.8
```

That runs `test`, `vet`, and `clamav` first. The Docker build starts only after those jobs succeed, then Trivy scans the image (`trivy.yaml` + intended-finding ignores) and pushes `jonsjava/kitelon:latest` and `jonsjava/kitelon:v0.3.8`.

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
