# Kitelon security notes

Kitelon runs offensive tooling on operator-supplied targets. Root CLI access, raw sockets, Metasploit aux modules (`ENABLE_METASPLOIT`), and Docker `NET_RAW`/`NET_ADMIN` on the scan worker are intentional when authorized.

## Web API

- `WEB_API_KEY` is required on all binds; generated on first start if unset (`/root/.kitelon_api_keys.conf`).
- Pass `X-API-Key` on every JSON route.
- Job scan args are allowlisted via `SCAN_OPTIONS` in `bin/kitelon_scan_config.py`, not raw CLI passthrough.

## Supply chain

- Go tarball SHA256 checked against [go.dev](https://go.dev/dl/) at install time.
- Go tools pinned in `conf/go-tool-versions.conf`.
- testssl.sh installed from git; restore never uses raw URL fallback.
- SecLists and vulners NSE fetched from known GitHub URLs during install.

Review `install.sh` before air-gapped deployments.

## Data and permissions

- Loot and findings stay on the host (filesystem + PostgreSQL).
- API keys are local only; the engine does not send them to third parties.
- Web UI calls same-origin `/api/v1` only.
- `bin/permissions.sh` sets loot dirs `700`, files `600`.

Report auth bypass, path traversal, or unintended exfil privately to the maintainer.
