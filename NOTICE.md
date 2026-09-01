# Notice

Kitelon is open-source security automation software (MIT License).

## Intended use

Kitelon is provided for **educational purposes** and **authorized security testing only**. You must have explicit permission before scanning any target you do not own. See [docs/LEGAL.md](docs/LEGAL.md).

## Scan engine

The Python scan engine lives under `bin/kitelon_engine/` and is invoked by `bin/kitelon_scan.py`. The `kitelon` bash driver and `kitelon-cli` REPL provide operator entry points. An authorized-use acknowledgement step runs before scan workloads unless policy is set in the environment.

## Third-party components

Kitelon orchestrates third-party security tools installed at runtime by `install.sh`. Each tool retains its own license. Plugin repositories cloned during installation are listed in [docs/TOOLS.md](docs/TOOLS.md).

Wordlists are fetched from [SecLists](https://github.com/danielmiessler/SecLists) during install when network access is available.

## Legal use

Only scan targets you are authorized to test. You are responsible for compliance with applicable laws and engagement rules. Authors and contributors disclaim liability for misuse; see [LICENSE.md](LICENSE.md).
