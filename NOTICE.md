# Notice

Kitelon is open-source security automation software (MIT License).

## Independence

Kitelon is **not** Sn1per, not a fork of Sn1per, and not a substitute for
Sn1per Professional or any other commercial scanner platform. README.md
explains the motivation: a maintained, self-hostable orchestrator for
authorized testing and learning when a paid product is not available.

Similarity in workflow (workspace loot, scan modes, bundled third-party tools)
reflects a common product category, not copied Sn1per source code. README.md
describes the public Sn1per CE repo as infrequently updated compared to Sn1per
Professional; Kitelon does not claim Sn1per is abandoned.

## Authorship

I'm a DevOps engineer. I built Kitelon with substantial help from AI coding
tools. It is a personal hobby project, not professional front-end or product
work; README.md explains the rationale in more detail.

## Intended use

Kitelon is provided for **educational purposes** and **authorized security testing only**. You must have explicit permission before scanning any target you do not own. See [docs/LEGAL.md](docs/LEGAL.md).

## Scan engine

The Python scan engine lives under `bin/kitelon_engine/` and is invoked by `bin/kitelon_scan.py`. The `kitelon` bash driver and `kitelon-cli` REPL provide operator entry points. An authorized-use acknowledgement step runs before scan workloads unless policy is set in the environment.

## Third-party components

Kitelon orchestrates third-party security tools installed at runtime by `install.sh`. Each tool retains its own license. Plugin repositories cloned during installation are listed in [docs/TOOLS.md](docs/TOOLS.md).

Wordlists are fetched from [SecLists](https://github.com/danielmiessler/SecLists) during install when network access is available.

## Legal use

Only scan targets you are authorized to test. You are responsible for compliance with applicable laws and engagement rules. Authors and contributors disclaim liability for misuse; see [LICENSE.md](LICENSE.md).
