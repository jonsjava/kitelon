# Legal use and disclaimer

Kitelon is open source software licensed under the [MIT License](../LICENSE.md).

## Intended use

Kitelon is intended **only** for:

- **Education**: learning defensive and offensive security concepts in controlled lab environments
- **Authorized testing**: engagements where you have **explicit written permission** to assess the target systems

Kitelon is **not** a weapon, exploit kit, or covert access tool. It orchestrates well-known public security utilities against targets **you** supply.

## Your responsibilities

By running Kitelon (especially scan workloads), you agree that:

1. You will scan **only** systems you own or are explicitly authorized to test.
2. You comply with applicable local, national, and international laws.
3. You comply with contracts, policies, and rules of engagement for your organization or client.
4. You accept that authors and contributors are **not liable** for misuse (see MIT License disclaimer).

The CLI may prompt once per machine for an authorized-use acknowledgement. Automation may set `KITELON_I_ACCEPT_AUTHORIZED_USE=1` only when your environment already enforces authorization policy.

## Project

Kitelon is maintained as open source under the MIT License. Third-party tool licenses apply to bundled scanners and plugins; see [NOTICE.md](../NOTICE.md).

## Third-party tools

Kitelon installs and invokes third-party tools (nmap, nuclei, Metasploit, etc.). Each tool has its own license and acceptable-use terms. You are responsible for those tools as well.

## Reporting misuse

If you discover a security defect in Kitelon itself (not a finding from a scan), report it privately to the project maintainer.
