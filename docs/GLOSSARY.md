# Kitelon glossary

Public vocabulary for plugins, addons, and packs. Runtime contracts live in [MODULARITY.md](MODULARITY.md).

## Core terms

| Term | Meaning | Example |
|------|---------|---------|
| **Plugin** | A whole external tool wired into Kitelon | Nmap, Nuclei, Metasploit, dnsrecon |
| **Addon** | Extra capability *inside* one plugin | Nmap vulners NSE, Metasploit auxiliary scanners |
| **Pack** | Shippable bundle of addon content (data, not new Python) | `conf/packs/metasploit/scanners.json`, nuclei templates, wordlists |

**Public line:** Kitelon has **plugins**. A plugin can grow **addons**. Related addons ship as a **pack**.

## Workspace archive (not a plugin pack)

**Workspace archive** (or **workspace ZIP**) is the portable export/import of scan data (`kitelon workspaces export`, Web UI **Export ZIP**). It is **not** a plugin pack — do not call it “install a pack” in the plugin sense.

Implementation: [`bin/kitelon_workspace_pack.py`](../bin/kitelon_workspace_pack.py).

## Upstream terms (keep inside the plugin)

Use these when referring to the upstream tool, not as Kitelon-wide names:

| Tool | Term | Example |
|------|------|---------|
| Metasploit | **module** | `auxiliary/scanner/smb/smb_ms17_010` |
| Nuclei | **template** | CVE check YAML |
| Nmap | **NSE script** | `vulners.nse` |

## Terms to avoid at Kitelon level

- **Extension** — collapses into “plugin”
- **Subplugin / submodule** — git collision on submodule
- **Payload** — Metasploit owns this
- **Module** — use *plugin* for Kitelon; *module* only for MSF/Nuclei/Nmap internals

## Related docs

- [MODULARITY.md](MODULARITY.md) — registry, pack loader, pipeline hooks
- [PLUGINS.md](PLUGINS.md) — inventory of integrated plugins
- [TOOLS.md](TOOLS.md) — install sources and config flags
