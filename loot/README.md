# Kitelon loot

Scan output is written under `/usr/share/kitelon/loot/` after installation.

**Canonical path:** `/usr/share/kitelon/loot/workspace/<alias>/`

`loot/workspaces` must be a **symlink** to `loot/workspace` (not a real directory).
If installs nested `workspace/` / `workspaces/` folders under `loot/workspaces/`, run:

```bash
sudo kitelon db fix-loot-layout
sudo kitelon db prune-workspaces
```
