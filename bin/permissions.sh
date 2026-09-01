#!/bin/bash
# Kitelon filesystem permission helpers

# Apply 755 to explicit executables only (after secure install baseline).
kitelon_mark_executable() {
  local path
  for path in "$@"; do
    [[ -n "$path" && -f "$path" ]] || continue
    chmod 755 "$path" 2>/dev/null
  done
}

# Install tree: dirs 755, regular files 644, +x only on named executables.
kitelon_secure_install() {
  local dir="${1:-$INSTALL_DIR}"
  [[ -n "$dir" && -d "$dir" ]] || return 0

  find "$dir" -type d -exec chmod 755 {} + 2>/dev/null
  find "$dir" -type f -exec chmod 644 {} + 2>/dev/null

  kitelon_mark_executable "$dir/kitelon"
  kitelon_mark_executable "$dir/bin/kitelon_cli.py"

  chown -R root:root "$dir" 2>/dev/null

  if [[ -d "$dir/loot" ]]; then
    kitelon_secure_loot "$dir/loot"
  fi
}

# Scan loot may contain credentials, vuln data, and raw tool output.
kitelon_secure_loot() {
  local dir="${1:-$LOOT_DIR}"
  [[ -n "$dir" && -d "$dir" ]] || return 0

  find "$dir" -type d -exec chmod 700 {} + 2>/dev/null
  find "$dir" -type f -exec chmod 600 {} + 2>/dev/null

  chown -R root:root "$dir" 2>/dev/null
}

# Ensure new loot subdirs are created with safe defaults.
kitelon_secure_loot_dir() {
  local dir="$1"
  [[ -n "$dir" ]] || return 0
  mkdir -p "$dir" 2>/dev/null
  chmod 700 "$dir" 2>/dev/null
  chown root:root "$dir" 2>/dev/null
}
