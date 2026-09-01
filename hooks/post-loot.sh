#!/bin/bash
# Optional post-loot hook for Kitelon.
# Copy to /usr/share/kitelon/hooks/post-loot.sh and customize.
#
# Available variables when sourced from kitelon:
#   INSTALL_DIR, LOOT_DIR, WORKSPACE, WORKSPACE_DIR, TARGET, MODE

# Example: open loot directory in file manager
# xdg-open "$LOOT_DIR" 2>/dev/null &

: