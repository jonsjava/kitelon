#!/bin/bash
# Shared Kitelon ASCII banner (source after color vars are set)

kitelon_banner() {
  local color="${1:-$KL_C_ERR}"
  local reset="${2:-$KL_RESET}"
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ -z "$line" ]] && continue
    printf '%b%s%b\n' "$color" "$line" "$reset"
  done <<'BANNER'
██╗  ██╗██╗████████╗███████╗██╗      ██████╗ ███╗   ██╗
██║ ██╔╝██║╚══██╔══╝██╔════╝██║     ██╔═══██╗████╗  ██║
█████╔╝ ██║   ██║   █████╗  ██║     ██║   ██║██╔██╗ ██║
██╔═██╗ ██║   ██║   ██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██╗██║   ██║   ███████╗███████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚═╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
BANNER
}
