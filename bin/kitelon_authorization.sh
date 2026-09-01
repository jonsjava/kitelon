#!/usr/bin/bash
# Authorized-use acknowledgement for scan workloads.

KITELON_LEGAL_VERSION="1"
KITELON_LEGAL_ACCEPT_FILE="${KITELON_LEGAL_ACCEPT_FILE:-/root/.kitelon/legal_accepted}"

kl_print_legal_notice() {
  cat <<'EOF'
================================================================================
  KITELON: AUTHORIZED USE ONLY
================================================================================

  This software is for EDUCATIONAL PURPOSES and AUTHORIZED SECURITY TESTING
  ONLY. You must have explicit written permission before probing any system
  you do not own or manage.

  Unauthorized scanning or exploitation may violate computer crime laws.
  You accept full responsibility for how you use Kitelon and for compliance
  with all applicable laws, contracts, and engagement rules.

  Licensed under the MIT License (see LICENSE.md). Provided AS IS with no
  warranty. See NOTICE.md and docs/SECURITY.md.
================================================================================
EOF
}

kl_require_authorized_use() {
  [[ "${KITELON_SKIP_LEGAL:-}" == "1" ]] && return 0
  [[ "${KITELON_I_ACCEPT_AUTHORIZED_USE:-}" == "1" ]] && return 0
  if [[ -f "$KITELON_LEGAL_ACCEPT_FILE" ]] \
    && grep -qx "$KITELON_LEGAL_VERSION" "$KITELON_LEGAL_ACCEPT_FILE" 2>/dev/null; then
    return 0
  fi
  kl_print_legal_notice
  echo ""
  read -r -p "Type YES to confirm authorized/educational use: " _kl_legal_ans
  if [[ "$_kl_legal_ans" != "YES" ]]; then
    kl_msg_err "Aborted: authorized use not confirmed."
    exit 1
  fi
  mkdir -p "$(dirname "$KITELON_LEGAL_ACCEPT_FILE")"
  printf '%s\n' "$KITELON_LEGAL_VERSION" > "$KITELON_LEGAL_ACCEPT_FILE"
}
