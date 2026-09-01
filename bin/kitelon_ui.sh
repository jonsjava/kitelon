#!/usr/bin/bash
# Kitelon terminal UI helpers.

[[ -n "${KL_UI_LOADED:-}" ]] && return 0
KL_UI_LOADED=1

KL_RESET="${KL_RESET:-\033[0m}"
KL_C_INFO="${KL_C_INFO:-\033[94m}"
KL_C_ERR="${KL_C_ERR:-\033[91m}"
KL_C_OK="${KL_C_OK:-\033[92m}"
KL_C_WARN="${KL_C_WARN:-\033[93m}"

kl_msg_info() {
  echo -e "${KL_C_INFO}[*]${KL_RESET} $*"
}

kl_msg_ok() {
  echo -e "${KL_C_OK}[ok]${KL_RESET} $*"
}

kl_msg_warn() {
  echo -e "${KL_C_WARN}[!]${KL_RESET} $*"
}

kl_msg_err() {
  echo -e "${KL_C_ERR}[x]${KL_RESET} $*"
}

kl_tag_ok() {
  echo -e "${KL_C_INFO}[${KL_RESET}${KL_C_OK}OK${KL_RESET}${KL_C_INFO}]${KL_RESET}"
}

kl_tag_fail() {
  echo -e "${KL_C_INFO}[${KL_RESET}${KL_C_ERR}FAIL${KL_RESET}${KL_C_INFO}]${KL_RESET}"
}

kl_msg_status() {
  echo -e "${KL_C_INFO}[*]${KL_RESET} $1 $(kl_tag_ok)"
}

kl_msg_status_fail() {
  echo -e "${KL_C_INFO}[*]${KL_RESET} $1 $(kl_tag_fail)"
}

kl_section() {
  echo -e "${KL_C_WARN}[kitelon]${KL_RESET} $*"
}

kl_hint() {
  echo -e "${KL_C_INFO}[i]${KL_RESET} $*"
}
