#!/bin/bash
# Uninstall script for Kitelon

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/bin/kitelon_ui.sh"
source "$SCRIPT_DIR/bin/banner.sh"
kitelon_banner
echo ""
kl_msg_info "Kitelon uninstall"
echo ""

INSTALL_DIR=/usr/share/kitelon

kl_msg_warn "This script will uninstall kitelon and remove ALL files under $INSTALL_DIR. Continue? [y/N]"
read answer

rm -Rf /usr/share/kitelon/
rm -f /usr/bin/kitelon /usr/local/bin/kitelon
rm -f /usr/share/applications/kitelon.desktop

kl_msg_info "Done!"
