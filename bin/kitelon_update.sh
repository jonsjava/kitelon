#!/usr/bin/env bash
# Update Kitelon from its GitHub repository (`kitelon -u`).
#
# Keeps a clone of the repository outside the install directory, fetches the
# update branch into it, and if it is newer than what is installed, runs its
# install.sh. install.sh drains the job queue before replacing any files, and
# the clone lives elsewhere, so fetching never touches code running scans use.
#
# Usage: kitelon_update.sh [-y|--yes] [--force] [install.sh flags...]
#   -y, --yes     don't ask before installing
#   --force       reinstall even when up to date or older than what's installed
#   other flags   passed to `install.sh force` (--drain-timeout SEC, --force-stop, --no-drain)
#
# Settings (environment or kitelon.conf):
#   KITELON_UPDATE_REPO    repository URL (default https://github.com/jonsjava/kitelon.git)
#   KITELON_UPDATE_BRANCH  branch to follow (default main)
#   KITELON_SRC_DIR        where the clone is kept (default /var/lib/kitelon/src)

set -uo pipefail

INSTALL_DIR="${INSTALL_DIR:-/usr/share/kitelon}"
REPO="${KITELON_UPDATE_REPO:-https://github.com/jonsjava/kitelon.git}"
BRANCH="${KITELON_UPDATE_BRANCH:-main}"
SRC_DIR="${KITELON_SRC_DIR:-/var/lib/kitelon/src}"
ASSUME_YES=0
FORCE=0
INSTALLER_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1 ;;
    --force) FORCE=1 ;;
    *) INSTALLER_ARGS+=("$1") ;;
  esac
  shift
done

say() { echo "[*] $*"; }
die() { echo "[!] $*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || die "git is not installed. Cannot update."
export GIT_TERMINAL_PROMPT=0  # fail instead of prompting for credentials

read_trimmed() { [[ -f "$1" ]] && tr -d '[:space:]' < "$1"; }
version_of() { read_trimmed "$1/VERSION"; }
commit_of() { read_trimmed "$1/SOURCE_COMMIT"; }

# True when version $1 sorts before $2.
version_lt() {
  [[ "$1" != "$2" ]] && [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" == "$1" ]]
}

fetch_source() {
  if [[ -d "$SRC_DIR/.git" ]] \
    && [[ "$(git -C "$SRC_DIR" remote get-url origin 2>/dev/null)" == "$REPO" ]]; then
    say "Fetching $BRANCH from $REPO"
    git -C "$SRC_DIR" fetch --quiet --depth 1 origin "$BRANCH" \
      || die "Could not fetch $BRANCH from $REPO (offline, or the branch doesn't exist)."
    git -C "$SRC_DIR" checkout --quiet --force -B "$BRANCH" FETCH_HEAD || die "Could not check out $BRANCH."
    git -C "$SRC_DIR" clean --quiet -fdx
    return
  fi

  say "Cloning $REPO ($BRANCH)"
  local tmp="$SRC_DIR.new.$$"
  rm -rf "$tmp"
  mkdir -p "$(dirname "$SRC_DIR")" || die "Cannot create $(dirname "$SRC_DIR")."
  git clone --quiet --depth 1 --branch "$BRANCH" "$REPO" "$tmp" \
    || { rm -rf "$tmp"; die "Could not clone $BRANCH from $REPO (offline, or the branch doesn't exist)."; }
  if [[ -e "$SRC_DIR" ]]; then
    # Only replace a previous clone (e.g. of another repository), never an
    # unrelated directory.
    if [[ -d "$SRC_DIR/.git" ]] || [[ -z "$(ls -A "$SRC_DIR" 2>/dev/null)" ]]; then
      rm -rf "$SRC_DIR"
    else
      rm -rf "$tmp"
      die "$SRC_DIR exists and isn't a Kitelon source clone. Move it or set KITELON_SRC_DIR."
    fi
  fi
  mv "$tmp" "$SRC_DIR" || die "Could not move the clone into $SRC_DIR."
}

fetch_source

current="$(version_of "$INSTALL_DIR")"
current_commit="$(commit_of "$INSTALL_DIR")"
latest="$(version_of "$SRC_DIR")"
latest_commit="$(git -C "$SRC_DIR" rev-parse HEAD)"
short="${latest_commit:0:7}"
[[ -n "$latest" ]] || die "The fetched source has no VERSION file; not installing it."

if [[ "$FORCE" != "1" ]]; then
  if [[ "$latest" == "$current" ]] && [[ "$latest_commit" == "$current_commit" ]]; then
    say "Kitelon $current is up to date ($BRANCH @ $short)."
    exit 0
  fi
  if [[ -n "$current" ]] && version_lt "$latest" "$current"; then
    say "$BRANCH has Kitelon $latest, older than the installed $current; not downgrading."
    say "To install it anyway: kitelon -u --force"
    exit 1
  fi
fi

if [[ "$latest" == "$current" ]]; then
  change="$current (${current_commit:0:7}) -> $latest ($short)"
  [[ -z "$current_commit" ]] && change="$current -> $latest ($short)"
else
  change="${current:-not installed} -> $latest ($short)"
fi

if [[ "$ASSUME_YES" != "1" ]]; then
  echo "[i] Update Kitelon $change from $REPO ($BRANCH)? (y or n)"
  read -r ans
  if [[ "$ans" != "y" ]] && [[ "$ans" != "Y" ]]; then
    say "Update cancelled. Nothing was changed."
    exit 0
  fi
fi

# kitelon.conf is local configuration (not in git): install.sh would otherwise
# start its interactive setup.
if [[ -f "$INSTALL_DIR/kitelon.conf" ]]; then
  cp -f "$INSTALL_DIR/kitelon.conf" "$SRC_DIR/kitelon.conf" || die "Could not copy kitelon.conf."
fi
# Installed alongside VERSION so the next update can tell commits apart.
echo "$latest_commit" > "$SRC_DIR/SOURCE_COMMIT"

say "Installing Kitelon $change"
exec bash "$SRC_DIR/install.sh" force "${INSTALLER_ARGS[@]}"
