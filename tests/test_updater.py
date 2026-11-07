"""Tests for bin/kitelon_update.sh (`kitelon -u`), run against a local git repo."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

UPDATER = Path(__file__).resolve().parent.parent / "bin" / "kitelon_update.sh"

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")

# Stands in for the real installer: records where it ran from and its args.
STUB_INSTALLER = """#!/usr/bin/env bash
cd "$(dirname "$0")"
{ echo "dir=$(pwd)"; echo "args=$*"; } > "$KITELON_TEST_LOG"
"""


def git(cwd: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    return subprocess.run(
        ["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True
    ).stdout.strip()


class Env:
    def __init__(self, tmp: Path):
        self.origin = tmp / "origin"
        self.install = tmp / "install"
        self.src = tmp / "var" / "src"
        self.log = tmp / "installer.log"
        self.origin.mkdir()
        git(self.origin, "init", "-q", "-b", "main")
        (self.origin / "install.sh").write_text(STUB_INSTALLER)
        self.commit("0.6.0")
        self.install.mkdir()
        (self.install / "kitelon.conf").write_text('DB_ENABLED="1"\n')

    @property
    def url(self) -> str:
        return f"file://{self.origin}"

    def commit(self, version: str, note: str = "") -> str:
        (self.origin / "VERSION").write_text(version + "\n")
        (self.origin / "NOTE").write_text(note)
        git(self.origin, "add", "-A")
        git(self.origin, "commit", "-q", "-m", f"v{version} {note}")
        return git(self.origin, "rev-parse", "HEAD")

    def installed(self, version: str, commit: str | None = None) -> None:
        (self.install / "VERSION").write_text(version + "\n")
        if commit:
            (self.install / "SOURCE_COMMIT").write_text(commit + "\n")

    def run(self, *args: str, answer: str = "") -> subprocess.CompletedProcess:
        if self.log.exists():
            self.log.unlink()
        env = {
            **os.environ,
            "INSTALL_DIR": str(self.install),
            "KITELON_UPDATE_REPO": self.url,
            "KITELON_SRC_DIR": str(self.src),
            "KITELON_TEST_LOG": str(self.log),
        }
        env.pop("KITELON_UPDATE_BRANCH", None)
        return subprocess.run(
            ["bash", str(UPDATER), *args],
            env=env,
            input=answer,
            capture_output=True,
            text=True,
            timeout=60,
        )

    def installer_ran(self) -> dict[str, str] | None:
        if not self.log.exists():
            return None
        return dict(line.split("=", 1) for line in self.log.read_text().splitlines())


@pytest.fixture
def env(tmp_path):
    return Env(tmp_path)


def test_newer_version_is_cloned_and_installed_from_the_clone(env):
    env.installed("0.5.2")
    result = env.run("-y", "--force-stop", "--drain-timeout", "60")
    assert result.returncode == 0, result.stderr
    ran = env.installer_ran()
    # install.sh runs from the separate clone, never from the install dir.
    assert ran == {"dir": str(env.src), "args": "force --force-stop --drain-timeout 60"}
    assert "0.5.2 -> 0.6.0" in result.stdout
    # Local config is carried over so install.sh doesn't prompt for it.
    assert (env.src / "kitelon.conf").read_text() == 'DB_ENABLED="1"\n'
    head = git(env.origin, "rev-parse", "HEAD")
    assert (env.src / "SOURCE_COMMIT").read_text().strip() == head


def test_up_to_date_install_does_nothing(env):
    env.installed("0.6.0", git(env.origin, "rev-parse", "HEAD"))
    result = env.run("-y")
    assert result.returncode == 0
    assert "up to date" in result.stdout
    assert env.installer_ran() is None


def test_new_commit_without_version_bump_is_an_update(env):
    env.installed("0.6.0", git(env.origin, "rev-parse", "HEAD"))
    env.run("-y")  # creates the clone
    env.commit("0.6.0", note="hotfix")
    result = env.run("-y")
    assert result.returncode == 0, result.stderr
    assert env.installer_ran() is not None
    assert (env.src / "NOTE").read_text() == "hotfix"  # existing clone was fetched


def test_older_version_is_not_installed_without_force(env):
    env.installed("0.7.0")
    result = env.run("-y")
    assert result.returncode == 1
    assert "not downgrading" in result.stdout
    assert env.installer_ran() is None
    result = env.run("-y", "--force")
    assert result.returncode == 0
    assert env.installer_ran() is not None


def test_answering_no_changes_nothing(env):
    env.installed("0.5.2")
    result = env.run(answer="n\n")
    assert result.returncode == 0
    assert "cancelled" in result.stdout
    assert env.installer_ran() is None


def test_answering_yes_installs(env):
    env.installed("0.5.2")
    result = env.run(answer="y\n")
    assert result.returncode == 0
    assert env.installer_ran() is not None


def test_clone_of_another_repo_is_replaced(env, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    git(other, "init", "-q", "-b", "main")
    (other / "VERSION").write_text("9.9.9\n")
    git(other, "add", "-A")
    git(other, "commit", "-q", "-m", "x")
    env.src.parent.mkdir(parents=True)
    git(tmp_path, "clone", "-q", str(other), str(env.src))
    env.installed("0.5.2")
    result = env.run("-y")
    assert result.returncode == 0, result.stderr
    assert (env.src / "VERSION").read_text().strip() == "0.6.0"


def test_unrelated_directory_is_never_deleted(env):
    env.src.mkdir(parents=True)
    (env.src / "precious.txt").write_text("keep me")
    env.installed("0.5.2")
    result = env.run("-y")
    assert result.returncode == 1
    assert "isn't a Kitelon source clone" in result.stderr
    assert (env.src / "precious.txt").read_text() == "keep me"
    assert env.installer_ran() is None


def test_unreachable_repository_fails_cleanly(env):
    env.installed("0.5.2")
    shutil.rmtree(env.origin)
    result = env.run("-y")
    assert result.returncode == 1
    assert "Could not clone" in result.stderr
    assert env.installer_ran() is None
    assert not env.src.exists()
