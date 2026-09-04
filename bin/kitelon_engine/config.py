"""Load Kitelon configuration."""


import os
import re
from pathlib import Path
from typing import Any

_PRESET_KEYS = {
    "THREADS": ("threads", int),
    "ENABLE_NUCLEI": ("enable_nuclei", "flag"),
    "ENABLE_TESTSSL": ("enable_testssl", "flag"),
    "ENABLE_DIRSEARCH": ("enable_dirsearch", "flag"),
    "ENABLE_GOBUSTER": ("enable_gobuster", "flag"),
    "ENABLE_FFUF": ("enable_ffuf", "flag"),
    "ENABLE_HTTPX": ("enable_httpx", "flag"),
    "ENABLE_WEBTECH": ("enable_webtech", "flag"),
    "ENABLE_GOWITNESS": ("enable_gowitness", "flag"),
    "ENABLE_NIKTO": ("enable_nikto", "flag"),
    "ENABLE_SUBFINDER": ("enable_subfinder", "flag"),
    "ENABLE_WAFW00F": ("enable_wafw00f", "flag"),
    "ENABLE_VULNERS": ("enable_vulners", "flag"),
    "ENABLE_OS_DETECT": ("enable_os_detect", "flag"),
    "ENABLE_ENUM4LINUX": ("enable_enum4linux", "flag"),
    "ENABLE_SMBMAP": ("enable_smbmap", "flag"),
    "ENABLE_SSH_AUDIT": ("enable_ssh_audit", "flag"),
    "ENABLE_NAABU": ("enable_naabu", "flag"),
    "ENABLE_DNSX": ("enable_dnsx", "flag"),
    "ENABLE_KATANA": ("enable_katana", "flag"),
    "ENABLE_TLSX": ("enable_tlsx", "flag"),
    "ENABLE_METASPLOIT": ("enable_metasploit", "flag"),
    "ENABLE_DNSRECON": ("enable_dnsrecon", "flag"),
    "ENABLE_METAGOOFILE": ("enable_metagoofil", "flag"),
    "ENABLE_GAU": ("enable_gau", "flag"),
    "ENABLE_SHODAN": ("enable_shodan", "flag"),
    "ENABLE_CENSYS": ("enable_censys", "flag"),
    "DNSRECON_AXFR": ("dnsrecon_axfr", "flag"),
    "GAU_INCLUDE_SUBS": ("gau_include_subs", "flag"),
    "MSF_MODULE_TIMEOUT": ("msf_module_timeout", int),
    "MSF_MAX_MODULES": ("msf_max_modules", int),
    "SHODAN_MAX_RESULTS": ("shodan_max_results", int),
    "CENSYS_MAX_RESULTS": ("censys_max_results", int),
    "GAU_MAX_URLS": ("gau_max_urls", int),
    "METAGOOFILE_LIMIT": ("metagoofil_limit", int),
    "DNSRECON_TIMEOUT": ("dnsrecon_timeout", int),
    "METAGOOFILE_TIMEOUT": ("metagoofil_timeout", int),
    "GAU_TIMEOUT": ("gau_timeout", int),
    "SHODAN_TIMEOUT": ("shodan_timeout", int),
    "CENSYS_TIMEOUT": ("censys_timeout", int),
    "CENSYS_MODE": ("censys_mode", "str"),
    "GAU_PROVIDERS": ("gau_providers", "str"),
    "METAGOOFILE_TYPES": ("metagoofil_types", "str"),
    "NUCLEI_TEMPLATES": ("nuclei_templates", "str"),
    "WORDLIST_DIR": ("wordlist_dir", "str"),
    "MAX_HOSTS": ("max_hosts", int),
}


def _parse_conf_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("source "):
            continue
        match = re.match(r'^([A-Z0-9_]+)=(".*?"|\S+)$', line)
        if not match:
            continue
        key, raw = match.group(1), match.group(2)
        if raw.startswith('"') and raw.endswith('"'):
            raw = raw[1:-1]
        values[key] = raw
    return values


def _expand_conf_values(values: dict[str, str]) -> dict[str, str]:
    """Expand $VAR and ${VAR} references like bash would for kitelon.conf."""
    expanded = dict(values)
    pattern = re.compile(r"\$\{([^}]+)\}|\$([A-Z0-9_]+)")
    for _ in range(16):
        changed = False
        for key, value in list(expanded.items()):
            if "$" not in value:
                continue

            def repl(match: re.Match[str]) -> str:
                name = match.group(1) or match.group(2) or ""
                return expanded.get(name, match.group(0))

            new_value = pattern.sub(repl, value)
            if new_value != value:
                expanded[key] = new_value
                changed = True
        if not changed:
            break
    return expanded


def _flag(values: dict[str, str], key: str, default: str = "1") -> bool:
    return values.get(key, default) not in ("0", "false", "False", "")


def _config_from_merged(merged: dict[str, str], install_dir: Path) -> dict[str, Any]:
    plugins_dir = merged.get("PLUGINS_DIR", str(install_dir / "plugins"))
    wordlist_dir = merged.get("WORDLIST_DIR", str(install_dir / "wordlists"))
    nuclei_templates = merged.get(
        "NUCLEI_TEMPLATES", str(Path(plugins_dir) / "nuclei-templates")
    )

    return {
        "install_dir": merged.get("INSTALL_DIR", str(install_dir)),
        "threads": int(merged.get("THREADS", "10")),
        "enable_nuclei": _flag(merged, "ENABLE_NUCLEI"),
        "enable_testssl": _flag(merged, "ENABLE_TESTSSL", merged.get("TESTSSL", "1")),
        "enable_dirsearch": _flag(merged, "ENABLE_DIRSEARCH", merged.get("DIRSEARCH", "1")),
        "enable_gobuster": _flag(merged, "ENABLE_GOBUSTER", merged.get("GOBUSTER", "1")),
        "enable_ffuf": _flag(merged, "ENABLE_FFUF", "0"),
        "enable_httpx": _flag(merged, "ENABLE_HTTPX", merged.get("HTTPX", "1")),
        "enable_webtech": _flag(merged, "ENABLE_WEBTECH", "1"),
        "enable_gowitness": _flag(merged, "ENABLE_GOWITNESS", "1"),
        "enable_nikto": _flag(merged, "ENABLE_NIKTO", "0"),
        "enable_subfinder": _flag(merged, "ENABLE_SUBFINDER", merged.get("SUBFINDER", "1")),
        "enable_wafw00f": _flag(merged, "ENABLE_WAFW00F", merged.get("WAFW00F", "1")),
        "enable_vulners": _flag(merged, "ENABLE_VULNERS", "1"),
        "enable_os_detect": _flag(merged, "ENABLE_OS_DETECT", "1"),
        "enable_enum4linux": _flag(merged, "ENABLE_ENUM4LINUX", "1"),
        "enable_smbmap": _flag(merged, "ENABLE_SMBMAP", "1"),
        "enable_ssh_audit": _flag(merged, "ENABLE_SSH_AUDIT", "1"),
        "enable_naabu": _flag(merged, "ENABLE_NAABU", "0"),
        "enable_dnsx": _flag(merged, "ENABLE_DNSX", "1"),
        "enable_katana": _flag(merged, "ENABLE_KATANA", "0"),
        "enable_tlsx": _flag(merged, "ENABLE_TLSX", "0"),
        "enable_metasploit": _flag(merged, "ENABLE_METASPLOIT", "1"),
        "enable_dnsrecon": _flag(merged, "ENABLE_DNSRECON", "1"),
        "enable_metagoofil": _flag(merged, "ENABLE_METAGOOFILE", "0"),
        "enable_gau": _flag(merged, "ENABLE_GAU", "1"),
        "enable_shodan": _flag(merged, "ENABLE_SHODAN", "1"),
        "enable_censys": _flag(merged, "ENABLE_CENSYS", "1"),
        "dnsrecon_axfr": _flag(merged, "DNSRECON_AXFR", "0"),
        "gau_include_subs": _flag(merged, "GAU_INCLUDE_SUBS", "1"),
        "shodan_max_results": int(merged.get("SHODAN_MAX_RESULTS", "25")),
        "censys_max_results": int(merged.get("CENSYS_MAX_RESULTS", "25")),
        "censys_mode": merged.get("CENSYS_MODE", "hosts").strip().lower() or "hosts",
        "gau_max_urls": int(merged.get("GAU_MAX_URLS", "500")),
        "gau_providers": merged.get("GAU_PROVIDERS", "wayback"),
        "metagoofil_limit": int(merged.get("METAGOOFILE_LIMIT", "25")),
        "metagoofil_types": merged.get("METAGOOFILE_TYPES", "pdf,doc,xls"),
        "dnsrecon_timeout": int(merged.get("DNSRECON_TIMEOUT", "300")),
        "metagoofil_timeout": int(merged.get("METAGOOFILE_TIMEOUT", "600")),
        "gau_timeout": int(merged.get("GAU_TIMEOUT", "300")),
        "shodan_timeout": int(merged.get("SHODAN_TIMEOUT", "60")),
        "censys_timeout": int(merged.get("CENSYS_TIMEOUT", "60")),
        "msf_module_timeout": int(merged.get("MSF_MODULE_TIMEOUT", "420")),
        "msf_max_modules": int(merged.get("MSF_MAX_MODULES", "12")),
        "nuclei_templates": nuclei_templates,
        "wordlist_dir": wordlist_dir,
        "shodan_api_key": merged.get("SHODAN_API_KEY", ""),
        "censys_app_id": merged.get("CENSYS_APP_ID", ""),
        "censys_api_secret": merged.get("CENSYS_API_SECRET", ""),
        "github_api_key": merged.get("GITHUB_API_KEY", ""),
        "wp_api_key": merged.get("WP_API_KEY", ""),
        "max_hosts": int(merged.get("MAX_HOSTS", "2000")),
        "raw": merged,
    }


def load_config(install_dir: Path) -> dict[str, Any]:
    merged: dict[str, str] = {}
    for path in (
        install_dir / "kitelon.conf",
        Path("/root/.kitelon.conf"),
        Path("/root/.kitelon_api_keys.conf"),
    ):
        merged.update(_parse_conf_file(path))

    merged.setdefault("INSTALL_DIR", str(install_dir))
    merged = _expand_conf_values(merged)
    return _config_from_merged(merged, install_dir)


def load_preset(install_dir: Path, name: str) -> dict[str, Any]:
    """Load conf/presets/<name>.conf and return scan option overrides."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name or ""):
        raise ValueError(f"invalid preset name: {name}")
    presets_dir = (install_dir / "conf" / "presets").resolve()
    preset_path = (presets_dir / f"{name}.conf").resolve()
    try:
        preset_path.relative_to(presets_dir)
    except ValueError as exc:
        raise ValueError(f"invalid preset name: {name}") from exc
    if not preset_path.is_file():
        raise ValueError(f"preset not found: {name}")

    base = _parse_conf_file(install_dir / "kitelon.conf")
    base.update(_parse_conf_file(preset_path))
    base.setdefault("INSTALL_DIR", str(install_dir))
    base = _expand_conf_values(base)

    config = _config_from_merged(base, install_dir)
    overrides: dict[str, Any] = {}
    for conf_key, (opt_key, kind) in _PRESET_KEYS.items():
        if conf_key not in base:
            continue
        raw = base[conf_key]
        if kind == "flag":
            overrides[opt_key] = _flag(base, conf_key, raw)
        elif kind is int:
            overrides[opt_key] = int(raw)
        else:
            overrides[opt_key] = raw
    return overrides


def list_presets(install_dir: Path) -> list[str]:
    preset_dir = install_dir / "conf" / "presets"
    if not preset_dir.is_dir():
        return []
    return sorted(p.stem for p in preset_dir.glob("*.conf"))
