#!/usr/bin/env python3
"""Source-aware SSH fleet access with an optional Git synchronization backend."""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

from . import __version__


DEFAULT_CONNECT_TIMEOUT = 10
FLEET_VERSION = 3
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
PRIVATE_KEY_MARKERS = (
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
)
SECRET_FIELD_PATTERN = re.compile(
    r"(^|_)(password|passwd|passphrase|private_key|secret|token|credential)(_|$)", re.IGNORECASE
)
ENDPOINT_PATTERN = re.compile(
    r"^(?:[A-Za-z0-9._-]+@)?(?:[A-Za-z0-9][A-Za-z0-9._-]*|\[[0-9A-Fa-f:]+\])$"
)


class UserError(RuntimeError):
    """An expected user-facing failure."""


@dataclass(frozen=True)
class FleetTarget:
    alias: str
    endpoint: str = ""
    role: str = ""
    platform: str = ""
    supports_herdr: bool = False


@dataclass(frozen=True)
class SourceProfile:
    name: str
    role: str
    detect_hostnames: list[str]
    local_target: str
    direct_targets: list[str]
    endpoint_overrides: dict[str, str]
    fallback_bastion: str = ""
    alias_mode: str = "target_endpoint"


@dataclass(frozen=True)
class FleetConfig:
    targets: list[FleetTarget]
    sources: dict[str, SourceProfile]


@dataclass(frozen=True)
class FleetRoute:
    source: str
    target: str
    kind: str
    endpoint: str = ""
    bastion: str = ""
    reason: str = ""


@dataclass(frozen=True)
class Settings:
    backend_url: str = ""


def xdg_path(variable: str, fallback: Path) -> Path:
    configured = os.environ.get(variable)
    return Path(configured).expanduser() if configured else fallback


def config_dir() -> Path:
    return xdg_path("XDG_CONFIG_HOME", Path.home() / ".config") / "sc-remote"


def data_dir() -> Path:
    return xdg_path("XDG_DATA_HOME", Path.home() / ".local" / "share") / "sc-remote"


def state_dir() -> Path:
    return xdg_path("XDG_STATE_HOME", Path.home() / ".local" / "state") / "sc-remote"


def settings_path() -> Path:
    return config_dir() / "config.json"


def local_fleet_path() -> Path:
    configured = os.environ.get("SC_REMOTE_FLEET")
    return Path(configured).expanduser() if configured else data_dir() / "fleet.json"


def backend_dir() -> Path:
    return state_dir() / "backend"


def backend_fleet_path() -> Path:
    return backend_dir() / "fleet.json"


def atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(data, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(0o600)
    temporary.replace(path)


def load_settings() -> Settings:
    path = settings_path()
    if not path.is_file():
        return Settings()
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise UserError(f"{path} must contain a JSON object")
    return Settings(backend_url=str(data.get("backend_url") or ""))


def save_settings(settings: Settings) -> None:
    atomic_write_json(settings_path(), asdict(settings))


def validate_name(value: str, label: str) -> None:
    if not NAME_PATTERN.fullmatch(value):
        raise UserError(f"invalid {label} {value!r}; use letters, numbers, dot, underscore, or dash")


def validate_text(value: str, label: str) -> None:
    if "\n" in value or "\r" in value or "\x00" in value:
        raise UserError(f"{label} may not contain control characters")
    if any(marker in value for marker in PRIVATE_KEY_MARKERS):
        raise UserError(f"{label} contains private-key material; credentials must remain outside sc-remote")


def validate_endpoint(value: str, label: str, *, allow_empty: bool = False) -> None:
    validate_text(value, label)
    if not value and allow_empty:
        return
    if not ENDPOINT_PATTERN.fullmatch(value):
        raise UserError(
            f"invalid {label}; use an SSH alias, host, user@host, or bracketed IPv6 address "
            "without credentials or URL parameters"
        )


def reject_secret_material(value: Any, path: str = "fleet") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if SECRET_FIELD_PATTERN.search(str(key)):
                raise UserError(f"secret-like field {path}.{key} is not allowed in fleet state")
            reject_secret_material(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_material(child, f"{path}[{index}]")
    elif isinstance(value, str):
        validate_text(value, path)


def target_by_name(fleet: FleetConfig, name: str) -> FleetTarget:
    for target in fleet.targets:
        if target.alias == name:
            return target
    available = ", ".join(target.alias for target in fleet.targets)
    raise UserError(f"unknown fleet target {name!r}; available: {available or '(none)'}")


def source_by_name(fleet: FleetConfig, name: str) -> SourceProfile:
    normalized = name.split(".", maxsplit=1)[0]
    for source in fleet.sources.values():
        if normalized in {source.name, source.local_target} or normalized in source.detect_hostnames:
            return source
    available = ", ".join(sorted(fleet.sources))
    raise UserError(f"unknown source host {name!r}; configured sources: {available or '(none)'}")


def detect_source(fleet: FleetConfig, override: str | None = None) -> SourceProfile:
    candidate = override or os.environ.get("SC_REMOTE_SOURCE") or socket.gethostname()
    return source_by_name(fleet, candidate)


def direct_endpoint(source: SourceProfile, target: FleetTarget) -> str:
    if target.alias in source.endpoint_overrides:
        return source.endpoint_overrides[target.alias]
    if source.alias_mode == "target_name":
        return target.alias
    if source.alias_mode in {"target_endpoint", "inventory_ssh_target"}:
        return target.endpoint
    raise UserError(f"source {source.name!r} has unsupported alias mode {source.alias_mode!r}")


def route_for(fleet: FleetConfig, source_name: str, target_name: str) -> FleetRoute:
    source = source_by_name(fleet, source_name)
    target = target_by_name(fleet, target_name)
    if target.alias == source.local_target:
        return FleetRoute(source=source.name, target=target.alias, kind="local")
    if target.alias in source.direct_targets:
        endpoint = direct_endpoint(source, target)
        if not endpoint:
            raise UserError(f"target {target.alias!r} has a direct route but no endpoint")
        return FleetRoute(source=source.name, target=target.alias, kind="direct", endpoint=endpoint)
    if source.fallback_bastion:
        bastion = target_by_name(fleet, source.fallback_bastion)
        if bastion.alias not in source.direct_targets:
            raise UserError(
                f"source {source.name!r} fallback bastion {bastion.alias!r} is not directly reachable"
            )
        endpoint = direct_endpoint(source, bastion)
        if not endpoint:
            raise UserError(f"fallback bastion {bastion.alias!r} has no endpoint")
        return FleetRoute(
            source=source.name,
            target=target.alias,
            kind="broker",
            endpoint=endpoint,
            bastion=bastion.alias,
        )
    return FleetRoute(
        source=source.name,
        target=target.alias,
        kind="unavailable",
        reason=f"no route from {source.name} to {target.alias}; add a direct route or fallback bastion",
    )


def validate_fleet(fleet: FleetConfig) -> None:
    aliases: set[str] = set()
    for target in fleet.targets:
        validate_name(target.alias, "host alias")
        validate_endpoint(target.endpoint, f"endpoint for {target.alias}", allow_empty=True)
        if target.alias in aliases:
            raise UserError(f"duplicate target alias {target.alias!r}")
        aliases.add(target.alias)
    for key, source in fleet.sources.items():
        validate_name(key, "source name")
        if key != source.name:
            raise UserError(f"source key {key!r} does not match profile name {source.name!r}")
        target_by_name(fleet, source.local_target)
        for hostname in source.detect_hostnames:
            validate_name(hostname.split(".", maxsplit=1)[0], "detected hostname")
        for alias in source.direct_targets:
            target = target_by_name(fleet, alias)
            if alias != source.local_target and not direct_endpoint(source, target):
                raise UserError(f"direct target {alias!r} from {source.name!r} has no endpoint")
        for alias, endpoint in source.endpoint_overrides.items():
            target_by_name(fleet, alias)
            validate_endpoint(endpoint, f"endpoint override for {source.name}/{alias}")
        if source.fallback_bastion:
            target_by_name(fleet, source.fallback_bastion)
            if source.fallback_bastion not in source.direct_targets:
                raise UserError(
                    f"fallback bastion {source.fallback_bastion!r} must be directly reachable from {source.name!r}"
                )


def fleet_to_dict(fleet: FleetConfig) -> dict[str, Any]:
    validate_fleet(fleet)
    data = {
        "version": FLEET_VERSION,
        "targets": [asdict(target) for target in sorted(fleet.targets, key=lambda item: item.alias)],
        "sources": {name: asdict(source) for name, source in sorted(fleet.sources.items())},
    }
    reject_secret_material(data)
    return data


def fleet_from_dict(data: dict[str, Any]) -> FleetConfig:
    reject_secret_material(data)
    version = data.get("version")
    if version not in {2, FLEET_VERSION}:
        raise UserError(f"unsupported fleet manifest version: {version!r}")
    targets: list[FleetTarget] = []
    for item in data.get("targets") or []:
        if not isinstance(item, dict):
            raise UserError("every target must be a JSON object")
        targets.append(
            FleetTarget(
                alias=str(item.get("alias") or ""),
                endpoint=str(item.get("endpoint") or item.get("ssh_target") or ""),
                role=str(item.get("role") or ""),
                platform=str(item.get("platform") or ""),
                supports_herdr=bool(item.get("supports_herdr")),
            )
        )
    sources: dict[str, SourceProfile] = {}
    for name, item in (data.get("sources") or {}).items():
        if not isinstance(item, dict):
            raise UserError(f"source {name!r} must be a JSON object")
        source = SourceProfile(
            name=str(item.get("name") or name),
            role=str(item.get("role") or ""),
            detect_hostnames=[str(value) for value in item.get("detect_hostnames") or []],
            local_target=str(item.get("local_target") or name),
            direct_targets=[str(value) for value in item.get("direct_targets") or []],
            endpoint_overrides={
                str(key): str(value) for key, value in (item.get("endpoint_overrides") or {}).items()
            },
            fallback_bastion=str(item.get("fallback_bastion") or ""),
            alias_mode=str(item.get("alias_mode") or "target_endpoint"),
        )
        sources[source.name] = source
    fleet = FleetConfig(targets=targets, sources=sources)
    validate_fleet(fleet)
    return fleet


def load_fleet(path: Path) -> FleetConfig:
    if not path.is_file():
        raise UserError(f"fleet state not found at {path}; run 'sc-remote init' or configure a backend")
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise UserError(f"invalid JSON in {path}: {error}") from error
    if not isinstance(data, dict):
        raise UserError(f"{path} must contain a JSON object")
    return fleet_from_dict(data)


def save_fleet(path: Path, fleet: FleetConfig) -> None:
    atomic_write_json(path, fleet_to_dict(fleet))


def selected_fleet_path(explicit: Path | None = None) -> Path:
    if explicit:
        return explicit.expanduser()
    settings = load_settings()
    if settings.backend_url and backend_fleet_path().is_file():
        return backend_fleet_path()
    return local_fleet_path()


def run_git(args: Sequence[str], cwd: Path | None = None, *, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
    )
    if check and result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise UserError(f"git {' '.join(args)} failed: {detail}")
    return result


def validate_backend_url(url: str) -> None:
    validate_text(url, "backend URL")
    if not url:
        raise UserError("backend URL may not be empty")
    if "?" in url or "#" in url:
        raise UserError("backend URL may not contain query parameters or fragments")
    if "://" in url:
        parsed = urlsplit(url)
        if parsed.password is not None or (parsed.scheme in {"http", "https"} and parsed.username):
            raise UserError("backend URL contains inline credentials; use SSH or a Git credential helper")
        if parsed.scheme not in {"file", "http", "https", "ssh"}:
            raise UserError(f"unsupported backend URL scheme {parsed.scheme!r}")
    elif "@" in url and not re.fullmatch(r"[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:.+", url):
        raise UserError("invalid SCP-style Git backend URL")


def ensure_backend_checkout(settings: Settings) -> Path:
    validate_backend_url(settings.backend_url)
    checkout = backend_dir()
    if (checkout / ".git").is_dir():
        current = run_git(["remote", "get-url", "origin"], checkout).stdout.strip()
        if current != settings.backend_url:
            raise UserError(
                f"backend checkout uses {current!r}, not configured {settings.backend_url!r}; "
                "run 'sc-remote backend reset-checkout'"
            )
        return checkout
    if checkout.exists() and any(checkout.iterdir()):
        raise UserError(f"backend path {checkout} exists and is not an sc-remote Git checkout")
    checkout.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    result = run_git(["clone", settings.backend_url, str(checkout)], check=False)
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise UserError(f"could not clone backend {settings.backend_url!r}: {detail}")
    return checkout


def git_has_head(checkout: Path) -> bool:
    return run_git(["rev-parse", "--verify", "HEAD"], checkout, check=False).returncode == 0


def git_branch(checkout: Path) -> str:
    result = run_git(["branch", "--show-current"], checkout).stdout.strip()
    if result:
        return result
    return "main"


def backend_dirty_paths(checkout: Path) -> list[str]:
    lines = run_git(["status", "--porcelain"], checkout).stdout.splitlines()
    return [line[3:] for line in lines if len(line) > 3]


def copy_local_fleet_into_empty_backend(checkout: Path) -> None:
    destination = checkout / "fleet.json"
    if destination.exists():
        return
    source = local_fleet_path()
    if source.is_file():
        fleet = load_fleet(source)
        save_fleet(destination, fleet)


def commit_pending_fleet(checkout: Path, message: str) -> bool:
    dirty = backend_dirty_paths(checkout)
    unexpected = [path for path in dirty if path != "fleet.json"]
    if unexpected:
        raise UserError(f"backend checkout contains unexpected changes: {', '.join(unexpected)}")
    if not (checkout / "fleet.json").is_file():
        return False
    load_fleet(checkout / "fleet.json")
    run_git(["add", "--", "fleet.json"], checkout)
    staged = run_git(["diff", "--cached", "--quiet"], checkout, check=False)
    if staged.returncode == 0:
        return False
    if staged.returncode != 1:
        raise UserError("could not inspect staged backend changes")
    run_git(
        [
            "-c",
            "user.name=sc-remote",
            "-c",
            "user.email=sc-remote@localhost",
            "commit",
            "-m",
            message,
        ],
        checkout,
    )
    return True


def remote_branch_exists(checkout: Path, branch: str) -> bool:
    return (
        run_git(["ls-remote", "--exit-code", "--heads", "origin", branch], checkout, check=False).returncode
        == 0
    )


def sync_backend(*, message: str = "Update fleet state") -> dict[str, Any]:
    settings = load_settings()
    if not settings.backend_url:
        raise UserError("no backend configured; run 'sc-remote backend set URL'")
    checkout = ensure_backend_checkout(settings)
    copy_local_fleet_into_empty_backend(checkout)
    branch = git_branch(checkout)
    if not git_has_head(checkout) and branch != "main":
        run_git(["checkout", "-B", "main"], checkout)
        branch = "main"

    committed = commit_pending_fleet(checkout, message)
    pulled = False
    if remote_branch_exists(checkout, branch):
        pull = run_git(["pull", "--rebase", "origin", branch], checkout, check=False)
        if pull.returncode:
            run_git(["rebase", "--abort"], checkout, check=False)
            detail = pull.stderr.strip() or pull.stdout.strip()
            raise UserError(
                "backend changed concurrently; rebase was aborted and local fleet state was restored. "
                f"Resolve the competing update or repeat the original mutation. Git said: {detail}"
            )
        pulled = True
    if not (checkout / "fleet.json").is_file():
        raise UserError("backend has no fleet.json and no local fleet exists; run 'sc-remote init' first")
    fleet = load_fleet(checkout / "fleet.json")
    save_fleet(local_fleet_path(), fleet)
    run_git(["push", "-u", "origin", f"HEAD:{branch}"], checkout)
    revision = run_git(["rev-parse", "--short", "HEAD"], checkout).stdout.strip()
    return {
        "backend": settings.backend_url,
        "branch": branch,
        "revision": revision,
        "committed": committed,
        "pulled": pulled,
        "fleet_path": str(checkout / "fleet.json"),
    }


def prepare_mutation(explicit: Path | None, should_sync: bool) -> Path:
    if explicit:
        return explicit.expanduser()
    settings = load_settings()
    if not settings.backend_url:
        return local_fleet_path()
    if should_sync:
        sync_backend(message="Synchronize fleet state")
    else:
        ensure_backend_checkout(settings)
        copy_local_fleet_into_empty_backend(backend_dir())
    return backend_fleet_path()


def mutate_fleet(
    explicit: Path | None,
    should_sync: bool,
    message: str,
    operation: Callable[[FleetConfig], FleetConfig],
) -> FleetConfig:
    if not explicit and load_settings().backend_url and should_sync:
        return mutate_synced_backend(message, operation)
    path = prepare_mutation(explicit, should_sync)
    fleet = load_fleet(path)
    updated = operation(fleet)
    save_fleet(path, updated)
    if not explicit and load_settings().backend_url and should_sync:
        sync_backend(message=message)
    return updated


def mutate_synced_backend(
    message: str,
    operation: Callable[[FleetConfig], FleetConfig],
    *,
    attempts: int = 3,
) -> FleetConfig:
    """Apply an operation to the latest remote revision and retry push races.

    The operation, rather than a textual JSON merge, is replayed on the newest
    fleet state. This lets independent host and route changes converge while
    making same-object conflicts fail through normal operation validation.
    """
    settings = load_settings()
    checkout = ensure_backend_checkout(settings)
    copy_local_fleet_into_empty_backend(checkout)
    # First settle any explicit --no-sync update. A textual conflict is
    # aborted by sync_backend, so the checkout never remains in rebase state.
    sync_backend(message="Synchronize fleet state")
    checkout = backend_dir()
    branch = git_branch(checkout)

    for attempt in range(1, attempts + 1):
        run_git(["fetch", "origin", branch], checkout)
        if remote_branch_exists(checkout, branch):
            local_revision = run_git(["rev-parse", "HEAD"], checkout).stdout.strip()
            remote_revision = run_git(["rev-parse", f"origin/{branch}"], checkout).stdout.strip()
            if local_revision != remote_revision:
                dirty = backend_dirty_paths(checkout)
                if dirty:
                    raise UserError(f"backend checkout has pending changes: {', '.join(dirty)}")
                # This checkout is dedicated managed state. Resetting it to the
                # fetched remote revision cannot affect user source files.
                run_git(["reset", "--hard", f"origin/{branch}"], checkout)

        latest = load_fleet(checkout / "fleet.json")
        updated = operation(latest)
        save_fleet(checkout / "fleet.json", updated)
        commit_pending_fleet(checkout, message)
        push = run_git(["push", "origin", f"HEAD:{branch}"], checkout, check=False)
        if push.returncode == 0:
            save_fleet(local_fleet_path(), updated)
            return updated
        if attempt == attempts:
            detail = push.stderr.strip() or push.stdout.strip()
            raise UserError(f"backend changed during {attempts} mutation attempts: {detail}")
    raise AssertionError("unreachable mutation retry loop")


def known_hosts_path(source: SourceProfile) -> Path:
    return state_dir() / f"known_hosts.{source.name}"


def ssh_command(endpoint: str, command: list[str], *, timeout: int, known_hosts_file: Path) -> list[str]:
    argv = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={timeout}",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={known_hosts_file}",
        endpoint,
    ]
    if command:
        argv.append(shlex.join(command))
    return argv


def ensure_known_hosts_parent(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)


def route_command(
    route: FleetRoute, command: list[str], *, timeout: int, known_hosts_file: Path
) -> list[str]:
    if route.kind == "direct":
        return ssh_command(route.endpoint, command, timeout=timeout, known_hosts_file=known_hosts_file)
    if route.kind == "broker":
        broker_command = ["sc-remote", "run", route.target, "--", *command]
        return ssh_command(
            route.endpoint,
            broker_command,
            timeout=timeout,
            known_hosts_file=known_hosts_file,
        )
    raise UserError(f"route kind {route.kind!r} does not use SSH")


def resolve_ssh(endpoint: str) -> dict[str, str]:
    result = subprocess.run(["ssh", "-G", endpoint], check=False, capture_output=True, text=True)
    if result.returncode:
        raise UserError(result.stderr.strip() or f"ssh -G failed with rc={result.returncode}")
    wanted = {"hostname", "user", "port", "identitiesonly"}
    resolved: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, _, value = line.partition(" ")
        if key in wanted:
            resolved[key] = value
    return resolved


def route_record(target: FleetTarget, route: FleetRoute) -> dict[str, Any]:
    return {
        **asdict(target),
        "ssh_target": target.endpoint,
        "route": route.kind,
        "route_endpoint": route.endpoint,
        "bastion": route.bastion,
        "reason": route.reason,
    }


def print_targets(fleet: FleetConfig, source: SourceProfile, *, as_json: bool) -> None:
    records = [route_record(target, route_for(fleet, source.name, target.alias)) for target in fleet.targets]
    if as_json:
        print(json.dumps(records, indent=2, sort_keys=True))
        return
    print("alias\troute\tbastion\therdr\trole\tendpoint")
    for record in records:
        print(
            "\t".join(
                [
                    record["alias"],
                    record["route"],
                    record["bastion"],
                    "yes" if record["supports_herdr"] else "no",
                    record["role"],
                    record["route_endpoint"],
                ]
            )
        )


def local_probe() -> int:
    print(f"hostname={socket.gethostname().split('.', maxsplit=1)[0]}")
    print(f"user={os.environ.get('USER') or os.getlogin()}")
    return 0


def add_sync_flags(parser: argparse.ArgumentParser) -> None:
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--sync", dest="sync", action="store_true", default=True, help="sync configured backend")
    group.add_argument("--no-sync", dest="sync", action="store_false", help="leave a local backend change pending")


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sc-remote",
        description="Discover, manage, synchronize, and access an SSH fleet from any configured source host.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--fleet", type=Path, help="use an explicit fleet JSON file (disables backend sync)")
    parser.add_argument("--source", help="override source-host detection")
    subparsers = parser.add_subparsers(dest="action", required=True)

    init_parser = subparsers.add_parser("init", help="initialize a local fleet and source profile")
    init_parser.add_argument("--source", dest="init_source", required=True, help="source profile name")
    init_parser.add_argument("--role", default="workstation")
    init_parser.add_argument("--local-target", help="local host alias (defaults to source name)")
    init_parser.add_argument("--endpoint", default="", help="SSH endpoint other sources can use")
    init_parser.add_argument("--detect-hostname", action="append", default=[])
    init_parser.add_argument("--herdr", action="store_true", help="mark the local target as Herdr-capable")
    init_parser.add_argument("--force", action="store_true", help="replace existing fleet state")

    subparsers.add_parser("source", help="show the detected source profile")
    list_parser = subparsers.add_parser("list", help="list fleet routes from this source")
    list_parser.add_argument("--json", action="store_true")

    resolve_parser = subparsers.add_parser("resolve", help="show the selected route and SSH settings")
    resolve_parser.add_argument("target")
    resolve_parser.add_argument("--json", action="store_true")

    check_parser = subparsers.add_parser("check", help="verify access using the selected route")
    check_parser.add_argument("target")
    check_parser.add_argument("--timeout", type=int, default=DEFAULT_CONNECT_TIMEOUT)

    run_parser = subparsers.add_parser("run", help="run a command using the selected route")
    run_parser.add_argument("target")
    run_parser.add_argument("--timeout", type=int, default=DEFAULT_CONNECT_TIMEOUT)
    run_parser.add_argument("command", nargs=argparse.REMAINDER)

    shell_parser = subparsers.add_parser("shell", help="open a shell using the selected route")
    shell_parser.add_argument("target")

    herdr_parser = subparsers.add_parser("herdr", help="attach Herdr using the selected route")
    herdr_parser.add_argument("target")
    herdr_parser.add_argument("--session", default="agents")

    sync_parser = subparsers.add_parser("sync", help="pull, validate, commit, and push fleet state")
    sync_parser.add_argument("--json", action="store_true")

    backend_parser = subparsers.add_parser("backend", help="configure the Git synchronization backend")
    backend_sub = backend_parser.add_subparsers(dest="backend_action", required=True)
    backend_set = backend_sub.add_parser("set", help="set the Git backend URL")
    backend_set.add_argument("url")
    backend_sub.add_parser("status", help="show backend configuration without credentials")
    backend_sub.add_parser("clear", help="disable backend sync without deleting data")
    backend_sub.add_parser("reset-checkout", help="delete only the cached backend checkout")

    host_parser = subparsers.add_parser("host", help="add or remove fleet hosts")
    host_sub = host_parser.add_subparsers(dest="host_action", required=True)
    host_add = host_sub.add_parser("add", help="add or replace a host")
    host_add.add_argument("alias")
    host_add.add_argument("--endpoint", required=True, help="SSH alias or user@host; never a key")
    host_add.add_argument("--role", default="")
    host_add.add_argument("--platform", default="")
    host_add.add_argument("--herdr", action="store_true")
    host_add.add_argument("--direct-from", action="append", default=[])
    host_add.add_argument("--no-direct", action="store_true")
    host_add.add_argument("--replace", action="store_true")
    add_sync_flags(host_add)
    host_remove = host_sub.add_parser("remove", help="remove a host and direct-route references")
    host_remove.add_argument("alias")
    add_sync_flags(host_remove)

    sources_parser = subparsers.add_parser("sources", help="manage source profiles and routes")
    source_sub = sources_parser.add_subparsers(dest="sources_action", required=True)
    source_add = source_sub.add_parser("add", help="add a source profile for an existing local target")
    source_add.add_argument("name")
    source_add.add_argument("--local-target", required=True)
    source_add.add_argument("--role", default="workstation")
    source_add.add_argument("--detect-hostname", action="append", default=[])
    source_add.add_argument("--fallback-bastion", default="")
    source_add.add_argument("--alias-mode", choices=["target_endpoint", "target_name"], default="target_endpoint")
    add_sync_flags(source_add)
    source_remove = source_sub.add_parser("remove", help="remove a source profile")
    source_remove.add_argument("name")
    add_sync_flags(source_remove)
    route_add = source_sub.add_parser("route-add", help="make a target directly reachable from a source")
    route_add.add_argument("source")
    route_add.add_argument("target")
    route_add.add_argument("--endpoint", help="source-specific endpoint override")
    add_sync_flags(route_add)
    route_remove = source_sub.add_parser("route-remove", help="remove a direct route")
    route_remove.add_argument("source")
    route_remove.add_argument("target")
    add_sync_flags(route_remove)
    set_bastion = source_sub.add_parser("set-bastion", help="set a directly reachable fallback bastion")
    set_bastion.add_argument("source")
    set_bastion.add_argument("bastion")
    add_sync_flags(set_bastion)
    clear_bastion = source_sub.add_parser("clear-bastion", help="clear a source's fallback bastion")
    clear_bastion.add_argument("source")
    add_sync_flags(clear_bastion)

    fleet_parser = subparsers.add_parser("fleet", help="import or export fleet state")
    fleet_sub = fleet_parser.add_subparsers(dest="fleet_action", required=True)
    fleet_import = fleet_sub.add_parser("import", help="import and migrate a version 2 or 3 fleet JSON file")
    fleet_import.add_argument("path", type=Path)
    fleet_import.add_argument("--force", action="store_true")
    add_sync_flags(fleet_import)
    fleet_export = fleet_sub.add_parser("export", help="write secret-checked fleet JSON to stdout")
    fleet_export.add_argument("--output", type=Path)
    return parser


def replace_source(fleet: FleetConfig, source: SourceProfile) -> FleetConfig:
    sources = dict(fleet.sources)
    sources[source.name] = source
    return FleetConfig(targets=fleet.targets, sources=sources)


def require_source_exact(fleet: FleetConfig, name: str) -> SourceProfile:
    if name not in fleet.sources:
        raise UserError(f"unknown source profile {name!r}")
    return fleet.sources[name]


def handle_mutation(args: argparse.Namespace) -> int:
    explicit = args.fleet
    if args.action == "host" and args.host_action == "add":
        def operation(fleet: FleetConfig) -> FleetConfig:
            validate_name(args.alias, "host alias")
            validate_endpoint(args.endpoint, "host endpoint")
            existing = next((target for target in fleet.targets if target.alias == args.alias), None)
            if existing and not args.replace:
                raise UserError(f"host {args.alias!r} already exists; use --replace")
            target = FleetTarget(args.alias, args.endpoint, args.role, args.platform, args.herdr)
            targets = [item for item in fleet.targets if item.alias != args.alias] + [target]
            updated = FleetConfig(targets=targets, sources=fleet.sources)
            direct_sources = list(args.direct_from)
            if not args.no_direct and not direct_sources:
                direct_sources = [detect_source(fleet, args.source).name]
            for source_name in direct_sources:
                source = require_source_exact(updated, source_name)
                direct = sorted(set(source.direct_targets) | {args.alias})
                updated = replace_source(updated, replace(source, direct_targets=direct))
            return updated

        mutate_fleet(explicit, args.sync, f"Add host {args.alias}", operation)
        print(f"added={args.alias}")
        return 0

    if args.action == "host" and args.host_action == "remove":
        def operation(fleet: FleetConfig) -> FleetConfig:
            target_by_name(fleet, args.alias)
            blockers = [source.name for source in fleet.sources.values() if source.local_target == args.alias]
            blockers += [source.name for source in fleet.sources.values() if source.fallback_bastion == args.alias]
            if blockers:
                raise UserError(
                    f"host {args.alias!r} is an active local target or bastion for: {', '.join(sorted(set(blockers)))}"
                )
            targets = [target for target in fleet.targets if target.alias != args.alias]
            sources = {
                name: replace(
                    source,
                    direct_targets=[target for target in source.direct_targets if target != args.alias],
                    endpoint_overrides={
                        key: value for key, value in source.endpoint_overrides.items() if key != args.alias
                    },
                )
                for name, source in fleet.sources.items()
            }
            return FleetConfig(targets=targets, sources=sources)

        mutate_fleet(explicit, args.sync, f"Remove host {args.alias}", operation)
        print(f"removed={args.alias}")
        return 0

    if args.action == "sources" and args.sources_action == "add":
        def operation(fleet: FleetConfig) -> FleetConfig:
            validate_name(args.name, "source name")
            if args.name in fleet.sources:
                raise UserError(f"source {args.name!r} already exists")
            target_by_name(fleet, args.local_target)
            hostnames = args.detect_hostname or [args.name]
            source = SourceProfile(
                name=args.name,
                role=args.role,
                detect_hostnames=hostnames,
                local_target=args.local_target,
                direct_targets=[],
                endpoint_overrides={},
                fallback_bastion=args.fallback_bastion,
                alias_mode=args.alias_mode,
            )
            if args.fallback_bastion:
                target_by_name(fleet, args.fallback_bastion)
                source = replace(source, direct_targets=[args.fallback_bastion])
            return replace_source(fleet, source)

        mutate_fleet(explicit, args.sync, f"Add source {args.name}", operation)
        print(f"added_source={args.name}")
        return 0

    if args.action == "sources" and args.sources_action == "remove":
        def operation(fleet: FleetConfig) -> FleetConfig:
            require_source_exact(fleet, args.name)
            removed = require_source_exact(fleet, args.name)
            dependents = [
                source.name
                for source in fleet.sources.values()
                if source.name != args.name and source.fallback_bastion == removed.local_target
            ]
            if dependents:
                raise UserError(f"source is a fallback bastion for: {', '.join(dependents)}")
            sources = dict(fleet.sources)
            del sources[args.name]
            if not sources:
                raise UserError("cannot remove the final source profile")
            return FleetConfig(targets=fleet.targets, sources=sources)

        mutate_fleet(explicit, args.sync, f"Remove source {args.name}", operation)
        print(f"removed_source={args.name}")
        return 0

    if args.action == "sources" and args.sources_action in {"route-add", "route-remove"}:
        def operation(fleet: FleetConfig) -> FleetConfig:
            source = require_source_exact(fleet, args.source)
            target_by_name(fleet, args.target)
            direct = set(source.direct_targets)
            overrides = dict(source.endpoint_overrides)
            if args.sources_action == "route-add":
                direct.add(args.target)
                if args.endpoint:
                    validate_endpoint(args.endpoint, "route endpoint")
                    overrides[args.target] = args.endpoint
            else:
                if source.fallback_bastion == args.target:
                    raise UserError("clear the fallback bastion before removing its direct route")
                direct.discard(args.target)
                overrides.pop(args.target, None)
            return replace_source(
                fleet,
                replace(source, direct_targets=sorted(direct), endpoint_overrides=overrides),
            )

        verb = "Add" if args.sources_action == "route-add" else "Remove"
        mutate_fleet(explicit, args.sync, f"{verb} route {args.source} to {args.target}", operation)
        print(f"route={args.source}:{args.target}")
        return 0

    if args.action == "sources" and args.sources_action in {"set-bastion", "clear-bastion"}:
        def operation(fleet: FleetConfig) -> FleetConfig:
            source = require_source_exact(fleet, args.source)
            if args.sources_action == "clear-bastion":
                return replace_source(fleet, replace(source, fallback_bastion=""))
            target_by_name(fleet, args.bastion)
            direct = sorted(set(source.direct_targets) | {args.bastion})
            return replace_source(fleet, replace(source, fallback_bastion=args.bastion, direct_targets=direct))

        label = args.bastion if args.sources_action == "set-bastion" else "none"
        mutate_fleet(explicit, args.sync, f"Set bastion for {args.source} to {label}", operation)
        print(f"bastion={args.source}:{label}")
        return 0
    raise AssertionError("unhandled mutation")


def main(argv: Sequence[str] | None = None) -> int:
    parser = make_parser()
    args = parser.parse_args(argv)
    try:
        if args.action == "backend":
            if args.backend_action == "set":
                validate_backend_url(args.url)
                save_settings(Settings(backend_url=args.url))
                print(f"backend={args.url}")
                print("next=sc-remote sync")
                return 0
            if args.backend_action == "status":
                settings = load_settings()
                print(f"backend={settings.backend_url or '(disabled)'}")
                print(f"checkout={backend_dir()}")
                print(f"checkout_ready={'yes' if (backend_dir() / '.git').is_dir() else 'no'}")
                return 0
            if args.backend_action == "clear":
                save_settings(Settings())
                print("backend=(disabled)")
                return 0
            if args.backend_action == "reset-checkout":
                checkout = backend_dir()
                if checkout.exists():
                    shutil.rmtree(checkout)
                print(f"removed_checkout={checkout}")
                return 0

        if args.action == "sync":
            if args.fleet:
                raise UserError("--fleet cannot be combined with backend sync")
            result = sync_backend()
            if args.json:
                print(json.dumps(result, indent=2, sort_keys=True))
            else:
                for key, value in result.items():
                    print(f"{key}={value}")
            return 0

        if args.action == "init":
            source_name = args.init_source
            local_target = args.local_target or source_name
            validate_name(source_name, "source name")
            validate_name(local_target, "local target")
            path = selected_fleet_path(args.fleet)
            if path.exists() and not args.force:
                raise UserError(f"fleet already exists at {path}; use --force to replace it")
            hostnames = args.detect_hostname or [socket.gethostname().split(".", maxsplit=1)[0], source_name]
            fleet = FleetConfig(
                targets=[FleetTarget(local_target, args.endpoint, args.role, "", args.herdr)],
                sources={
                    source_name: SourceProfile(
                        source_name,
                        args.role,
                        sorted(set(hostnames)),
                        local_target,
                        [],
                        {},
                    )
                },
            )
            save_fleet(path, fleet)
            print(f"fleet={path}")
            print(f"source={source_name}")
            return 0

        if args.action == "fleet" and args.fleet_action == "import":
            imported = load_fleet(args.path.expanduser())
            # An empty configured backend cannot be synchronized until it has
            # fleet state, so import prepares the checkout without a pre-pull.
            path = prepare_mutation(args.fleet, False)
            if path.exists() and not args.force:
                raise UserError(f"fleet already exists at {path}; use --force to replace it")
            save_fleet(path, imported)
            if not args.fleet and load_settings().backend_url and args.sync:
                sync_backend(message="Import fleet state")
            print(f"imported={len(imported.targets)}")
            return 0

        if args.action == "fleet" and args.fleet_action == "export":
            fleet = load_fleet(selected_fleet_path(args.fleet))
            payload = json.dumps(fleet_to_dict(fleet), indent=2, sort_keys=True) + "\n"
            if args.output:
                args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                args.output.write_text(payload)
                args.output.chmod(0o600)
                print(f"exported={args.output}")
            else:
                print(payload, end="")
            return 0

        if args.action in {"host", "sources"}:
            return handle_mutation(args)

        fleet = load_fleet(selected_fleet_path(args.fleet))
        source = detect_source(fleet, args.source)
        known_hosts = known_hosts_path(source)

        if args.action == "source":
            print(f"source={source.name}")
            print(f"role={source.role}")
            print(f"local_target={source.local_target}")
            return 0
        if args.action == "list":
            print_targets(fleet, source, as_json=args.json)
            return 0

        target = target_by_name(fleet, args.target)
        route = route_for(fleet, source.name, target.alias)
        if route.kind == "unavailable":
            raise UserError(route.reason)

        if args.action == "resolve":
            resolved = route_record(target, route)
            if route.endpoint:
                resolved["ssh"] = resolve_ssh(route.endpoint)
            if args.json:
                print(json.dumps(resolved, indent=2, sort_keys=True))
            else:
                for key in ("alias", "route", "route_endpoint", "bastion", "reason"):
                    if resolved.get(key):
                        print(f"{key}={resolved[key]}")
                for key, value in resolved.get("ssh", {}).items():
                    print(f"ssh_{key}={value}")
            return 0

        if args.action == "check":
            if route.kind == "local":
                return local_probe()
            ensure_known_hosts_parent(known_hosts)
            if route.kind == "broker":
                command = ["sc-remote", "check", target.alias, "--timeout", str(args.timeout)]
                return subprocess.run(
                    ssh_command(route.endpoint, command, timeout=args.timeout, known_hosts_file=known_hosts),
                    check=False,
                ).returncode
            probe = ["sh", "-c", "printf 'hostname=%s\\nuser=%s\\n' \"$(hostname)\" \"$(id -un)\""]
            return subprocess.run(
                route_command(route, probe, timeout=args.timeout, known_hosts_file=known_hosts),
                check=False,
            ).returncode

        if args.action == "run":
            command = args.command[1:] if args.command[:1] == ["--"] else args.command
            if not command:
                parser.error("sc-remote run requires a command after --")
            if route.kind == "local":
                return subprocess.run(command, check=False).returncode
            ensure_known_hosts_parent(known_hosts)
            return subprocess.run(
                route_command(route, command, timeout=args.timeout, known_hosts_file=known_hosts),
                check=False,
            ).returncode

        if args.action == "shell":
            if route.kind == "local":
                shell = os.environ.get("SHELL", "/bin/sh")
                os.execvp(shell, [shell])
            ensure_known_hosts_parent(known_hosts)
            command = ssh_command(route.endpoint, [], timeout=DEFAULT_CONNECT_TIMEOUT, known_hosts_file=known_hosts)
            if route.kind == "broker":
                command.insert(-1, "-t")
                command.append(shlex.join(["sc-remote", "shell", target.alias]))
            os.execvp("ssh", command)

        if args.action == "herdr":
            if not target.supports_herdr:
                raise UserError(f"target {target.alias!r} does not have verified Herdr support")
            if route.kind == "local":
                os.execvp("herdr", ["herdr", "--session", args.session])
            if route.kind == "direct":
                os.execvp("herdr", ["herdr", "--remote", route.endpoint, "--session", args.session])
            ensure_known_hosts_parent(known_hosts)
            command = ssh_command(route.endpoint, [], timeout=DEFAULT_CONNECT_TIMEOUT, known_hosts_file=known_hosts)
            command.insert(-1, "-t")
            command.append(shlex.join(["sc-remote", "herdr", target.alias, "--session", args.session]))
            os.execvp("ssh", command)

        raise AssertionError(f"unhandled action {args.action}")
    except (FileNotFoundError, json.JSONDecodeError, OSError, UserError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
