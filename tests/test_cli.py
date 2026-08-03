from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sc_remote import cli


def sample_v2() -> dict:
    return {
        "version": 2,
        "targets": [
            {
                "alias": "laptop",
                "inventory_host": "personal-laptop",
                "role": "workstation",
                "platform": "linux",
                "supports_herdr": True,
                "ssh_target": "me@laptop.example",
                "inventory_path": "inventory/hosts/laptop.yaml",
            },
            {
                "alias": "server",
                "inventory_host": "server",
                "role": "app-server",
                "platform": "linux",
                "supports_herdr": False,
                "ssh_target": "admin@server.example",
                "inventory_path": "inventory/hosts/server.yaml",
            },
        ],
        "sources": {
            "laptop": {
                "name": "laptop",
                "role": "workstation",
                "detect_hostnames": ["laptop"],
                "local_target": "laptop",
                "alias_mode": "inventory_ssh_target",
                "direct_targets": ["server"],
                "endpoint_overrides": {},
                "fallback_bastion": "",
            }
        },
    }


class TemporaryEnvironment(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.environment = patch.dict(
            os.environ,
            {
                "HOME": str(self.root / "home"),
                "XDG_CONFIG_HOME": str(self.root / "config"),
                "XDG_DATA_HOME": str(self.root / "data"),
                "XDG_STATE_HOME": str(self.root / "state"),
                "SC_REMOTE_SOURCE": "laptop",
            },
            clear=False,
        )
        self.environment.start()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temporary.cleanup()

    def run_cli(self, *arguments: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = cli.main(arguments)
        return result, stdout.getvalue(), stderr.getvalue()


class FleetTests(TemporaryEnvironment):
    def test_version_two_manifest_migrates_without_inventory_dependency(self) -> None:
        fleet = cli.fleet_from_dict(sample_v2())
        rendered = cli.fleet_to_dict(fleet)

        self.assertEqual(rendered["version"], 3)
        self.assertEqual(rendered["targets"][1]["endpoint"], "admin@server.example")
        self.assertNotIn("inventory_path", rendered["targets"][1])
        route = cli.route_for(fleet, "laptop", "server")
        self.assertEqual((route.kind, route.endpoint), ("direct", "admin@server.example"))

    def test_host_add_and_remove_update_routes(self) -> None:
        code, _, error = self.run_cli("init", "--source", "laptop", "--role", "workstation")
        self.assertEqual((code, error), (0, ""))

        code, output, error = self.run_cli(
            "--source",
            "laptop",
            "host",
            "add",
            "server",
            "--endpoint",
            "admin@server.example",
            "--role",
            "app-server",
        )
        self.assertEqual((code, error), (0, ""))
        self.assertIn("added=server", output)
        fleet = cli.load_fleet(cli.local_fleet_path())
        self.assertEqual(cli.route_for(fleet, "laptop", "server").kind, "direct")

        code, output, error = self.run_cli("host", "remove", "server")
        self.assertEqual((code, error), (0, ""))
        self.assertIn("removed=server", output)
        fleet = cli.load_fleet(cli.local_fleet_path())
        self.assertEqual([target.alias for target in fleet.targets], ["laptop"])
        self.assertEqual(fleet.sources["laptop"].direct_targets, [])

    def test_local_target_cannot_be_removed(self) -> None:
        self.run_cli("init", "--source", "laptop")
        code, _, error = self.run_cli("host", "remove", "laptop")
        self.assertEqual(code, 2)
        self.assertIn("active local target", error)

    def test_private_key_and_secret_fields_are_rejected(self) -> None:
        self.run_cli("init", "--source", "laptop")
        code, _, error = self.run_cli(
            "host",
            "add",
            "bad",
            "--endpoint",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
        )
        self.assertEqual(code, 2)
        self.assertIn("private-key material", error)

        payload = sample_v2()
        payload["api_token"] = "not-actually-a-token"
        with self.assertRaises(cli.UserError):
            cli.fleet_from_dict(payload)

    def test_backend_url_with_inline_credentials_is_rejected(self) -> None:
        code, _, error = self.run_cli("backend", "set", "https://user:password@example.com/fleet.git")
        self.assertEqual(code, 2)
        self.assertIn("inline credentials", error)

    def test_bastion_routes_are_source_aware(self) -> None:
        fleet = cli.FleetConfig(
            targets=[
                cli.FleetTarget("laptop"),
                cli.FleetTarget("bastion", "ops@bastion.example"),
                cli.FleetTarget("server", "root@server.internal"),
            ],
            sources={
                "laptop": cli.SourceProfile(
                    "laptop",
                    "workstation",
                    ["laptop"],
                    "laptop",
                    ["bastion"],
                    {},
                    "bastion",
                ),
                "bastion": cli.SourceProfile(
                    "bastion",
                    "agent-bastion",
                    ["bastion"],
                    "bastion",
                    ["server"],
                    {},
                ),
            },
        )
        cli.validate_fleet(fleet)
        route = cli.route_for(fleet, "laptop", "server")
        self.assertEqual((route.kind, route.bastion, route.endpoint), (
            "broker",
            "bastion",
            "ops@bastion.example",
        ))


class BackendTests(TemporaryEnvironment):
    def setUp(self) -> None:
        super().setUp()
        self.remote = self.root / "remote.git"
        subprocess.run(
            ["git", "init", "--bare", "--initial-branch=main", str(self.remote)],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_empty_git_backend_bootstraps_and_syncs_mutations(self) -> None:
        self.assertEqual(self.run_cli("init", "--source", "laptop")[0], 0)
        self.assertEqual(self.run_cli("backend", "set", str(self.remote))[0], 0)
        code, output, error = self.run_cli("sync")
        self.assertEqual((code, error), (0, ""))
        self.assertIn("revision=", output)

        code, _, error = self.run_cli(
            "--source",
            "laptop",
            "host",
            "add",
            "server",
            "--endpoint",
            "admin@server.example",
        )
        self.assertEqual((code, error), (0, ""))

        clone = self.root / "verification"
        subprocess.run(["git", "clone", str(self.remote), str(clone)], check=True, capture_output=True)
        data = json.loads((clone / "fleet.json").read_text())
        self.assertEqual({item["alias"] for item in data["targets"]}, {"laptop", "server"})
        tracked = subprocess.run(
            ["git", "ls-files"], cwd=clone, check=True, capture_output=True, text=True
        ).stdout.splitlines()
        self.assertEqual(tracked, ["fleet.json"])

    def test_second_machine_can_clone_backend(self) -> None:
        self.run_cli("init", "--source", "laptop")
        self.run_cli("backend", "set", str(self.remote))
        self.assertEqual(self.run_cli("sync")[0], 0)

        second = self.root / "second"
        with patch.dict(
            os.environ,
            {
                "HOME": str(second / "home"),
                "XDG_CONFIG_HOME": str(second / "config"),
                "XDG_DATA_HOME": str(second / "data"),
                "XDG_STATE_HOME": str(second / "state"),
                "SC_REMOTE_SOURCE": "laptop",
            },
        ):
            self.assertEqual(self.run_cli("backend", "set", str(self.remote))[0], 0)
            code, _, error = self.run_cli("sync")
            self.assertEqual((code, error), (0, ""))
            fleet = cli.load_fleet(cli.backend_fleet_path())
            self.assertEqual([target.alias for target in fleet.targets], ["laptop"])


if __name__ == "__main__":
    unittest.main()
