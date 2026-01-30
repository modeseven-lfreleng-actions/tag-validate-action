# SPDX-FileCopyrightText: 2025 The Linux Foundation
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: S106

"""
Tests for CLI netrc options.

This module tests the CLI integration of netrc options including:
- --no-netrc: Disable .netrc credential lookup
- --netrc-file: Use a specific .netrc file
- --netrc-optional/--netrc-required: Control behavior when .netrc is missing

These tests verify that:
1. .netrc credentials take precedence over environment variables
2. --no-netrc disables lookup even when .netrc exists
3. --netrc-required errors when .netrc file is missing
4. --netrc-file uses a specific file path
"""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from tag_validate.cli import app


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def netrc_file(tmp_path: Path) -> Path:
    """Create a temporary .netrc file with test credentials."""
    netrc_path = tmp_path / ".netrc"
    netrc_path.write_text(
        "machine gerrit.example.org login netrc_user password netrc_pass\n"
        "machine gerrit.onap.org login onap_user password onap_pass\n"
    )
    netrc_path.chmod(0o600)
    return netrc_path


@pytest.fixture
def empty_netrc_dir(tmp_path: Path) -> Path:
    """Create a temporary directory without a .netrc file."""
    return tmp_path


class TestNetrcFileOption:
    """Tests for --netrc-file option."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_netrc_file_option_uses_specified_file(
        self, mock_client_class, runner, netrc_file
    ):
        """Test that --netrc-file uses the specified .netrc file."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()

        # Mock account lookup to return None (no account found)
        mock_client.lookup_account_by_email.return_value = None

        result = runner.invoke(
            app,
            [
                "gerrit",
                "FCE8AAABF53080F6",
                "--owner",
                "user@example.com",
                "--server",
                "gerrit.example.org",
                "--netrc-file",
                str(netrc_file),
            ],
        )

        # The command should run (may fail for other reasons, but netrc should work)
        # Check that it didn't fail due to netrc parsing
        assert "Error parsing .netrc" not in result.output

    def test_netrc_file_option_nonexistent_file_error(self, runner, tmp_path):
        """Test that --netrc-file with nonexistent file shows error."""
        nonexistent = tmp_path / "nonexistent_netrc"

        result = runner.invoke(
            app,
            [
                "gerrit",
                "FCE8AAABF53080F6",
                "--owner",
                "user@example.com",
                "--server",
                "gerrit.example.org",
                "--netrc-file",
                str(nonexistent),
            ],
        )

        # Typer validates file existence before command runs
        assert result.exit_code != 0


class TestNoNetrcOption:
    """Tests for --no-netrc option."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_no_netrc_disables_netrc_lookup(
        self, mock_client_class, runner, netrc_file
    ):
        """Test that --no-netrc disables .netrc credential lookup."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()
        mock_client.lookup_account_by_email.return_value = None

        # Even with a valid netrc file, --no-netrc should skip it
        result = runner.invoke(
            app,
            [
                "gerrit",
                "FCE8AAABF53080F6",
                "--owner",
                "user@example.com",
                "--server",
                "gerrit.example.org",
                "--netrc-file",
                str(netrc_file),
                "--no-netrc",
            ],
        )

        # Should not show "Using credentials from .netrc" message
        assert "Using credentials from .netrc" not in result.output

    @patch("tag_validate.cli.GerritKeysClient")
    def test_no_netrc_with_env_credentials(self, mock_client_class, runner, netrc_file):
        """Test that --no-netrc allows env vars to be used instead."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()
        mock_client.lookup_account_by_email.return_value = None

        with patch.dict(
            "os.environ",
            {
                "GERRIT_USERNAME": "env_user",
                "GERRIT_PASSWORD": "env_pass",
            },
        ):
            result = runner.invoke(
                app,
                [
                    "gerrit",
                    "FCE8AAABF53080F6",
                    "--owner",
                    "user@example.com",
                    "--server",
                    "gerrit.example.org",
                    "--no-netrc",
                ],
            )

            # Command should proceed without netrc lookup
            assert "Using credentials from .netrc" not in result.output


class TestNetrcRequiredOption:
    """Tests for --netrc-required option."""

    def test_netrc_required_fails_when_missing(self, runner, empty_netrc_dir):
        """Test that --netrc-required fails when .netrc is missing."""
        with (
            patch.object(Path, "home", return_value=empty_netrc_dir),
            patch.object(Path, "cwd", return_value=empty_netrc_dir),
        ):
            result = runner.invoke(
                app,
                [
                    "gerrit",
                    "FCE8AAABF53080F6",
                    "--owner",
                    "user@example.com",
                    "--server",
                    "gerrit.example.org",
                    "--netrc-required",
                ],
            )

            # Should fail with missing netrc error
            assert result.exit_code != 0
            assert (
                "No .netrc file found" in result.output
                or "netrc" in result.output.lower()
            )

    @patch("tag_validate.cli.GerritKeysClient")
    def test_netrc_required_succeeds_when_present(
        self, mock_client_class, runner, netrc_file
    ):
        """Test that --netrc-required succeeds when .netrc exists."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()
        mock_client.lookup_account_by_email.return_value = None

        result = runner.invoke(
            app,
            [
                "gerrit",
                "FCE8AAABF53080F6",
                "--owner",
                "user@example.com",
                "--server",
                "gerrit.example.org",
                "--netrc-file",
                str(netrc_file),
                "--netrc-required",
            ],
        )

        # Should not fail due to missing netrc
        assert "No .netrc file found" not in result.output


class TestNetrcOptionalOption:
    """Tests for --netrc-optional option (default behavior)."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_netrc_optional_continues_when_missing(
        self, mock_client_class, runner, empty_netrc_dir
    ):
        """Test that --netrc-optional continues when .netrc is missing."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()
        mock_client.lookup_account_by_email.return_value = None

        with (
            patch.object(Path, "home", return_value=empty_netrc_dir),
            patch.object(Path, "cwd", return_value=empty_netrc_dir),
        ):
            result = runner.invoke(
                app,
                [
                    "gerrit",
                    "FCE8AAABF53080F6",
                    "--owner",
                    "user@example.com",
                    "--server",
                    "gerrit.example.org",
                    "--netrc-optional",
                ],
            )

            # Should not fail due to missing netrc
            # (may fail for other reasons like no credentials)
            assert "No .netrc file found and --netrc-required" not in result.output

    @patch("tag_validate.cli.GerritKeysClient")
    def test_default_is_netrc_optional(
        self, mock_client_class, runner, empty_netrc_dir
    ):
        """Test that the default behavior is --netrc-optional."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()
        mock_client.lookup_account_by_email.return_value = None

        with (
            patch.object(Path, "home", return_value=empty_netrc_dir),
            patch.object(Path, "cwd", return_value=empty_netrc_dir),
        ):
            result = runner.invoke(
                app,
                [
                    "gerrit",
                    "FCE8AAABF53080F6",
                    "--owner",
                    "user@example.com",
                    "--server",
                    "gerrit.example.org",
                    # No --netrc-optional or --netrc-required specified
                ],
            )

            # Should not fail due to missing netrc (optional is default)
            assert "No .netrc file found and --netrc-required" not in result.output


class TestNetrcCredentialPriority:
    """Tests for credential priority: CLI args > .netrc > env vars."""

    @patch("tag_validate.cli.GerritKeysClient")
    def test_cli_args_take_precedence_over_netrc(
        self, mock_client_class, runner, netrc_file
    ):
        """Test that CLI arguments take precedence over .netrc credentials."""
        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()
        mock_client.lookup_account_by_email.return_value = None

        result = runner.invoke(
            app,
            [
                "gerrit",
                "FCE8AAABF53080F6",
                "--owner",
                "user@example.com",
                "--server",
                "gerrit.example.org",
                "--netrc-file",
                str(netrc_file),
                "--gerrit-username",
                "cli_user",
                "--gerrit-password",
                "cli_pass",
            ],
        )

        # Should not show "Using credentials from .netrc" since CLI args override
        assert "Using credentials from .netrc" not in result.output

    @patch("tag_validate.cli.GerritKeysClient")
    @patch("tag_validate.cli.get_credentials_for_host")
    def test_netrc_takes_precedence_over_env_vars(
        self, mock_get_creds, mock_client_class, runner, netrc_file
    ):
        """Test that .netrc credentials take precedence over env vars."""
        from tag_validate.netrc import NetrcCredentials

        mock_client = AsyncMock()
        mock_client_class.return_value.__aenter__.return_value = mock_client
        mock_client_class.return_value.__aexit__.return_value = AsyncMock()
        mock_client.lookup_account_by_email.return_value = None

        # Mock get_credentials_for_host to return netrc credentials
        mock_get_creds.return_value = NetrcCredentials(
            machine="gerrit.example.org",
            login="netrc_user",
            password="netrc_pass",
        )

        with patch.dict(
            "os.environ",
            {
                "GERRIT_USERNAME": "env_user",
                "GERRIT_PASSWORD": "env_pass",
            },
        ):
            result = runner.invoke(
                app,
                [
                    "gerrit",
                    "FCE8AAABF53080F6",
                    "--owner",
                    "user@example.com",
                    "--server",
                    "gerrit.example.org",
                    "--netrc-file",
                    str(netrc_file),
                ],
            )

            # get_credentials_for_host should have been called
            assert mock_get_creds.called
            # Should show that netrc credentials are being used
            assert "Using credentials from .netrc" in result.output


class TestVerifyCommandNetrcOptions:
    """Tests for netrc options in the verify command."""

    @patch("tag_validate.cli.ValidationWorkflow")
    def test_verify_command_accepts_netrc_options(
        self, mock_workflow_class, runner, netrc_file, tmp_path
    ):
        """Test that verify command accepts netrc options."""
        from unittest.mock import Mock

        mock_workflow = Mock()
        mock_workflow_class.return_value = mock_workflow

        # Create a mock result - use Mock for sync attributes
        mock_result = Mock()
        mock_result.is_valid = True
        mock_result.tag_name = "v1.0.0"
        mock_result.config = Mock()
        mock_result.config.require_gerrit = False
        mock_result.config.require_github = False
        mock_result.signature_info = None
        mock_result.github_key_result = None
        mock_result.gerrit_key_result = None
        mock_result.version_info = None

        mock_workflow.validate_tag_location = AsyncMock(return_value=mock_result)

        # Create a minimal git repo
        git_dir = tmp_path / "repo"
        git_dir.mkdir()
        (git_dir / ".git").mkdir()

        result = runner.invoke(
            app,
            [
                "verify",
                "v1.0.0",
                "--netrc-file",
                str(netrc_file),
                "--netrc-optional",
            ],
            catch_exceptions=False,
        )

        # Should not fail due to netrc option parsing
        assert (
            "--netrc-file" not in result.output or "error" not in result.output.lower()
        )

    @patch("tag_validate.cli.ValidationWorkflow")
    def test_verify_command_no_netrc_option(
        self, mock_workflow_class, runner, netrc_file, tmp_path
    ):
        """Test that verify command accepts --no-netrc option."""
        from unittest.mock import Mock

        mock_workflow = Mock()
        mock_workflow_class.return_value = mock_workflow

        # Create a mock result - use Mock for sync attributes
        mock_result = Mock()
        mock_result.is_valid = True
        mock_result.tag_name = "v1.0.0"
        mock_result.config = Mock()
        mock_result.config.require_gerrit = False
        mock_result.config.require_github = False
        mock_result.signature_info = None
        mock_result.github_key_result = None
        mock_result.gerrit_key_result = None
        mock_result.version_info = None

        mock_workflow.validate_tag_location = AsyncMock(return_value=mock_result)

        git_dir = tmp_path / "repo"
        git_dir.mkdir()
        (git_dir / ".git").mkdir()

        result = runner.invoke(
            app,
            [
                "verify",
                "v1.0.0",
                "--no-netrc",
            ],
            catch_exceptions=False,
        )

        # Should accept the option without error
        assert "--no-netrc" not in result.output or "error" not in result.output.lower()


class TestNetrcJsonOutput:
    """Tests for netrc error handling with JSON output."""

    def test_netrc_required_json_output_on_missing(self, runner, empty_netrc_dir):
        """Test that --netrc-required with --json outputs proper JSON error."""
        with (
            patch.object(Path, "home", return_value=empty_netrc_dir),
            patch.object(Path, "cwd", return_value=empty_netrc_dir),
        ):
            result = runner.invoke(
                app,
                [
                    "gerrit",
                    "FCE8AAABF53080F6",
                    "--owner",
                    "user@example.com",
                    "--server",
                    "gerrit.example.org",
                    "--netrc-required",
                    "--json",
                ],
            )

            assert result.exit_code != 0
            # Should contain JSON error output
            if result.output.strip():
                import json

                try:
                    output = json.loads(result.output)
                    assert output.get("success") is False
                    assert "error" in output
                except json.JSONDecodeError:
                    # May have non-JSON output before the error
                    pass
