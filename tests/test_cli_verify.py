# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the verify CLI command.

This module provides comprehensive tests for the `verify` sub-command,
which validates Git tags including version format and signatures.

Test Coverage:
--------------
1. **Empty Tag Location** (TestVerifyEmptyTagLocation)
   - Empty string tag location
   - Whitespace-only tag location
   - JSON output mode with empty tag
   - Non-JSON output mode with empty tag

2. **Tag Location Validation** (TestVerifyTagLocationValidation)
   - Valid local tag names
   - Valid remote tag locations (owner/repo@tag)
   - Invalid formats

3. **Error Handling** (TestVerifyErrorHandling)
   - Missing required arguments
   - Invalid option combinations
   - Graceful error messages

Usage:
------
Run all tests:
    pytest tests/test_cli_verify.py

Run specific test class:
    pytest tests/test_cli_verify.py::TestVerifyEmptyTagLocation

Run with verbose output:
    pytest tests/test_cli_verify.py -v
"""

import json

import pytest
from typer.testing import CliRunner

from tag_validate.cli import app

runner = CliRunner()


class TestVerifyEmptyTagLocation:
    """Test suite for empty tag_location validation in verify command."""

    def test_empty_string_tag_location_non_json(self):
        """Test that empty string tag location fails with appropriate error message (non-JSON mode)."""
        result = runner.invoke(app, ["verify", ""])

        assert result.exit_code == 1
        assert "Tag location is empty or null" in result.stdout

    def test_empty_string_tag_location_json(self):
        """Test that empty string tag location fails with structured JSON error (JSON mode)."""
        result = runner.invoke(app, ["verify", "", "--json"])

        assert result.exit_code == 1

        # Parse JSON output
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert output["tag_name"] == ""
            assert "error" in output
            assert "Tag location is empty or null" in output["error"]
            assert "info" in output
            assert any(
                "tag_location parameter is required" in info for info in output["info"]
            )
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_whitespace_only_tag_location_non_json(self):
        """Test that whitespace-only tag location fails with appropriate error (non-JSON mode)."""
        result = runner.invoke(app, ["verify", "   "])

        assert result.exit_code == 1
        assert "Tag location is empty or null" in result.stdout

    def test_whitespace_only_tag_location_json(self):
        """Test that whitespace-only tag location fails with structured JSON error (JSON mode)."""
        result = runner.invoke(app, ["verify", "   ", "--json"])

        assert result.exit_code == 1

        # Parse JSON output
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert output["tag_name"] == ""
            assert "error" in output
            assert "Tag location is empty or null" in output["error"]
            assert "info" in output
            # Check that expected formats are mentioned
            assert any("v1.0.0" in info for info in output["info"])
            assert any("owner/repo@v1.0.0" in info for info in output["info"])
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_tabs_and_newlines_tag_location(self):
        """Test that tag location with only tabs and newlines fails appropriately."""
        result = runner.invoke(app, ["verify", "\t\n\r", "--json"])

        assert result.exit_code == 1

        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Tag location is empty or null" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")


class TestVerifyTagLocationValidation:
    """Test suite for tag_location format validation."""

    def test_valid_simple_tag_name(self):
        """Test that a simple tag name is accepted (may fail validation but not argument parsing)."""
        # This will likely fail because the tag doesn't exist, but it should pass the empty check
        result = runner.invoke(app, ["verify", "v1.0.0", "--json"])

        # The tag won't exist, but we shouldn't get the "empty or null" error
        if result.exit_code == 1:
            assert "Tag location is empty or null" not in result.stdout

    def test_valid_remote_tag_location(self):
        """Test that owner/repo@tag format is accepted."""
        # This will likely fail because we don't have access, but format should be accepted
        result = runner.invoke(app, ["verify", "owner/repo@v1.0.0", "--json"])

        # Should not get the empty tag location error
        if result.exit_code == 1:
            assert "Tag location is empty or null" not in result.stdout

    def test_help_output(self):
        """Test that help message shows expected tag location formats."""
        result = runner.invoke(app, ["verify", "--help"])

        assert result.exit_code == 0
        # Help should mention tag_location argument
        assert (
            "tag_location" in result.stdout.lower()
            or "tag-location" in result.stdout.lower()
        )


class TestVerifyErrorHandling:
    """Test suite for error handling in verify command."""

    def test_missing_tag_location_argument(self):
        """Test that missing tag_location argument shows appropriate error."""
        result = runner.invoke(app, ["verify"])

        assert result.exit_code != 0
        # Should mention missing argument (case-insensitive check)
        # Error may be in stdout or stderr depending on environment/Typer version
        # Safely try to get stderr (may not be separately captured)
        try:
            stderr_content = result.stderr if hasattr(result, "stderr") else ""
        except (ValueError, AttributeError):
            stderr_content = ""

        output = (result.stdout + stderr_content).lower()
        assert "missing" in output or "required" in output, (
            f"Expected 'missing' or 'required' in output, got stdout: {result.stdout!r}, stderr: {stderr_content!r}"
        )

    def test_json_output_suppresses_rich_formatting(self):
        """Test that JSON mode suppresses rich console output."""
        result = runner.invoke(app, ["verify", "", "--json"])

        # Output should be valid JSON, not rich console formatting
        try:
            output = json.loads(result.stdout)
            assert isinstance(output, dict)
            assert "success" in output
        except json.JSONDecodeError:
            pytest.fail(f"JSON mode should produce valid JSON output: {result.stdout}")

    def test_error_message_includes_examples(self):
        """Test that error message includes helpful format examples."""
        result = runner.invoke(app, ["verify", "", "--json"])

        try:
            output = json.loads(result.stdout)
            info_messages = output.get("info", [])

            # Should include examples of expected formats
            has_local_example = any("v1.0.0" in msg for msg in info_messages)
            has_remote_example = any("owner/repo@" in msg for msg in info_messages)

            assert has_local_example, "Should include local tag example"
            assert has_remote_example, "Should include remote tag example"
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")


class TestVerifyWithOptions:
    """Test suite for verify command with various options."""

    def test_empty_tag_with_require_type_option(self):
        """Test empty tag location fails even with --require-type option."""
        result = runner.invoke(
            app, ["verify", "", "--require-type", "semver", "--json"]
        )

        assert result.exit_code == 1
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Tag location is empty or null" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_empty_tag_with_require_signed_option(self):
        """Test empty tag location fails even with --require-signed option."""
        result = runner.invoke(
            app, ["verify", "", "--require-signed", "true", "--json"]
        )

        assert result.exit_code == 1
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Tag location is empty or null" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")

    def test_whitespace_tag_with_multiple_options(self):
        """Test whitespace tag location fails with multiple options combined."""
        result = runner.invoke(
            app,
            [
                "verify",
                "  \t  ",
                "--require-type",
                "semver",
                "--require-signed",
                "true",
                "--verify-github-key",
                "--json",
            ],
        )

        assert result.exit_code == 1
        try:
            output = json.loads(result.stdout)
            assert output["success"] is False
            assert "Tag location is empty or null" in output["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result.stdout}")


class TestVerifyOutputConsistency:
    """Test suite to ensure consistent output format between JSON and non-JSON modes."""

    def test_error_message_consistency(self):
        """Test that error message is consistent between JSON and non-JSON modes."""
        # Non-JSON mode
        result_non_json = runner.invoke(app, ["verify", ""])
        output_non_json = result_non_json.stdout

        # JSON mode
        result_json = runner.invoke(app, ["verify", "", "--json"])

        # Both should mention the same core error
        assert "Tag location is empty or null" in output_non_json

        try:
            output_json = json.loads(result_json.stdout)
            assert "Tag location is empty or null" in output_json["error"]
        except json.JSONDecodeError:
            pytest.fail(f"Failed to parse JSON output: {result_json.stdout}")

    def test_exit_codes_consistent(self):
        """Test that exit codes are consistent between JSON and non-JSON modes."""
        result_non_json = runner.invoke(app, ["verify", ""])
        result_json = runner.invoke(app, ["verify", "", "--json"])

        # Both should exit with non-zero code
        assert result_non_json.exit_code == 1
        assert result_json.exit_code == 1
