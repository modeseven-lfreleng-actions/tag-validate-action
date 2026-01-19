# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Tests for 'both' version type handling.

This module tests tags that are valid as both SemVer and CalVer,
ensuring consistent behavior across validate and verify commands.
"""

import json

import pytest
from typer.testing import CliRunner

from tag_validate.cli import app
from tag_validate.validation import TagValidator

runner = CliRunner()


class TestBothVersionTypeValidation:
    """Test 'both' version type in validation."""

    def test_validator_detects_both(self):
        """Test that validator detects when version is valid as both."""
        validator = TagValidator()

        # 2024.1.15 is valid as both CalVer (2024.1.15) and SemVer (2024.1.15)
        result = validator.validate_version("2024.1.15")

        assert result.is_valid is True
        assert result.version_type == "both"
        assert result.normalized == "2024.1.15"

    def test_validator_both_with_prefix(self):
        """Test both detection with v prefix."""
        validator = TagValidator()

        result = validator.validate_version("v2024.1.15")

        assert result.is_valid is True
        assert result.version_type == "both"
        assert result.has_prefix is True

    def test_validator_semver_only(self):
        """Test that pure SemVer is not marked as both."""
        validator = TagValidator()

        # 1.2.3 is SemVer but not valid CalVer (year < 2000)
        result = validator.validate_version("1.2.3")

        assert result.is_valid is True
        assert result.version_type == "semver"

    def test_validator_calver_only(self):
        """Test that pure CalVer is not marked as both."""
        validator = TagValidator()

        # 2024.01.15.1 is CalVer (4 components) but not valid SemVer
        result = validator.validate_version("2024.01.15.1")

        assert result.is_valid is True
        assert result.version_type == "calver"

    def test_validator_both_examples(self):
        """Test multiple examples that should be 'both'."""
        validator = TagValidator()

        both_examples = [
            "2024.1.1",
            "2024.1.15",
            "2024.2.3",
            "2024.11.12",  # Valid CalVer date and SemVer version
            "v2025.1.10",
        ]

        for version in both_examples:
            result = validator.validate_version(version)
            assert result.is_valid is True, f"{version} should be valid"
            assert result.version_type == "both", f"{version} should be 'both'"


class TestBothVersionTypeValidateCommand:
    """Test 'both' version type in validate command."""

    def test_validate_both_no_requirement(self):
        """Test validate command with both type and no requirement."""
        result = runner.invoke(app, ["validate", "2024.1.15"])

        assert result.exit_code == 0
        assert "BOTH" in result.stdout
        assert "Valid" in result.stdout or "✅" in result.stdout

    def test_validate_both_require_semver(self):
        """Test that 'both' satisfies semver requirement."""
        result = runner.invoke(
            app, ["validate", "2024.1.15", "--require-type", "semver"]
        )

        assert result.exit_code == 0
        assert "BOTH" in result.stdout

    def test_validate_both_require_calver(self):
        """Test that 'both' satisfies calver requirement."""
        result = runner.invoke(
            app, ["validate", "2024.1.15", "--require-type", "calver"]
        )

        assert result.exit_code == 0
        assert "BOTH" in result.stdout

    def test_validate_both_require_both(self):
        """Test that 'both' satisfies requirement for both types."""
        result = runner.invoke(
            app, ["validate", "2024.1.15", "--require-type", "semver,calver"]
        )

        assert result.exit_code == 0
        assert "BOTH" in result.stdout

    def test_validate_both_require_both_space_separated(self):
        """Test space-separated requirement."""
        result = runner.invoke(
            app, ["validate", "2024.1.15", "--require-type", "semver calver"]
        )

        assert result.exit_code == 0
        assert "BOTH" in result.stdout

    def test_validate_both_json_output(self):
        """Test JSON output for both type."""
        result = runner.invoke(app, ["validate", "2024.1.15", "--json"])

        assert result.exit_code == 0

        output = json.loads(result.stdout)
        assert output["success"] is True
        assert output["version_type"] == "both"
        assert output["is_valid"] is True

    def test_validate_both_require_semver_json(self):
        """Test JSON output with semver requirement."""
        result = runner.invoke(
            app, ["validate", "2024.1.15", "--require-type", "semver", "--json"]
        )

        assert result.exit_code == 0

        output = json.loads(result.stdout)
        assert output["success"] is True
        assert output["version_type"] == "both"

    def test_validate_semver_only_fails_calver_requirement(self):
        """Test that pure SemVer fails CalVer-only requirement."""
        result = runner.invoke(app, ["validate", "1.2.3", "--require-type", "calver"])

        assert result.exit_code == 1
        assert "mismatch" in result.stdout.lower()

    def test_validate_calver_only_fails_semver_requirement(self):
        """Test that pure CalVer fails SemVer-only requirement."""
        result = runner.invoke(
            app, ["validate", "2024.01.15.1", "--require-type", "semver"]
        )

        assert result.exit_code == 1
        assert "mismatch" in result.stdout.lower()


class TestBothVersionTypeVerifyCommand:
    """Test 'both' version type in verify command (using validate logic)."""

    # Note: These tests use the validate subcommand since verify requires actual git tags
    # The version type checking logic is shared via helper functions

    def test_helper_check_version_type_match_both_with_semver(self):
        """Test helper function: both matches semver requirement."""
        from tag_validate.cli import check_version_type_match

        assert check_version_type_match("both", ["semver"]) is True

    def test_helper_check_version_type_match_both_with_calver(self):
        """Test helper function: both matches calver requirement."""
        from tag_validate.cli import check_version_type_match

        assert check_version_type_match("both", ["calver"]) is True

    def test_helper_check_version_type_match_both_with_both(self):
        """Test helper function: both matches semver,calver requirement."""
        from tag_validate.cli import check_version_type_match

        assert check_version_type_match("both", ["semver", "calver"]) is True

    def test_helper_check_version_type_match_semver_only(self):
        """Test helper function: semver only matches semver requirement."""
        from tag_validate.cli import check_version_type_match

        assert check_version_type_match("semver", ["semver"]) is True
        assert check_version_type_match("semver", ["calver"]) is False

    def test_helper_check_version_type_match_calver_only(self):
        """Test helper function: calver only matches calver requirement."""
        from tag_validate.cli import check_version_type_match

        assert check_version_type_match("calver", ["calver"]) is True
        assert check_version_type_match("calver", ["semver"]) is False

    def test_helper_check_version_type_match_or_logic(self):
        """Test helper function: OR logic for multiple requirements."""
        from tag_validate.cli import check_version_type_match

        # SemVer should match when either semver or calver is required
        assert check_version_type_match("semver", ["semver", "calver"]) is True
        assert check_version_type_match("calver", ["semver", "calver"]) is True

    def test_helper_check_version_type_match_no_requirement(self):
        """Test helper function: no requirement always matches."""
        from tag_validate.cli import check_version_type_match

        assert check_version_type_match("semver", []) is True
        assert check_version_type_match("calver", []) is True
        assert check_version_type_match("both", []) is True
        assert check_version_type_match("unknown", []) is True


class TestBothVersionTypeEdgeCases:
    """Test edge cases for both version type."""

    def test_both_with_development_suffix(self):
        """Test both type with development suffix."""
        validator = TagValidator()

        result = validator.validate_version("2024.1.15-beta")

        assert result.is_valid is True
        assert result.version_type == "both"
        assert result.is_development is True

    def test_validate_both_with_development_suffix(self):
        """Test validate command with both type and development suffix."""
        result = runner.invoke(app, ["validate", "2024.1.15-alpha"])

        assert result.exit_code == 0
        assert "BOTH" in result.stdout

    def test_invalid_day_not_both(self):
        """Test that invalid CalVer day prevents both classification."""
        validator = TagValidator()

        # 2024.1.0 is valid SemVer but invalid CalVer (day must be 1-31)
        result = validator.validate_version("2024.1.0")

        assert result.is_valid is True
        assert result.version_type == "semver"  # Not both

    def test_invalid_month_not_both(self):
        """Test that invalid CalVer month prevents both classification."""
        validator = TagValidator()

        # 2024.13.1 is valid SemVer but invalid CalVer (month must be 1-12)
        result = validator.validate_version("2024.13.1")

        assert result.is_valid is True
        assert result.version_type == "semver"  # Not both

    def test_large_year_both(self):
        """Test that large year values work as both."""
        validator = TagValidator()

        result = validator.validate_version("2099.1.15")

        assert result.is_valid is True
        assert result.version_type == "both"

    def test_min_valid_year_both(self):
        """Test that various years work as both."""
        validator = TagValidator()

        # Years in CalVer range should be both
        result = validator.validate_version("2000.1.1")
        assert result.is_valid is True
        assert result.version_type == "both"

        # Even older years can be both if they meet all criteria
        result = validator.validate_version("1999.1.1")
        assert result.is_valid is True
        assert result.version_type == "both"


class TestBothVersionTypeConsistency:
    """Test consistency between validate and verify commands."""

    def test_parse_multi_value_helper(self):
        """Test parse_multi_value_option helper function."""
        from tag_validate.cli import parse_multi_value_option

        # Comma-separated
        assert parse_multi_value_option("gpg,ssh") == ["gpg", "ssh"]
        assert parse_multi_value_option("semver,calver") == ["semver", "calver"]

        # Space-separated
        assert parse_multi_value_option("gpg ssh") == ["gpg", "ssh"]
        assert parse_multi_value_option("semver calver") == ["semver", "calver"]

        # Single value
        assert parse_multi_value_option("gpg") == ["gpg"]
        assert parse_multi_value_option("semver") == ["semver"]

        # None/empty
        assert parse_multi_value_option(None) == []
        assert parse_multi_value_option("") == []

        # With extra whitespace
        assert parse_multi_value_option("gpg , ssh ") == ["gpg", "ssh"]
        assert parse_multi_value_option("  semver   calver  ") == ["semver", "calver"]

    def test_validate_version_types_helper_valid(self):
        """Test validate_version_types helper with valid types."""
        from tag_validate.cli import validate_version_types

        # Should not raise
        validate_version_types(["semver"])
        validate_version_types(["calver"])
        validate_version_types(["semver", "calver"])

    def test_validate_version_types_helper_invalid(self):
        """Test validate_version_types helper with invalid types."""
        import typer

        from tag_validate.cli import validate_version_types

        with pytest.raises(typer.Exit):
            validate_version_types(["invalid"])

        with pytest.raises(typer.Exit):
            validate_version_types(["semver", "invalid"])

    def test_validate_signature_types_helper_valid(self):
        """Test validate_signature_types helper with valid types."""
        from tag_validate.cli import validate_signature_types

        # Should not raise
        validate_signature_types(["gpg"])
        validate_signature_types(["ssh"])
        validate_signature_types(["gpg", "ssh"])
        validate_signature_types(["gpg", "ssh", "gpg-unverifiable"])
        validate_signature_types(["unsigned"])

    def test_validate_signature_types_helper_invalid(self):
        """Test validate_signature_types helper with invalid types."""
        import typer

        from tag_validate.cli import validate_signature_types

        with pytest.raises(typer.Exit):
            validate_signature_types(["invalid"])

        with pytest.raises(typer.Exit):
            validate_signature_types(["gpg", "unsigned"])  # Invalid combination


class TestBothVersionTypeDocumentation:
    """Test that both version type is properly documented in output."""

    def test_validate_displays_both_type(self):
        """Test that validate command displays 'both' type."""
        result = runner.invoke(app, ["validate", "2024.1.15"])

        assert result.exit_code == 0
        assert "BOTH" in result.stdout or "both" in result.stdout

    def test_validate_json_includes_both_type(self):
        """Test that JSON output includes 'both' type."""
        result = runner.invoke(app, ["validate", "2024.1.15", "--json"])

        assert result.exit_code == 0

        output = json.loads(result.stdout)
        assert "version_type" in output
        assert output["version_type"] == "both"

    def test_validate_help_mentions_types(self):
        """Test that help text mentions valid types."""
        result = runner.invoke(app, ["validate", "--help"])

        assert result.exit_code == 0
        assert "semver" in result.stdout.lower()
        assert "calver" in result.stdout.lower()
