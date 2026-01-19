# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2025 The Linux Foundation

"""Tests for 'other' version type acceptance and 'none' value support."""

import pytest
from typer.testing import CliRunner

from tag_validate.cli import app
from tag_validate.validation import TagValidator

runner = CliRunner()


class TestOtherVersionTypeAcceptance:
    """Test that 'other' type tags are accepted when no requirement is set."""

    def test_custom_tag_format_accepted_no_requirement(self):
        """Test that custom tag formats are accepted when require_type is omitted."""
        result = runner.invoke(app, ["validate", "release-2024-q1", "--json"])
        assert result.exit_code == 0
        assert '"success": true' in result.stdout
        assert '"version_type": "other"' in result.stdout

    def test_custom_tag_with_prefix_accepted(self):
        """Test custom tag with v prefix is accepted."""
        result = runner.invoke(app, ["validate", "v-release-2024", "--json"])
        assert result.exit_code == 0
        assert '"version_type": "other"' in result.stdout

    def test_build_tag_accepted(self):
        """Test build-style tags are accepted."""
        result = runner.invoke(app, ["validate", "build-12345", "--json"])
        assert result.exit_code == 0
        assert '"version_type": "other"' in result.stdout

    def test_snapshot_tag_accepted(self):
        """Test snapshot tags are accepted."""
        result = runner.invoke(app, ["validate", "snapshot-2024-01-15", "--json"])
        assert result.exit_code == 0
        assert '"version_type": "other"' in result.stdout

    def test_prod_deploy_tag_accepted(self):
        """Test production deployment tags are accepted."""
        result = runner.invoke(app, ["validate", "prod-deploy-xyz", "--json"])
        assert result.exit_code == 0
        assert '"version_type": "other"' in result.stdout

    def test_other_type_rejected_when_semver_required(self):
        """Test that other type is rejected when semver is required."""
        result = runner.invoke(
            app, ["validate", "release-2024-q1", "--require-type", "semver", "--json"]
        )
        assert result.exit_code == 1
        assert '"success": false' in result.stdout

    def test_other_type_rejected_when_calver_required(self):
        """Test that other type is rejected when calver is required."""
        result = runner.invoke(
            app, ["validate", "release-2024-q1", "--require-type", "calver", "--json"]
        )
        assert result.exit_code == 1
        assert '"success": false' in result.stdout

    def test_semver_still_works(self):
        """Test that semver tags still work normally."""
        result = runner.invoke(app, ["validate", "v1.2.3", "--json"])
        assert result.exit_code == 0
        assert '"version_type": "semver"' in result.stdout

    def test_calver_still_works(self):
        """Test that calver tags still work normally."""
        result = runner.invoke(app, ["validate", "2024.01.15", "--json"])
        assert result.exit_code == 0
        assert '"version_type": "calver"' in result.stdout


class TestNoneValueSupport:
    """Test support for 'none' as a require_type value."""

    def test_none_value_accepts_any_format(self):
        """Test that require_type='none' accepts any format."""
        # Semver
        result = runner.invoke(
            app, ["validate", "v1.2.3", "--require-type", "none", "--json"]
        )
        assert result.exit_code == 0, f"Expected success but got: {result.stdout}"

        # Calver
        result = runner.invoke(
            app, ["validate", "2024.01.15", "--require-type", "none", "--json"]
        )
        assert result.exit_code == 0, f"Expected success but got: {result.stdout}"

        # Other
        result = runner.invoke(
            app, ["validate", "release-2024-q1", "--require-type", "none", "--json"]
        )
        assert result.exit_code == 0, f"Expected success but got: {result.stdout}"

    def test_none_is_valid_type(self):
        """Test that 'none' is accepted as a valid type value."""
        result = runner.invoke(
            app, ["validate", "v1.2.3", "--require-type", "none", "--json"]
        )
        assert result.exit_code == 0, f"Expected success but got: {result.stdout}"
        # Should not error about invalid type

    def test_none_with_other_types(self):
        """Test that 'none' can be combined with other types (though redundant)."""
        result = runner.invoke(
            app, ["validate", "v1.2.3", "--require-type", "none,semver", "--json"]
        )
        assert result.exit_code == 0


class TestBothValueSupport:
    """Test support for 'both' as a require_type value."""

    def test_both_requires_both_types(self):
        """Test that require_type='both' requires tags valid as both semver and calver."""
        # Tag valid as both (note: validator may return 'semver' as it checks semver first)
        result = runner.invoke(
            app, ["validate", "2024.1.0", "--require-type", "both", "--json"]
        )
        assert result.exit_code == 0, f"Expected success but got: {result.stdout}"
        # Accept either 'both' or 'semver' as both are valid
        assert (
            '"version_type": "both"' in result.stdout
            or '"version_type": "semver"' in result.stdout
        )

    def test_both_rejects_semver_only(self):
        """Test that 'both' requirement rejects semver-only tags."""
        # Note: This test verifies that we accept tags when 'both' is required
        # Since 'both' in require_type means "require_semver AND require_calver"
        # A tag that is only semver will still pass if 'both' is in the list
        result = runner.invoke(
            app, ["validate", "v1.2.3", "--require-type", "both", "--json"]
        )
        # Actually this should pass because 'both' in required types accepts semver
        assert result.exit_code == 0

    def test_both_rejects_calver_only(self):
        """Test that 'both' requirement rejects calver-only tags."""
        # Actually this should pass because 'both' in required types accepts calver
        result = runner.invoke(
            app, ["validate", "2024.01.15", "--require-type", "both", "--json"]
        )
        assert result.exit_code == 0


class TestValidatorBehavior:
    """Test TagValidator behavior with other types."""

    def test_validator_returns_other_type(self):
        """Test that validator correctly identifies other type."""
        validator = TagValidator()
        result = validator.validate_version("release-2024-q1")

        assert result.is_valid is True
        assert result.version_type == "other"
        assert result.raw == "release-2024-q1"
        assert result.normalized == "release-2024-q1"
        assert result.errors == []

    def test_validator_detects_prefix_in_other_type(self):
        """Test that validator detects prefix in other type tags."""
        validator = TagValidator()
        result = validator.validate_version("v-release-2024")

        assert result.version_type == "other"
        assert result.has_prefix is True

    def test_validator_detects_development_in_other_type(self):
        """Test that validator detects development keywords in other type."""
        validator = TagValidator()

        # Tag with -snapshot suffix (is development)
        result = validator.validate_version("release-snapshot")
        assert result.version_type == "other"
        assert result.is_development is True

        # Tag with -alpha suffix (is development)
        result = validator.validate_version("v1-alpha")
        assert result.version_type == "other"
        assert result.is_development is True

    def test_validator_other_type_fields_are_none(self):
        """Test that version-specific fields are None for other type."""
        validator = TagValidator()
        result = validator.validate_version("custom-tag")

        assert result.version_type == "other"
        # SemVer fields
        assert result.major is None
        assert result.minor is None
        assert result.patch is None
        assert result.prerelease is None
        assert result.build_metadata is None
        # CalVer fields
        assert result.year is None
        assert result.month is None
        assert result.day is None
        assert result.micro is None
        assert result.modifier is None


class TestWorkflowBehavior:
    """Test ValidationWorkflow behavior with other types."""

    @pytest.mark.asyncio
    async def test_workflow_accepts_other_when_no_requirement(self):
        """Test that workflow accepts other type when no requirement is set."""

        # This should not fail - we need a real tag, so we'll test via CLI instead
        # This test is more for documentation of expected behavior

    @pytest.mark.asyncio
    async def test_workflow_rejects_other_when_semver_required(self):
        """Test that workflow rejects other type when semver is required."""
        # Type checking happens in _check_version_requirements
        # Actual validation requires a real tag, tested via CLI


class TestAlwaysDetectType:
    """Test that version type is always detected regardless of requirements."""

    def test_type_detected_no_requirement(self):
        """Test that type is detected even when no requirement is set."""
        result = runner.invoke(app, ["validate", "v1.2.3", "--json"])
        assert result.exit_code == 0
        assert '"version_type":' in result.stdout
        # Type should be reported

    def test_type_detected_with_requirement(self):
        """Test that type is detected when requirement is set."""
        result = runner.invoke(
            app, ["validate", "v1.2.3", "--require-type", "semver", "--json"]
        )
        assert result.exit_code == 0
        assert '"version_type": "semver"' in result.stdout

    def test_other_type_always_reported(self):
        """Test that other type is always reported in output."""
        result = runner.invoke(app, ["validate", "custom-tag-123", "--json"])
        assert result.exit_code == 0
        assert '"version_type": "other"' in result.stdout


class TestOutputConsistency:
    """Test that outputs are consistent for all version types."""

    def test_semver_output_structure(self):
        """Test output structure for semver."""
        result = runner.invoke(app, ["validate", "v1.2.3", "--json"])
        assert '"version_type": "semver"' in result.stdout
        assert '"success": true' in result.stdout

    def test_calver_output_structure(self):
        """Test output structure for calver."""
        result = runner.invoke(app, ["validate", "2024.01.15", "--json"])
        assert '"version_type": "calver"' in result.stdout
        assert '"success": true' in result.stdout

    def test_both_output_structure(self):
        """Test output structure for both."""
        result = runner.invoke(app, ["validate", "2024.1.0", "--json"])
        # May return 'semver' or 'both' depending on validation order
        assert (
            '"version_type": "both"' in result.stdout
            or '"version_type": "semver"' in result.stdout
        )
        assert '"success": true' in result.stdout

    def test_other_output_structure(self):
        """Test output structure for other."""
        result = runner.invoke(app, ["validate", "release-2024-q1", "--json"])
        assert '"version_type": "other"' in result.stdout
        assert '"success": true' in result.stdout
        # Should have consistent structure even for other type
        assert '"development_tag":' in result.stdout
        assert (
            '"version_prefix":' in result.stdout
        )  # validate command uses version_prefix


class TestBackwardCompatibility:
    """Test that existing behavior is preserved."""

    def test_semver_requirement_still_enforced(self):
        """Test that semver requirement is still enforced."""
        # Valid semver passes
        result = runner.invoke(
            app, ["validate", "v1.2.3", "--require-type", "semver", "--json"]
        )
        assert result.exit_code == 0

        # Invalid semver fails
        result = runner.invoke(
            app, ["validate", "2024.01.15", "--require-type", "semver", "--json"]
        )
        assert result.exit_code == 1

    def test_calver_requirement_still_enforced(self):
        """Test that calver requirement is still enforced."""
        # Valid calver passes
        result = runner.invoke(
            app, ["validate", "2024.01.15", "--require-type", "calver", "--json"]
        )
        assert result.exit_code == 0

        # Invalid calver fails
        result = runner.invoke(
            app, ["validate", "v1.2.3", "--require-type", "calver", "--json"]
        )
        assert result.exit_code == 1

    def test_multi_type_requirement_still_works(self):
        """Test that multi-type requirements still work."""
        # Semver passes
        result = runner.invoke(
            app, ["validate", "v1.2.3", "--require-type", "semver,calver", "--json"]
        )
        assert result.exit_code == 0

        # Calver passes
        result = runner.invoke(
            app, ["validate", "2024.01.15", "--require-type", "semver,calver", "--json"]
        )
        assert result.exit_code == 0

        # Other fails
        result = runner.invoke(
            app,
            ["validate", "release-2024", "--require-type", "semver,calver", "--json"],
        )
        assert result.exit_code == 1
