# SPDX-FileCopyrightText: 2025 Linux Foundation
# SPDX-License-Identifier: Apache-2.0

"""
Gerrit Keys Client for Tag Validation.

This module provides a client for verifying cryptographic keys (GPG and SSH)
against Gerrit Code Review servers. It handles Gerrit server discovery,
account resolution, and key verification.

The client supports:
- Automatic Gerrit server discovery from GitHub organization names
- Account lookup by email address and username
- SSH key verification against registered keys
- GPG key verification against registered keys
- Fingerprint matching for both SSH and GPG keys
"""

import base64
import hashlib
import json
import logging
import os
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import httpx

from .models import (
    GerritAccountInfo,
    GerritSSHKeyInfo,
    GerritGPGKeyInfo,
    KeyVerificationResult,
)

logger = logging.getLogger(__name__)


class GerritKeysError(Exception):
    """Base exception for Gerrit keys operations."""
    pass


class GerritServerError(Exception):
    """Raised when Gerrit server communication fails."""
    pass


class GerritKeysClient:
    """
    Client for Gerrit account and keys APIs.

    This client provides tag validation-specific operations for key verification
    against Gerrit Code Review servers. It handles automatic server discovery
    and supports both SSH and GPG key verification.

    Example:
        >>> async with GerritKeysClient(server="gerrit.onap.org") as client:
        ...     account = await client.lookup_account_by_email("user@example.com")
        ...     result = await client.verify_ssh_key_registered(
        ...         account.account_id, ssh_fingerprint
        ...     )
    """

    def __init__(
        self,
        server: str | None = None,
        github_org: str | None = None,
        timeout: float = 30.0,
        logger_instance: logging.Logger | None = None,
    ):
        """
        Initialize Gerrit keys client.

        Args:
            server: Gerrit server hostname or URL. If None, will be auto-discovered from github_org.
            github_org: GitHub organization name for server discovery (e.g., "onap" -> "gerrit.onap.org").
            timeout: Request timeout in seconds.
            logger_instance: Optional logger instance for client messages.

        Raises:
            GerritKeysError: If neither server nor github_org is provided.
        """
        self.logger: logging.Logger = logger_instance or logger
        self.timeout: float = timeout

        if server:
            self.server = self._normalize_server_url(server)
        elif github_org:
            self.server = self._discover_server_from_github_org(github_org)
        else:
            raise GerritKeysError("Either server or github_org must be provided")

        self._client: httpx.AsyncClient | None = None
        self._base_url: str | None = None

    async def __aenter__(self) -> "GerritKeysClient":
        """Async context manager entry."""
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=10.0),
            follow_redirects=True,
            headers={
                "User-Agent": "tag-validate-action/1.0.0",
                "Accept": "application/json",
            },
        )

        # Discover the API base URL
        self._base_url = await self._discover_api_base_url()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None

    def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure client is initialized."""
        if not self._client:
            raise RuntimeError(
                "GerritKeysClient must be used as an async context manager. "
                "Use 'async with GerritKeysClient(...) as client:'"
            )
        return self._client

    def _normalize_server_url(self, server: str) -> str:
        """
        Normalize server URL to just the hostname.

        Args:
            server: Server hostname or URL

        Returns:
            Normalized hostname
        """
        if server.startswith(("http://", "https://")):
            parsed = urlparse(server)
            return parsed.netloc
        return server

    def _discover_server_from_github_org(self, github_org: str) -> str:
        """
        Discover Gerrit server from GitHub organization name.

        Uses the pattern: [GITHUB_ORG] -> gerrit.[GITHUB_ORG].org

        Args:
            github_org: GitHub organization name

        Returns:
            Gerrit server hostname
        """
        return f"gerrit.{github_org}.org"

    async def _discover_api_base_url(self) -> str:
        """
        Discover the correct API base URL for the Gerrit server.

        Gerrit instances can be deployed with different path prefixes.
        This method tests common patterns to find the working API endpoint.

        Returns:
            Working API base URL

        Raises:
            GerritServerError: If no working endpoint is found
        """
        client = self._ensure_client()

        # Common Gerrit API path patterns to test
        test_paths = [
            "",  # Direct: https://host/
            "/r",  # Standard: https://host/r/
            "/gerrit",  # OpenDaylight style: https://host/gerrit/
            "/a",  # Authenticated API: https://host/a/
        ]

        self.logger.debug(f"Discovering API base URL for Gerrit server: {self.server}")

        for path in test_paths:
            base_url = f"https://{self.server}{path}"
            self.logger.debug(f"Testing API endpoint: {base_url}")

            try:
                # Test the accounts API endpoint
                test_url = urljoin(base_url.rstrip("/") + "/", "accounts/")
                response = await client.get(test_url)

                if response.status_code in (200, 403):  # 403 is acceptable (auth required)
                    self.logger.debug(f"Discovered working API base URL: {base_url}")
                    return base_url

            except Exception as e:
                self.logger.debug(f"Error testing API endpoint {base_url}: {e}")
                continue

        raise GerritServerError(
            f"Could not discover Gerrit API endpoint for {self.server}. "
            f"Tested paths: {test_paths}"
        )

    async def lookup_account_by_email(self, email: str) -> GerritAccountInfo | None:
        """
        Look up a Gerrit account by email address.

        Args:
            email: Email address to search for

        Returns:
            GerritAccountInfo if found, None otherwise

        Raises:
            GerritServerError: If API request fails
        """
        client = self._ensure_client()

        try:
            # Use the accounts query API
            base_url = self._base_url or ""
            url = urljoin(base_url.rstrip("/") + "/", f"accounts/?q=email:{email}")
            response = await client.get(url)

            if response.status_code == 200:
                data = self._parse_gerrit_response(response.text)
                if isinstance(data, list) and len(data) > 0:
                    account_data = data[0]
                    return GerritAccountInfo(
                        account_id=account_data.get("_account_id", 0),
                        name=account_data.get("name"),
                        email=account_data.get("email"),
                        username=account_data.get("username"),
                        status=account_data.get("status", "ACTIVE"),
                    )
                return None
            else:
                self.logger.warning(f"Failed to lookup account by email {email}: HTTP {response.status_code}")
                return None

        except Exception as e:
            self.logger.error(f"Error looking up account by email {email}: {e}")
            raise GerritServerError(f"Failed to lookup account: {e}") from e

    async def lookup_account_by_username(self, username: str) -> GerritAccountInfo | None:
        """
        Look up a Gerrit account by username.

        Args:
            username: Username to search for

        Returns:
            GerritAccountInfo if found, None otherwise

        Raises:
            GerritServerError: If API request fails
        """
        client = self._ensure_client()

        try:
            # Use the accounts query API
            base_url = self._base_url or ""
            url = urljoin(base_url.rstrip("/") + "/", f"accounts/?q=username:{username}")
            response = await client.get(url)

            if response.status_code == 200:
                data = self._parse_gerrit_response(response.text)
                if isinstance(data, list) and len(data) > 0:
                    account_data = data[0]
                    return GerritAccountInfo(
                        account_id=account_data.get("_account_id", 0),
                        name=account_data.get("name"),
                        email=account_data.get("email"),
                        username=account_data.get("username"),
                        status=account_data.get("status", "ACTIVE"),
                    )
                return None
            else:
                self.logger.warning(f"Failed to lookup account by username {username}: HTTP {response.status_code}")
                return None

        except Exception as e:
            self.logger.error(f"Error looking up account by username {username}: {e}")
            raise GerritServerError(f"Failed to lookup account: {e}") from e

    async def get_account_ssh_keys(self, account_id: int) -> list[GerritSSHKeyInfo]:
        """
        Get all SSH keys registered to a Gerrit account.

        Args:
            account_id: Gerrit account ID

        Returns:
            List of GerritSSHKeyInfo objects

        Raises:
            GerritServerError: If API request fails
        """
        client = self._ensure_client()

        try:
            base_url = self._base_url or ""
            url = urljoin(base_url.rstrip("/") + "/", f"accounts/{account_id}/sshkeys")
            response = await client.get(url)

            if response.status_code == 200:
                data = self._parse_gerrit_response(response.text)
                if not isinstance(data, list):
                    return []

                keys = []
                for key_data in data:
                    try:
                        key_info = GerritSSHKeyInfo(
                            seq=key_data.get("seq", 0),
                            ssh_public_key=key_data.get("ssh_public_key", ""),
                            encoded_key=key_data.get("encoded_key", ""),
                            algorithm=key_data.get("algorithm", ""),
                            comment=key_data.get("comment"),
                            valid=key_data.get("valid", False),
                        )
                        keys.append(key_info)
                    except Exception as e:
                        self.logger.warning(f"Failed to parse SSH key data: {e}")
                        continue

                return keys
            else:
                self.logger.warning(f"Failed to get SSH keys for account {account_id}: HTTP {response.status_code}")
                return []

        except Exception as e:
            self.logger.error(f"Error getting SSH keys for account {account_id}: {e}")
            raise GerritServerError(f"Failed to get SSH keys: {e}") from e

    async def get_account_gpg_keys(self, account_id: int) -> list[GerritGPGKeyInfo]:
        """
        Get all GPG keys registered to a Gerrit account.

        Args:
            account_id: Gerrit account ID

        Returns:
            List of GerritGPGKeyInfo objects

        Raises:
            GerritServerError: If API request fails
        """
        client = self._ensure_client()

        try:
            base_url = self._base_url or ""
            url = urljoin(base_url.rstrip("/") + "/", f"accounts/{account_id}/gpgkeys")
            response = await client.get(url)

            if response.status_code == 200:
                data = self._parse_gerrit_response(response.text)
                if not isinstance(data, dict):
                    return []

                keys = []
                for key_id, key_data in data.items():
                    try:
                        key_info = GerritGPGKeyInfo(
                            id=key_id,
                            fingerprint=key_data.get("fingerprint", key_id),
                            user_ids=key_data.get("user_ids", []),
                            key=key_data.get("key", ""),
                            status=key_data.get("status", ""),
                            problems=key_data.get("problems", []),
                        )
                        keys.append(key_info)
                    except Exception as e:
                        self.logger.warning(f"Failed to parse GPG key data: {e}")
                        continue

                return keys
            else:
                self.logger.warning(f"Failed to get GPG keys for account {account_id}: HTTP {response.status_code}")
                return []

        except Exception as e:
            self.logger.error(f"Error getting GPG keys for account {account_id}: {e}")
            raise GerritServerError(f"Failed to get GPG keys: {e}") from e

    async def verify_ssh_key_registered(
        self,
        account_id: int,
        fingerprint: str,
    ) -> KeyVerificationResult:
        """
        Verify if an SSH key fingerprint is registered to a Gerrit account.

        Args:
            account_id: Gerrit account ID
            fingerprint: SSH key fingerprint to verify

        Returns:
            KeyVerificationResult with verification details
        """
        try:
            ssh_keys = await self.get_account_ssh_keys(account_id)
            normalized_fingerprint = self._normalize_ssh_fingerprint(fingerprint)

            for key in ssh_keys:
                if key.valid and key.ssh_public_key:
                    key_fingerprint = await self._calculate_ssh_fingerprint(key.ssh_public_key)
                    if key_fingerprint == normalized_fingerprint:
                        return KeyVerificationResult(
                            key_registered=True,
                            username=str(account_id),  # Use account ID as username
                            enumerated=False,
                            key_info=key,
                            service="gerrit",
                            server=self.server,
                        )

            return KeyVerificationResult(
                key_registered=False,
                username=str(account_id),
                enumerated=False,
                key_info=None,
                service="gerrit",
                server=self.server,
            )

        except Exception as e:
            self.logger.error(f"Error verifying SSH key: {e}")
            return KeyVerificationResult(
                key_registered=False,
                username=str(account_id),
                enumerated=False,
                key_info=None,
                service="gerrit",
                server=self.server,
            )

    async def verify_gpg_key_registered(
        self,
        account_id: int,
        key_id: str,
    ) -> KeyVerificationResult:
        """
        Verify if a GPG key ID is registered to a Gerrit account.

        Args:
            account_id: Gerrit account ID
            key_id: GPG key ID to verify (short or long form)

        Returns:
            KeyVerificationResult with verification details
        """
        try:
            gpg_keys = await self.get_account_gpg_keys(account_id)
            normalized_key_id = key_id.upper().replace("0X", "")

            for key in gpg_keys:
                # Check if the key ID matches (can be short or long form)
                if (key.id.upper().endswith(normalized_key_id) or
                    key.fingerprint.upper().endswith(normalized_key_id)):
                    return KeyVerificationResult(
                        key_registered=True,
                        username=str(account_id),
                        enumerated=False,
                        key_info=key,
                        service="gerrit",
                        server=self.server,
                    )
            return KeyVerificationResult(
                key_registered=False,
                username=str(account_id),
                enumerated=False,
                key_info=None,
                service="gerrit",
                server=self.server,
            )

        except Exception as e:
            self.logger.error(f"Error verifying GPG key: {e}")
            return KeyVerificationResult(
                key_registered=False,
                username=str(account_id),
                enumerated=False,
                key_info=None,
                service="gerrit",
                server=self.server,
            )

    def _normalize_ssh_fingerprint(self, fingerprint: str) -> str:
        """
        Normalize SSH fingerprint to consistent format.

        Args:
            fingerprint: Raw SSH fingerprint

        Returns:
            Normalized fingerprint (lowercase, no prefixes)
        """
        # Remove common prefixes and make lowercase
        normalized = fingerprint.lower()
        for prefix in ["sha256:", "md5:", "ssh-"]:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]

        # Remove any colons or spaces
        normalized = normalized.replace(":", "").replace(" ", "")

        return normalized

    async def _calculate_ssh_fingerprint(self, public_key: str) -> str:
        """
        Calculate SSH fingerprint from public key.

        Args:
            public_key: SSH public key string

        Returns:
            SHA256 fingerprint (base64 encoded without padding)
        """
        try:
            # Split the key into parts
            parts = public_key.strip().split()
            if len(parts) < 2:
                return ""

            # Get the key data (second part)
            key_data = parts[1]

            # Decode base64 key data
            key_bytes = base64.b64decode(key_data)

            # Calculate SHA256 hash
            sha256_hash = hashlib.sha256(key_bytes).digest()

            # Encode as base64 and remove padding
            fingerprint = base64.b64encode(sha256_hash).decode('ascii').rstrip('=')

            return fingerprint.lower()

        except Exception as e:
            self.logger.warning(f"Failed to calculate SSH fingerprint: {e}")
            return ""

    def _parse_gerrit_response(self, response_text: str) -> dict[str, Any] | list[Any]:
        """
        Parse Gerrit JSON response, handling magic prefix.

        Gerrit prepends ")]}'" to JSON responses as a security measure.
        This method strips it before parsing.

        Args:
            response_text: Raw response text from Gerrit API

        Returns:
            Parsed JSON as dictionary or list
        """
        import json
        from typing import cast

        # Remove Gerrit's magic prefix if present
        if response_text.startswith(")]}'"):
            clean_text = response_text[4:].lstrip()
        else:
            clean_text = response_text

        try:
            result = json.loads(clean_text)
            return cast(dict[str, Any] | list[Any], result)
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON response: {e}")
            return {}
