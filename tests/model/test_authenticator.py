#
# Copyright 2026 ABSA Group Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Tests for authenticator module.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from src.model.authenticator import AquaSecAuthenticator


class TestAquaSecAuthenticator:
    """Test cases for AquaSecAuthenticator class."""

    @patch("builtins.print")
    def test_init_masks_secrets(self, mock_print):
        """Test that secrets are masked on initialization."""
        authenticator = AquaSecAuthenticator("test-key", "test-secret")

        assert authenticator.api_key == "test-key"
        assert authenticator.api_secret == "test-secret"
        assert mock_print.call_count == 2

    def test_generate_signature(self):
        """Test HMAC-SHA256 signature generation."""
        authenticator = AquaSecAuthenticator("test-key", "test-secret")

        timestamp = 1234567890
        method = "POST"
        endpoint = "/v2/tokens"
        body = '{"group_id": 1228, "allowed_endpoints": ["GET"], "validity": 240}'

        signature = authenticator._generate_signature(timestamp, method, endpoint, body)

        # Verify signature is a valid hex string
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA256 produces 64 hex characters
        # Verify signature is deterministic
        signature2 = authenticator._generate_signature(timestamp, method, endpoint, body)
        assert signature == signature2

    @patch("src.model.authenticator.requests.post")
    @patch("src.model.authenticator.time.time")
    @patch("builtins.print")
    def test_authenticate_success(self, mock_print, mock_time, mock_post):
        """Test successful authentication."""
        mock_time.return_value = 1234567890
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": 200, "data": "test-bearer-token"}
        mock_post.return_value = mock_response

        authenticator = AquaSecAuthenticator("test-key", "test-secret")
        token = authenticator.authenticate()

        assert token == "test-bearer-token"
        # Verify API call
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert call_args[0][0] == "https://eu-1.api.cloudsploit.com/v2/tokens"
        assert "X-API-Key" in call_args[1]["headers"]
        assert "X-Timestamp" in call_args[1]["headers"]
        assert "X-Signature" in call_args[1]["headers"]

    @patch("src.model.authenticator.requests.post")
    @patch("src.model.authenticator.time.time")
    @patch("builtins.print")
    def test_authenticate_http_error(self, mock_print, mock_time, mock_post):
        """Test authentication failure with HTTP error."""
        mock_time.return_value = 1234567890
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.text = "Unauthorized"
        mock_post.return_value = mock_response

        authenticator = AquaSecAuthenticator("test-key", "test-secret")

        with pytest.raises(RuntimeError, match="AquaSec API authentication failed with status 401"):
            authenticator.authenticate()

    @patch("src.model.authenticator.requests.post")
    @patch("src.model.authenticator.time.time")
    @patch("builtins.print")
    def test_authenticate_network_error(self, mock_print, mock_time, mock_post):
        """Test authentication failure with network error."""
        mock_time.return_value = 1234567890
        mock_post.side_effect = requests.exceptions.ConnectionError("Network error")

        authenticator = AquaSecAuthenticator("test-key", "test-secret")

        with pytest.raises(RuntimeError, match="Failed to connect to AquaSec API"):
            authenticator.authenticate()

    @patch("src.model.authenticator.requests.post")
    @patch("src.model.authenticator.time.time")
    @patch("builtins.print")
    def test_authenticate_invalid_json(self, mock_print, mock_time, mock_post):
        """Test authentication failure with invalid JSON response."""
        mock_time.return_value = 1234567890
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
        mock_post.return_value = mock_response

        authenticator = AquaSecAuthenticator("test-key", "test-secret")

        with pytest.raises(RuntimeError, match="Failed to parse AquaSec API response"):
            authenticator.authenticate()

    @patch("src.model.authenticator.requests.post")
    @patch("src.model.authenticator.time.time")
    @patch("builtins.print")
    def test_authenticate_error_status_in_response(self, mock_print, mock_time, mock_post):
        """Test authentication failure with error status in response."""
        mock_time.return_value = 1234567890
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": 400, "error": "Invalid request"}
        mock_post.return_value = mock_response

        authenticator = AquaSecAuthenticator("test-key", "test-secret")

        with pytest.raises(RuntimeError, match="AquaSec API returned error status: 400"):
            authenticator.authenticate()

    @patch("src.model.authenticator.requests.post")
    @patch("src.model.authenticator.time.time")
    @patch("builtins.print")
    def test_authenticate_missing_token_data(self, mock_print, mock_time, mock_post):
        """Test authentication failure with missing token in response."""
        mock_time.return_value = 1234567890
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": 200, "data": None}
        mock_post.return_value = mock_response

        authenticator = AquaSecAuthenticator("test-key", "test-secret")

        with pytest.raises(RuntimeError, match="AquaSec API response missing token data"):
            authenticator.authenticate()

    @patch("src.model.authenticator.requests.post")
    @patch("src.model.authenticator.time.time")
    @patch("builtins.print")
    def test_authenticate_request_body_structure(self, mock_print, mock_time, mock_post):
        """Test that the request body has correct structure."""
        mock_time.return_value = 1234567890
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": 200, "data": "test-token"}
        mock_post.return_value = mock_response

        authenticator = AquaSecAuthenticator("test-key", "test-secret")
        authenticator.authenticate()

        call_args = mock_post.call_args
        request_body = json.loads(call_args[1]["data"])
        assert request_body["group_id"] == 1228
        assert request_body["allowed_endpoints"] == ["GET"]
        assert request_body["validity"] == 240

    @patch("src.model.authenticator.requests.post")
    @patch("src.model.authenticator.time.time")
    @patch("builtins.print")
    def test_authenticate_signature_calculation(self, mock_print, mock_time, mock_post):
        """Test that signature is calculated correctly."""
        mock_time.return_value = 1234567890
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": 200, "data": "test-token"}
        mock_post.return_value = mock_response

        authenticator = AquaSecAuthenticator("test-key", "test-secret")
        authenticator.authenticate()

        call_args = mock_post.call_args
        headers = call_args[1]["headers"]
        # Verify signature is present and is a hex string
        assert "X-Signature" in headers
        signature = headers["X-Signature"]
        assert isinstance(signature, str)
        assert len(signature) == 64
        # Verify it's valid hex
        int(signature, 16)
