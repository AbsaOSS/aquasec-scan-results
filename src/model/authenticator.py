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
This module implements AquaSec authentication logic.
"""

import hashlib
import hmac
import json
import logging
import time
from typing import Any, Dict

import requests

logger = logging.getLogger(__name__)


class AquaSecAuthenticator:
    """Class to handle AquaSec API authentication."""

    API_URL = "https://eu-1.api.cloudsploit.com/v2/tokens"
    GROUP_ID = 1228
    ALLOWED_ENDPOINTS = ["GET"]
    VALIDITY = 240
    HTTP_TIMEOUT = 30

    def __init__(self, api_key: str, api_secret: str) -> None:
        """
        Initialize the AquaSec authenticator.

        Args:
            api_key: The AquaSec API key.
            api_secret: The AquaSec API secret.
        """
        self.api_key = api_key
        self.api_secret = api_secret
        print(f"::add-mask::{self.api_key}")
        print(f"::add-mask::{self.api_secret}")

    def _generate_signature(self, timestamp: int, method: str, endpoint: str, body: str) -> str:
        """
        Generate HMAC-SHA256 signature for AquaSec API request.

        Args:
            timestamp: Unix timestamp in seconds.
            method: HTTP method (e.g., 'POST').
            endpoint: API endpoint (e.g., '/v2/tokens').
            body: Request body as JSON string.

        Returns:
            Hexadecimal signature string.
        """
        string_to_sign = f"{timestamp}{method}{endpoint}{body}"
        signature = hmac.new(
            self.api_secret.encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return signature

    def authenticate(self) -> str:
        """
        Authenticate with AquaSec API and return bearer token.

        Returns:
            Bearer token string.

        Raises:
            RuntimeError: If authentication fails or returns non-200 status.
        """
        timestamp = int(time.time())
        method = "POST"
        endpoint = "/v2/tokens"

        # Prepare request body
        request_body: Dict[str, Any] = {
            "group_id": self.GROUP_ID,
            "allowed_endpoints": self.ALLOWED_ENDPOINTS,
            "validity": self.VALIDITY,
        }
        body_json = json.dumps(request_body)

        # Generate signature
        signature = self._generate_signature(timestamp, method, endpoint, body_json)

        # Prepare headers
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
            "X-Timestamp": str(timestamp),
            "X-Signature": signature,
        }

        # Make API request
        logger.info("Authenticating with AquaSec API")
        try:
            response = requests.post(self.API_URL, headers=headers, data=body_json, timeout=self.HTTP_TIMEOUT)
        except requests.exceptions.RequestException as ex:
            logger.error("Failed to connect to AquaSec API: %s", str(ex))
            raise RuntimeError(f"Failed to connect to AquaSec API: {ex}") from ex

        # Check response status
        if response.status_code != 200:
            logger.error("AquaSec API returned status %d: %s", response.status_code, response.text)
            raise RuntimeError(f"AquaSec API authentication failed with status {response.status_code}")

        # Parse response
        try:
            response_data = response.json()
        except json.JSONDecodeError as ex:
            logger.error("Failed to parse AquaSec API response as JSON")
            raise RuntimeError("Failed to parse AquaSec API response") from ex

        # Validate response structure
        if response_data.get("status") != 200:
            logger.error("AquaSec API returned error status in response: %s", response_data.get("status"))
            raise RuntimeError(f"AquaSec API returned error status: {response_data.get('status')}")

        token = response_data.get("data")
        if not token:
            logger.error("AquaSec API response missing token data")
            raise RuntimeError("AquaSec API response missing token data")

        # Mask the token in logs
        print(f"::add-mask::{token}")
        logger.info("Successfully authenticated with AquaSec API")
        return token
