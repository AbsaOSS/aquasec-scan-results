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

import requests

from src.utils.constants import GROUP_ID, AUTH_API_URL, HTTP_TIMEOUT, AQUA_KEY, AQUA_SECRET
from src.utils.utils import get_action_input

logger = logging.getLogger(__name__)


class AquaSecAuthenticator:
    """
    Class to handle AquaSec API authentication.
    """

    def __init__(self) -> None:
        self.api_key: str = ""
        self.api_secret: str = ""

    def _generate_signature(self, string_to_sign: str) -> str:
        """
        Generate HMAC-SHA256 signature for AquaSec API request.

        Args:
            string_to_sign: String to sign with HMAC.

        Returns:
            Hexadecimal signature string.
        """
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
            ValueError: If API returns invalid response or missing token.
            RequestException: If connection to API fails.
        """
        logger.info("AquaSec Scan Results - API authentication starting.")

        self.api_key = get_action_input(AQUA_KEY)
        self.api_secret = get_action_input(AQUA_SECRET)
        method: str = "POST"
        timestamp: int = int(time.time())
        auth_endpoint: str = AUTH_API_URL + "/v2/tokens"
        post_body: str = json.dumps(
            {"group_id": GROUP_ID, "allowed_endpoints": ["GET"], "validity": 240}, separators=(",", ":")
        )
        string_to_sign: str = f"{timestamp}{method}/v2/tokens{post_body}"

        # Generate signature
        signature = self._generate_signature(string_to_sign)

        # Request headers
        headers = {
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
            "X-Timestamp": str(timestamp),
            "X-Signature": signature,
        }

        # Make authentication API request
        response = requests.post(auth_endpoint, headers=headers, data=post_body, timeout=HTTP_TIMEOUT)

        # Check response status
        if response.status_code != 200:
            raise ValueError(f"Status {response.status_code}: {response.text}")

        # Extract token from response
        bearer_token = response.json().get("data", "")
        if not bearer_token:
            raise ValueError("API response missing bearer token data.")

        logger.info("AquaSec Scan Results - API authentication successful.")
        return bearer_token
