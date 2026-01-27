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
This module implements AquaSec scan results fetching logic.
"""

import json
import logging
import time

import requests

from src.utils.constants import SCAN_API_URL, PAGE_SIZE, FETCH_SLEEP_SECONDS, HTTP_TIMEOUT, REPOSITORY_ID
from src.utils.utils import get_action_input

logger = logging.getLogger(__name__)


class ScanFetcher:
    """
    Class to fetch AquaSec security scan results with pagination support.
    """

    def __init__(self, bearer_token: str) -> None:
        self.bearer_token: str = bearer_token
        self.repository_id: str = ""

    def fetch_findings(self) -> dict:
        """
        Fetch all security findings from AquaSec API with pagination.

        Returns:
            Dictionary containing total count and security findings.

        Raises:
            ValueError: If API returns invalid response or empty response.
            RequestException: If connection to API fails.
        """
        logger.info("AquaSec Scan Results - Scan findings fetch starting.")

        findings = []
        page_num = 1
        total_expected = 0
        self.repository_id = get_action_input(REPOSITORY_ID)

        while True:
            logger.info("AquaSec Scan Results - Fetching page %d...", page_num)

            fetch_endpoint = f"{SCAN_API_URL}?repositoryIds={self.repository_id}&size={PAGE_SIZE}&page={page_num}"
            headers = {"Authorization": f"Bearer {self.bearer_token}", "Accept": "application/json"}

            # Make scan fetching API request
            response = requests.get(fetch_endpoint, headers=headers, timeout=HTTP_TIMEOUT)

            # Check response status
            if response.status_code != 200:
                raise ValueError(f"Status {response.status_code}: {response.text}")

            # Parse JSON response
            try:
                page_response = response.json()
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON response: {str(e)}") from e

            # Extract total expected findings
            if page_num == 1:
                total_expected = page_response.get("total", 0)
                logger.debug("Expected %d of total findings.", total_expected)

            # Accumulate findings
            page_data = page_response.get("data", [])
            page_count = len(page_data)
            logger.debug("Retrieved %d findings on page %d", page_count, page_num)

            # Accumulate findings
            findings.extend(page_data)

            # Check if we've fetched all findings
            if len(findings) >= total_expected or page_count == 0:
                break

            # Move to next page with sleep to avoid rate limiting
            page_num += 1
            time.sleep(FETCH_SLEEP_SECONDS)

        findings_total = len(findings)
        logger.info("AquaSec Scan Results - Scan findings fetch successful (%d total).", findings_total)

        return {"total": findings_total, "data": findings}
