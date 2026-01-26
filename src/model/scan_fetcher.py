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

from src.utils.constants import SCAN_API_URL, PAGE_SIZE, SCAN_DELAY_SECONDS, HTTP_TIMEOUT

logger = logging.getLogger(__name__)


class ScanFetcher:
    """
    Class to fetch AquaSec security scan results with pagination support.
    """

    def __init__(self, bearer_token: str, repository_id: str) -> None:
        """
        Initialize with bearer token and repository ID.

        Args:
            bearer_token: Bearer token for authentication.
            repository_id: AquaSec repository ID.
        """
        self.bearer_token: str = bearer_token
        self.repository_id: str = repository_id

    def fetch_findings(self) -> dict:
        """
        Fetch all security findings from AquaSec API with pagination.

        Returns:
            Dictionary containing total count and all findings data.

        Raises:
            ValueError: If API returns invalid response or empty response.
            RequestException: If connection to API fails.
        """
        logger.info("AquaSec Scan Results - Starting to fetch scan findings.")

        findings_list = []
        page_num = 1
        total_expected = 0

        while True:
            logger.info("Fetching page %d...", page_num)

            request_url = f"{SCAN_API_URL}?repositoryIds={self.repository_id}&size={PAGE_SIZE}&page={page_num}"

            headers = {
                "Authorization": f"Bearer {self.bearer_token}",
                "Accept": "application/json"
            }

            # Make API request
            response = requests.get(request_url, headers=headers, timeout=HTTP_TIMEOUT)

            # Check response status
            if response.status_code != 200:
                raise ValueError(f"Status {response.status_code}: {response.text}")

            # Check for empty response
            if not response.text:
                raise ValueError("API returned empty response")

            # Parse JSON response
            try:
                page_response = response.json()
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON response: {str(e)}") from e

            # Extract total from first page
            if page_num == 1:
                total_expected = page_response.get("total", 0)
                logger.info("Total findings expected: %d", total_expected)

            # Extract page data
            page_data = page_response.get("data", [])
            page_count = len(page_data)
            logger.info("Retrieved %d findings on page %d", page_count, page_num)

            # Accumulate findings
            findings_list.extend(page_data)

            findings_count = len(findings_list)

            # Check if we've fetched all findings
            if findings_count >= total_expected or page_count == 0:
                break

            # Move to next page
            page_num += 1

            # Add delay between requests
            time.sleep(SCAN_DELAY_SECONDS)

        logger.info("AquaSec Scan Results - Fetched %d total findings.", len(findings_list))

        return {
            "total": len(findings_list),
            "data": findings_list
        }
