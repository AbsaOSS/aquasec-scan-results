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
This module implements AquaSec scan triggering and polling logic.
"""

import logging
import time
from urllib.parse import quote

import requests

from src.utils.constants import BRANCH_STATUS_URL, HTTP_TIMEOUT, POLL_INTERVAL, POLL_TIMEOUT, SCAN_TRIGGER_URL

logger = logging.getLogger(__name__)


class ScanTrigger:
    """
    Class to trigger AquaSec scans on a branch and poll for completion.
    """

    def __init__(self, bearer_token: str) -> None:
        self.bearer_token: str = bearer_token

    def trigger_and_get_scan_id(self, repository_id: str, branch: str) -> str:
        """
        Trigger a scan on the given branch and wait for it to complete.

        Args:
            repository_id: The AquaSec repository ID.
            branch: The branch name to scan.
        Returns:
            The scan ID of the completed scan.
        """
        self._trigger(repository_id, branch)
        return self._get_scan_id(repository_id, branch)

    def _trigger(self, repository_id: str, branch: str) -> None:
        """
        Trigger an AquaSec security scan on the given branch.

        Args:
            repository_id: The AquaSec repository ID.
            branch: The branch name to scan.
        Raises:
            ValueError: If API returns non-2xx status.
        """
        logger.info("AquaSec Scan Results - Triggering scan on branch '%s'.", branch)

        headers = {"Authorization": f"Bearer {self.bearer_token}", "Content-Type": "application/json"}
        payload = {"repositories": [{"id": repository_id, "branch": branch}]}

        response = requests.post(SCAN_TRIGGER_URL, headers=headers, json=payload, timeout=HTTP_TIMEOUT)

        if response.status_code < 200 or response.status_code >= 300:
            raise ValueError(f"Scan trigger failed with status {response.status_code}: {response.text}")

        logger.info("AquaSec Scan Results - Scan triggered successfully.")

    def _get_scan_id(self, repository_id: str, branch: str) -> str:
        """
        Poll the branch status API until the scan completes or times out.

        Args:
            repository_id: The AquaSec repository ID.
            branch: The branch name to check.
        Returns:
            The scan ID of the completed scan.
        Raises:
            ValueError: If scan fails or times out.
        """
        logger.info(
            "AquaSec Scan Results - Pulling for scan completion (interval %ds, timeout %ds).",
            POLL_INTERVAL,
            POLL_TIMEOUT,
        )

        headers = {"Authorization": f"Bearer {self.bearer_token}", "Content-Type": "application/json"}
        encoded_branch = quote(branch, safe="")  # Encoding the special characters into API request friendly format
        elapsed = 0

        while elapsed < POLL_TIMEOUT:
            poll_url = (
                f"{BRANCH_STATUS_URL}/{repository_id}/branches"
                f"?page=1&page_size=10&order_by=-scan_date&branch_name={encoded_branch}"
            )

            response = requests.get(poll_url, headers=headers, timeout=HTTP_TIMEOUT)

            if response.status_code < 200 or response.status_code >= 300:
                logger.warning(
                    "AquaSec Scan Results - Branch status returned HTTP %d, retrying...", response.status_code
                )
                time.sleep(POLL_INTERVAL)
                elapsed += POLL_INTERVAL
                continue

            # Parse response and check scan status for the target branch.
            branch_records = response.json()
            for branch_record in branch_records.get("data", []):
                if branch_record.get("branch_name") == branch:
                    status = branch_record.get("status", "")
                    if status == "scan_completed" and branch_record.get("scan_details"):
                        scan_id = branch_record["scan_details"].get("scan_id", "")
                        if not scan_id:
                            logger.warning("AquaSec Scan Results - scan_details missing scan_id.")
                            break
                        logger.info("AquaSec Scan Results - Scan completed, scan_id received.")
                        return scan_id
                    if status == "scan_failed":
                        raise ValueError(
                            f"Scan failed on branch '{branch}': {branch_record.get('last_error', 'unknown error')}"
                        )
                    break

            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL
            logger.info(
                "AquaSec Scan Results - Polling for scan completion next try... (%ds/%ds).", elapsed, POLL_TIMEOUT
            )

        raise ValueError(f"Scan did not complete within {POLL_TIMEOUT}s for branch '{branch}'.")
