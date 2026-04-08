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
This module implements the developer branch comparison flow for AquaSec scan results.
"""

import logging
import os

from src.action_inputs import ActionInputs
from src.services.branch_comparator import BranchComparator
from src.services.scan_fetcher import ScanFetcher
from src.services.scan_trigger import ScanTrigger

logger = logging.getLogger(__name__)


class BranchComparisonMode:
    """
    Class to orchestrate the developer branch comparison flow.
    """

    def __init__(self, bearer_token: str) -> None:
        self.bearer_token = bearer_token

    def run(self) -> tuple[str, bool]:
        """
        Run the developer branch/master comparison flow.

        Returns:
            Tuple of (absolute path to comparison summary Markdown file,
            whether new findings were detected).
        Raises:
            ValueError: If GITHUB_HEAD_REF is not set or API returns invalid response.
        """
        branch_name = os.getenv("GITHUB_HEAD_REF", "")
        if not branch_name:
            raise ValueError("GITHUB_HEAD_REF not available. This action has to run in a PR.")

        repository_id = ActionInputs.get_repository_id()
        poll_interval = ActionInputs.get_poll_interval()
        poll_timeout = ActionInputs.get_poll_timeout()
        logger.info("AquaSec Scan Results - Starting branch comparison mode.")

        # Fetch findings for comparison
        scan_fetcher = ScanFetcher(self.bearer_token)
        scan_id = ScanTrigger(self.bearer_token, poll_interval, poll_timeout).trigger_and_get_scan_id(
            repository_id, branch_name
        )
        dev_scan_response = scan_fetcher.fetch_findings(scan_id=scan_id)
        master_scan_response = scan_fetcher.fetch_findings()

        # Compare findings and generate comparison summary
        comparator = BranchComparator(branch_name, master_scan_response, dev_scan_response)
        findings_comparison = comparator.compute_findings_delta()
        has_new_findings = bool(findings_comparison.new_findings)
        summary = comparator.build_comparison_summary(findings_comparison)

        # Save comparison Markdown summary
        summary_file = os.path.abspath("comparison_summary.md")
        with open(summary_file, "w", encoding="utf-8") as md_file:
            md_file.write(summary)
        logger.info("AquaSec Scan Results - Comparison summary saved in `%s`.", summary_file)

        return summary_file, has_new_findings
