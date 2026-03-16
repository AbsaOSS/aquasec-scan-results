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

import json
import logging
import os

from src.model.branch_comparator import BranchComparator
from src.model.sarif_convertor import SarifConvertor
from src.model.scan_fetcher import ScanFetcher
from src.model.scan_trigger import ScanTrigger
from src.utils.constants import REPOSITORY_ID
from src.utils.utils import get_action_input

logger = logging.getLogger(__name__)


class BranchComparisonMode:
    """
    Class to orchestrate the developer branch comparison flow.
    """

    def __init__(self, bearer_token: str) -> None:
        self.bearer_token = bearer_token
        self.summary_file: str | None = None
        self.new_findings_sarif: str | None = None

    def run(self) -> dict[str, str | None]:
        """
        Run the developer branch/master comparison flow.

        Returns:
            Dictionary with paths to summary comparison comment and new security alerts if any.
        Raises:
            ValueError: If GITHUB_HEAD_REF is not set or API returns invalid response.
        """
        branch_name = os.getenv("GITHUB_HEAD_REF", "")
        if not branch_name:
            raise ValueError("GITHUB_HEAD_REF not available. This action has to run in a PR.")

        repository_id = get_action_input(REPOSITORY_ID)
        logger.info("AquaSec Scan Results - Starting branch comparison mode.")

        # Fetch findings for comparison
        scan_fetcher = ScanFetcher(self.bearer_token)
        scan_id = ScanTrigger(self.bearer_token).trigger_and_get_scan_id(repository_id, branch_name)
        dev_findings = scan_fetcher.fetch_findings(scan_id=scan_id)
        master_findings = scan_fetcher.fetch_findings()

        # Compare findings and generate comparison summary
        comparator = BranchComparator(branch_name, master_findings, dev_findings)
        findings_comparison = comparator.compare()
        summary = comparator.build_comparison_summary(findings_comparison)

        # Saving comparison Markdown summary
        self.summary_file = os.path.abspath("comparison_summary.md")
        with open(self.summary_file, "w", encoding="utf-8") as md_file:
            md_file.write(summary)
        logger.info("AquaSec Scan Results - Comparison summary saved in `%s`.", self.summary_file)

        # Saving new security findings in SARIF format if any
        self._save_new_findings_sarif(findings_comparison["new_findings"])

        return {
            "summary_file": self.summary_file,
            "new_findings_sarif": self.new_findings_sarif,
        }

    def _save_new_findings_sarif(self, new_findings: list[dict]) -> None:
        """Save new findings as a SARIF file when present."""
        if not new_findings:
            return

        new_findings_json = {"total": len(new_findings), "data": new_findings}
        sarif_data = SarifConvertor().convert_to_sarif(new_findings_json)

        self.new_findings_sarif = os.path.abspath("new_findings.sarif")
        with open(self.new_findings_sarif, "w", encoding="utf-8") as sarif_file:
            json.dump(sarif_data, sarif_file, indent=2)
        logger.info(
            "AquaSec Scan Results - New findings SARIF file saved in `%s`.",
            self.new_findings_sarif,
        )
