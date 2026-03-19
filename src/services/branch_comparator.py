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
This module implements branch comparison logic for AquaSec scan findings.
"""

import logging

from src.types import ComparisonFinding, ComparisonFindingsList, ComparisonResult, ScanResponse
from src.utils.constants import SEVERITY_MAP, SEVERITY_ORDER

logger = logging.getLogger(__name__)


class BranchComparator:
    """
    Class to compare AquaSec scan findings between master and developer branches.
    """

    def __init__(
        self,
        branch_name: str,
        master_scan_response: ScanResponse,
        dev_scan_response: ScanResponse,
    ) -> None:
        self.branch_name: str = branch_name
        self.master_scan_response = master_scan_response
        self.dev_scan_response = dev_scan_response

    @staticmethod
    def _severity_label(raw_severity: int, default_output: str = "LOW") -> str:
        """
        Convert a severity integer to a human-readable label.

        Args:
            raw_severity: The severity integer from the API.
            default_output: The fallback label when the value is not in the severity map.
        Returns:
            A severity label string such as "CRITICAL", "HIGH", etc.
        """
        return SEVERITY_MAP.get(raw_severity, default_output)

    @staticmethod
    def _getting_unique_key(finding: ComparisonFinding) -> str:
        """
        Generate a unique key for a finding for deduplication.

        Args:
            finding: A single JSON finding.
        Returns:
            A unique string key for the finding.
        """
        result_hash = finding.get("result_hash", "")
        if result_hash:
            return result_hash

        avd_id = str(finding.get("avd_id", ""))
        target_file = str(finding.get("target_file", ""))
        target_start_line = str(finding.get("target_start_line", ""))
        return f"{avd_id}|{target_file}|{target_start_line}"

    def _format_findings_list(self, findings: ComparisonFindingsList) -> list[str]:
        """
        Format a list of findings as Markdown bullet points.

        Args:
            findings: List of finding dictionaries.
        Returns:
            List of formatted findings as Markdown strings.
        """
        formatted_findings: list[str] = []
        for f in findings:
            sev = self._severity_label(f.get("severity", 0))
            target_file = f.get("target_file", "")
            start_line = f.get("target_start_line", 0)
            location = f"{target_file}:{start_line}" if target_file and start_line else target_file
            formatted_findings.append(f"- **[{sev}]** {f.get('avd_id', 'N/A')} — {f.get('title', '')} (`{location}`)")
        return formatted_findings

    def compute_findings_delta(self) -> ComparisonResult:
        """
        Compute the delta between master and developer branch findings.

        Returns:
            A ComparisonResult with new and reduced findings.
        """
        logger.info("AquaSec Scan Results - Comparing master/dev branch findings.")

        master_findings: ComparisonFindingsList = self.master_scan_response.get("data", [])
        dev_findings: ComparisonFindingsList = self.dev_scan_response.get("data", [])

        master_findings_keyed = {self._getting_unique_key(f): f for f in master_findings}
        dev_findings_keyed = {self._getting_unique_key(f): f for f in dev_findings}

        new_keys = set(dev_findings_keyed.keys()) - set(master_findings_keyed.keys())
        reduced_keys = set(master_findings_keyed.keys()) - set(dev_findings_keyed.keys())

        new_findings = [dev_findings_keyed[k] for k in new_keys]
        reduced_findings = [master_findings_keyed[k] for k in reduced_keys]

        logger.info(
            "AquaSec Scan Results - Comparison complete: %d new, %d reduced.",
            len(new_findings),
            len(reduced_findings),
        )

        return ComparisonResult(
            new_findings=new_findings,
            reduced_findings=reduced_findings,
        )

    def build_comparison_summary(self, comparison: ComparisonResult) -> str:
        """
        Build a GitHub PR comment text of the branch comparison.

        Args:
            comparison: ComparisonResult returned by compute_findings_delta().
        Returns:
            A markdown-formatted string.
        """
        new_findings: ComparisonFindingsList = comparison.new_findings
        reduced_findings: ComparisonFindingsList = comparison.reduced_findings

        lines = [
            "<!-- aquasec-branch-comparison -->",
            "## AquaSec Security Scan — Branch Comparison",
            "",
            f"Master compared with branch: **{self.branch_name}**",
        ]

        if not new_findings and not reduced_findings:
            lines.extend(["", "> No differences found between master and developer branch."])
            lines.append("")
            return "\n".join(lines)

        # Severity breakdown table
        new_counts = {s: 0 for s in SEVERITY_ORDER}
        reduced_counts = {s: 0 for s in SEVERITY_ORDER}

        for f in new_findings:
            new_counts[self._severity_label(f.get("severity", 0))] += 1

        for f in reduced_findings:
            reduced_counts[self._severity_label(f.get("severity", 0))] += 1

        lines.extend(
            [
                "",
                "### Severity Breakdown",
                "",
                "| | CRITICAL | HIGH | MEDIUM | LOW |",
                "|---|---|---|---|---|",
                f"| **New (+)** | {new_counts['CRITICAL']} | {new_counts['HIGH']} "
                f"| {new_counts['MEDIUM']} | {new_counts['LOW']} |",
                f"| **Reduced (-)** | {reduced_counts['CRITICAL']} | {reduced_counts['HIGH']} "
                f"| {reduced_counts['MEDIUM']} | {reduced_counts['LOW']} |",
            ]
        )

        if new_findings:
            lines.extend(["", "### New Findings", ""])
            lines.extend(self._format_findings_list(new_findings))

        if reduced_findings:
            lines.extend(["", "### Reduced Findings", ""])
            lines.extend(self._format_findings_list(reduced_findings))

        lines.append("")
        return "\n".join(lines)
