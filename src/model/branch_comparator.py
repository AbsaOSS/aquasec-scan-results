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
from typing import Any

from src.utils.constants import SEVERITY_MAP, SEVERITY_ORDER

logger = logging.getLogger(__name__)

Finding = dict[str, Any]
FindingsList = list[Finding]


class BranchComparator:
    """
    Class to compare AquaSec scan findings between master and developer branches.
    """

    def __init__(self, branch_name, master_findings, dev_findings) -> None:
        self.branch_name: str = branch_name
        self.master_findings = master_findings
        self.dev_findings = dev_findings

    @staticmethod
    def _getting_unique_key(finding: Finding) -> str:
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
        return finding.get("avd_id", "") + finding.get("target_file", "") + str(finding.get("target_start_line", ""))

    def compare(self) -> dict:
        """
        Compare master and developer branch findings.

        Returns:
            Dictionary with new_findings, reduced_findings, master_total, and dev_total.
        """
        logger.info("AquaSec Scan Results - Comparing master/dev branch findings.")

        master_data: FindingsList = self.master_findings.get("data", [])
        dev_data: FindingsList = self.dev_findings.get("data", [])

        master_findings_keyed = {self._getting_unique_key(f): f for f in master_data}
        dev_findings_keyed = {self._getting_unique_key(f): f for f in dev_data}

        new_keys = set(dev_findings_keyed.keys()) - set(master_findings_keyed.keys())
        reduced_keys = set(master_findings_keyed.keys()) - set(dev_findings_keyed.keys())

        new_findings = [dev_findings_keyed[k] for k in new_keys]
        reduced_findings = [master_findings_keyed[k] for k in reduced_keys]

        logger.info(
            "AquaSec Scan Results - Comparison complete: %d new, %d reduced.",
            len(new_findings),
            len(reduced_findings),
        )

        return {
            "new_findings": new_findings,
            "reduced_findings": reduced_findings,
        }

    def build_comparison_summary(self, comparison: dict) -> str:
        """
        Build a GitHub PR comment text of the branch comparison.

        Args:
            comparison: Comparison dict output returned by compare().
        Returns:
            A markdown-formatted string.
        """
        new_findings: FindingsList = comparison["new_findings"]
        reduced_findings: FindingsList = comparison["reduced_findings"]

        lines = [
            "<!-- aquasec-branch-comparison -->",
            "## AquaSec Security Scan — Branch Comparison",
            "",
            f"Git branch compared with master: **{self.branch_name}**",
        ]

        if not new_findings and not reduced_findings:
            lines.extend(["", "> No differences found between master and developer branch."])
            lines.append("")
            return "\n".join(lines)

        # Severity breakdown table
        new_counts = {s: 0 for s in SEVERITY_ORDER}
        reduced_counts = {s: 0 for s in SEVERITY_ORDER}

        for f in new_findings:
            sev = SEVERITY_MAP.get(int(f.get("severity", 0)), "LOW")
            new_counts[sev] += 1

        for f in reduced_findings:
            sev = SEVERITY_MAP.get(int(f.get("severity", 0)), "LOW")
            reduced_counts[sev] += 1

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

    @staticmethod
    def _format_findings_list(findings: FindingsList) -> list[str]:
        """
        Format a list of findings as Markdown bullet points sorted by severity.

        Args:
            findings: List of finding dictionaries.
        Returns:
            List of formatted findings as Markdown strings.
        """
        formatted_findings: list[str] = []
        for f in sorted(findings, key=lambda x: x.get("severity", 99)):
            sev = SEVERITY_MAP.get(int(f.get("severity", 0)), "N/A")
            target_file = f.get("target_file", "")
            start_line = f.get("target_start_line", "")
            location = f"{target_file}:{start_line}" if target_file and start_line else target_file
            formatted_findings.append(f"- **[{sev}]** {f.get('avd_id', 'N/A')} — {f.get('title', '')} (`{location}`)")
        return formatted_findings
