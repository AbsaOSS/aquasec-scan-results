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
This module implements AquaSec findings to SARIF conversion logic.
"""

import logging
from typing import Any

from src.utils.constants import (
    SARIF_SCHEMA_URL,
    SARIF_VERSION,
    SARIF_RULE_ID_MAX,
    SARIF_SHORT_DESC_MAX,
    SARIF_FULL_DESC_MAX,
    SARIF_MESSAGE_MAX,
)

logger = logging.getLogger(__name__)


class Convertor:
    """
    Class to convert AquaSec scan findings to SARIF 2.1.0 format.
    """

    def __init__(self, findings: dict) -> None:
        self.findings: dict = findings

    def _truncate_text(self, text: str, max_length: int) -> str:
        """
        Truncate text to maximum length.

        Args:
            text: Text to truncate.
            max_length: Maximum allowed length.

        Returns:
            Truncated text.
        """
        if len(text) > max_length:
            return text[:max_length]
        return text

    def _map_severity_to_level(self, severity: str) -> str:
        """
        Map AquaSec severity to SARIF level.

        Args:
            severity: AquaSec severity level.

        Returns:
            SARIF level string.
        """
        severity_lower = severity.lower() if severity else "unknown"

        if severity_lower in ["critical", "high"]:
            return "error"
        if severity_lower == "medium":
            return "warning"
        # low, negligible, unknown and any other value
        return "note"

    def _build_rule(self, finding: dict) -> dict:
        """
        Build a SARIF rule object from an AquaSec finding.

        Args:
            finding: AquaSec finding dictionary.

        Returns:
            SARIF rule dictionary.
        """
        rule_id = finding.get("rule_name", finding.get("rule_id", "unknown"))
        rule_id = self._truncate_text(str(rule_id), SARIF_RULE_ID_MAX)

        short_desc = finding.get("name", finding.get("rule_name", "Security finding"))
        short_desc = self._truncate_text(str(short_desc), SARIF_SHORT_DESC_MAX)

        full_desc = finding.get("description", short_desc)
        full_desc = self._truncate_text(str(full_desc), SARIF_FULL_DESC_MAX)

        rule = {
            "id": rule_id,
            "shortDescription": {"text": short_desc},
            "fullDescription": {"text": full_desc},
            "help": {"text": full_desc},
        }

        # Add help URI if available
        reference = finding.get("reference", finding.get("url", ""))
        if reference:
            rule["helpUri"] = str(reference)

        return rule

    def _build_result(self, finding: dict) -> dict:
        """
        Build a SARIF result object from an AquaSec finding.

        Args:
            finding: AquaSec finding dictionary.

        Returns:
            SARIF result dictionary.
        """
        rule_id = finding.get("rule_name", finding.get("rule_id", "unknown"))
        rule_id = self._truncate_text(str(rule_id), SARIF_RULE_ID_MAX)

        severity = finding.get("severity", "unknown")
        level = self._map_severity_to_level(str(severity))

        # Build message text with remediation if available
        message_parts = []
        name = finding.get("name", finding.get("rule_name", "Security finding"))
        message_parts.append(str(name))

        description = finding.get("description", "")
        if description and str(description) != str(name):
            message_parts.append(str(description))

        remediation = finding.get("remediation", "")
        if remediation:
            message_parts.append(f"Remediation: {remediation}")

        message_text = " - ".join(message_parts)
        message_text = self._truncate_text(message_text, SARIF_MESSAGE_MAX)

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message_text},
        }

        # Add location information if available
        file_path = finding.get("file_path", finding.get("path", ""))
        if file_path:
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": str(file_path)},
                }
            }

            # Add line information if available
            line_start = finding.get("line_start", finding.get("line", 0))
            if line_start and isinstance(line_start, int) and line_start > 0:
                region: dict[str, Any] = {"startLine": line_start}

                line_end = finding.get("line_end", 0)
                if line_end and isinstance(line_end, int) and line_end > 0:
                    region["endLine"] = line_end

                location["physicalLocation"]["region"] = region

            result["locations"] = [location]

        return result

    def convert_to_sarif(self) -> dict:
        """
        Convert AquaSec findings to SARIF 2.1.0 format.

        Returns:
            SARIF dictionary.
        """
        logger.info("AquaSec Scan Results - SARIF conversion starting.")

        findings_data = self.findings.get("data", [])
        total_findings = len(findings_data)

        logger.debug("Converting %d findings to SARIF format.", total_findings)

        # Build unique rules
        rules_dict = {}
        for finding in findings_data:
            rule_id = finding.get("rule_name", finding.get("rule_id", "unknown"))
            rule_id = self._truncate_text(str(rule_id), SARIF_RULE_ID_MAX)

            if rule_id not in rules_dict:
                rules_dict[rule_id] = self._build_rule(finding)

        rules = list(rules_dict.values())

        # Build results
        results = []
        for finding in findings_data:
            results.append(self._build_result(finding))

        # Build SARIF structure
        sarif = {
            "$schema": SARIF_SCHEMA_URL,
            "version": SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AquaSec",
                            "version": "1.0.0",
                            "informationUri": "https://www.aquasec.com/",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

        logger.info("AquaSec Scan Results - SARIF conversion successful (%d findings).", total_findings)

        return sarif
