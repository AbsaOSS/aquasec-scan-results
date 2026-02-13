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
    RULE_ID_MAX_LENGTH,
    TITLE_MAX_LENGTH,
    LONG_TEXT_MAX_LENGTH,
    SARIF_PLACEHOLDER,
)

logger = logging.getLogger(__name__)

# Type aliases
Finding = dict[str, Any]
FindingsList = list[Finding]


class SarifConvertor:
    """
    Class to convert AquaSec scan findings to SARIF 2.1.0 format.
    """

    def __init__(self) -> None:
        self.findings_json: FindingsList = []

    # Text utility
    @staticmethod
    def _truncate_text(text: str, max_length: int) -> str:
        """
        Truncate text to maximum length.

        Args:
            text: Text to truncate.
            max_length: Maximum allowed length.

        Returns:
            Truncated text if needed.
        """
        if len(text) > max_length:
            return text[:max_length]
        return text

    # Severity mapping utilities
    @staticmethod
    def _map_severity_to_level(severity: int) -> str:
        """
        Map AquaSec severity to SARIF level.

        Args:
            severity: AquaSec severity level (4=critical, 3=high, 2=medium, 1=low).

        Returns:
            SARIF level string.
        """
        if severity >= 3:
            return "error"
        if severity == 2:
            return "warning"
        return "note"

    @staticmethod
    def _map_severity_to_score(severity: int) -> str:
        """
        Map AquaSec severity to security-severity score.

        Args:
            severity: AquaSec severity level (4=critical, 3=high, 2=medium, 1=low).

        Returns:
            Security severity score as string.
        """
        severity_map = {4: "9.5", 3: "8.0", 2: "5.5", 1: "2.0"}
        return severity_map.get(severity, "2.0")

    @staticmethod
    def _get_severity_tag(severity: int) -> str:
        """
        Get severity tag for SARIF properties.

        Args:
            severity: AquaSec severity level (4=critical, 3=high, 2=medium, 1=low).

        Returns:
            Severity tag string.
        """
        severity_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}
        return severity_map.get(severity, "UNKNOWN")

    def _build_rule(self, finding_json: Finding) -> dict:
        """
        Build a SARIF rule object from an AquaSec finding.


        Args:
            finding_json: AquaSec finding dictionary.

        Returns:
            SARIF rule dictionary.
        """
        rule_id = finding_json.get("avd_id", SARIF_PLACEHOLDER)
        rule_id = self._truncate_text(rule_id, RULE_ID_MAX_LENGTH)
        logger.debug("Building a new security rule in SARIF format (rule id: %s).", rule_id)

        title = finding_json.get("title", SARIF_PLACEHOLDER)
        short_desc = self._truncate_text(title, TITLE_MAX_LENGTH)

        severity = finding_json.get("severity", 1)
        level = self._map_severity_to_level(severity)
        security_severity = self._map_severity_to_score(severity)
        severity_tag = self._get_severity_tag(severity)
        category = finding_json.get("category", SARIF_PLACEHOLDER)

        extra_data = finding_json.get("extraData", {})
        references = extra_data.get("references", [])
        cwe = extra_data.get("cwe", "")
        remediation = extra_data.get("remediation", "")

        # Build help text
        help_text_parts = [
            f"**{rule_id}**",
            f"**Type:** {category}",
            f"**Severity:** {severity_tag}",
            f"**Check:** {title}",
            f"**CWE:** {cwe}" if cwe else "",
            f"**Remediation:** {remediation}" if remediation else "",
        ]

        if references:
            help_text_parts.append(f"**Link:** [{rule_id}]({references[0]})")

        help_text = "\n".join(help_text_parts)

        rule: dict[str, Any] = {
            "id": rule_id,
            "name": category,
            "shortDescription": {"text": short_desc},
            "defaultConfiguration": {"level": level},
            "helpUri": references[0] if references else "",
            "help": {"text": help_text},
            "properties": {
                "precision": "very-high",
                "security-severity": security_severity,
                "tags": [category, "security", severity_tag],
            },
        }

        logger.debug("Created a new `%s` rule with id `%s`.", category, rule_id)

        return rule

    def _build_sarif_finding(self, finding_json: Finding, rule_index: int) -> dict:
        """
        Build a SARIF finding object from an AquaSec finding.

        Args:
            finding_json: AquaSec finding dictionary in JSON format.
            rule_index: Index of the rule in the rules array.

        Returns:
            Security finding in SARIF format.
        """
        rule_id = finding_json.get("avd_id", SARIF_PLACEHOLDER)
        rule_id = self._truncate_text(rule_id, RULE_ID_MAX_LENGTH)

        severity = finding_json.get("severity", 1)
        level = self._map_severity_to_level(severity)

        # Build message text
        category = finding_json.get("category", SARIF_PLACEHOLDER)
        target_file = finding_json.get("target_file", "")
        logger.debug(
            "Building a finding in category `%s` that targets a file `%s` (rule: `%s`).",
            category,
            target_file,
            rule_id,
        )
        message_content = finding_json.get("message", SARIF_PLACEHOLDER)
        finding_hash = finding_json.get("result_hash", SARIF_PLACEHOLDER)

        message_parts = []
        if target_file:
            message_parts.append(f"Artifact: {target_file}")
        message_parts.append(f"Type: {category}")
        message_parts.append(f"Vulnerability: {rule_id}")
        message_parts.append(f"Severity: {self._get_severity_tag(severity)}")
        message_parts.append(f"Message: {message_content}")
        message_parts.append(f"Alert hash: {finding_hash}")

        message_text = "\n".join(message_parts)
        message_text = self._truncate_text(message_text, LONG_TEXT_MAX_LENGTH)

        finding: dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index,
            "level": level,
            "message": {"text": message_text},
        }

        # Add location information
        if target_file:
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": target_file,
                        "uriBaseId": "ROOTPATH",
                    },
                },
                "message": {"text": str(target_file)},
            }

            # Add line information
            start_line = finding_json.get("target_start_line", 0)
            end_line = finding_json.get("target_end_line", 0)

            if start_line and isinstance(start_line, int) and start_line > 0:
                region: dict[str, Any] = {
                    "startLine": start_line,
                    "startColumn": 1,
                }
                if end_line and isinstance(end_line, int) and end_line > 0:
                    region["endLine"] = end_line
                    region["endColumn"] = 1
                else:
                    region["endLine"] = start_line
                    region["endColumn"] = 1

                location["physicalLocation"]["region"] = region

            finding["locations"] = [location]

        return finding

    def convert_to_sarif(self, findings_json: dict) -> dict:
        """
        Convert AquaSec findings to SARIF 2.1.0 format.

        Args:
            findings_json: Dictionary containing AquaSec scan findings in JSON format.
        Returns:
            SARIF dictionary.
        """
        logger.info("AquaSec Scan Results - SARIF conversion starting.")

        self.findings_json = findings_json.get("data", [])

        # Build unique security rules and track their indices
        rules_dict: dict[str, dict] = {}
        rule_indexes: dict[str, int] = {}

        for finding_json in self.findings_json:
            rule_id = finding_json.get("avd_id", SARIF_PLACEHOLDER)
            rule_id = self._truncate_text(str(rule_id), RULE_ID_MAX_LENGTH)

            if rule_id not in rules_dict:
                rules_dict[rule_id] = self._build_rule(finding_json)
                rule_indexes[rule_id] = len(rules_dict) - 1

        # SARIF output has to be JSON serializable
        rules = list(rules_dict.values())

        # Build result findings output
        findings = []
        for finding_json in self.findings_json:
            rule_id = finding_json.get("avd_id", SARIF_PLACEHOLDER)
            rule_id = self._truncate_text(str(rule_id), RULE_ID_MAX_LENGTH)
            rule_index = rule_indexes.get(rule_id, 0)
            findings.append(self._build_sarif_finding(finding_json, rule_index))

        # Build SARIF structure
        sarif = {
            "version": SARIF_VERSION,
            "$schema": SARIF_SCHEMA_URL,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "fullName": "AquaSec Security Scanner",
                            "informationUri": "https://www.aquasec.com/",
                            "name": "AquaSec",
                            "rules": rules,
                            "version": "1.0.0",
                        }
                    },
                    "results": findings,
                }
            ],
        }

        logger.info("AquaSec Scan Results - SARIF conversion successful.")

        return sarif
