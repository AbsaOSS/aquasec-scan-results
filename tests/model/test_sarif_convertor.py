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
Tests for SarifConvertor module.
"""

from src.model.sarif_convertor import SarifConvertor
from src.utils.constants import (
    SARIF_SCHEMA_URL,
    SARIF_VERSION,
    TITLE_MAX_LENGTH,
)


# convert_to_sarif


def test_convert_to_sarif_returns_valid_structure():
    findings = {
        "total": 1,
        "data": [
            {
                "avd_id": "test-rule",
                "severity": 3,
                "title": "Test Finding",
                "message": "Test description",
                "category": "sast",
            }
        ],
    }

    actual = SarifConvertor().convert_to_sarif(findings)

    assert SARIF_SCHEMA_URL == actual["$schema"]
    assert SARIF_VERSION == actual["version"]
    assert "runs" in actual
    assert 1 == len(actual["runs"])
    assert "tool" in actual["runs"][0]
    assert "results" in actual["runs"][0]


def test_convert_to_sarif_handles_empty_findings():
    findings = {"total": 0, "data": []}

    actual = SarifConvertor().convert_to_sarif(findings)

    assert 0 == len(actual["runs"][0]["results"])
    assert 0 == len(actual["runs"][0]["tool"]["driver"]["rules"])


def test_convert_to_sarif_maps_severity_null_to_note():
    findings = {"total": 1, "data": [{"avd_id": "test-rule-low"}]}

    actual = SarifConvertor().convert_to_sarif(findings)

    assert "note" == actual["runs"][0]["results"][0]["level"]


def test_convert_to_sarif_maps_severity_4_to_error():
    findings = {"total": 1, "data": [{"avd_id": "test-rule-critical", "severity": 4}]}

    actual = SarifConvertor().convert_to_sarif(findings)

    assert "error" == actual["runs"][0]["results"][0]["level"]


def test_convert_to_sarif_truncates_short_description():
    long_title = "a" * (TITLE_MAX_LENGTH + 100)
    findings = {"total": 1, "data": [{"avd_id": "test-rule", "title": long_title}]}

    actual = SarifConvertor().convert_to_sarif(findings)

    short_desc = actual["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"]
    assert TITLE_MAX_LENGTH == len(short_desc)


def test_convert_to_sarif_includes_file_location():
    findings = {
        "total": 1,
        "data": [{"avd_id": "test-rule", "target_file": "src/main.py"}],
    }

    actual = SarifConvertor().convert_to_sarif(findings)

    locations = actual["runs"][0]["results"][0]["locations"]
    assert 1 == len(locations)
    assert "src/main.py" == locations[0]["physicalLocation"]["artifactLocation"]["uri"]


def test_convert_to_sarif_includes_line_location():
    findings = {
        "total": 1,
        "data": [{"avd_id": "test-rule", "title": "Test", "target_file": "src/main.py", "target_start_line": 42}],
    }

    actual = SarifConvertor().convert_to_sarif(findings)

    region = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert 42 == region["startLine"]


def test_convert_to_sarif_includes_line_range():
    findings = {
        "total": 1,
        "data": [
            {
                "avd_id": "test-rule",
                "title": "Test",
                "target_file": "src/main.py",
                "target_start_line": 42,
                "target_end_line": 45,
            }
        ],
    }

    actual = SarifConvertor().convert_to_sarif(findings)

    region = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert 42 == region["startLine"]
    assert 45 == region["endLine"]


def test_convert_to_sarif_handles_missing_avd_id():
    findings = {"total": 1, "data": [{"title": "Test", "severity": 2}]}

    actual = SarifConvertor().convert_to_sarif(findings)

    assert "N/A" == actual["runs"][0]["results"][0]["ruleId"]


def test_convert_to_sarif_includes_reference_as_help_uri():
    findings = {
        "total": 1,
        "data": [
            {
                "avd_id": "test-rule",
                "title": "Test",
                "extraData": {"references": ["https://example.com"]},
            }
        ],
    }

    actual = SarifConvertor().convert_to_sarif(findings)

    assert "https://example.com" == actual["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"]


def test_convert_to_sarif_rule_message_text_includes_all_fields():
    findings = {
        "total": 1,
        "data": [
            {
                "avd_id": "test-rule",
                "title": "Test",
                "severity": 3,
                "category": "sast",
                "fixed_version": "1.2.3",
                "published_date": "2026-01-01",
                "package_name": "test-pkg",
                "extraData": {
                    "cwe": "CWE-295",
                    "owasp": ["A03:2017 - Sensitive Data Exposure", "A07:2021"],
                    "category": "security/audit",
                    "impact": "HIGH",
                    "confidence": "MEDIUM",
                    "likelihood": "LOW",
                    "remediation": "Fix it",
                    "references": ["https://example.com", "https://other.com"],
                },
            }
        ],
    }

    actual = SarifConvertor().convert_to_sarif(findings)

    help_text = actual["runs"][0]["tool"]["driver"]["rules"][0]["help"]["text"]
    assert "**test-rule**" in help_text
    assert "**Type:** sast" in help_text
    assert "**Severity:** HIGH" in help_text
    assert "**CWE:** CWE-295" in help_text
    assert "**Fixed version:** 1.2.3" in help_text
    assert "**Published date:** 2026-01-01" in help_text
    assert "**Package name:** test-pkg" in help_text
    assert "**Category:** security/audit" in help_text
    assert "**Impact:** HIGH" in help_text
    assert "**Confidence:** MEDIUM" in help_text
    assert "**Likelihood:** LOW" in help_text
    assert "**Remediation:** Fix it" in help_text
    assert "**OWASP:**" in help_text
    assert "  - A03:2017 - Sensitive Data Exposure" in help_text
    assert "  - A07:2021" in help_text
    assert "**References:**" in help_text
    assert "  - https://example.com" in help_text
    assert "  - https://other.com" in help_text


def test_convert_to_sarif_rule_message_text_shows_placeholder_for_missing_fields():
    findings = {
        "total": 1,
        "data": [
            {
                "avd_id": "test-rule",
                "title": "Test",
                "severity": 2,
                "category": "sast",
                "extraData": {},
            }
        ],
    }

    actual = SarifConvertor().convert_to_sarif(findings)

    help_text = actual["runs"][0]["tool"]["driver"]["rules"][0]["help"]["text"]
    assert "**CWE:** N/A" in help_text
    assert "**Fixed version:** N/A" in help_text
    assert "**Published date:** N/A" in help_text
    assert "**Package name:** N/A" in help_text
    assert "**Category:** N/A" in help_text
    assert "**Impact:** N/A" in help_text
    assert "**Confidence:** N/A" in help_text
    assert "**Likelihood:** N/A" in help_text
    assert "**Remediation:** N/A" in help_text
    assert "**OWASP:**" not in help_text
    assert "**References:**" not in help_text


def test_convert_to_sarif_alert_message_includes_all_fields():
    findings = {
        "total": 1,
        "data": [
            {
                "avd_id": "test-rule",
                "severity": 3,
                "category": "sast",
                "message": "Test message",
                "target_file": "src/main.py",
                "target_start_line": 42,
                "target_end_line": 45,
                "repository_full_name": "org/repo",
                "reachable": False,
                "scan_date": "2026-02-08T15:16:40.219Z",
                "first_seen": "2025-09-17T12:46:48.271Z",
                "scm_file": "https://github.com/org/repo/blob/abc/src/main.py",
                "installed_version": "1.0.0",
                "result_hash": "abc123",
            }
        ],
    }

    actual = SarifConvertor().convert_to_sarif(findings)

    message = actual["runs"][0]["results"][0]["message"]["text"]
    assert "Artifact: src/main.py" in message
    assert "Type: sast" in message
    assert "Vulnerability: test-rule" in message
    assert "Severity: HIGH" in message
    assert "Message: Test message" in message
    assert "Repository: org/repo" in message
    assert "Reachable: False" in message
    assert "Scan date: 2026-02-08T15:16:40.219Z" in message
    assert "First seen: 2025-09-17T12:46:48.271Z" in message
    assert "SCM file: https://github.com/org/repo/blob/abc/src/main.py" in message
    assert "Installed version: 1.0.0" in message
    assert "Start line: 42" in message
    assert "End line: 45" in message
    assert "Alert hash: abc123" in message


# _build_message_body


def test_build_message_body_formats_with_bold():
    fields = [("Label", "value"), ("Empty", ""), ("Other", "data")]

    actual = SarifConvertor._build_message_body(fields, bold_labels=True)

    assert ["**Label:** value", "**Other:** data"] == actual


def test_build_message_body_skips_empty_values():
    fields = [("First", ""), ("Second", "val"), ("Third", "")]

    actual = SarifConvertor._build_message_body(fields, bold_labels=True)

    assert ["**Second:** val"] == actual


# _format_list_as_markdown


def test_format_list_as_markdown():
    actual = SarifConvertor._format_list_as_markdown(["Item 1", "Item 2"])

    assert "  - Item 1\n  - Item 2" == actual


def test_convert_to_sarif_handles_duplicate_rules():
    findings = {
        "total": 2,
        "data": [
            {"avd_id": "test-rule", "title": "Test 1", "severity": 3},
            {"avd_id": "test-rule", "title": "Test 2", "severity": 2},
        ],
    }

    actual = SarifConvertor().convert_to_sarif(findings)

    assert 1 == len(actual["runs"][0]["tool"]["driver"]["rules"])
    assert 2 == len(actual["runs"][0]["results"])


def test_convert_to_sarif_handles_multiple_different_rules():
    findings = {
        "total": 2,
        "data": [
            {"avd_id": "rule-1", "title": "Test 1", "severity": 3},
            {"avd_id": "rule-2", "title": "Test 2", "severity": 1},
        ],
    }

    actual = SarifConvertor().convert_to_sarif(findings)

    assert 2 == len(actual["runs"][0]["tool"]["driver"]["rules"])
    assert 2 == len(actual["runs"][0]["results"])


def test_convert_to_sarif_includes_tool_metadata():
    findings = {"total": 0, "data": []}

    actual = SarifConvertor().convert_to_sarif(findings)

    driver = actual["runs"][0]["tool"]["driver"]
    assert "AquaSec" == driver["name"]
    assert "1.0.0" == driver["version"]
    assert "https://www.aquasec.com/" == driver["informationUri"]


def test_convert_to_sarif_handles_zero_line_number():
    findings = {
        "total": 1,
        "data": [{"avd_id": "test-rule", "title": "Test", "target_file": "src/main.py", "target_start_line": 0}],
    }

    actual = SarifConvertor().convert_to_sarif(findings)

    location = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in location


def test_convert_to_sarif_handles_negative_line_number():
    findings = {
        "total": 1,
        "data": [{"avd_id": "test-rule", "title": "Test", "target_file": "src/main.py", "target_start_line": -1}],
    }

    actual = SarifConvertor().convert_to_sarif(findings)

    location = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in location


# _truncate_text


def test_truncate_text_returns_original_when_within_limit():
    actual = SarifConvertor._truncate_text("short text", 100)

    assert "short text" == actual


def test_truncate_text_truncates_when_exceeds_limit():
    actual = SarifConvertor._truncate_text("long text here", 4)

    assert "long" == actual


# _map_severity_to_level


def test_map_severity_to_level_returns_correctly():
    assert "error" == SarifConvertor._map_severity_to_level(4)
    assert "error" == SarifConvertor._map_severity_to_level(3)
    assert "warning" == SarifConvertor._map_severity_to_level(2)
    assert "note" == SarifConvertor._map_severity_to_level(1)


# _map_severity_to_score


def test_map_severity_to_score_returns_correctly():
    assert "9.5" == SarifConvertor._map_severity_to_score(4)
    assert "8.0" == SarifConvertor._map_severity_to_score(3)
    assert "5.5" == SarifConvertor._map_severity_to_score(2)
    assert "2.0" == SarifConvertor._map_severity_to_score(1)


# _get_severity_tag


def test_get_severity_tag_returns_correctly():
    assert "CRITICAL" == SarifConvertor._get_severity_tag(4)
    assert "HIGH" == SarifConvertor._get_severity_tag(3)
    assert "MEDIUM" == SarifConvertor._get_severity_tag(2)
    assert "LOW" == SarifConvertor._get_severity_tag(1)
