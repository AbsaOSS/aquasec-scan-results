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
Tests for convertor module.
"""

import pytest

from src.model.convertor import Convertor
from src.utils.constants import (
    SARIF_SCHEMA_URL,
    SARIF_VERSION,
    SARIF_RULE_ID_MAX,
    SARIF_SHORT_DESC_MAX,
    SARIF_FULL_DESC_MAX,
    SARIF_MESSAGE_MAX,
)


# convert_to_sarif


def test_convert_to_sarif_returns_valid_structure():
    findings = {
        "total": 1,
        "data": [
            {
                "rule_name": "test-rule",
                "severity": "high",
                "name": "Test Finding",
                "description": "Test description",
            }
        ],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert SARIF_SCHEMA_URL == actual["$schema"]
    assert SARIF_VERSION == actual["version"]
    assert "runs" in actual
    assert 1 == len(actual["runs"])
    assert "tool" in actual["runs"][0]
    assert "results" in actual["runs"][0]


def test_convert_to_sarif_maps_critical_severity_to_error():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "severity": "critical", "name": "Critical finding"}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "error" == actual["runs"][0]["results"][0]["level"]


def test_convert_to_sarif_maps_high_severity_to_error():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "severity": "high", "name": "High finding"}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "error" == actual["runs"][0]["results"][0]["level"]


def test_convert_to_sarif_maps_medium_severity_to_warning():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "severity": "medium", "name": "Medium finding"}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "warning" == actual["runs"][0]["results"][0]["level"]


def test_convert_to_sarif_maps_low_severity_to_note():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "severity": "low", "name": "Low finding"}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "note" == actual["runs"][0]["results"][0]["level"]


def test_convert_to_sarif_maps_negligible_severity_to_note():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "severity": "negligible", "name": "Negligible finding"}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "note" == actual["runs"][0]["results"][0]["level"]


def test_convert_to_sarif_maps_unknown_severity_to_note():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "severity": "unknown", "name": "Unknown finding"}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "note" == actual["runs"][0]["results"][0]["level"]


def test_convert_to_sarif_handles_empty_findings():
    findings = {"total": 0, "data": []}
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert 0 == len(actual["runs"][0]["results"])
    assert 0 == len(actual["runs"][0]["tool"]["driver"]["rules"])


def test_convert_to_sarif_truncates_rule_id():
    long_rule_id = "a" * (SARIF_RULE_ID_MAX + 100)
    findings = {"total": 1, "data": [{"rule_name": long_rule_id, "name": "Test"}]}
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    rule_id = actual["runs"][0]["results"][0]["ruleId"]
    assert SARIF_RULE_ID_MAX == len(rule_id)


def test_convert_to_sarif_truncates_short_description():
    long_name = "a" * (SARIF_SHORT_DESC_MAX + 100)
    findings = {"total": 1, "data": [{"rule_name": "test-rule", "name": long_name}]}
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    short_desc = actual["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"]
    assert SARIF_SHORT_DESC_MAX == len(short_desc)


def test_convert_to_sarif_truncates_full_description():
    long_desc = "a" * (SARIF_FULL_DESC_MAX + 100)
    findings = {"total": 1, "data": [{"rule_name": "test-rule", "name": "Test", "description": long_desc}]}
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    full_desc = actual["runs"][0]["tool"]["driver"]["rules"][0]["fullDescription"]["text"]
    assert SARIF_FULL_DESC_MAX == len(full_desc)


def test_convert_to_sarif_truncates_message_text():
    long_name = "a" * (SARIF_MESSAGE_MAX + 100)
    findings = {"total": 1, "data": [{"rule_name": "test-rule", "name": long_name}]}
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    message = actual["runs"][0]["results"][0]["message"]["text"]
    assert SARIF_MESSAGE_MAX == len(message)


def test_convert_to_sarif_includes_remediation_in_message():
    findings = {
        "total": 1,
        "data": [
            {
                "rule_name": "test-rule",
                "name": "Test",
                "description": "Description",
                "remediation": "Fix this issue",
            }
        ],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    message = actual["runs"][0]["results"][0]["message"]["text"]
    assert "Remediation: Fix this issue" in message


def test_convert_to_sarif_includes_file_location():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "name": "Test", "file_path": "src/main.py"}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    locations = actual["runs"][0]["results"][0]["locations"]
    assert 1 == len(locations)
    assert "src/main.py" == locations[0]["physicalLocation"]["artifactLocation"]["uri"]


def test_convert_to_sarif_includes_line_location():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "name": "Test", "file_path": "src/main.py", "line_start": 42}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    region = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert 42 == region["startLine"]


def test_convert_to_sarif_includes_line_range():
    findings = {
        "total": 1,
        "data": [
            {"rule_name": "test-rule", "name": "Test", "file_path": "src/main.py", "line_start": 42, "line_end": 45}
        ],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    region = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert 42 == region["startLine"]
    assert 45 == region["endLine"]


def test_convert_to_sarif_handles_missing_severity():
    findings = {"total": 1, "data": [{"rule_name": "test-rule", "name": "Test"}]}
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "note" == actual["runs"][0]["results"][0]["level"]


def test_convert_to_sarif_handles_null_severity():
    findings = {"total": 1, "data": [{"rule_name": "test-rule", "name": "Test", "severity": None}]}
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "note" == actual["runs"][0]["results"][0]["level"]


def test_convert_to_sarif_handles_missing_rule_name():
    findings = {"total": 1, "data": [{"name": "Test", "severity": "high"}]}
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "unknown" == actual["runs"][0]["results"][0]["ruleId"]


def test_convert_to_sarif_uses_rule_id_fallback():
    findings = {"total": 1, "data": [{"rule_id": "custom-id", "name": "Test", "severity": "high"}]}
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "custom-id" == actual["runs"][0]["results"][0]["ruleId"]


def test_convert_to_sarif_handles_missing_name():
    findings = {"total": 1, "data": [{"rule_name": "test-rule", "severity": "high"}]}
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "test-rule" in actual["runs"][0]["results"][0]["message"]["text"]


def test_convert_to_sarif_includes_reference_as_help_uri():
    findings = {
        "total": 1,
        "data": [
            {
                "rule_name": "test-rule",
                "name": "Test",
                "reference": "https://example.com/vuln",
            }
        ],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "https://example.com/vuln" == actual["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"]


def test_convert_to_sarif_uses_url_fallback_for_reference():
    findings = {
        "total": 1,
        "data": [
            {
                "rule_name": "test-rule",
                "name": "Test",
                "url": "https://example.com/info",
            }
        ],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert "https://example.com/info" == actual["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"]


def test_convert_to_sarif_handles_duplicate_rules():
    findings = {
        "total": 2,
        "data": [
            {"rule_name": "test-rule", "name": "Test 1", "severity": "high"},
            {"rule_name": "test-rule", "name": "Test 2", "severity": "medium"},
        ],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert 1 == len(actual["runs"][0]["tool"]["driver"]["rules"])
    assert 2 == len(actual["runs"][0]["results"])


def test_convert_to_sarif_handles_multiple_different_rules():
    findings = {
        "total": 2,
        "data": [
            {"rule_name": "rule-1", "name": "Test 1", "severity": "high"},
            {"rule_name": "rule-2", "name": "Test 2", "severity": "low"},
        ],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    assert 2 == len(actual["runs"][0]["tool"]["driver"]["rules"])
    assert 2 == len(actual["runs"][0]["results"])


def test_convert_to_sarif_includes_tool_metadata():
    findings = {"total": 0, "data": []}
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    driver = actual["runs"][0]["tool"]["driver"]
    assert "AquaSec" == driver["name"]
    assert "1.0.0" == driver["version"]
    assert "https://www.aquasec.com/" == driver["informationUri"]


def test_convert_to_sarif_handles_zero_line_number():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "name": "Test", "file_path": "src/main.py", "line_start": 0}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    location = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in location


def test_convert_to_sarif_handles_negative_line_number():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "name": "Test", "file_path": "src/main.py", "line_start": -1}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    location = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in location


def test_convert_to_sarif_handles_invalid_line_type():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "name": "Test", "file_path": "src/main.py", "line_start": "invalid"}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    location = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in location


def test_convert_to_sarif_uses_path_fallback_for_file_path():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "name": "Test", "path": "src/test.py"}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    locations = actual["runs"][0]["results"][0]["locations"]
    assert "src/test.py" == locations[0]["physicalLocation"]["artifactLocation"]["uri"]


def test_convert_to_sarif_uses_line_fallback_for_line_start():
    findings = {
        "total": 1,
        "data": [{"rule_name": "test-rule", "name": "Test", "file_path": "src/main.py", "line": 10}],
    }
    convertor = Convertor(findings)

    actual = convertor.convert_to_sarif()

    region = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert 10 == region["startLine"]


# _truncate_text


def test_truncate_text_returns_original_when_within_limit():
    convertor = Convertor({"total": 0, "data": []})
    text = "short text"

    actual = convertor._truncate_text(text, 100)  # pylint: disable=protected-access

    assert text == actual


def test_truncate_text_truncates_when_exceeds_limit():
    convertor = Convertor({"total": 0, "data": []})
    text = "a" * 100

    actual = convertor._truncate_text(text, 50)  # pylint: disable=protected-access

    assert 50 == len(actual)
    assert text[:50] == actual


# _map_severity_to_level


def test_map_severity_to_level_returns_error_for_critical():
    convertor = Convertor({"total": 0, "data": []})

    actual = convertor._map_severity_to_level("critical")  # pylint: disable=protected-access

    assert "error" == actual


def test_map_severity_to_level_returns_error_for_high():
    convertor = Convertor({"total": 0, "data": []})

    actual = convertor._map_severity_to_level("high")  # pylint: disable=protected-access

    assert "error" == actual


def test_map_severity_to_level_returns_warning_for_medium():
    convertor = Convertor({"total": 0, "data": []})

    actual = convertor._map_severity_to_level("medium")  # pylint: disable=protected-access

    assert "warning" == actual


def test_map_severity_to_level_returns_note_for_low():
    convertor = Convertor({"total": 0, "data": []})

    actual = convertor._map_severity_to_level("low")  # pylint: disable=protected-access

    assert "note" == actual


def test_map_severity_to_level_returns_note_for_negligible():
    convertor = Convertor({"total": 0, "data": []})

    actual = convertor._map_severity_to_level("negligible")  # pylint: disable=protected-access

    assert "note" == actual


def test_map_severity_to_level_returns_note_for_unknown():
    convertor = Convertor({"total": 0, "data": []})

    actual = convertor._map_severity_to_level("unknown")  # pylint: disable=protected-access

    assert "note" == actual


def test_map_severity_to_level_handles_empty_string():
    convertor = Convertor({"total": 0, "data": []})

    actual = convertor._map_severity_to_level("")  # pylint: disable=protected-access

    assert "note" == actual


def test_map_severity_to_level_handles_case_insensitive():
    convertor = Convertor({"total": 0, "data": []})

    actual_upper = convertor._map_severity_to_level("HIGH")  # pylint: disable=protected-access
    actual_mixed = convertor._map_severity_to_level("MeDiUm")  # pylint: disable=protected-access

    assert "error" == actual_upper
    assert "warning" == actual_mixed
