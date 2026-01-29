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
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    assert SARIF_SCHEMA_URL == actual["$schema"]
    assert SARIF_VERSION == actual["version"]
    assert "runs" in actual
    assert 1 == len(actual["runs"])
    assert "tool" in actual["runs"][0]
    assert "results" in actual["runs"][0]


def test_convert_to_sarif_handles_empty_findings():
    findings = {"total": 0, "data": []}
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    assert 0 == len(actual["runs"][0]["results"])
    assert 0 == len(actual["runs"][0]["tool"]["driver"]["rules"])


def test_convert_to_sarif_maps_severity_null_to_note():
    findings = {"total": 1, "data": [{"avd_id": "test-rule-low"}]}
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    assert "note" == actual["runs"][0]["results"][0]["level"]


def test_convert_to_sarif_maps_severity_4_to_error():
    findings = {"total": 1, "data": [{"avd_id": "test-rule-critical", "severity": 4}]}
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    assert "error" == actual["runs"][0]["results"][0]["level"]


def test_convert_to_sarif_truncates_short_description():
    long_title = "a" * (TITLE_MAX_LENGTH + 100)
    findings = {"total": 1, "data": [{"avd_id": "test-rule", "title": long_title}]}
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    short_desc = actual["runs"][0]["tool"]["driver"]["rules"][0]["shortDescription"]["text"]
    assert TITLE_MAX_LENGTH == len(short_desc)


def test_convert_to_sarif_includes_file_location():
    findings = {
        "total": 1,
        "data": [{"avd_id": "test-rule", "target_file": "src/main.py"}],
    }
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    locations = actual["runs"][0]["results"][0]["locations"]
    assert 1 == len(locations)
    assert "src/main.py" == locations[0]["physicalLocation"]["artifactLocation"]["uri"]


def test_convert_to_sarif_includes_line_location():
    findings = {
        "total": 1,
        "data": [{"avd_id": "test-rule", "title": "Test", "target_file": "src/main.py", "target_start_line": 42}],
    }
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

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
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    region = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert 42 == region["startLine"]
    assert 45 == region["endLine"]


def test_convert_to_sarif_handles_missing_avd_id():
    findings = {"total": 1, "data": [{"title": "Test", "severity": 2}]}
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    assert "Unknown" == actual["runs"][0]["results"][0]["ruleId"]


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
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    assert "https://example.com" == actual["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"]


def test_convert_to_sarif_handles_duplicate_rules():
    findings = {
        "total": 2,
        "data": [
            {"avd_id": "test-rule", "title": "Test 1", "severity": 3},
            {"avd_id": "test-rule", "title": "Test 2", "severity": 2},
        ],
    }
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

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
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    assert 2 == len(actual["runs"][0]["tool"]["driver"]["rules"])
    assert 2 == len(actual["runs"][0]["results"])


def test_convert_to_sarif_includes_tool_metadata():
    findings = {"total": 0, "data": []}
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    driver = actual["runs"][0]["tool"]["driver"]
    assert "AquaSec" == driver["name"]
    assert "1.0.0" == driver["version"]
    assert "https://www.aquasec.com/" == driver["informationUri"]


def test_convert_to_sarif_handles_zero_line_number():
    findings = {
        "total": 1,
        "data": [{"avd_id": "test-rule", "title": "Test", "target_file": "src/main.py", "target_start_line": 0}],
    }
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    location = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in location


def test_convert_to_sarif_handles_negative_line_number():
    findings = {
        "total": 1,
        "data": [{"avd_id": "test-rule", "title": "Test", "target_file": "src/main.py", "target_start_line": -1}],
    }
    convertor = SarifConvertor(findings)

    actual = convertor.convert_to_sarif()

    location = actual["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in location


# _truncate_text


def test_truncate_text_returns_original_when_within_limit():
    convertor = SarifConvertor({"total": 0, "data": []})

    actual = convertor._truncate_text("short text", 100)

    assert "short text" == actual


def test_truncate_text_truncates_when_exceeds_limit():
    convertor = SarifConvertor({"total": 0, "data": []})

    actual = convertor._truncate_text("long text here", 4)

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
