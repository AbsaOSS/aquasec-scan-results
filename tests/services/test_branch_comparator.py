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
Tests for branch_comparator module.
"""

from src.types import ComparisonResult
from src.services.branch_comparator import BranchComparator


# _severity_label


def test_severity_label_returns_mapped_label():
    comparator = BranchComparator("feature/test", {}, {})

    assert "CRITICAL" == comparator._severity_label(1)
    assert "HIGH" == comparator._severity_label(2)
    assert "MEDIUM" == comparator._severity_label(3)
    assert "LOW" == comparator._severity_label(4)


def test_severity_label_returns_default_for_unmapped_int():
    comparator = BranchComparator("feature/test", {}, {})

    assert "LOW" == comparator._severity_label(999)


# _getting_unique_key


def test_finding_key_uses_result_hash():
    comparator = BranchComparator("feature/test", {}, {})
    finding = {"result_hash": "hash123", "avd_id": "AVD-001", "target_file": "file.py", "target_start_line": 10}

    actual = comparator._getting_unique_key(finding)

    assert "hash123" == actual


def test_finding_key_uses_fallback_when_no_result_hash():
    comparator = BranchComparator("feature/test", {}, {})
    finding = {"avd_id": "AVD-001", "target_file": "file.py", "target_start_line": 10}

    actual = comparator._getting_unique_key(finding)

    assert "AVD-001|file.py|10" == actual


def test_finding_key_handles_empty_finding():
    comparator = BranchComparator("feature/test", {}, {})

    actual = comparator._getting_unique_key({})

    assert "||" == actual


# compute_findings_delta


def test_compute_findings_delta_returns_no_diff_for_identical_findings():
    findings = {"data": [{"result_hash": "h1", "severity": 1}]}

    actual = BranchComparator("feature/test", findings, findings).compute_findings_delta()

    assert [] == actual.new_findings
    assert [] == actual.reduced_findings


def test_compute_findings_delta_detects_new_findings():
    master = {"data": [{"result_hash": "h1", "severity": 1}]}
    dev = {"data": [{"result_hash": "h1", "severity": 1}, {"result_hash": "h2", "severity": 2}]}

    actual = BranchComparator("feature/test", master, dev).compute_findings_delta()

    assert 1 == len(actual.new_findings)
    assert "h2" == actual.new_findings[0]["result_hash"]
    assert [] == actual.reduced_findings


def test_compute_findings_delta_detects_reduced_findings():
    master = {"data": [{"result_hash": "h1", "severity": 1}, {"result_hash": "h2", "severity": 2}]}
    dev = {"data": [{"result_hash": "h1", "severity": 1}]}

    actual = BranchComparator("feature/test", master, dev).compute_findings_delta()

    assert [] == actual.new_findings
    assert 1 == len(actual.reduced_findings)
    assert "h2" == actual.reduced_findings[0]["result_hash"]


def test_compute_findings_delta_detects_both_new_and_reduced():
    master = {"data": [{"result_hash": "h1", "severity": 1}]}
    dev = {"data": [{"result_hash": "h2", "severity": 3}]}

    actual = BranchComparator("feature/test", master, dev).compute_findings_delta()

    assert 1 == len(actual.new_findings)
    assert 1 == len(actual.reduced_findings)


def test_compute_findings_delta_handles_empty_findings():
    actual = BranchComparator("feature/test", {"data": []}, {"data": []}).compute_findings_delta()

    assert [] == actual.new_findings
    assert [] == actual.reduced_findings


# build_comparison_summary


def test_build_markdown_summary_contains_header():
    comparison = ComparisonResult()

    actual = BranchComparator("feature/test", {}, {}).build_comparison_summary(comparison)

    assert "## AquaSec Security Scan — Branch Comparison" in actual
    assert "Master compared with branch: **feature/test**" in actual


def test_build_markdown_summary_shows_new_findings():
    comparison = ComparisonResult(
        new_findings=[
            {"severity": 1, "avd_id": "AVD-001", "title": "Critical issue", "target_file": "app.py", "target_start_line": 10}
        ],
    )

    actual = BranchComparator("feature/test", {}, {}).build_comparison_summary(comparison)

    assert "### New Findings" in actual
    assert "**[CRITICAL]**" in actual
    assert "AVD-001" in actual
    assert "`app.py:10`" in actual


def test_build_markdown_summary_shows_reduced_findings():
    comparison = ComparisonResult(
        reduced_findings=[
            {"severity": 2, "avd_id": "AVD-002", "title": "High issue", "target_file": "lib.py", "target_start_line": 42}
        ],
    )

    actual = BranchComparator("feature/test", {}, {}).build_comparison_summary(comparison)

    assert "### Reduced Findings" in actual
    assert "**[HIGH]**" in actual
    assert "AVD-002" in actual
    assert "`lib.py:42`" in actual


def test_build_markdown_summary_shows_no_diff_message():
    comparison = ComparisonResult()

    actual = BranchComparator("feature/test", {}, {}).build_comparison_summary(comparison)

    assert "No differences found" in actual
    assert "### Severity Breakdown" not in actual
    assert "| **New (+)**" not in actual


def test_build_markdown_summary_severity_counts():
    comparison = ComparisonResult(
        new_findings=[
            {"severity": 1, "avd_id": "AVD-001", "title": "Crit", "target_file": "a.py"},
            {"severity": 3, "avd_id": "AVD-002", "title": "Med", "target_file": "b.py"},
        ],
        reduced_findings=[
            {"severity": 2, "avd_id": "AVD-003", "title": "High", "target_file": "c.py"},
        ],
    )

    actual = BranchComparator("feature/test", {}, {}).build_comparison_summary(comparison)

    assert "| **New (+)** | 1 | 0 | 1 | 0 |" in actual
    assert "| **Reduced (-)** | 0 | 1 | 0 | 0 |" in actual
