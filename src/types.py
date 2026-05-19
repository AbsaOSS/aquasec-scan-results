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
Data types for AquaSec scan results project.
"""

from dataclasses import dataclass, field
from typing import TypedDict


# Shared for both modes
class ScanResponse(TypedDict, total=False):
    """Raw AquaSec API scan response envelope."""

    total: int
    data: list


# Branch Comparison mode
class ComparisonFinding(TypedDict, total=False):
    """Subset of AquaSec finding fields used for branch comparison."""

    result_hash: str
    avd_id: str
    title: str
    severity: int
    target_file: str
    target_start_line: int


ComparisonFindingsList = list[ComparisonFinding]


@dataclass
class ComparisonResult:
    """Result of comparing master and developer branch findings."""

    new_findings: ComparisonFindingsList = field(default_factory=list)
    reduced_findings: ComparisonFindingsList = field(default_factory=list)
