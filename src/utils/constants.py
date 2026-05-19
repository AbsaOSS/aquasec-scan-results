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
This module centralises all constants used across the project.
"""

# General Action inputs
AQUA_KEY = "AQUA_KEY"
AQUA_SECRET = "AQUA_SECRET"
GROUP_ID = "GROUP_ID"
REPOSITORY_ID = "REPOSITORY_ID"
DEV_BRANCH_COMPARISON = "DEV_BRANCH_COMPARISON"
BRANCH_COMPARISON_POLL_INTERVAL = "BRANCH_COMPARISON_POLL_INTERVAL"
BRANCH_COMPARISON_POLL_TIMEOUT = "BRANCH_COMPARISON_POLL_TIMEOUT"

# Authentication
AUTH_API_URL = "https://eu-1.api.cloudsploit.com"
HTTP_TIMEOUT = 30

# Scan fetching
SCAN_API_URL = "https://eu-1.codesec.aquasec.com/api/v1/scans/results"
PAGE_SIZE = 100
FETCH_SLEEP_SECONDS = 2

# Scan triggering
SCAN_TRIGGER_URL = "https://eu-1.codesec.aquasec.com/api/v2/repositories/scan"
BRANCH_STATUS_URL = "https://api.eu-1.supply-chain.cloud.aquasec.com/v2/build/repositories"
POLL_INTERVAL = 30
POLL_TIMEOUT = 600

# Branch comparison
SEVERITY_MAP: dict[int, str] = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
SEVERITY_ORDER: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
