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
REPOSITORY_ID = "REPOSITORY_ID"

# Authentication
AUTH_API_URL = "https://eu-1.api.cloudsploit.com"
GROUP_ID = 1228
HTTP_TIMEOUT = 30

# Scan fetching
SCAN_API_URL = "https://eu-1.codesec.aquasec.com/api/v1/scans/results"
PAGE_SIZE = 100
FETCH_SLEEP_SECONDS = 2

# SARIF converting
SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_PLACEHOLDER = "Unknown"

# SARIF field truncation limits
RULE_ID_MAX_LENGTH = 512
TITLE_MAX_LENGTH = 1024
LONG_TEXT_MAX_LENGTH = 4096
