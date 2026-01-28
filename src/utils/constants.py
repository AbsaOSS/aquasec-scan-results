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

# Authentication related constants
AUTH_API_URL = "https://eu-1.api.cloudsploit.com"
GROUP_ID = 1228
HTTP_TIMEOUT = 30

# Scan fetching related constants
SCAN_API_URL = "https://eu-1.codesec.aquasec.com/api/v1/scans/results"
PAGE_SIZE = 100
FETCH_SLEEP_SECONDS = 2

# SARIF related constants
SARIF_SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
SARIF_OUTPUT_FILE = "aquasec_scan.sarif"

# SARIF field truncation limits
SARIF_RULE_ID_MAX = 512
SARIF_SHORT_DESC_MAX = 1024
SARIF_FULL_DESC_MAX = 4096
SARIF_MESSAGE_MAX = 4096
