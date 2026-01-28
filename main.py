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
This module contains the main script for the AquaSec Scan Results GH Action.
"""

import json
import logging
import sys

from requests.exceptions import RequestException

from src.action_inputs import ActionInputs
from src.model.authenticator import AquaSecAuthenticator
from src.model.convertor import Convertor
from src.model.scan_fetcher import ScanFetcher
from src.utils.constants import SARIF_OUTPUT_FILE
from src.utils.logging_config import setup_logging
from src.utils.utils import set_action_output


def run() -> None:
    """
    The main function to run the AquaSec Scan Result solution on GitHub.
    """
    setup_logging()
    logger = logging.getLogger(__name__)

    logger.info("AquaSec Scan Results - Starting.")

    if not ActionInputs().validate():
        logger.error("AquaSec Scan Results - Input validation failed.")
        sys.exit(1)

    try:
        bearer_token = AquaSecAuthenticator().authenticate()
    except (ValueError, RequestException) as e:
        logger.exception("Authentication failed: %s", str(e))
        sys.exit(1)

    try:
        findings = ScanFetcher(bearer_token).fetch_findings()
    except (ValueError, RequestException) as e:
        logger.exception("Fetching scan results failed: %s", str(e))
        sys.exit(1)

    set_action_output("scan_findings", json.dumps(findings))

    # Convert findings to SARIF format
    sarif_data = Convertor(findings).convert_to_sarif()

    # Write SARIF file
    try:
        with open(SARIF_OUTPUT_FILE, "w", encoding="utf-8") as sarif_file:
            json.dump(sarif_data, sarif_file, indent=2)
        logger.info("AquaSec Scan Results - SARIF file written to %s", SARIF_OUTPUT_FILE)
    except IOError as e:
        logger.exception("Failed to write SARIF file: %s", str(e))
        sys.exit(1)

    set_action_output("sarif_file", SARIF_OUTPUT_FILE)

    logger.info("AquaSec Scan Results - Finished.")


if __name__ == "__main__":
    run()
