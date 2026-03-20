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

import logging
import sys

from requests.exceptions import RequestException

from src.action_inputs import ActionInputs
from src.services.authenticator import AquaSecAuthenticator
from src.modes.branch_comparison_mode import BranchComparisonMode
from src.modes.night_scan_mode import NightScanMode
from src.utils.logging_config import setup_logging
from src.utils.utils import set_action_failed, set_action_output


def run() -> None:
    """
    The main function to run the AquaSec Scan Result solution on GitHub.
    """
    setup_logging()
    logger = logging.getLogger(__name__)

    logger.info("AquaSec Scan Results - Starting.")

    # Validate inputs
    if not ActionInputs().validate():
        logger.error("AquaSec Scan Results - Input validation failed.")
        sys.exit(1)

    # Authentication
    try:
        bearer_token = AquaSecAuthenticator().authenticate()
    except (ValueError, RequestException) as e:
        logger.exception("Authentication failed: %s", str(e))
        sys.exit(1)

    # Determine if branch comparison mode is wanted
    branch_comparison_mode: bool = ActionInputs.get_dev_branch_comparison()

    # AquaSec modes run
    try:
        has_new_findings: bool | None = None
        if branch_comparison_mode:
            summary_file, has_new_findings = BranchComparisonMode(bearer_token).run()
            set_action_output("comparison-summary-file", summary_file)
        else:
            sarif_filepath = NightScanMode(bearer_token).run()
            set_action_output("nightscan-sarif-file", sarif_filepath)

    except (ValueError, RequestException, IOError) as e:
        logger.exception("AquaSec Scan Results - Failed: %s", str(e))
        sys.exit(1)

    logger.info("AquaSec Scan Results - Finished.")

    if branch_comparison_mode and has_new_findings:
        set_action_failed("New security findings detected in branch comparison. Please resolve them before merging.")


if __name__ == "__main__":
    run()
