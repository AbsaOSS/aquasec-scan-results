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
This module implements the standard night scan flow for AquaSec scan results.
"""

import json
import logging
import os

from src.services.sarif_convertor import SarifConvertor
from src.services.scan_fetcher import ScanFetcher
from src.utils.utils import get_sarif_output_filename

logger = logging.getLogger(__name__)


class NightScanMode:
    """
    Class to orchestrate the standard AquaSec night scan flow.
    """

    def __init__(self, bearer_token: str) -> None:
        self.bearer_token = bearer_token

    def run(self) -> str:
        """
        Run the standard scan results flow.

        Returns:
            Absolute path to the generated SARIF file.
        Raises:
            ValueError: If API returns invalid response.
            RequestException: If connection to API fails.
            IOError: If writing the SARIF file fails.
        """
        logger.info("AquaSec Scan Results - Running night scan flow.")

        findings_json = ScanFetcher(self.bearer_token).fetch_findings()
        sarif_data = SarifConvertor().convert_to_sarif(findings_json)

        output_filename = get_sarif_output_filename()
        output_filepath = os.path.abspath(output_filename)
        with open(output_filepath, "w", encoding="utf-8") as sarif_file:
            json.dump(sarif_data, sarif_file, indent=2)

        logger.info("AquaSec Scan Results - SARIF output file saved in `%s`.", output_filepath)
        return output_filepath
