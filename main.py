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
import os
import sys

from src.action_inputs import ActionInputs
from src.model.authenticator import AquaSecAuthenticator

# Initialize logging
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

logger = logging.getLogger(__name__)


def set_output(name: str, value: str) -> None:
    """
    Set a GitHub Actions output.

    Args:
        name: The output name.
        value: The output value.
    """
    github_output = os.getenv("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as output_file:
            output_file.write(f"{name}={value}\n")
        logger.debug("Set output '%s' to masked value", name)
    else:
        # Fallback for local testing
        print(f"{name}=***")
        logger.debug("GITHUB_OUTPUT not set, using fallback output method")


def run() -> None:
    """
    The main function is to run the AquaSec Scan Result solution on GitHub.

    Returns:
        None
    """
    try:
        logger.info("Starting AquaSec authentication")

        # Load and validate inputs
        inputs = ActionInputs()
        logger.info("Inputs loaded and validated successfully")

        # Authenticate with AquaSec
        authenticator = AquaSecAuthenticator(inputs.aqua_key, inputs.aqua_secret)
        bearer_token = authenticator.authenticate()

        # Set the bearer token as output
        set_output("bearer-token", bearer_token)

        logger.info("AquaSec authentication completed successfully")
    except ValueError as ex:
        logger.error("Input validation error: %s", str(ex))
        sys.exit(1)
    except RuntimeError as ex:
        logger.error("Authentication error: %s", str(ex))
        sys.exit(1)
    except Exception as ex:  # pylint: disable=broad-except
        logger.error("Unexpected error: %s", str(ex))
        sys.exit(1)


if __name__ == "__main__":
    run()
