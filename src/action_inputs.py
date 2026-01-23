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
This module handles loading and validation of GitHub Actions inputs.
"""

import logging
import os

logger = logging.getLogger(__name__)


class ActionInputs:  # pylint: disable=too-few-public-methods
    """Class to load and validate GitHub Actions inputs."""

    def __init__(self) -> None:
        """
        Initialize ActionInputs and load environment variables.

        Raises:
            ValueError: If required inputs are missing or empty.
        """
        self.aqua_key = self._load_input("INPUT_AQUA-KEY")
        self.aqua_secret = self._load_input("INPUT_AQUA-SECRET")
        self._mask_secrets()

    def _load_input(self, env_var: str) -> str:
        """
        Load an input from environment variables.

        Args:
            env_var: The environment variable name.

        Returns:
            The value of the environment variable.

        Raises:
            ValueError: If the environment variable is not set or is empty.
        """
        value = os.getenv(env_var)
        if not value or not value.strip():
            raise ValueError(f"Required input '{env_var}' is missing or empty")
        return value.strip()

    def _mask_secrets(self) -> None:
        """
        Mask secrets in GitHub Actions logs.

        This adds special GitHub Actions commands to mask the secret values.
        """
        print(f"::add-mask::{self.aqua_key}")
        print(f"::add-mask::{self.aqua_secret}")
        logger.debug("Secrets have been masked in logs")
