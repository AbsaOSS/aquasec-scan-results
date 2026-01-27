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
This module contains an ActionInputs class method that loads and validates
the inputs required for running a GitHub Action from environment variables.
"""

import logging
import re

from src.utils.constants import AQUA_KEY, AQUA_SECRET, REPOSITORY_ID
from src.utils.utils import get_action_input

logger = logging.getLogger(__name__)


class ActionInputs:
    """
    A class representing all the action inputs. It is responsible for loading and managing
    and validating the inputs required for running the GH Action.
    """

    @staticmethod
    def _get_aquasec_key() -> str:
        """
        Getter of the Aqua Security key.

        Returns:
            The Aqua Security key as a string.
        """
        return get_action_input(AQUA_KEY)

    @staticmethod
    def _get_aquasec_secret() -> str:
        """
        Getter of the Aqua Security secret.

        Returns:
            The Aqua Security secret as a string.
        """
        return get_action_input(AQUA_SECRET)

    @staticmethod
    def _get_repository_id() -> str:
        """
        Getter of the repository ID.

        Returns:
            The repository ID as a string.
        """
        return get_action_input(REPOSITORY_ID)

    @staticmethod
    def _is_valid_uuid(uuid_string: str) -> bool:
        """
        Validates if the given string is a valid UUID format.

        Args:
            uuid_string: The string to validate as UUID.

        Returns:
            True if the string is a valid UUID, False otherwise.
        """
        uuid_pattern = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
        return bool(re.match(uuid_pattern, uuid_string))

    def validate(self):
        """
        Validates the action inputs.

        Returns:
            True if all required inputs are valid, False otherwise.
        """
        logger.info("AquaSec Scan Results - Input validation starting.")
        error_count: int = 0
        aquasec_key: str = self._get_aquasec_key()
        aquasec_secret: str = self._get_aquasec_secret()
        repository_id: str = self._get_repository_id()

        ## AquaSec Key
        if not aquasec_key or not isinstance(aquasec_key, str):
            logger.error("AQUASEC_KEY: str - not provided.")
            error_count += 1

        ## AquaSec Secret
        if not aquasec_secret or not isinstance(aquasec_secret, str):
            logger.error("AQUASEC_SECRET: str - not provided.")
            error_count += 1

        ## Repository ID
        if not repository_id or not isinstance(repository_id, str):
            logger.error("REPOSITORY_ID: str - not provided.")
            error_count += 1
        elif not self._is_valid_uuid(repository_id):
            logger.error("REPOSITORY_ID: str - invalid UUID format.")
            error_count += 1

        if error_count > 0:
            return False

        logger.info("AquaSec Scan Results - Input validation successful.")
        return True
