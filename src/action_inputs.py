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

from src.utils.constants import (
    AQUA_KEY,
    AQUA_SECRET,
    BRANCH_COMPARISON_POLL_INTERVAL,
    BRANCH_COMPARISON_POLL_TIMEOUT,
    DEV_BRANCH_COMPARISON,
    GROUP_ID,
    POLL_INTERVAL,
    POLL_TIMEOUT,
    REPOSITORY_ID,
)
from src.utils.utils import get_action_input

logger = logging.getLogger(__name__)


class ActionInputs:
    """
    Central access point for all action inputs.
    Provides public static getters and input validation.
    """

    @staticmethod
    def get_aquasec_key() -> str:
        """
        Get the Aqua Security key.

        Returns:
            The Aqua Security key as a string.
        """
        return get_action_input(AQUA_KEY)

    @staticmethod
    def get_aquasec_secret() -> str:
        """
        Get the Aqua Security secret.

        Returns:
            The Aqua Security secret as a string.
        """
        return get_action_input(AQUA_SECRET)

    @staticmethod
    def get_group_id() -> str:
        """
        Get the AquaSec Group ID for authentication.

        Returns:
            The Group ID as a string.
        """
        return get_action_input(GROUP_ID)

    @staticmethod
    def get_repository_id() -> str:
        """
        Get the repository ID.

        Returns:
            The repository ID as a string.
        """
        return get_action_input(REPOSITORY_ID)

    @staticmethod
    def get_dev_branch_comparison() -> bool:
        """
        Check if the dev branch comparison mode is enabled.

        Returns:
            True if dev branch comparison is enabled, False otherwise.
        """
        return get_action_input(DEV_BRANCH_COMPARISON).lower() == "true"

    @staticmethod
    def get_poll_interval() -> int:
        """
        Get the polling interval in seconds for branch scan completion check.

        Returns:
            The polling interval as an integer.
        """
        raw_poll_interval = get_action_input(BRANCH_COMPARISON_POLL_INTERVAL)
        if not raw_poll_interval:
            return POLL_INTERVAL
        return int(raw_poll_interval)

    @staticmethod
    def get_poll_timeout() -> int:
        """
        Get the maximum time in seconds to wait for branch scan completion.

        Returns:
            The polling timeout as an integer.
        """
        raw_poll_timeout = get_action_input(BRANCH_COMPARISON_POLL_TIMEOUT)
        if not raw_poll_timeout:
            return POLL_TIMEOUT
        return int(raw_poll_timeout)

    @staticmethod
    def _get_raw_dev_branch_comparison() -> str:
        """
        Get the raw dev branch comparison flag for validation purposes.

        Returns:
            The raw dev branch comparison flag as a string.
        """
        return get_action_input(DEV_BRANCH_COMPARISON)

    @staticmethod
    def _get_raw_poll_interval() -> str:
        """
        Get the raw poll interval value for validation purposes.

        Returns:
            The raw poll interval as a string.
        """
        return get_action_input(BRANCH_COMPARISON_POLL_INTERVAL)

    @staticmethod
    def _get_raw_poll_timeout() -> str:
        """
        Get the raw poll timeout value for validation purposes.

        Returns:
            The raw poll timeout as a string.
        """
        return get_action_input(BRANCH_COMPARISON_POLL_TIMEOUT)

    @staticmethod
    def _is_valid_positive_integer(value: str) -> bool:
        """
        Validates if the given string is a positive integer.

        Args:
            value: The string to validate.

        Returns:
            True if the string represents a positive integer, False otherwise.
        """
        try:
            return int(value) > 0
        except ValueError:
            return False

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

    def validate(self) -> bool:
        """
        Validates the action inputs.

        Returns:
            True if all required inputs are valid, False otherwise.
        """
        logger.info("AquaSec Scan Results - Input validation starting.")
        error_count: int = 0
        aquasec_key: str = self.get_aquasec_key()
        aquasec_secret: str = self.get_aquasec_secret()
        group_id: str = self.get_group_id()
        repository_id: str = self.get_repository_id()

        ## AquaSec Key
        if not aquasec_key or not isinstance(aquasec_key, str):
            logger.error("AQUASEC_KEY: str - not provided.")
            error_count += 1

        ## AquaSec Secret
        if not aquasec_secret or not isinstance(aquasec_secret, str):
            logger.error("AQUASEC_SECRET: str - not provided.")
            error_count += 1

        ## Group ID
        if not group_id or not isinstance(group_id, str):
            logger.error("GROUP_ID: str - not provided.")
            error_count += 1

        ## Repository ID
        if not repository_id or not isinstance(repository_id, str):
            logger.error("REPOSITORY_ID: str - not provided.")
            error_count += 1
        elif not self._is_valid_uuid(repository_id):
            logger.error("REPOSITORY_ID: str - invalid UUID format.")
            error_count += 1

        ## Dev Branch Comparison
        dev_branch_comparison: str = self._get_raw_dev_branch_comparison()
        if dev_branch_comparison.lower() not in ("true", "false", ""):
            logger.error("DEV_BRANCH_COMPARISON: str - must be 'true' or 'false'.")
            error_count += 1

        ## Branch Comparison Poll Interval
        raw_poll_interval: str = self._get_raw_poll_interval()
        if raw_poll_interval and not self._is_valid_positive_integer(raw_poll_interval):
            logger.error("BRANCH_COMPARISON_POLL_INTERVAL: int - must be a positive integer.")
            error_count += 1

        ## Branch Comparison Poll Timeout
        raw_poll_timeout: str = self._get_raw_poll_timeout()
        if raw_poll_timeout and not self._is_valid_positive_integer(raw_poll_timeout):
            logger.error("BRANCH_COMPARISON_POLL_TIMEOUT: int - must be a positive integer.")
            error_count += 1

        ## Poll Interval must be less than Poll Timeout
        if (
            raw_poll_interval
            and raw_poll_timeout
            and self._is_valid_positive_integer(raw_poll_interval)
            and self._is_valid_positive_integer(raw_poll_timeout)
            and int(raw_poll_interval) >= int(raw_poll_timeout)
        ):
            logger.error("BRANCH_COMPARISON_POLL_INTERVAL must be less than BRANCH_COMPARISON_POLL_TIMEOUT.")
            error_count += 1

        if error_count > 0:
            return False

        logger.info("AquaSec Scan Results - Input validation successful.")
        return True
