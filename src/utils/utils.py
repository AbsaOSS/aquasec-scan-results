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
This module contains utility functions used across the project.
"""

import logging
import os

logger = logging.getLogger(__name__)


def get_action_input(name: str, default: str = "") -> str:
    """
    Get the input value from the environment variables.

    Args:
        name: The name of the input parameter.
        default: The default value to return if the environment variable is not set.

    Returns:
        The value of the specified input parameter, or the default value.
    """
    return os.getenv(f'INPUT_{name.replace("-", "_").upper()}', default=default)
