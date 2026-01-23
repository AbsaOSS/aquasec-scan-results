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
Tests for action_inputs module.
"""

import os
from unittest.mock import patch

import pytest

from src.action_inputs import ActionInputs


class TestActionInputs:
    """Test cases for ActionInputs class."""

    @patch("src.action_inputs.os.getenv")
    @patch("builtins.print")
    def test_load_inputs_success(self, mock_print, mock_getenv):
        """Test successful loading of inputs."""
        mock_getenv.side_effect = lambda key: {
            "INPUT_AQUA-KEY": "test-api-key",
            "INPUT_AQUA-SECRET": "test-api-secret",
        }.get(key)

        inputs = ActionInputs()

        assert inputs.aqua_key == "test-api-key"
        assert inputs.aqua_secret == "test-api-secret"
        # Verify secrets are masked
        assert mock_print.call_count == 2

    @patch("src.action_inputs.os.getenv")
    def test_load_inputs_missing_key(self, mock_getenv):
        """Test error when API key is missing."""
        mock_getenv.side_effect = lambda key: {
            "INPUT_AQUA-KEY": None,
            "INPUT_AQUA-SECRET": "test-api-secret",
        }.get(key)

        with pytest.raises(ValueError, match="Required input 'INPUT_AQUA-KEY' is missing or empty"):
            ActionInputs()

    @patch("src.action_inputs.os.getenv")
    def test_load_inputs_missing_secret(self, mock_getenv):
        """Test error when API secret is missing."""
        mock_getenv.side_effect = lambda key: {
            "INPUT_AQUA-KEY": "test-api-key",
            "INPUT_AQUA-SECRET": None,
        }.get(key)

        with pytest.raises(ValueError, match="Required input 'INPUT_AQUA-SECRET' is missing or empty"):
            ActionInputs()

    @patch("src.action_inputs.os.getenv")
    def test_load_inputs_empty_key(self, mock_getenv):
        """Test error when API key is empty."""
        mock_getenv.side_effect = lambda key: {
            "INPUT_AQUA-KEY": "   ",
            "INPUT_AQUA-SECRET": "test-api-secret",
        }.get(key)

        with pytest.raises(ValueError, match="Required input 'INPUT_AQUA-KEY' is missing or empty"):
            ActionInputs()

    @patch("src.action_inputs.os.getenv")
    def test_load_inputs_empty_secret(self, mock_getenv):
        """Test error when API secret is empty."""
        mock_getenv.side_effect = lambda key: {
            "INPUT_AQUA-KEY": "test-api-key",
            "INPUT_AQUA-SECRET": "",
        }.get(key)

        with pytest.raises(ValueError, match="Required input 'INPUT_AQUA-SECRET' is missing or empty"):
            ActionInputs()

    @patch("src.action_inputs.os.getenv")
    @patch("builtins.print")
    def test_load_inputs_with_whitespace(self, mock_print, mock_getenv):
        """Test that inputs are trimmed properly."""
        mock_getenv.side_effect = lambda key: {
            "INPUT_AQUA-KEY": "  test-api-key  ",
            "INPUT_AQUA-SECRET": "  test-api-secret  ",
        }.get(key)

        inputs = ActionInputs()

        assert inputs.aqua_key == "test-api-key"
        assert inputs.aqua_secret == "test-api-secret"
