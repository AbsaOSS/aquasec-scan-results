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
Tests for main module.
"""

from unittest.mock import MagicMock, mock_open, patch

import pytest

import main


class TestMain:
    """Test cases for main module."""

    @patch("main.ActionInputs")
    @patch("main.AquaSecAuthenticator")
    @patch("main.set_output")
    @patch("main.os.getenv")
    def test_run_success(self, mock_getenv, mock_set_output, mock_authenticator_class, mock_inputs_class):
        """Test successful run."""
        # Setup mocks
        mock_getenv.return_value = "/tmp/github_output"
        mock_inputs = MagicMock()
        mock_inputs.aqua_key = "test-key"
        mock_inputs.aqua_secret = "test-secret"
        mock_inputs_class.return_value = mock_inputs

        mock_authenticator = MagicMock()
        mock_authenticator.authenticate.return_value = "test-bearer-token"
        mock_authenticator_class.return_value = mock_authenticator

        # Run
        main.run()

        # Verify
        mock_inputs_class.assert_called_once()
        mock_authenticator_class.assert_called_once_with("test-key", "test-secret")
        mock_authenticator.authenticate.assert_called_once()
        mock_set_output.assert_called_once_with("bearer-token", "test-bearer-token")

    @patch("main.ActionInputs")
    def test_run_input_validation_error(self, mock_inputs_class):
        """Test run with input validation error."""
        mock_inputs_class.side_effect = ValueError("Missing input")

        with pytest.raises(SystemExit) as exc_info:
            main.run()

        assert exc_info.value.code == 1

    @patch("main.ActionInputs")
    @patch("main.AquaSecAuthenticator")
    def test_run_authentication_error(self, mock_authenticator_class, mock_inputs_class):
        """Test run with authentication error."""
        mock_inputs = MagicMock()
        mock_inputs.aqua_key = "test-key"
        mock_inputs.aqua_secret = "test-secret"
        mock_inputs_class.return_value = mock_inputs

        mock_authenticator = MagicMock()
        mock_authenticator.authenticate.side_effect = RuntimeError("Authentication failed")
        mock_authenticator_class.return_value = mock_authenticator

        with pytest.raises(SystemExit) as exc_info:
            main.run()

        assert exc_info.value.code == 1

    @patch("main.ActionInputs")
    @patch("main.AquaSecAuthenticator")
    def test_run_unexpected_error(self, mock_authenticator_class, mock_inputs_class):
        """Test run with unexpected error."""
        mock_inputs = MagicMock()
        mock_inputs.aqua_key = "test-key"
        mock_inputs.aqua_secret = "test-secret"
        mock_inputs_class.return_value = mock_inputs

        mock_authenticator = MagicMock()
        mock_authenticator.authenticate.side_effect = Exception("Unexpected error")
        mock_authenticator_class.return_value = mock_authenticator

        with pytest.raises(SystemExit) as exc_info:
            main.run()

        assert exc_info.value.code == 1

    @patch("main.os.getenv")
    @patch("builtins.open", new_callable=mock_open)
    def test_set_output_with_github_output(self, mock_file, mock_getenv):
        """Test set_output with GITHUB_OUTPUT environment variable."""
        mock_getenv.return_value = "/tmp/github_output"

        main.set_output("test-name", "test-value")

        mock_file.assert_called_once_with("/tmp/github_output", "a", encoding="utf-8")
        mock_file().write.assert_called_once_with("test-name=test-value\n")

    @patch("main.os.getenv")
    @patch("builtins.print")
    def test_set_output_without_github_output(self, mock_print, mock_getenv):
        """Test set_output without GITHUB_OUTPUT environment variable."""
        mock_getenv.return_value = None

        main.set_output("test-name", "test-value")

        mock_print.assert_called_once_with("test-name=***")
