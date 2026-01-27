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

import pytest

from src.action_inputs import ActionInputs


@pytest.fixture
def mock_logging_setup(mocker):
    """Mocks logging.basicConfig to prevent actual logging setup during tests."""
    mock_log_config = mocker.patch("logging.basicConfig")
    yield mock_log_config


@pytest.fixture
def mock_main_setup(mocker):
    """Common setup for main.py tests - mocks setup_logging and validates."""
    mocker.patch("main.setup_logging")
    mocker.patch("main.ActionInputs.validate", return_value=True)
    mocker.patch("main.AquaSecAuthenticator.authenticate", return_value="test_token")
    mocker.patch("main.set_action_output")


@pytest.fixture
def mock_valid_action_inputs(mocker):
    """Common setup for ActionInputs validation tests with valid inputs."""
    mocker.patch.object(ActionInputs, "_get_aquasec_key", return_value="valid_key")
    mocker.patch.object(ActionInputs, "_get_aquasec_secret", return_value="valid_secret")
    mocker.patch.object(ActionInputs, "_get_repository_id", return_value="123e4567-e89b-12d3-a456-426614174000")


@pytest.fixture
def mock_scan_fetcher_setup(mocker):
    """Common setup for ScanFetcher tests - mocks get_action_input for repository_id."""
    mocker.patch("src.model.scan_fetcher.get_action_input", return_value="123e4567-e89b-12d3-a456-426614174000")
