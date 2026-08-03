# Copyright © 2026 Michael Shields
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

"""Exceptions raised by this package."""


class Error(Exception):
    """Base class for every error this package raises deliberately."""


class TransportError(Error):
    """A device could not be found, connected to, or talked to."""


class FirmwareError(Error):
    """A firmware image is missing, malformed, or too large for the device."""


class OtaError(Error):
    """The device rejected or aborted an over-the-air update."""


class ActivationError(Error):
    """Xiaomi registration or login did not complete."""


class ConfigError(Error):
    """A configuration value or device response was not usable."""
