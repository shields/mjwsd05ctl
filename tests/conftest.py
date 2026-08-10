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

"""Fakes shared by more than one test module.

Each module still keeps its own `FakeLink`, shaped for the protocol it drives;
only what all of them need to borrow the real `transport.Link` lives here.
"""

import asyncio


class FakeGATTClient:
    """The one thing `Link.take`'s disconnect poll reads from `self._client`.

    Several fake links borrow the real `transport.Link.take` rather than
    imitate it, so that they are tested against the disconnect semantics that
    ship. `take` asks `self._client.is_connected` whenever a wait outlasts
    `DISCONNECT_POLL` with neither a notification nor a disconnect event, so a
    fake with no client there crashes with `AttributeError` on the very branch
    it should be exercising — which is how this class came to exist.
    """

    def __init__(self, disconnected: asyncio.Event) -> None:
        self._disconnected = disconnected

    @property
    def is_connected(self) -> bool:
        return not self._disconnected.is_set()
