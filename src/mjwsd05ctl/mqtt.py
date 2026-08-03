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

"""Publishing readings to an MQTT broker."""

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Self
from urllib.parse import urlsplit

from .errors import Error

if TYPE_CHECKING:
    from types import TracebackType

    from .reader import Reading

log = logging.getLogger(__name__)

DEFAULT_TOPIC_PREFIX = "mjwsd05ctl"
DEFAULT_PORT = 1883
DEFAULT_TLS_PORT = 8883
KEEPALIVE = 60


@dataclass
class Publisher:
    """Sends each reading to `<prefix>/<address>` as JSON.

    Retained, because a sensor's last reading is its current state and a
    subscriber that starts later should see it without waiting for the next
    broadcast.
    """

    url: str
    topic_prefix: str = DEFAULT_TOPIC_PREFIX
    client: Any = None

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def connect(self) -> None:
        try:
            import paho.mqtt.client as mqtt  # noqa: PLC0415
        except ImportError as exc:
            msg = "publishing to MQTT needs paho-mqtt; install mjwsd05ctl[mqtt]"
            raise Error(msg) from exc

        parts = urlsplit(self.url if "://" in self.url else f"mqtt://{self.url}")
        if not parts.hostname:
            msg = f"no host in broker URL {self.url!r}"
            raise Error(msg)
        secure = parts.scheme in ("mqtts", "ssl", "mqtt+ssl")
        port = parts.port or (DEFAULT_TLS_PORT if secure else DEFAULT_PORT)

        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        if parts.username:
            client.username_pw_set(parts.username, parts.password)
        if secure:
            client.tls_set()
        try:
            client.connect(parts.hostname, port, KEEPALIVE)
        except OSError as exc:
            msg = f"cannot reach MQTT broker at {parts.hostname}:{port}: {exc}"
            raise Error(msg) from exc
        client.loop_start()
        self.client = client
        log.info(
            "publishing to %s:%d under %s/", parts.hostname, port, self.topic_prefix
        )

    def publish(self, reading: Reading) -> None:
        if self.client is None:
            msg = "publisher is not connected"
            raise Error(msg)
        topic = f"{self.topic_prefix}/{reading.address.replace(':', '').upper()}"
        self.client.publish(topic, reading.as_json(), qos=0, retain=True)

    def close(self) -> None:
        if self.client is None:
            return
        self.client.loop_stop()
        self.client.disconnect()
        self.client = None
