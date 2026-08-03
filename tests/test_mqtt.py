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

import sys

import paho.mqtt.client as paho_client
import pytest

from mjwsd05ctl import mqtt
from mjwsd05ctl.errors import Error
from mjwsd05ctl.reader import Reading


class FakeMQTTClient:
    """Records what `Publisher.connect` does to a paho `Client`, without a network."""

    def __init__(self, callback_api_version: paho_client.CallbackAPIVersion) -> None:
        self.callback_api_version = callback_api_version
        self.username: str | None = None
        self.password: str | None = None
        self.username_pw_set_calls = 0
        self.tls_set_called = False
        self.connected: tuple[str, int, int] | None = None
        self.loop_started = False
        self.loop_stopped = False
        self.loop_stop_calls = 0
        self.disconnected = False
        self.disconnect_calls = 0
        self.published: list[tuple[str, str, int, bool]] = []

    def username_pw_set(self, username: str, password: str | None) -> None:
        self.username = username
        self.password = password
        self.username_pw_set_calls += 1

    def tls_set(self) -> None:
        self.tls_set_called = True

    def connect(self, host: str, port: int, keepalive: int) -> None:
        self.connected = (host, port, keepalive)

    def loop_start(self) -> None:
        self.loop_started = True

    def publish(self, topic: str, payload: str, qos: int, retain: bool) -> None:
        self.published.append((topic, payload, qos, retain))

    def loop_stop(self) -> None:
        self.loop_stopped = True
        self.loop_stop_calls += 1

    def disconnect(self) -> None:
        self.disconnected = True
        self.disconnect_calls += 1


@pytest.fixture(autouse=True)
def _fake_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(paho_client, "Client", FakeMQTTClient)


def a_reading() -> Reading:
    return Reading(
        address="A4:C1:38:12:34:56",
        format="pvvx",
        values={"temperature": 21.5},
    )


def test_connect_defaults_to_the_plain_port_when_the_url_has_no_scheme() -> None:
    pub = mqtt.Publisher("broker.example")
    pub.connect()
    client: FakeMQTTClient = pub.client
    assert client.connected == ("broker.example", mqtt.DEFAULT_PORT, mqtt.KEEPALIVE)
    assert client.loop_started
    assert not client.tls_set_called


def test_connect_uses_an_explicit_port() -> None:
    pub = mqtt.Publisher("mqtt://broker.example:1900")
    pub.connect()
    client: FakeMQTTClient = pub.client
    assert client.connected == ("broker.example", 1900, mqtt.KEEPALIVE)


@pytest.mark.parametrize("scheme", ["mqtts", "ssl", "mqtt+ssl"])
def test_a_tls_scheme_defaults_to_the_tls_port_and_enables_tls(scheme: str) -> None:
    pub = mqtt.Publisher(f"{scheme}://broker.example")
    pub.connect()
    client: FakeMQTTClient = pub.client
    assert client.connected == ("broker.example", mqtt.DEFAULT_TLS_PORT, mqtt.KEEPALIVE)
    assert client.tls_set_called


def test_username_and_password_from_the_url_are_passed_to_the_client() -> None:
    pub = mqtt.Publisher("mqtt://alice:hunter2@broker.example")
    pub.connect()
    client: FakeMQTTClient = pub.client
    assert client.username == "alice"
    assert client.password == "hunter2"  # noqa: S105 -- parsed from the test URL, not a real secret


def test_no_username_in_the_url_means_username_pw_set_is_never_called() -> None:
    pub = mqtt.Publisher("mqtt://broker.example")
    pub.connect()
    client: FakeMQTTClient = pub.client
    assert client.username_pw_set_calls == 0
    assert client.username is None
    assert client.password is None


def test_a_url_with_no_host_raises_error() -> None:
    with pytest.raises(Error, match="no host in broker URL"):
        mqtt.Publisher("mqtt://").connect()


class FailingConnectClient(FakeMQTTClient):
    """A fake whose `connect` always fails, to exercise `Publisher`'s error path."""

    def connect(self, host: str, port: int, keepalive: int) -> None:
        del host, port, keepalive
        msg = "connection refused"
        raise OSError(msg)


def test_a_connect_failure_raises_error_naming_host_and_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(paho_client, "Client", FailingConnectClient)
    with pytest.raises(
        Error, match=r"cannot reach MQTT broker at broker\.example:1883"
    ):
        mqtt.Publisher("mqtt://broker.example").connect()


def test_publish_sends_the_reading_as_retained_json_under_the_prefixed_topic() -> None:
    pub = mqtt.Publisher("mqtt://broker.example", topic_prefix="sensors")
    pub.connect()
    pub.publish(a_reading())
    client: FakeMQTTClient = pub.client
    assert len(client.published) == 1
    topic, payload, qos, retain = client.published[0]
    # Address colons stripped and uppercased, per the docstring's `<prefix>/<address>`.
    assert topic == "sensors/A4C138123456"
    # Pinned independently of Reading.as_json (which has its own tests in
    # test_reader.py) so a bug there wouldn't be masked by both sides calling
    # the same method.
    assert payload == (
        '{"address": "A4:C1:38:12:34:56", "encrypted": false, '
        '"format": "pvvx", "temperature": 21.5}'
    )
    assert qos == 0
    assert retain is True


def test_publish_uppercases_a_lower_case_address_in_the_topic() -> None:
    # a_reading()'s address is already upper-case, so it can't tell us
    # whether .upper() is actually applied; many BLE stacks and some
    # pvvx/atc firmwares report lower-case addresses, so exercise that case
    # explicitly with a literal expected topic (not a recomputation of the
    # source's own .replace/.upper expression).
    reading = Reading(
        address="a4:c1:38:12:34:56",
        format="pvvx",
        values={"temperature": 21.5},
    )
    pub = mqtt.Publisher("mqtt://broker.example", topic_prefix="sensors")
    pub.connect()
    pub.publish(reading)
    client: FakeMQTTClient = pub.client
    topic, _payload, _qos, _retain = client.published[0]
    assert topic == "sensors/A4C138123456"


def test_publish_uses_the_default_topic_prefix_when_none_is_given() -> None:
    # DEFAULT_TOPIC_PREFIX is documented as "mjwsd05ctl"; every other test
    # constructs Publisher with an explicit topic_prefix, which would never
    # notice this constant silently changing.
    assert mqtt.DEFAULT_TOPIC_PREFIX == "mjwsd05ctl"
    pub = mqtt.Publisher("mqtt://broker.example")
    pub.connect()
    pub.publish(a_reading())
    client: FakeMQTTClient = pub.client
    topic, _payload, _qos, _retain = client.published[0]
    assert topic == "mjwsd05ctl/A4C138123456"


def test_publish_before_connect_raises_error() -> None:
    with pytest.raises(Error, match="publisher is not connected"):
        mqtt.Publisher("mqtt://broker.example").publish(a_reading())


def test_close_stops_the_loop_and_disconnects() -> None:
    pub = mqtt.Publisher("mqtt://broker.example")
    pub.connect()
    client: FakeMQTTClient = pub.client
    pub.close()
    assert client.loop_stopped
    assert client.disconnected
    assert pub.client is None


def test_close_before_connect_is_a_no_op() -> None:
    pub = mqtt.Publisher("mqtt://broker.example")
    pub.close()
    assert pub.client is None


def test_close_is_idempotent() -> None:
    pub = mqtt.Publisher("mqtt://broker.example")
    pub.connect()
    first_client: FakeMQTTClient = pub.client
    pub.close()
    pub.close()
    # A second close must not touch the already-closed client again: the
    # underlying loop_stop/disconnect calls must still have happened exactly
    # once each, not twice.
    assert first_client.loop_stop_calls == 1
    assert first_client.disconnect_calls == 1


def test_context_manager_connects_on_enter_and_closes_on_exit() -> None:
    with mqtt.Publisher("mqtt://broker.example") as pub:
        client: FakeMQTTClient = pub.client
        assert client.connected == ("broker.example", mqtt.DEFAULT_PORT, mqtt.KEEPALIVE)
        assert pub.client is not None
    assert pub.client is None
    assert client.disconnected


def test_context_manager_closes_even_if_the_body_raises() -> None:
    pub = mqtt.Publisher("mqtt://broker.example")
    seen_clients: list[FakeMQTTClient] = []

    def run_and_raise() -> None:
        with pub:
            seen_clients.append(pub.client)
            msg = "boom"
            raise RuntimeError(msg)

    with pytest.raises(RuntimeError, match="boom"):
        run_and_raise()

    assert seen_clients[0].disconnected
    assert pub.client is None


def test_missing_paho_raises_an_error_naming_the_optional_extra(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "paho.mqtt.client", None)
    with pytest.raises(Error, match=r"mjwsd05ctl\[mqtt\]"):
        mqtt.Publisher("mqtt://broker.example").connect()
