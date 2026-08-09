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

import asyncio
from collections.abc import Callable, Iterator, Sequence
from typing import Any

import pytest
from bleak import (
    AdvertisementData,
    BleakError,
    BLEDevice,
    BlueZClientArgs,
    BlueZScannerArgs,
)

from mjwsd05ctl import transport
from mjwsd05ctl.constants import (
    CUSTOM_CHAR,
    CUSTOM_SERVICE,
    DIS_FIRMWARE_REVISION_CHAR,
    DIS_HARDWARE_REVISION_CHAR,
    DIS_SERVICE,
    DIS_SOFTWARE_REVISION_CHAR,
    HW_ID_CH,
    HW_ID_EN,
    MI_AUTH_CONTROL_CHAR,
    MI_AUTH_DATA_CHAR,
)
from mjwsd05ctl.errors import TransportError
from mjwsd05ctl.transport import DeviceInfo


def seen(address: str, name: str, rssi: int) -> tuple[BLEDevice, AdvertisementData]:
    return (
        BLEDevice(address, name, None),
        AdvertisementData(
            local_name=name,
            manufacturer_data={},
            service_data={},
            service_uuids=[],
            tx_power=None,
            rssi=rssi,
            platform_data=(),
        ),
    )


@pytest.fixture
def discovered(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, tuple[BLEDevice, AdvertisementData]]:
    found: dict[str, tuple[BLEDevice, AdvertisementData]] = {}

    async def fake_discover(
        **kwargs: Any,
    ) -> dict[str, tuple[BLEDevice, AdvertisementData]]:
        del kwargs
        return found

    monkeypatch.setattr(transport.BleakScanner, "discover", fake_discover)
    return found


async def test_scan_puts_the_strongest_signal_first(
    discovered: dict[str, tuple[BLEDevice, AdvertisementData]],
) -> None:
    discovered["far"] = seen("A4:C1:38:00:00:01", "ATC_far", -90)
    discovered["near"] = seen("A4:C1:38:00:00:02", "ATC_near", -40)
    results = await transport.scan()
    assert [device.address for device, _ in results] == [
        "A4:C1:38:00:00:02",
        "A4:C1:38:00:00:01",
    ]


async def test_a_zero_rssi_is_a_strong_signal_not_a_missing_one(
    discovered: dict[str, tuple[BLEDevice, AdvertisementData]],
) -> None:
    discovered["zero"] = seen("A4:C1:38:00:00:01", "ATC_zero", 0)
    discovered["weak"] = seen("A4:C1:38:00:00:02", "ATC_weak", -80)
    results = await transport.scan()
    assert results[0][0].address == "A4:C1:38:00:00:01"


async def test_scan_treats_a_missing_rssi_as_weaker_than_any_reported_signal(
    discovered: dict[str, tuple[BLEDevice, AdvertisementData]],
) -> None:
    # Some backends occasionally omit RSSI from an advertisement; scan()
    # falls back to -127 (the weakest signal GAP can report) so such a
    # device sorts last rather than crashing the comparison.
    discovered["unknown"] = (
        BLEDevice("A4:C1:38:00:00:01", "ATC_unknown", None),
        AdvertisementData(
            local_name="ATC_unknown",
            manufacturer_data={},
            service_data={},
            service_uuids=[],
            tx_power=None,
            rssi=None,  # ty: ignore[invalid-argument-type]
            platform_data=(),
        ),
    )
    discovered["weak"] = seen("A4:C1:38:00:00:02", "ATC_weak", -80)
    results = await transport.scan()
    assert results[0][0].address == "A4:C1:38:00:00:02"


async def test_a_missing_rssi_ties_with_a_reported_minus_127(
    discovered: dict[str, tuple[BLEDevice, AdvertisementData]],
) -> None:
    # -127 is GAP's defined floor for RSSI: the missing-RSSI fallback must be
    # exactly that value, not one below it, so a device that genuinely
    # reports -127 dBm ties with (rather than beats) a device with no
    # reported signal. list.sort() is stable even with reverse=True, so a
    # genuine tie preserves insertion order.
    discovered["missing"] = (
        BLEDevice("A4:C1:38:00:00:01", "ATC_missing", None),
        AdvertisementData(
            local_name="ATC_missing",
            manufacturer_data={},
            service_data={},
            service_uuids=[],
            tx_power=None,
            rssi=None,  # ty: ignore[invalid-argument-type]
            platform_data=(),
        ),
    )
    discovered["real"] = seen("A4:C1:38:00:00:02", "ATC_real", -127)
    results = await transport.scan()
    assert [device.address for device, _ in results] == [
        "A4:C1:38:00:00:01",
        "A4:C1:38:00:00:02",
    ]


def test_matches_falls_back_to_the_cached_device_name_when_unadvertised() -> None:
    device = BLEDevice("A4:C1:38:00:00:01", "MJWSD05MMC", None)
    advertisement = AdvertisementData(
        local_name=None,
        manufacturer_data={},
        service_data={},
        service_uuids=[],
        tx_power=None,
        rssi=-50,
        platform_data=(),
    )
    assert transport._matches(device, advertisement)


@pytest.mark.parametrize("name", ["BTH_51CD84", "BTH_1"])
def test_matches_accepts_the_name_the_flashed_firmware_gives_itself(name: str) -> None:
    # `ble_set_name()` derives "BTH_<n>" from the fleet device number, falling
    # back to the last three bytes of the address. Without this prefix `scan`
    # and every address-less command are blind to the firmware this package
    # installs, which is how a successful flash came to look like a brick.
    device, advertisement = seen("A4:C1:38:51:CD:84", name, -50)
    assert transport._matches(device, advertisement)


def test_matches_requires_the_full_bth_prefix() -> None:
    # Both parametrized cases above start with "BTH", not just "BTH_" — on
    # their own they cannot tell a trailing-underscore typo in NAME_PREFIXES
    # from a correct one, and a bare "BTH" would also catch unrelated
    # products (a "BTHub", say) that happen to share the first three letters.
    device, advertisement = seen("A4:C1:38:51:CD:84", "BTHomeOther", -50)
    assert not transport._matches(device, advertisement)


def test_matches_is_false_when_no_name_is_available_anywhere() -> None:
    device = BLEDevice("A4:C1:38:00:00:01", None, None)
    advertisement = AdvertisementData(
        local_name=None,
        manufacturer_data={},
        service_data={},
        service_uuids=[],
        tx_power=None,
        rssi=-50,
        platform_data=(),
    )
    assert not transport._matches(device, advertisement)


def test_bluez_scanner_args_selects_the_given_adapter() -> None:
    assert transport.bluez_scanner_args("hci1") == BlueZScannerArgs(adapter="hci1")


def test_bluez_scanner_args_defaults_to_no_adapter_preference() -> None:
    assert transport.bluez_scanner_args(None) == BlueZScannerArgs()


async def test_scan_selects_the_given_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    async def fake_discover(
        **kwargs: Any,
    ) -> dict[str, tuple[BLEDevice, AdvertisementData]]:
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(transport.BleakScanner, "discover", fake_discover)
    await transport.scan(adapter="hci1")
    assert captured["bluez"] == BlueZScannerArgs(adapter="hci1")


async def test_scan_keeps_only_thermometers_by_default(
    discovered: dict[str, tuple[BLEDevice, AdvertisementData]],
) -> None:
    discovered["ours"] = seen("A4:C1:38:00:00:01", "ATC_1", -50)
    discovered["stock"] = seen("A4:C1:38:00:00:02", "MJWSD05MMC", -60)
    discovered["other"] = seen("00:11:22:33:44:55", "Someone's earbuds", -30)

    assert len(await transport.scan()) == 2
    assert len(await transport.scan(all_devices=True)) == 3


async def test_find_device_explains_an_empty_scan(
    discovered: dict[str, tuple[BLEDevice, AdvertisementData]],
) -> None:
    del discovered
    with pytest.raises(TransportError, match="hold both buttons"):
        await transport.find_device()


async def test_find_device_picks_the_closest(
    discovered: dict[str, tuple[BLEDevice, AdvertisementData]],
) -> None:
    discovered["far"] = seen("A4:C1:38:00:00:01", "ATC_far", -90)
    discovered["near"] = seen("A4:C1:38:00:00:02", "ATC_near", -40)
    device = await transport.find_device()
    assert device.address == "A4:C1:38:00:00:02"


@pytest.mark.parametrize(
    ("revision", "expected"),
    [("0005", HW_ID_EN), ("0004", HW_ID_CH), (None, HW_ID_CH), ("", HW_ID_CH)],
)
def test_the_firmware_revision_picks_the_lcd_variant(
    revision: str | None, expected: int
) -> None:
    info = DeviceInfo(
        firmware_revision=revision, hardware_revision=None, software_revision=None
    )
    assert info.hardware_id == expected


def test_uuids_are_abbreviated_in_logs() -> None:
    assert transport._short("00001f1f-0000-1000-8000-00805f9b34fb") == "0x1f1f"
    assert transport._short("ebe0ccd8-7a0a-4b0c-8a1a-6ff2997da3a6") == (
        "ebe0ccd8-7a0a-4b0c-8a1a-6ff2997da3a6"
    )


async def test_find_device_warns_when_several_are_in_range(
    discovered: dict[str, tuple[BLEDevice, AdvertisementData]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    discovered["far"] = seen("A4:C1:38:00:00:01", "ATC_far", -90)
    discovered["near"] = seen("A4:C1:38:00:00:02", "ATC_near", -40)
    device = await transport.find_device()
    assert device.address == "A4:C1:38:00:00:02"
    assert "several devices in range" in caplog.text
    assert "A4:C1:38:00:00:01" in caplog.text
    assert "A4:C1:38:00:00:02" in caplog.text


async def test_find_device_does_not_warn_about_a_single_candidate(
    discovered: dict[str, tuple[BLEDevice, AdvertisementData]],
    caplog: pytest.LogCaptureFixture,
) -> None:
    discovered["only"] = seen("A4:C1:38:00:00:03", "ATC_only", -50)
    device = await transport.find_device()
    assert device.address == "A4:C1:38:00:00:03"
    assert "several devices" not in caplog.text


async def test_find_device_resolves_a_given_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device = BLEDevice("A4:C1:38:00:00:04", "ATC_4", None)
    captured: dict[str, Any] = {}

    async def fake_find(address: str, **kwargs: Any) -> BLEDevice:
        assert address == device.address
        captured.update(kwargs)
        return device

    monkeypatch.setattr(transport.BleakScanner, "find_device_by_address", fake_find)
    assert await transport.find_device(device.address, adapter="hci1") is device
    assert captured["bluez"] == BlueZScannerArgs(adapter="hci1")


async def test_find_device_explains_an_address_that_cannot_be_found(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def fake_find(address: str, **kwargs: Any) -> None:
        del address, kwargs

    monkeypatch.setattr(transport.BleakScanner, "find_device_by_address", fake_find)
    with pytest.raises(TransportError, match="no device with address AA:BB found"):
        await transport.find_device("AA:BB", timeout=5)


class FakeCharacteristic:
    def __init__(
        self,
        uuid: str,
        properties: Sequence[str] = ("read", "write-without-response", "notify"),
    ) -> None:
        self.uuid = uuid
        self.properties = list(properties)


class FakeService:
    def __init__(self, uuid: str) -> None:
        self.uuid = uuid


class FakeServices:
    """Enough of `BleakGATTServiceCollection` for `Link` to introspect."""

    def __init__(
        self,
        service_uuids: Sequence[str] = (),
        characteristic_uuids: Sequence[str] = (),
    ) -> None:
        self._services = [FakeService(uuid) for uuid in service_uuids]
        self._characteristics = {
            uuid: FakeCharacteristic(uuid) for uuid in characteristic_uuids
        }
        self._error: Exception | None = None

    def fail(self, error: Exception) -> None:
        """Simulate Bleak's discarded-on-disconnect service cache."""
        self._error = error

    def __iter__(self) -> Iterator[FakeService]:
        if self._error is not None:
            raise self._error
        return iter(self._services)

    def get_characteristic(self, uuid: str) -> FakeCharacteristic | None:
        if self._error is not None:
            raise self._error
        return self._characteristics.get(uuid)


NotifyHandler = Callable[[FakeCharacteristic | None, bytearray], None]


class FakeGATTClient:
    """Enough of `BleakClient` to drive `Link` and `connect()` without hardware."""

    def __init__(
        self,
        address: str = "A4:C1:38:00:00:01",
        *,
        service_uuids: Sequence[str] = (),
        characteristic_uuids: Sequence[str] = (),
    ) -> None:
        self.address = address
        self.kwargs: dict[str, Any] = {}
        self.services = FakeServices(service_uuids, characteristic_uuids)
        self._notify_handlers: dict[str, NotifyHandler] = {}
        self._reads: dict[str, bytes] = {}
        self._read_errors: dict[str, Exception] = {}
        self.writes: list[tuple[str, bytes, bool | None]] = []
        self.write_error: Exception | None = None
        self.connect_error: Exception | None = None
        self.disconnect_error: Exception | None = None
        self.connect_calls = 0
        self.disconnect_calls = 0
        self.notify_calls: list[str] = []
        self.notify_error: Exception | None = None

    async def start_notify(self, uuid: str, handler: NotifyHandler) -> None:
        if self.notify_error is not None:
            raise self.notify_error
        self._notify_handlers[uuid] = handler
        self.notify_calls.append(uuid)

    def notify(self, uuid: str, data: bytes) -> None:
        """Simulate the device pushing a notification, as Bleak's backend would."""
        characteristic = self.services.get_characteristic(uuid)
        self._notify_handlers[uuid](characteristic, bytearray(data))

    async def write_gatt_char(
        self, uuid: str, data: bytes, *, response: bool | None = None
    ) -> None:
        if self.write_error is not None:
            raise self.write_error
        self.writes.append((uuid, bytes(data), response))

    def set_read(self, uuid: str, value: bytes) -> None:
        self._reads[uuid] = value

    def fail_read(self, uuid: str, error: Exception) -> None:
        self._read_errors[uuid] = error

    async def read_gatt_char(self, uuid: str) -> bytes:
        if uuid in self._read_errors:
            raise self._read_errors[uuid]
        return self._reads.get(uuid, b"")

    async def connect(self) -> None:
        self.connect_calls += 1
        if self.connect_error is not None:
            raise self.connect_error

    async def disconnect(self) -> None:
        self.disconnect_calls += 1
        if self.disconnect_error is not None:
            raise self.disconnect_error


async def test_take_returns_a_notification() -> None:
    link = transport.Link(FakeGATTClient())  # ty: ignore[invalid-argument-type]
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    queue.put_nowait(b"\x01")
    assert await link.take(queue) == b"\x01"


async def test_take_raises_as_soon_as_the_connection_drops() -> None:
    # Nothing posts to a notification queue after a disconnect, so without
    # this a consumer would sit out its whole protocol timeout and then
    # report a misleading "did not answer". The outer bound turns a
    # regression into a fast failure rather than a hung test run.
    dropped = asyncio.Event()
    link = transport.Link(FakeGATTClient(), dropped)  # ty: ignore[invalid-argument-type]
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    dropped.set()
    async with asyncio.timeout(1):
        with pytest.raises(TransportError, match="device disconnected"):
            await link.take(queue)


async def test_take_requeues_an_item_grabbed_as_the_caller_is_cancelled() -> None:
    # A surrounding asyncio.timeout can cancel take() in the same tick that
    # its internal get dequeues a notification; the item is already off the
    # queue then, and dropping it would lose a protocol message for good.
    link = transport.Link(FakeGATTClient())  # ty: ignore[invalid-argument-type]
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    task = asyncio.get_running_loop().create_task(link.take(queue))
    await asyncio.sleep(0)  # let take() start waiting on the queue
    queue.put_nowait(b"\x07")
    asyncio.get_running_loop().call_soon(task.cancel)
    async with asyncio.timeout(1):
        with pytest.raises(asyncio.CancelledError):
            await task
    assert queue.get_nowait() == b"\x07"


async def test_take_cancelled_while_the_queue_is_empty_requeues_nothing() -> None:
    link = transport.Link(FakeGATTClient())  # ty: ignore[invalid-argument-type]
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    task = asyncio.get_running_loop().create_task(link.take(queue))
    await asyncio.sleep(0)
    task.cancel()
    async with asyncio.timeout(1):
        with pytest.raises(asyncio.CancelledError):
            await task
    assert queue.empty()


async def test_take_prefers_data_over_a_simultaneous_disconnect() -> None:
    # A notification that arrived before the drop must not be discarded.
    dropped = asyncio.Event()
    link = transport.Link(FakeGATTClient(), dropped)  # ty: ignore[invalid-argument-type]
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    queue.put_nowait(b"\x02")
    dropped.set()
    assert await link.take(queue) == b"\x02"


async def test_connect_wires_disconnection_into_take(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    del no_sleep
    device = BLEDevice("A4:C1:38:00:00:15", "ATC_o", None)
    factory, made = bleak_client_factory()
    monkeypatch.setattr(transport, "BleakClient", factory)

    async with transport.connect(device) as link:
        queue: asyncio.Queue[bytes] = asyncio.Queue()
        made[0].kwargs["disconnected_callback"](made[0])
        async with asyncio.timeout(1):
            with pytest.raises(TransportError, match="device disconnected"):
                await link.take(queue)


def test_link_exposes_the_client_and_its_address() -> None:
    client = FakeGATTClient("A4:C1:38:00:00:09")
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    assert link.client is client
    assert link.address == "A4:C1:38:00:00:09"


def test_has_service_and_has_characteristic_reflect_the_gatt_table() -> None:
    client = FakeGATTClient(
        service_uuids=[DIS_SERVICE], characteristic_uuids=[DIS_FIRMWARE_REVISION_CHAR]
    )
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    assert link.has_service(DIS_SERVICE)
    # has_service lowercases its argument, so a device advertising the
    # canonical (lowercase) UUID still matches a caller who passes it upper.
    assert link.has_service(DIS_SERVICE.upper())
    assert not link.has_service(CUSTOM_SERVICE)
    assert link.has_characteristic(DIS_FIRMWARE_REVISION_CHAR)
    assert not link.has_characteristic(CUSTOM_CHAR)


@pytest.mark.parametrize(
    ("method", "uuid"),
    [("has_service", CUSTOM_SERVICE), ("has_characteristic", CUSTOM_CHAR)],
)
def test_has_service_and_has_characteristic_report_a_dropped_link(
    method: str, uuid: str
) -> None:
    # Both reach `self._client.services`, exactly what `write()` was given a
    # fast disconnect check for; without the same check here, a device that
    # dropped moments after connecting (the flaky window `bootstrap`'s
    # post-reboot retry loop exists to ride out) surfaces as a raw BleakError
    # instead of the TransportError callers actually handle.
    dropped = asyncio.Event()
    dropped.set()
    client = FakeGATTClient()
    link = transport.Link(client, dropped)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TransportError, match="device disconnected"):
        getattr(link, method)(uuid)


@pytest.mark.parametrize(
    ("method", "uuid"),
    [("has_service", CUSTOM_SERVICE), ("has_characteristic", CUSTOM_CHAR)],
)
def test_has_service_and_has_characteristic_translate_a_lost_service_cache(
    method: str, uuid: str
) -> None:
    # The same loss, but reached before the disconnect callback has landed.
    client = FakeGATTClient()
    client.services.fail(BleakError("Service Discovery has not been performed yet"))
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TransportError, match="Service Discovery"):
        getattr(link, method)(uuid)


async def test_subscribe_enqueues_notifications_as_they_arrive() -> None:
    client = FakeGATTClient()
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    queue = await link.subscribe(CUSTOM_CHAR)
    client.notify(CUSTOM_CHAR, b"\x01\x02")
    assert await queue.get() == b"\x01\x02"
    # The same queue is what a later caller gets back for that UUID.
    assert link.queue(CUSTOM_CHAR) is queue


def test_queue_raises_for_a_characteristic_never_subscribed() -> None:
    client = FakeGATTClient()
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TransportError, match="not subscribed"):
        link.queue(CUSTOM_CHAR)


async def test_ensure_subscribed_subscribes_when_nobody_has_yet() -> None:
    client = FakeGATTClient()
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    queue = await link.ensure_subscribed(CUSTOM_CHAR)
    client.notify(CUSTOM_CHAR, b"\x99")
    assert await queue.get() == b"\x99"
    assert client.notify_calls == [CUSTOM_CHAR]


async def test_subscribe_reports_a_dropped_link_as_a_disconnect() -> None:
    # `Session.open` subscribes immediately after checking for its
    # characteristic, and `cmd_bootstrap`'s post-reboot loop retries only on
    # TransportError. A bare BleakError from here would escape that loop and
    # abort after one attempt, defeating the retry it exists for.
    dropped = asyncio.Event()
    dropped.set()
    client = FakeGATTClient(characteristic_uuids=[CUSTOM_CHAR])
    link = transport.Link(client, dropped)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TransportError, match="device disconnected"):
        await link.subscribe(CUSTOM_CHAR)
    assert client.notify_calls == []


async def test_subscribe_translates_a_bleak_error_into_a_transport_error() -> None:
    # The narrower race: the drop is discovered only by start_notify itself,
    # which refuses with "Not connected" before it reaches the backend.
    client = FakeGATTClient(characteristic_uuids=[CUSTOM_CHAR])
    client.notify_error = BleakError("Not connected")
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TransportError, match="Not connected"):
        await link.subscribe(CUSTOM_CHAR)


async def test_subscribe_tagged_translates_a_bleak_error_too() -> None:
    # The Xiaomi handshake subscribes through this path rather than subscribe().
    client = FakeGATTClient()
    client.notify_error = BleakError("Not connected")
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TransportError, match="could not subscribe"):
        await link.subscribe_tagged((MI_AUTH_CONTROL_CHAR, MI_AUTH_DATA_CHAR))


async def test_ensure_subscribed_reuses_an_existing_subscription() -> None:
    # Subscribing a second time would hand Bleak a new callback, so whoever
    # holds the first queue would stop receiving anything at all.
    client = FakeGATTClient()
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    first = await link.subscribe(CUSTOM_CHAR)
    again = await link.ensure_subscribed(CUSTOM_CHAR)
    assert again is first
    assert client.notify_calls == [CUSTOM_CHAR]
    client.notify(CUSTOM_CHAR, b"\x77")
    assert await first.get() == b"\x77"


async def test_subscribe_tagged_tags_the_characteristic_a_payload_came_from() -> None:
    client = FakeGATTClient()
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    merged = await link.subscribe_tagged([MI_AUTH_CONTROL_CHAR, MI_AUTH_DATA_CHAR])
    client.notify(MI_AUTH_DATA_CHAR, b"\xaa")
    client.notify(MI_AUTH_CONTROL_CHAR, b"\xbb")
    assert await merged.get() == (MI_AUTH_DATA_CHAR, b"\xaa")
    assert await merged.get() == (MI_AUTH_CONTROL_CHAR, b"\xbb")


async def test_write_sends_the_bytes_to_the_named_characteristic() -> None:
    client = FakeGATTClient()
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    await link.write(CUSTOM_CHAR, b"\x01\x02", response=True)
    assert client.writes == [(CUSTOM_CHAR, b"\x01\x02", True)]


async def test_write_resolves_no_preference_to_without_response() -> None:
    # The bool is resolved locally rather than left as None for Bleak, which
    # deprecates omitting it; resolving here keeps the choice pinned by these
    # tests instead of inherited from a dependency.
    client = FakeGATTClient(characteristic_uuids=[CUSTOM_CHAR])
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    await link.write(CUSTOM_CHAR, b"\x55")
    assert client.writes == [(CUSTOM_CHAR, b"\x55", False)]


async def test_write_resolves_no_preference_to_with_response_when_it_must() -> None:
    client = FakeGATTClient(characteristic_uuids=[CUSTOM_CHAR])
    char = client.services.get_characteristic(CUSTOM_CHAR)
    assert char is not None
    char.properties = ["read", "write"]
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    await link.write(CUSTOM_CHAR, b"\x55")
    assert client.writes == [(CUSTOM_CHAR, b"\x55", True)]


async def test_write_defaults_to_with_response_for_an_unknown_characteristic() -> None:
    client = FakeGATTClient()
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    await link.write(CUSTOM_CHAR, b"\x55")
    assert client.writes == [(CUSTOM_CHAR, b"\x55", True)]


async def test_write_translates_a_bleak_error_into_a_transport_error() -> None:
    client = FakeGATTClient()
    client.write_error = BleakError("gatt busy")
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TransportError, match="gatt busy"):
        await link.write(CUSTOM_CHAR, b"\x00")


async def test_write_reports_a_dropped_link_as_a_disconnect() -> None:
    # Stock firmware hangs up the moment an unauthenticated OTA starts. Bleak
    # discards its service cache on disconnect, so resolving the write type is
    # the first thing to fail afterwards, with "Service Discovery has not been
    # performed yet" — a message that sends the reader looking for a fault here
    # instead of telling them the device refused.
    dropped = asyncio.Event()
    dropped.set()
    client = FakeGATTClient(characteristic_uuids=[CUSTOM_CHAR])
    link = transport.Link(client, dropped)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TransportError, match="device disconnected"):
        await link.write(CUSTOM_CHAR, b"\x55")
    assert client.writes == []


async def test_write_translates_a_lost_service_cache_into_a_transport_error() -> None:
    # The same loss, but reached before the disconnect callback has landed.
    client = FakeGATTClient()
    client.services.fail(BleakError("Service Discovery has not been performed yet"))
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TransportError, match="Service Discovery"):
        await link.write(CUSTOM_CHAR, b"\x55")


async def test_read_reports_a_dropped_link_as_a_disconnect() -> None:
    # `read()` reaches `self._client.services` internally (via bleak's own
    # `read_gatt_char`) exactly as `write()` does, and OTA's periodic status
    # read sits in the same per-block loop as its now-fixed write — so it
    # needs the same fast, clean disconnect check `write()` was given.
    dropped = asyncio.Event()
    dropped.set()
    client = FakeGATTClient()
    link = transport.Link(client, dropped)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TransportError, match="device disconnected"):
        await link.read(CUSTOM_CHAR)


async def test_read_returns_the_characteristic_value() -> None:
    client = FakeGATTClient()
    client.set_read(CUSTOM_CHAR, b"\x01\x02\x03")
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    assert await link.read(CUSTOM_CHAR) == b"\x01\x02\x03"


async def test_read_logs_the_value_it_receives(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    client = FakeGATTClient()
    client.set_read(CUSTOM_CHAR, b"\x01\x02\x03")
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    await link.read(CUSTOM_CHAR)
    assert "010203" in caplog.text


async def test_read_translates_a_bleak_error_into_a_transport_error() -> None:
    client = FakeGATTClient()
    client.fail_read(CUSTOM_CHAR, BleakError("disconnected"))
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    with pytest.raises(TransportError, match="disconnected"):
        await link.read(CUSTOM_CHAR)


async def test_read_string_returns_none_for_an_absent_characteristic() -> None:
    client = FakeGATTClient()
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    assert await link.read_string(DIS_FIRMWARE_REVISION_CHAR) is None


async def test_read_string_stops_at_the_first_nul() -> None:
    client = FakeGATTClient(characteristic_uuids=[DIS_FIRMWARE_REVISION_CHAR])
    client.set_read(DIS_FIRMWARE_REVISION_CHAR, b"0005\x00\xff\xff")
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    assert await link.read_string(DIS_FIRMWARE_REVISION_CHAR) == "0005"


async def test_read_string_replaces_bytes_that_are_not_valid_utf8() -> None:
    client = FakeGATTClient(characteristic_uuids=[DIS_FIRMWARE_REVISION_CHAR])
    client.set_read(DIS_FIRMWARE_REVISION_CHAR, b"\xff\xfe")
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    assert await link.read_string(DIS_FIRMWARE_REVISION_CHAR) == "��"


async def test_read_string_returns_none_when_the_read_itself_fails() -> None:
    client = FakeGATTClient(characteristic_uuids=[DIS_FIRMWARE_REVISION_CHAR])
    client.fail_read(DIS_FIRMWARE_REVISION_CHAR, BleakError("gone"))
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    assert await link.read_string(DIS_FIRMWARE_REVISION_CHAR) is None


async def test_device_info_is_all_none_without_the_dis_service() -> None:
    client = FakeGATTClient()
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    assert await link.device_info() == DeviceInfo(None, None, None)


async def test_device_info_reads_all_three_dis_characteristics() -> None:
    client = FakeGATTClient(
        service_uuids=[DIS_SERVICE],
        characteristic_uuids=[
            DIS_FIRMWARE_REVISION_CHAR,
            DIS_HARDWARE_REVISION_CHAR,
            DIS_SOFTWARE_REVISION_CHAR,
        ],
    )
    client.set_read(DIS_FIRMWARE_REVISION_CHAR, b"0005\x00")
    client.set_read(DIS_HARDWARE_REVISION_CHAR, b"v1\x00")
    client.set_read(DIS_SOFTWARE_REVISION_CHAR, b"1.2.3\x00")
    link = transport.Link(client)  # ty: ignore[invalid-argument-type]
    assert await link.device_info() == DeviceInfo(
        firmware_revision="0005", hardware_revision="v1", software_revision="1.2.3"
    )


async def test_expect_returns_the_next_queued_notification() -> None:
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    queue.put_nowait(b"\x01")
    assert await transport.expect(queue) == b"\x01"


async def test_expect_times_out_rather_than_hanging_forever() -> None:
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    with pytest.raises(TransportError, match=r"timed out after 0\.01s"):
        await transport.expect(queue, timeout=0.01)


def bleak_client_factory(
    *,
    fail_attempts: int = 0,
    fail_error: Exception | None = None,
    disconnect_error: Exception | None = None,
) -> tuple[Callable[..., FakeGATTClient], list[FakeGATTClient]]:
    """Build a `transport.BleakClient` stand-in that fails its first N connects.

    Each retry in `connect()` constructs a brand-new client, so the failure
    count has to live in the factory rather than on any one instance.
    """
    made: list[FakeGATTClient] = []

    def factory(device: BLEDevice, **kwargs: Any) -> FakeGATTClient:
        client = FakeGATTClient(device.address)
        client.kwargs = kwargs
        if len(made) < fail_attempts:
            client.connect_error = fail_error or BleakError("connection refused")
        client.disconnect_error = disconnect_error
        made.append(client)
        return client

    return factory, made


@pytest.fixture
def no_sleep(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Replace the retry backoff with a no-op, recording the delays requested."""
    delays: list[float] = []

    async def fake_sleep(delay: float) -> None:
        delays.append(delay)

    monkeypatch.setattr(transport.asyncio, "sleep", fake_sleep)
    return delays


async def test_connect_uses_a_ble_device_passed_directly_without_scanning(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    del no_sleep

    async def unexpected_scan(*args: Any, **kwargs: Any) -> None:
        del args, kwargs
        pytest.fail("connect() scanned despite being given a BLEDevice")

    monkeypatch.setattr(
        transport.BleakScanner, "find_device_by_address", unexpected_scan
    )
    monkeypatch.setattr(transport.BleakScanner, "discover", unexpected_scan)

    factory, made = bleak_client_factory()
    monkeypatch.setattr(transport, "BleakClient", factory)

    device = BLEDevice("A4:C1:38:00:00:0A", "ATC_a", None)
    async with transport.connect(device) as link:
        assert link.address == device.address
    assert made[0].connect_calls == 1
    assert made[0].disconnect_calls == 1


async def test_connect_scans_for_an_address_it_is_given(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    del no_sleep
    device = BLEDevice("A4:C1:38:00:00:0B", "ATC_b", None)

    async def fake_find(address: str, **kwargs: Any) -> BLEDevice:
        assert address == device.address
        del kwargs
        return device

    monkeypatch.setattr(transport.BleakScanner, "find_device_by_address", fake_find)

    factory, made = bleak_client_factory()
    monkeypatch.setattr(transport, "BleakClient", factory)

    async with transport.connect(device.address) as link:
        assert link.address == device.address
    assert made[0].connect_calls == 1


async def test_connect_selects_the_given_adapter(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    del no_sleep
    device = BLEDevice("A4:C1:38:00:00:10", "ATC_g", None)
    captured: dict[str, Any] = {}

    def factory(device: BLEDevice, **kwargs: Any) -> FakeGATTClient:
        captured.update(kwargs)
        return FakeGATTClient(device.address)

    monkeypatch.setattr(transport, "BleakClient", factory)
    async with transport.connect(device, adapter="hci1"):
        pass
    assert captured["bluez"] == BlueZClientArgs(adapter="hci1")


async def test_connect_omits_the_bluez_adapter_key_when_none_given(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    del no_sleep
    device = BLEDevice("A4:C1:38:00:00:11", "ATC_h", None)
    captured: dict[str, Any] = {}

    def factory(device: BLEDevice, **kwargs: Any) -> FakeGATTClient:
        captured.update(kwargs)
        return FakeGATTClient(device.address)

    monkeypatch.setattr(transport, "BleakClient", factory)
    async with transport.connect(device):
        pass
    # BlueZClientArgs is a TypedDict, so an explicit adapter=None is a
    # different value from the key being absent; pin the absence, not just a
    # falsy adapter.
    assert captured["bluez"] == BlueZClientArgs()
    assert "adapter" not in captured["bluez"]


async def test_connect_retries_after_a_failed_attempt_then_succeeds(
    monkeypatch: pytest.MonkeyPatch,
    no_sleep: list[float],
    caplog: pytest.LogCaptureFixture,
) -> None:
    device = BLEDevice("A4:C1:38:00:00:0C", "ATC_c", None)
    factory, made = bleak_client_factory(fail_attempts=1)
    monkeypatch.setattr(transport, "BleakClient", factory)

    async with transport.connect(device) as link:
        assert link.address == device.address

    assert [c.connect_calls for c in made] == [1, 1]
    # The failed client must be cancelled, not abandoned: an uncancelled
    # request stays pending in the OS daemon (CoreBluetooth ones never
    # expire), which then captures the device at its next advertisement.
    assert [c.disconnect_calls for c in made] == [1, 1]
    assert no_sleep == [1.0]
    assert "connection attempt 1/3 failed" in caplog.text


async def test_connect_retries_after_a_timeout_error(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    # BLE stacks routinely time out rather than raising a clean BleakError,
    # so a bare TimeoutError from client.connect() must be retried the same
    # way a BleakError is, not left to crash out of connect().
    device = BLEDevice("A4:C1:38:00:00:12", "ATC_i", None)
    factory, made = bleak_client_factory(fail_attempts=1, fail_error=TimeoutError())
    monkeypatch.setattr(transport, "BleakClient", factory)

    async with transport.connect(device) as link:
        assert link.address == device.address

    assert [c.connect_calls for c in made] == [1, 1]
    assert [c.disconnect_calls for c in made] == [1, 1]
    assert no_sleep == [1.0]


async def test_connect_raises_after_every_attempt_fails(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    device = BLEDevice("A4:C1:38:00:00:0D", "ATC_d", None)
    factory, made = bleak_client_factory(fail_attempts=2)
    monkeypatch.setattr(transport, "BleakClient", factory)

    with pytest.raises(
        TransportError,
        match=f"could not connect to {device.address} after 2 attempts",
    ):
        async with transport.connect(device, attempts=2):
            pytest.fail("the body must not run if every attempt failed")

    assert len(made) == 2
    assert [c.disconnect_calls for c in made] == [1, 1]
    assert no_sleep == [1.0, 1.0]


async def test_connect_disconnects_even_when_the_body_raises(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    del no_sleep
    device = BLEDevice("A4:C1:38:00:00:0E", "ATC_e", None)
    factory, made = bleak_client_factory()
    monkeypatch.setattr(transport, "BleakClient", factory)

    msg = "boom"
    with pytest.raises(ValueError, match="boom"):
        async with transport.connect(device):
            raise ValueError(msg)

    assert made[0].disconnect_calls == 1


async def test_connect_suppresses_a_bleak_error_raised_while_disconnecting(
    monkeypatch: pytest.MonkeyPatch, no_sleep: list[float]
) -> None:
    del no_sleep
    device = BLEDevice("A4:C1:38:00:00:0F", "ATC_f", None)
    factory, made = bleak_client_factory(disconnect_error=BleakError("already gone"))
    monkeypatch.setattr(transport, "BleakClient", factory)

    async with transport.connect(device):
        pass

    assert made[0].disconnect_calls == 1
