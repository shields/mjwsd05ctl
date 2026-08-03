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

"""Scanning, connecting, and framing GATT traffic."""

import asyncio
import contextlib
import logging
from collections.abc import AsyncGenerator, Callable, Sequence
from dataclasses import dataclass

from bleak import (
    AdvertisementData,
    BleakClient,
    BleakError,
    BleakGATTCharacteristic,
    BleakScanner,
    BLEDevice,
    BlueZClientArgs,
    BlueZScannerArgs,
)

from .constants import (
    DEVICE_NAME,
    DIS_FIRMWARE_REVISION_CHAR,
    DIS_HARDWARE_REVISION_CHAR,
    DIS_SERVICE,
    DIS_SOFTWARE_REVISION_CHAR,
    FIRMWARE_REVISION_EN,
    HW_ID_CH,
    HW_ID_EN,
)
from .errors import TransportError

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0
DEFAULT_SCAN_TIMEOUT = 10.0
CONNECT_ATTEMPTS = 3
NOTIFY_TIMEOUT = 10.0

# Devices advertise under several names depending on firmware: the stock name,
# the pvvx default, and whatever the user has since set.
NAME_PREFIXES = (DEVICE_NAME, "ATC_")

type NotifyHandler = Callable[[BleakGATTCharacteristic, bytearray], None]


@dataclass(frozen=True, slots=True)
class DeviceInfo:
    """Strings read from the Device Information Service."""

    firmware_revision: str | None
    hardware_revision: str | None
    software_revision: str | None

    @property
    def hardware_id(self) -> int:
        """The pvvx hardware id for this unit's LCD variant."""
        if self.firmware_revision and self.firmware_revision.startswith(
            FIRMWARE_REVISION_EN
        ):
            return HW_ID_EN
        return HW_ID_CH


class Link:
    """A connected device, with a notification queue per characteristic.

    Queues decouple the callbacks Bleak invokes from the sequential
    request/response flows in the Xiaomi and Telink protocols, both of which are
    written as straight-line `await` code against these queues.
    """

    def __init__(self, client: BleakClient) -> None:
        self._client = client
        self._queues: dict[str, asyncio.Queue[bytes]] = {}

    @property
    def client(self) -> BleakClient:
        return self._client

    @property
    def address(self) -> str:
        return self._client.address

    def has_service(self, uuid: str) -> bool:
        return any(service.uuid == uuid.lower() for service in self._client.services)

    def has_characteristic(self, uuid: str) -> bool:
        return self._client.services.get_characteristic(uuid) is not None

    async def subscribe(self, uuid: str) -> asyncio.Queue[bytes]:
        """Enable notifications on a characteristic and return their queue."""
        queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._queues[uuid] = queue

        def handler(_char: BleakGATTCharacteristic, data: bytearray) -> None:
            log.debug("notify %s <- %s", _short(uuid), bytes(data).hex())
            queue.put_nowait(bytes(data))

        await self._client.start_notify(uuid, handler)
        return queue

    async def subscribe_tagged(
        self, uuids: Sequence[str]
    ) -> asyncio.Queue[tuple[str, bytes]]:
        """Merge notifications from several characteristics into one queue.

        The Xiaomi handshake interleaves two characteristics and the order
        between them is significant, so they have to share a queue; the tag says
        which one a payload arrived on, which the payload itself cannot always
        tell you.
        """
        merged: asyncio.Queue[tuple[str, bytes]] = asyncio.Queue()

        def make_handler(uuid: str) -> NotifyHandler:
            def handler(_char: BleakGATTCharacteristic, data: bytearray) -> None:
                log.debug("notify %s <- %s", _short(uuid), bytes(data).hex())
                merged.put_nowait((uuid, bytes(data)))

            return handler

        for uuid in uuids:
            await self._client.start_notify(uuid, make_handler(uuid))
        return merged

    def queue(self, uuid: str) -> asyncio.Queue[bytes]:
        try:
            return self._queues[uuid]
        except KeyError:
            msg = f"not subscribed to {uuid}"
            raise TransportError(msg) from None

    async def ensure_subscribed(self, uuid: str) -> asyncio.Queue[bytes]:
        """Return a characteristic's queue, subscribing only if needed.

        Subscribing again would hand Bleak a fresh callback and leave whoever
        holds the previous queue waiting on notifications that now arrive
        somewhere else, so a caller that cannot know whether someone else got
        there first asks for this instead.
        """
        existing = self._queues.get(uuid)
        if existing is not None:
            return existing
        return await self.subscribe(uuid)

    async def write(
        self, uuid: str, data: bytes, *, response: bool | None = None
    ) -> None:
        """Write a characteristic.

        `response=None` lets Bleak pick write-with-response only when the
        characteristic lacks write-without-response, matching what Web
        Bluetooth's `writeValue` does for the reference implementation. Both the
        Telink OTA and pvvx config characteristics are write-without-response,
        which is what makes an upload finish in a reasonable time.
        """
        log.debug("write %s -> %s", _short(uuid), data.hex())
        try:
            await self._client.write_gatt_char(uuid, data, response=response)
        except BleakError as exc:
            msg = f"write to {uuid} failed: {exc}"
            raise TransportError(msg) from exc

    async def read(self, uuid: str) -> bytes:
        try:
            value = bytes(await self._client.read_gatt_char(uuid))
        except BleakError as exc:
            msg = f"read from {uuid} failed: {exc}"
            raise TransportError(msg) from exc
        log.debug("read %s <- %s", _short(uuid), value.hex())
        return value

    async def read_string(self, uuid: str) -> str | None:
        """Read a UTF-8 characteristic, tolerating its absence."""
        if not self.has_characteristic(uuid):
            return None
        try:
            raw = await self.read(uuid)
        except TransportError:
            return None
        return raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

    async def device_info(self) -> DeviceInfo:
        if not self.has_service(DIS_SERVICE):
            return DeviceInfo(None, None, None)
        return DeviceInfo(
            firmware_revision=await self.read_string(DIS_FIRMWARE_REVISION_CHAR),
            hardware_revision=await self.read_string(DIS_HARDWARE_REVISION_CHAR),
            software_revision=await self.read_string(DIS_SOFTWARE_REVISION_CHAR),
        )


async def expect(
    queue: asyncio.Queue[bytes], *, timeout: float = NOTIFY_TIMEOUT
) -> bytes:
    """Await the next notification, or fail rather than hang."""
    try:
        async with asyncio.timeout(timeout):
            return await queue.get()
    except TimeoutError:
        msg = f"timed out after {timeout:g}s waiting for a notification"
        raise TransportError(msg) from None


def _short(uuid: str) -> str:
    """Abbreviate a Bluetooth SIG UUID to its 16-bit form for log messages."""
    if uuid.startswith("0000") and uuid.endswith("-0000-1000-8000-00805f9b34fb"):
        return f"0x{uuid[4:8]}"
    return uuid


def _matches(device: BLEDevice, advertisement: AdvertisementData) -> bool:
    name = advertisement.local_name or device.name or ""
    return any(name.startswith(prefix) for prefix in NAME_PREFIXES)


async def scan(
    *,
    adapter: str | None = None,
    timeout: float = DEFAULT_SCAN_TIMEOUT,
    all_devices: bool = False,
) -> list[tuple[BLEDevice, AdvertisementData]]:
    """Discover nearby devices, by default only ones that look like ours."""
    found = await BleakScanner.discover(
        timeout=timeout, return_adv=True, bluez=bluez_scanner_args(adapter)
    )
    results = [
        (device, advertisement)
        for device, advertisement in found.values()
        if all_devices or _matches(device, advertisement)
    ]
    results.sort(
        key=lambda item: item[1].rssi if item[1].rssi is not None else -127,
        reverse=True,
    )
    return results


async def find_device(
    address: str | None = None,
    *,
    adapter: str | None = None,
    timeout: float = DEFAULT_SCAN_TIMEOUT,
) -> BLEDevice:
    """Resolve an address, or pick the strongest nearby device if given none."""
    if address is not None:
        device = await BleakScanner.find_device_by_address(
            address, timeout=timeout, bluez=bluez_scanner_args(adapter)
        )
        if device is None:
            msg = f"no device with address {address} found within {timeout:g}s"
            raise TransportError(msg)
        return device

    results = await scan(adapter=adapter, timeout=timeout)
    if not results:
        msg = (
            f"no MJWSD05MMC found within {timeout:g}s; "
            "hold both buttons to wake a sleeping device"
        )
        raise TransportError(msg)
    if len(results) > 1:
        addresses = ", ".join(device.address for device, _ in results)
        log.warning("several devices in range (%s); using the closest", addresses)
    return results[0][0]


@contextlib.asynccontextmanager
async def connect(
    target: str | BLEDevice | None = None,
    *,
    adapter: str | None = None,
    pair: bool = False,
    timeout: float = DEFAULT_TIMEOUT,
    attempts: int = CONNECT_ATTEMPTS,
) -> AsyncGenerator[Link]:
    """Connect to a device, retrying, and disconnect on the way out.

    Pairing is off by default: the firmware leaves its characteristics at
    `No_Security` unless a PIN has been set, so bonding is normally pointless
    and on some stacks it is actively unreliable.
    """
    if isinstance(target, BLEDevice):
        device = target
    else:
        device = await find_device(
            target, adapter=adapter, timeout=min(timeout, DEFAULT_SCAN_TIMEOUT)
        )

    last: Exception | None = None
    for attempt in range(1, attempts + 1):
        client = BleakClient(
            device,
            timeout=timeout,
            pair=pair,
            bluez=BlueZClientArgs(adapter=adapter) if adapter else BlueZClientArgs(),
        )
        try:
            await client.connect()
        except (BleakError, TimeoutError) as exc:
            last = exc
            log.warning("connection attempt %d/%d failed: %s", attempt, attempts, exc)
            await asyncio.sleep(1.0)
            continue

        log.info("connected to %s", device.address)
        try:
            yield Link(client)
        finally:
            with contextlib.suppress(BleakError, TimeoutError):
                await client.disconnect()
        return

    msg = f"could not connect to {device.address} after {attempts} attempts: {last}"
    raise TransportError(msg) from last


def bluez_scanner_args(adapter: str | None) -> BlueZScannerArgs:
    """Adapter selection, which only the BlueZ backend understands."""
    return BlueZScannerArgs(adapter=adapter) if adapter else BlueZScannerArgs()
