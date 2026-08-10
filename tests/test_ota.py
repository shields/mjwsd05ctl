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
import struct

import pytest
from conftest import FakeGATTClient

from mjwsd05ctl import ota, transport
from mjwsd05ctl.constants import (
    CUSTOM_CHAR,
    HW_ID_CH,
    HW_ID_EN,
    MAX_BLE_OTA_SIZE,
    MAX_BLE_OTA_SIZE_EN,
    MAX_EXT_OTA_SIZE,
    MI_SPEED_CHAR,
    MI_SPEED_FAST,
    OTA_START_COMMANDS,
    CommandId,
)
from mjwsd05ctl.errors import OTAError, TransportError
from mjwsd05ctl.firmware import FirmwareImage
from mjwsd05ctl.ota import crc16_modbus, describe, end_frame, frame


def test_crc16_modbus_known_answers() -> None:
    # The canonical CRC-16/MODBUS check value for "123456789".
    assert crc16_modbus(b"123456789") == 0x4B37
    assert crc16_modbus(b"") == 0xFFFF
    assert crc16_modbus(b"\x00") == 0x40BF


def test_frame_layout() -> None:
    payload = bytes(range(16))
    built = frame(0x1234, payload)
    assert len(built) == 20
    assert built[:2] == b"\x34\x12"
    assert built[2:18] == payload
    # The CRC covers the sequence number as well as the data.
    assert built[18:] == crc16_modbus(built[:18]).to_bytes(2, "little")


def test_frame_rejects_a_short_block() -> None:
    with pytest.raises(OTAError, match="expected 16"):
        frame(0, b"\x00" * 15)


def test_end_frame_repeats_the_last_block_inverted() -> None:
    # 5355 blocks means the last is 5354 == 0x14EA, whose complement is 0xEB15.
    assert end_frame(5355) == bytes.fromhex("02ffea1415eb")
    assert end_frame(1) == bytes.fromhex("02ff0000ffff")


def test_describe_covers_the_error_table() -> None:
    assert describe(0) == "success"
    assert describe(2) == "CRC error in data"
    # OTA_ERRORS has 7 entries (indices 0-6); the boundary one past the last
    # defined entry must still fall back cleanly rather than index out of range.
    assert describe(7) == "unknown status 7"
    assert describe(99) == "unknown status 99"


class FakeLink:
    """Enough of `transport.Link` for the extended-update request."""

    def __init__(self, *, replies: list[bytes] | None = None) -> None:
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.writes: list[bytes] = []
        self.subscribed: list[str] = []
        self._disconnected = asyncio.Event()
        self._client = FakeGATTClient(self._disconnected)
        for reply in replies or []:
            self._queue.put_nowait(reply)

    def disconnect(self) -> None:
        self._disconnected.set()

    def has_characteristic(self, uuid: str) -> bool:
        del uuid
        return True

    def queue(self, uuid: str) -> asyncio.Queue[bytes]:
        del uuid
        return self._queue

    async def ensure_subscribed(self, uuid: str) -> asyncio.Queue[bytes]:
        self.subscribed.append(uuid)
        return self._queue

    async def take(self, queue: asyncio.Queue[bytes]) -> bytes:
        # Borrow the real implementation, so the erase wait is tested against
        # the disconnect semantics it actually relies on.
        return await transport.Link.take(self, queue)  # ty: ignore[invalid-argument-type]

    async def write(
        self, uuid: str, data: bytes, *, response: bool | None = None
    ) -> None:
        del uuid, response
        self.writes.append(data)


async def test_extended_update_asks_for_the_right_area() -> None:
    link = FakeLink(replies=[bytes([CommandId.SET_OTA, 3, 0, 0, 4, 0, 200, 0, 0, 0])])
    await ota.request_ext_ota(link, 200 * 1024)  # ty: ignore[invalid-argument-type]
    request = link.writes[0]
    assert request[0] == CommandId.SET_OTA
    assert struct.unpack("<II", request[1:]) == (0x40000, 200)


async def test_extended_update_waits_through_the_erase() -> None:
    # ext_ota.c: check_ext_ota() acks the request with BUSY (2), then
    # clear_ota_area() pushes EVENT (4) once per flash sector it clears, and
    # finally READY (3) once the whole area is erased. Script that real
    # sequence rather than a single acknowledgement.
    link = FakeLink(
        replies=[
            bytes([CommandId.MEASURE, 0]),  # unrelated chatter
            bytes([CommandId.SET_OTA, 2]),  # accepted, erase starting
            bytes([CommandId.SET_OTA, 4]),  # sector cleared
            bytes([CommandId.SET_OTA, 4]),  # sector cleared
            bytes([CommandId.SET_OTA, 4]),  # sector cleared
            bytes([CommandId.SET_OTA, 3]),  # ready
        ]
    )
    await ota.request_ext_ota(link, 8192)  # ty: ignore[invalid-argument-type]
    # It kept reading through every progress tick until the terminal READY
    # rather than stopping early at the unrelated notification or treating a
    # progress tick as a refusal.
    assert link.queue(CUSTOM_CHAR).empty()


async def test_extended_update_reports_address_below_the_slot_as_a_failure() -> None:
    # ext_ota.c: status 0 means the requested address was below the extended
    # slot's base (BIG_OTA2_FADDR), so nothing started -- it is not an ack.
    link = FakeLink(replies=[bytes([CommandId.SET_OTA, 0])])
    with pytest.raises(OTAError, match="address is below the extended update area"):
        await ota.request_ext_ota(link, 8192)  # ty: ignore[invalid-argument-type]


async def test_extended_update_subscribes_to_the_config_characteristic_itself() -> None:
    # Nothing subscribes on this path before request_ext_ota runs, so it has to
    # establish the subscription rather than assume a caller already did; asking
    # for a queue that does not exist yet is a TransportError.
    link = FakeLink(replies=[bytes([CommandId.SET_OTA, 3])])
    await ota.request_ext_ota(link, 8192)  # ty: ignore[invalid-argument-type]
    assert link.subscribed == [CUSTOM_CHAR]


async def test_extended_update_reports_a_refusal() -> None:
    link = FakeLink(replies=[bytes([CommandId.SET_OTA, 0xFE])])
    with pytest.raises(OTAError, match="bad address or size"):
        await ota.request_ext_ota(link, 8192)  # ty: ignore[invalid-argument-type]


async def test_extended_update_rounds_the_erase_size_up_to_a_kilobyte() -> None:
    link = FakeLink(replies=[bytes([CommandId.SET_OTA, 3])])
    # One byte past a KiB boundary must still ask the device to erase a whole
    # extra KiB, or the device would erase less flash than the image needs.
    await ota.request_ext_ota(link, 8193)  # ty: ignore[invalid-argument-type]
    request = link.writes[0]
    assert struct.unpack("<II", request[1:])[1] == 9  # ceil(8193 / 1024)


async def test_extended_update_times_out_as_a_domain_error() -> None:
    link = FakeLink()
    with pytest.raises(OTAError, match="did not finish erasing"):
        await ota.request_ext_ota(link, 8192, timeout=0.05)  # ty: ignore[invalid-argument-type]


async def test_extended_update_gives_up_when_the_device_goes_away() -> None:
    # The erase deadline is two minutes, and this path has already discarded
    # the stored Mi Home keys and the measurement history by the time it is
    # waiting. Reading the queue directly would spend all two minutes on a dead
    # link and then blame the erase; going through `take` says what happened,
    # and says it at once. The outer bound turns a regression into a fast
    # failure rather than a two-minute hang.
    link = FakeLink()
    link.disconnect()
    async with asyncio.timeout(1):
        with pytest.raises(TransportError, match="device disconnected"):
            await ota.request_ext_ota(link, 8192)  # ty: ignore[invalid-argument-type]


class FakeOTADevice:
    """Records the update stream and answers the periodic status reads."""

    def __init__(
        self,
        *,
        fail_at: int | None = None,
        speed_char: bool = False,
        custom_char: bool = True,
    ) -> None:
        self.frames: list[bytes] = []
        self.fail_at = fail_at
        self.speed_char = speed_char
        self.custom_char = custom_char
        self.status = 0
        self.reads = 0
        self.subscribed: list[str] = []
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._disconnected = asyncio.Event()
        self._client = FakeGATTClient(self._disconnected)
        # Whatever asks for the extended area gets an immediate all-clear.
        self._queue.put_nowait(bytes([CommandId.SET_OTA, 3]))

    def has_characteristic(self, uuid: str) -> bool:
        if uuid == MI_SPEED_CHAR:
            return self.speed_char
        if uuid == CUSTOM_CHAR:
            return self.custom_char
        return True

    async def ensure_subscribed(self, uuid: str) -> asyncio.Queue[bytes]:
        self.subscribed.append(uuid)
        return self._queue

    async def take(self, queue: asyncio.Queue[bytes]) -> bytes:
        return await transport.Link.take(self, queue)  # ty: ignore[invalid-argument-type]

    async def write(
        self, uuid: str, data: bytes, *, response: bool | None = None
    ) -> None:
        del uuid, response
        self.frames.append(data)
        if self.fail_at is not None and len(self.frames) > self.fail_at:
            self.status = 2  # CRC error

    async def read(self, uuid: str) -> bytes:
        del uuid
        self.reads += 1
        return bytes([self.status])


@pytest.fixture
def _instant(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ota, "SPEED_SETTLE", 0.0)
    monkeypatch.setattr(ota, "START_SETTLE", 0.0)
    monkeypatch.setattr(ota, "END_SETTLE", 0.0)


@pytest.mark.usefixtures("_instant")
async def test_update_streams_the_whole_image() -> None:
    image = FirmwareImage(name="test.bin", data=bytes(range(256)) * 2)
    device = FakeOTADevice()
    seen: list[tuple[int, int]] = []
    await ota.update(device, image, progress=lambda d, t: seen.append((d, t)))  # ty: ignore[invalid-argument-type]

    start = list(OTA_START_COMMANDS)
    assert device.frames[: len(start)] == start
    body = device.frames[len(start) : -1]
    assert len(body) == image.block_count
    assert b"".join(f[2:18] for f in body) == image.data
    assert device.frames[-1] == ota.end_frame(image.block_count)
    # 32 blocks is a multiple of the polling interval, so the loop's own last
    # poll already covered the final block; a further read would be redundant.
    assert device.reads == image.block_count // 8
    # Check an intermediate call, where done != total: at completion both
    # coordinates are equal, so that alone can't tell (done, total) from a
    # swapped (total, done).
    assert seen[0] == (1, image.block_count)
    assert seen[-1] == (image.block_count, image.block_count)


@pytest.mark.usefixtures("_instant")
async def test_update_uses_the_speed_characteristic_when_the_device_has_one() -> None:
    image = FirmwareImage(name="test.bin", data=bytes(16))
    device = FakeOTADevice(speed_char=True)
    await ota.update(device, image)  # ty: ignore[invalid-argument-type]
    assert device.frames[0] == MI_SPEED_FAST


@pytest.mark.usefixtures("_instant")
async def test_update_stops_when_the_device_reports_an_error() -> None:
    # Long enough to reach the first status poll, which is after eight blocks.
    image = FirmwareImage(name="test.bin", data=bytes(16 * 32))
    device = FakeOTADevice(fail_at=4)
    # Pin the block number, not just the error text: OTA_STATUS_INTERVAL is 8,
    # so the first poll must fire after the block numbered 7 (the 8th block),
    # not one early or late.
    with pytest.raises(OTAError, match="device aborted at block 7: CRC error in data"):
        await ota.update(device, image)  # ty: ignore[invalid-argument-type]
    # It gave up rather than sending the rest of the image.
    assert len(device.frames) < image.block_count


@pytest.mark.usefixtures("_instant")
async def test_update_checks_the_status_after_the_final_block() -> None:
    # Four blocks never reach the every-eighth poll, so only a status read
    # after the last block can notice the device rejected the tail. Without
    # it the update would report success, and the device would abandon the
    # incomplete image and boot back into the old firmware.
    image = FirmwareImage(name="test.bin", data=bytes(16 * 4))
    device = FakeOTADevice(fail_at=3)
    with pytest.raises(OTAError, match="device aborted at block 3: CRC error in data"):
        await ota.update(device, image)  # ty: ignore[invalid-argument-type]
    # It stopped rather than asking the device to commit a bad image, and the
    # final read was the only one: four blocks never reach the periodic poll.
    assert device.reads == 1
    assert ota.end_frame(image.block_count) not in device.frames


async def test_update_refuses_a_device_with_no_update_service() -> None:
    class NoOTA(FakeOTADevice):
        def has_characteristic(self, uuid: str) -> bool:
            del uuid
            return False

    with pytest.raises(OTAError, match="does not expose"):
        await ota.update(NoOTA(), FirmwareImage(name="t", data=bytes(16)))  # ty: ignore[invalid-argument-type]


def test_the_slot_size_depends_on_what_the_device_is_running() -> None:
    # Stock firmware lends out its whole 208 KiB slot; custom firmware is in
    # low flash already and keeps 128 KiB, or 112 KiB on the EN unit, which is
    # the case the reference flasher singles out by hardware id.
    assert ota.ordinary_slot_size(FakeOTADevice(custom_char=False)) == MAX_EXT_OTA_SIZE  # ty: ignore[invalid-argument-type]
    assert ota.ordinary_slot_size(FakeOTADevice()) == MAX_BLE_OTA_SIZE  # ty: ignore[invalid-argument-type]
    assert ota.ordinary_slot_size(FakeOTADevice(), HW_ID_CH) == MAX_BLE_OTA_SIZE  # ty: ignore[invalid-argument-type]
    assert ota.ordinary_slot_size(FakeOTADevice(), HW_ID_EN) == MAX_BLE_OTA_SIZE_EN  # ty: ignore[invalid-argument-type]
    # A stock device's slot does not shrink just because it is the EN unit.
    assert (
        ota.ordinary_slot_size(FakeOTADevice(custom_char=False), HW_ID_EN)  # ty: ignore[invalid-argument-type]
        == MAX_EXT_OTA_SIZE
    )


@pytest.mark.usefixtures("_instant")
async def test_update_erases_the_extended_area_for_an_image_over_the_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A real oversize image is ~8200 blocks; shrink the limit instead of the
    # image so the test stays fast.
    monkeypatch.setattr(ota, "MAX_BLE_OTA_SIZE", 32)
    image = FirmwareImage(name="big.bin", data=bytes(48))
    device = FakeOTADevice()
    await ota.update(device, image)  # ty: ignore[invalid-argument-type]

    # The area has to be erased before the update starts, not after: the
    # device only redirects the stream once it reports the area ready.
    assert device.frames[0][0] == CommandId.SET_OTA
    assert device.subscribed == [CUSTOM_CHAR]
    assert device.frames[1 : 1 + len(OTA_START_COMMANDS)] == list(OTA_START_COMMANDS)
    assert device.frames[-1] == ota.end_frame(image.block_count)


@pytest.mark.usefixtures("_instant")
async def test_update_leaves_the_extended_area_alone_when_the_image_fits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An image that exactly fills the slot is not oversize. Erasing the
    # extended area needlessly would throw away the Mi Home keys and the
    # measurement history, so the boundary has to be strictly greater than.
    monkeypatch.setattr(ota, "MAX_BLE_OTA_SIZE", 32)
    image = FirmwareImage(name="fits.bin", data=bytes(32))
    device = FakeOTADevice()
    await ota.update(device, image)  # ty: ignore[invalid-argument-type]

    assert device.subscribed == []
    assert device.frames[0] == OTA_START_COMMANDS[0]


@pytest.mark.usefixtures("_instant")
async def test_update_sends_the_international_unit_through_the_extended_area_sooner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(ota, "MAX_BLE_OTA_SIZE", 48)
    monkeypatch.setattr(ota, "MAX_BLE_OTA_SIZE_EN", 32)
    image = FirmwareImage(name="mid.bin", data=bytes(48))

    chinese = FakeOTADevice()
    await ota.update(chinese, image, hardware_id=HW_ID_CH)  # ty: ignore[invalid-argument-type]
    assert chinese.subscribed == []

    english = FakeOTADevice()
    await ota.update(english, image, hardware_id=HW_ID_EN)  # ty: ignore[invalid-argument-type]
    assert english.subscribed == [CUSTOM_CHAR]


@pytest.mark.usefixtures("_instant")
async def test_update_refuses_an_image_too_big_for_a_slot_it_cannot_enlarge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Without the pvvx config characteristic there is no way to ask for the
    # extended area, and streaming anyway would overrun the slot.
    monkeypatch.setattr(ota, "MAX_EXT_OTA_SIZE", 32)
    image = FirmwareImage(name="huge.bin", data=bytes(48))
    device = FakeOTADevice(custom_char=False)

    with pytest.raises(OTAError, match="no way to enlarge it"):
        await ota.update(device, image)  # ty: ignore[invalid-argument-type]

    assert device.frames == []


async def test_extended_update_refuses_a_device_with_no_config_characteristic() -> None:
    class NoConfigChar(FakeLink):
        def has_characteristic(self, uuid: str) -> bool:
            del uuid
            return False

    with pytest.raises(OTAError, match="pvvx config characteristic"):
        await ota.request_ext_ota(NoConfigChar(), 8192)  # ty: ignore[invalid-argument-type]
