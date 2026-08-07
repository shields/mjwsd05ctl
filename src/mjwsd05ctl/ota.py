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

"""The Telink over-the-air update protocol."""

import asyncio
import logging
import struct
from typing import TYPE_CHECKING

from .constants import (
    CUSTOM_CHAR,
    HW_ID_EN,
    MAX_BLE_OTA_SIZE,
    MAX_BLE_OTA_SIZE_EN,
    MAX_EXT_OTA_SIZE,
    MI_SPEED_CHAR,
    MI_SPEED_FAST,
    OTA_BLOCK_SIZE,
    OTA_CHAR,
    OTA_END_COMMAND,
    OTA_ERRORS,
    OTA_START_COMMANDS,
    OTA_STATUS_INTERVAL,
    CommandId,
)
from .errors import OTAError

if TYPE_CHECKING:
    from collections.abc import Callable

    from .firmware import FirmwareImage
    from .transport import Link

log = logging.getLogger(__name__)

# The device needs a moment to apply the shorter connection interval, and again
# to erase its update slot, before it will take data. Taken from the reference
# flasher, which is the only description of the timing that exists.
SPEED_SETTLE = 0.5
START_SETTLE = 0.3
# The terminator is an unacknowledged write and the caller disconnects as soon
# as the update returns, which discards anything the local stack still has
# queued; give the final frame time to reach the air.
END_SETTLE = 1.0

type ProgressCallback = Callable[[int, int], None]

# Return codes from the firmware's `check_ext_ota()` and `clear_ota_area()`
# (`ext_ota.c`). Code 0 is not an acknowledgement: it means the address was
# below the extended slot's base and nothing started. Code 2 is the reply that
# accepts the request, and 4 is one progress tick per flash sector cleared.
_EXT_OTA_RESULTS = {
    0: "address is below the extended update area",
    1: "an update is already in progress",
    2: "erasing the update area",
    3: "update area ready",
    4: "erase in progress",
    0xFE: "bad address or size",
}
_EXT_OTA_READY = 3
_EXT_OTA_ERASING = 2
_EXT_OTA_PROGRESS = 4
_EXT_OTA_MIN_RESPONSE = 2
_EXT_OTA_DEFAULT_ADDRESS = 0x40000
_EXT_OTA_ERASE_TIMEOUT = 120.0


def crc16_modbus(data: bytes) -> int:
    """CRC-16/MODBUS: reflected polynomial 0xA001, initial value 0xFFFF."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def frame(number: int, payload: bytes) -> bytes:
    """Build one 20-byte update frame: sequence, 16 bytes of data, CRC."""
    if len(payload) != OTA_BLOCK_SIZE:
        msg = f"block {number} has {len(payload)} bytes, expected {OTA_BLOCK_SIZE}"
        raise OTAError(msg)
    body = struct.pack("<H", number) + payload
    return body + struct.pack("<H", crc16_modbus(body))


def end_frame(block_count: int) -> bytes:
    """Build the terminator, which repeats the last block number inverted."""
    last = block_count - 1
    return OTA_END_COMMAND + struct.pack("<HH", last, ~last & 0xFFFF)


def describe(status: int) -> str:
    if status < len(OTA_ERRORS):
        return OTA_ERRORS[status]
    return f"unknown status {status}"


def ordinary_slot_size(link: Link, hardware_id: int | None = None) -> int:
    """How large an image the plain update path can take on this device.

    Stock firmware hands over its whole 208 KiB slot. Custom firmware is itself
    living in low flash and keeps the update slot to 128 KiB — 112 KiB on the
    international unit, whose hardware id the reference flasher singles out.
    """
    if not link.has_characteristic(CUSTOM_CHAR):
        return MAX_EXT_OTA_SIZE
    if hardware_id == HW_ID_EN:
        return MAX_BLE_OTA_SIZE_EN
    return MAX_BLE_OTA_SIZE


async def _check_status(link: Link, number: int) -> None:
    status = await link.read(OTA_CHAR)
    if status and status[0]:
        msg = f"device aborted at block {number}: {describe(status[0])}"
        raise OTAError(msg)


async def update(
    link: Link,
    image: FirmwareImage,
    *,
    hardware_id: int | None = None,
    progress: ProgressCallback | None = None,
) -> None:
    """Stream a firmware image to the device.

    The device reboots into the new image once it accepts the terminator, so
    the connection dropping immediately afterwards is success, not failure.
    """
    if not link.has_characteristic(OTA_CHAR):
        msg = "device does not expose the Telink OTA characteristic"
        raise OTAError(msg)

    limit = ordinary_slot_size(link, hardware_id)
    if len(image.data) > limit:
        if not link.has_characteristic(CUSTOM_CHAR):
            # Only custom firmware can be asked to open the extended area, and
            # sending anyway would overrun the slot rather than fail cleanly.
            msg = (
                f"{image.name} is {len(image.data)} bytes, over this device's "
                f"{limit}-byte update slot, and it offers no way to enlarge it"
            )
            raise OTAError(msg)
        log.info(
            "%s is %d bytes, over the %d-byte slot; erasing the extended area, "
            "which discards the stored Mi Home keys and measurement history",
            image.name,
            len(image.data),
            limit,
        )
        await request_ext_ota(link, len(image.data))

    if link.has_characteristic(MI_SPEED_CHAR):
        # Only stock firmware has this; it asks for a faster connection.
        await link.write(MI_SPEED_CHAR, MI_SPEED_FAST)
        await asyncio.sleep(SPEED_SETTLE)

    for command in OTA_START_COMMANDS:
        await link.write(OTA_CHAR, command)
    await asyncio.sleep(START_SETTLE)

    total = image.block_count
    log.info("sending %s: %d blocks (%d bytes)", image.name, total, len(image.data))
    for number in range(total):
        await link.write(OTA_CHAR, frame(number, image.block(number)))
        if (number + 1) % OTA_STATUS_INTERVAL == 0:
            await _check_status(link, number)
        if progress is not None:
            progress(number + 1, total)

    if total % OTA_STATUS_INTERVAL:
        # The data frames are unacknowledged writes, so a final status read
        # both verifies the tail of the image and forces it out of the local
        # stack's queue before the terminator asks the device to commit. When
        # the count is a multiple of the polling interval, the loop's own last
        # poll has just done exactly this.
        await _check_status(link, total - 1)
    await link.write(OTA_CHAR, end_frame(total))
    log.info("sent %d blocks; device is rebooting into the new firmware", total)
    await asyncio.sleep(END_SETTLE)


async def request_ext_ota(
    link: Link,
    size: int,
    *,
    address: int = _EXT_OTA_DEFAULT_ADDRESS,
    timeout: float = _EXT_OTA_ERASE_TIMEOUT,
) -> None:
    """Ask custom firmware to erase its extended update area.

    Only needed for an image too large for the ordinary slot, which for stock
    MJWSD05MMC never happens: its slot already holds 208 KiB and the pvvx images
    are under 90 KiB. Reflashing a *stock* image over custom firmware does need
    it. Requires the pvvx config characteristic, so it cannot be used on a
    device still running stock firmware.
    """
    if not link.has_characteristic(CUSTOM_CHAR):
        msg = "extended OTA needs the pvvx config characteristic"
        raise OTAError(msg)

    kilobytes = (size + 1023) >> 10
    queue = await link.ensure_subscribed(CUSTOM_CHAR)
    await link.write(
        CUSTOM_CHAR,
        bytes([CommandId.SET_OTA]) + struct.pack("<II", address, kilobytes),
    )

    # The device acknowledges with ERASING, then sends one PROGRESS notification
    # per sector cleared, then READY. Erasing 200 KiB of flash takes a while, so
    # this deadline covers the whole sequence.
    try:
        async with asyncio.timeout(timeout):
            while True:
                response = await queue.get()
                if (
                    len(response) < _EXT_OTA_MIN_RESPONSE
                    or response[0] != CommandId.SET_OTA
                ):
                    continue
                result = response[1]
                log.debug("extended OTA: %s", _EXT_OTA_RESULTS.get(result, result))
                if result == _EXT_OTA_READY:
                    return
                if result not in (_EXT_OTA_ERASING, _EXT_OTA_PROGRESS):
                    detail = _EXT_OTA_RESULTS.get(result, f"code {result}")
                    msg = f"device refused the extended OTA request: {detail}"
                    raise OTAError(msg)
    except TimeoutError:
        msg = f"device did not finish erasing within {timeout:g}s"
        raise OTAError(msg) from None
