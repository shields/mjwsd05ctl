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

"""Telink firmware images: validation, padding, and locating them on disk."""

import logging
import os
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from .constants import (
    FIRMWARE_NAMES,
    MAX_EXT_OTA_SIZE,
    OTA_BLOCK_SIZE,
    TELINK_HSIZE_OFFSET,
    TELINK_MAGIC,
    TELINK_MAGIC_OFFSET,
    TELINK_MIN_SIZE,
)
from .errors import FirmwareError

log = logging.getLogger(__name__)

RELEASES_URL = "https://github.com/pvvx/ATC_MiThermometer/tree/master/bin"
FIRMWARE_DIR_ENV = "MJWSD05CTL_FIRMWARE_DIR"

# A Zigbee OTA container wraps a Telink image in a 0x3E-byte header. We do not
# flash Zigbee images, but recognise them to explain the refusal.
ZIGBEE_OTA_MAGIC = 0x0BEEF11E

# The header stores its own length with the low nibble set to 4, which is a
# cheap way to catch a file that is not a Telink image at all.
HSIZE_ALIGNMENT_REMAINDER = 4


def telink_crc32(data: bytes) -> int:
    """CRC-32 in the form the Telink image header stores it.

    Same table and loop as zlib's CRC-32, but without the final complement.
    A plain `zlib.crc32` disagrees with every real image.
    """
    return zlib.crc32(data) ^ 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class FirmwareImage:
    """A validated image, padded to a whole number of OTA blocks."""

    name: str
    data: bytes

    @property
    def block_count(self) -> int:
        return len(self.data) // OTA_BLOCK_SIZE

    def block(self, number: int) -> bytes:
        start = number * OTA_BLOCK_SIZE
        return self.data[start : start + OTA_BLOCK_SIZE]


def parse(data: bytes, name: str = "<memory>") -> FirmwareImage:
    """Validate a Telink OTA image and pad it to a block boundary.

    Mirrors `testOTAFirmware` in the reference flasher. Padding uses 0xFF so the
    tail matches erased flash.
    """
    if len(data) < TELINK_MIN_SIZE:
        msg = f"{name}: {len(data)} bytes is too small to be a firmware image"
        raise FirmwareError(msg)

    if struct.unpack_from("<I", data, 0)[0] == ZIGBEE_OTA_MAGIC:
        msg = (
            f"{name}: this is a Zigbee OTA image, which this tool does not flash; "
            "use a BLE image such as BTH_v58.bin or BTE_v58.bin"
        )
        raise FirmwareError(msg)

    magic = struct.unpack_from("<I", data, TELINK_MAGIC_OFFSET)[0]
    if magic != TELINK_MAGIC:
        msg = (
            f"{name}: not a Telink image "
            f"(magic {magic:#010x}, want {TELINK_MAGIC:#010x})"
        )
        raise FirmwareError(msg)

    hsize = struct.unpack_from("<I", data, TELINK_HSIZE_OFFSET)[0]
    if hsize > len(data) or hsize & 0x0F != HSIZE_ALIGNMENT_REMAINDER:
        msg = f"{name}: implausible size {hsize:#x} in image header"
        raise FirmwareError(msg)

    stored = struct.unpack_from("<I", data, hsize - 4)[0]
    computed = telink_crc32(data[: hsize - 4])
    if stored != computed:
        msg = (
            f"{name}: image CRC mismatch "
            f"(header says {stored:#010x}, computed {computed:#010x})"
        )
        raise FirmwareError(msg)

    if len(data) > MAX_EXT_OTA_SIZE:
        msg = (
            f"{name}: {len(data)} bytes exceeds the largest slot any "
            f"MJWSD05MMC firmware offers ({MAX_EXT_OTA_SIZE} bytes)"
        )
        raise FirmwareError(msg)

    padding = -len(data) % OTA_BLOCK_SIZE
    log.debug(
        "%s: %d bytes, header size %#x, CRC %#010x, %d padding bytes",
        name,
        len(data),
        hsize,
        stored,
        padding,
    )
    return FirmwareImage(name=name, data=data + b"\xff" * padding)


def load(path: Path) -> FirmwareImage:
    try:
        data = path.read_bytes()
    except OSError as exc:
        msg = f"cannot read {path}: {exc}"
        raise FirmwareError(msg) from exc
    return parse(data, path.name)


def search_dirs() -> list[Path]:
    """Directories searched for a firmware image, most specific first."""
    dirs = []
    if env := os.environ.get(FIRMWARE_DIR_ENV):
        dirs.append(Path(env))
    dirs += [Path.cwd(), Path.cwd() / "bin", Path.home() / ".local/share/mjwsd05ctl"]
    return dirs


def resolve(hardware_id: int, path: Path | None = None) -> FirmwareImage:
    """Load an explicitly named image, or find the one for this hardware."""
    if path is not None:
        return load(path)

    name = FIRMWARE_NAMES.get(hardware_id)
    if name is None:
        msg = f"no default firmware known for hardware id {hardware_id}"
        raise FirmwareError(msg)

    for directory in search_dirs():
        candidate = directory / name
        if candidate.is_file():
            log.info("using firmware %s", candidate)
            return load(candidate)

    searched = ", ".join(str(d) for d in search_dirs())
    msg = (
        f"could not find {name} in {searched}. Download it from {RELEASES_URL}, "
        f"or pass --firmware, or set {FIRMWARE_DIR_ENV}"
    )
    raise FirmwareError(msg)
