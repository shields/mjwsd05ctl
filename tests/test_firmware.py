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

import os
import struct
import zlib
from pathlib import Path

import pytest

from mjwsd05ctl import firmware, ota
from mjwsd05ctl.constants import (
    FIRMWARE_NAMES,
    HW_ID_CH,
    HW_ID_EN,
    MAX_BLE_OTA_SIZE_EN,
    OTA_END_COMMAND,
)
from mjwsd05ctl.errors import FirmwareError


def build_image(body_size: int = 2048, *, corrupt: bool = False) -> bytes:
    """A minimal but genuinely valid Telink OTA image."""
    # The header length must end in 4 after masking, per the format.
    hsize = (body_size & ~0x0F) + 4
    if hsize > body_size:
        hsize -= 16
    data = bytearray(b"\x00" * body_size)
    struct.pack_into("<I", data, firmware.TELINK_MAGIC_OFFSET, firmware.TELINK_MAGIC)
    struct.pack_into("<I", data, firmware.TELINK_HSIZE_OFFSET, hsize)
    checksum = firmware.telink_crc32(bytes(data[: hsize - 4]))
    if corrupt:
        checksum ^= 1
    struct.pack_into("<I", data, hsize - 4, checksum)
    return bytes(data)


def test_telink_crc32_is_zlib_without_the_final_complement() -> None:
    for sample in (b"", b"a", b"123456789", bytes(range(256))):
        assert firmware.telink_crc32(sample) == zlib.crc32(sample) ^ 0xFFFFFFFF


def test_telink_crc32_matches_the_published_jamcrc_check_value() -> None:
    # The test above restates the implementation formula, so it can't catch a
    # wrong formula that's merely internally consistent. Pin an independent,
    # published value instead: Telink's checksum (CRC-32 without the final
    # complement) is the standardized CRC-32/JAMCRC variant, whose check value
    # for the ASCII string "123456789" is 0x340BC6D9 (reveng.sourceforge.io's
    # "Catalogue of parametrised CRC algorithms").
    assert firmware.telink_crc32(b"123456789") == 0x340BC6D9


def test_telink_crc32_of_an_empty_message_is_all_ones() -> None:
    # A plain CRC-32's shift register starts at 0xFFFFFFFF and the final
    # complement step XORs that back to 0 for an empty message. Telink skips
    # that final step, so the initial all-ones value passes straight through.
    assert firmware.telink_crc32(b"") == 0xFFFFFFFF


def test_parse_accepts_a_valid_image() -> None:
    image = firmware.parse(build_image(), "test.bin")
    assert image.name == "test.bin"
    assert len(image.data) % 16 == 0
    assert image.block_count == len(image.data) // 16
    assert image.block(0) == b"\x00" * 8 + struct.pack("<I", firmware.TELINK_MAGIC) + (
        b"\x00" * 4
    )


def test_block_count_is_a_true_floor_for_data_not_aligned_to_a_block() -> None:
    # parse() always pads to a block boundary, so this can only be exercised
    # by building a FirmwareImage directly, as tests/test_cli.py and
    # tests/test_ota.py do. 15 bytes is one short of a full 16-byte block, so
    # the true count of *complete* blocks is 0, not 1.
    image = firmware.FirmwareImage(name="t", data=b"\x00" * 15)
    assert image.block_count == 0


def test_parse_pads_to_a_block_boundary_with_erased_flash() -> None:
    # 2052 bytes is four past a block boundary, so twelve bytes of padding.
    image = firmware.parse(build_image(2052), "test.bin")
    assert len(image.data) == 2064
    assert image.data[2052:] == b"\xff" * 12


def test_parse_rejects_a_bad_checksum() -> None:
    with pytest.raises(FirmwareError, match="CRC mismatch"):
        firmware.parse(build_image(corrupt=True), "test.bin")


def test_parse_rejects_a_tiny_file() -> None:
    with pytest.raises(FirmwareError, match="too small"):
        firmware.parse(b"\x00" * 16, "test.bin")


def test_parse_accepts_an_image_exactly_at_the_minimum_size() -> None:
    # TELINK_MIN_SIZE (1024 bytes) is documented as the smallest valid image,
    # so it must be accepted, not just "anything clearly bigger than it".
    image = firmware.parse(build_image(firmware.TELINK_MIN_SIZE), "test.bin")
    assert image.name == "test.bin"


def test_parse_rejects_a_file_that_is_not_telink() -> None:
    data = bytearray(build_image())
    struct.pack_into("<I", data, firmware.TELINK_MAGIC_OFFSET, 0xDEADBEEF)
    with pytest.raises(FirmwareError, match="not a Telink image"):
        firmware.parse(bytes(data), "test.bin")


def test_parse_explains_a_zigbee_image() -> None:
    data = bytearray(build_image())
    struct.pack_into("<I", data, 0, firmware.ZIGBEE_OTA_MAGIC)
    with pytest.raises(FirmwareError, match="Zigbee"):
        firmware.parse(bytes(data), "ZBTH01_v58.bin")


def test_parse_rejects_an_implausible_header_size() -> None:
    # A header claiming to be bigger than the whole file cannot be real,
    # regardless of what its CRC would say.
    data = bytearray(build_image())
    struct.pack_into("<I", data, firmware.TELINK_HSIZE_OFFSET, len(data) + 16)
    with pytest.raises(FirmwareError, match="implausible size"):
        firmware.parse(bytes(data), "test.bin")


def test_parse_rejects_a_header_size_with_the_wrong_alignment() -> None:
    # The low nibble of the header size must be 4 (HSIZE_ALIGNMENT_REMAINDER).
    # One byte off is in-bounds but misaligned, which is a distinct branch of
    # the implausible-size check from "bigger than the whole file".
    data = bytearray(build_image())
    hsize = struct.unpack_from("<I", data, firmware.TELINK_HSIZE_OFFSET)[0]
    struct.pack_into("<I", data, firmware.TELINK_HSIZE_OFFSET, hsize - 1)
    with pytest.raises(FirmwareError, match="implausible size"):
        firmware.parse(bytes(data), "test.bin")


def test_parse_rejects_an_image_larger_than_any_flash_slot() -> None:
    oversized = firmware.MAX_EXT_OTA_SIZE + 16
    with pytest.raises(FirmwareError, match="exceeds the largest slot"):
        firmware.parse(build_image(oversized), "test.bin")


def test_parse_accepts_an_image_exactly_at_the_largest_slot() -> None:
    # MAX_EXT_OTA_SIZE (0x34000) is the largest slot any device offers, so an
    # image exactly that size is the largest legitimate image and must be
    # accepted, not just "anything clearly smaller than it".
    image = firmware.parse(build_image(firmware.MAX_EXT_OTA_SIZE), "test.bin")
    assert image.name == "test.bin"


def test_load_reports_a_missing_file_with_a_helpful_message(tmp_path: Path) -> None:
    missing = tmp_path / "nope.bin"
    with pytest.raises(FirmwareError, match=f"cannot read {missing}"):
        firmware.load(missing)


def test_load_reports_an_unreadable_file_with_a_helpful_message(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unreadable.bin"
    path.write_bytes(build_image())
    path.chmod(0)
    with pytest.raises(FirmwareError, match=f"cannot read {path}"):
        firmware.load(path)


def test_search_dirs_puts_the_env_override_first(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(firmware.FIRMWARE_DIR_ENV, str(tmp_path))
    dirs = firmware.search_dirs()
    assert dirs[0] == tmp_path
    assert Path.cwd() in dirs
    assert Path.cwd() / "bin" in dirs
    assert Path.home() / ".local/share/mjwsd05ctl" in dirs


def test_search_dirs_omits_the_override_when_the_env_var_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(firmware.FIRMWARE_DIR_ENV, raising=False)
    dirs = firmware.search_dirs()
    assert dirs == [
        Path.cwd(),
        Path.cwd() / "bin",
        Path.home() / ".local/share/mjwsd05ctl",
    ]


def test_search_dirs_omits_the_override_when_it_is_set_to_the_empty_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A misconfigured shell/CI environment (variable exported but empty) is
    # treated the same as unset, not as an override of "" (which Path()
    # would resolve to the current directory).
    monkeypatch.setenv(firmware.FIRMWARE_DIR_ENV, "")
    dirs = firmware.search_dirs()
    assert dirs == [
        Path.cwd(),
        Path.cwd() / "bin",
        Path.home() / ".local/share/mjwsd05ctl",
    ]


@pytest.mark.parametrize("hardware_id", [HW_ID_CH, HW_ID_EN])
def test_resolve_finds_the_image_for_each_hardware_variant(
    hardware_id: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(firmware.FIRMWARE_DIR_ENV, str(tmp_path))
    (tmp_path / FIRMWARE_NAMES[hardware_id]).write_bytes(build_image())
    image = firmware.resolve(hardware_id)
    assert image.name == FIRMWARE_NAMES[hardware_id]


def test_resolve_loads_an_explicit_path_without_searching(tmp_path: Path) -> None:
    path = tmp_path / "custom.bin"
    path.write_bytes(build_image())
    # An unknown hardware id would fail if resolve() fell through to the
    # search, so this also proves the explicit path short-circuits it.
    image = firmware.resolve(99, path)
    assert image.name == "custom.bin"


def test_resolve_says_where_it_looked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(firmware.FIRMWARE_DIR_ENV, str(tmp_path))
    with pytest.raises(FirmwareError, match="could not find") as exc_info:
        firmware.resolve(HW_ID_EN)
    message = str(exc_info.value)
    assert str(tmp_path) in message
    assert firmware.RELEASES_URL in message
    assert firmware.FIRMWARE_DIR_ENV in message


def test_resolve_rejects_unknown_hardware() -> None:
    with pytest.raises(FirmwareError, match="no default firmware"):
        firmware.resolve(99)


@pytest.mark.skipif(
    firmware.FIRMWARE_DIR_ENV not in os.environ,
    reason=f"set {firmware.FIRMWARE_DIR_ENV} to check the released images",
)
@pytest.mark.parametrize("hardware_id", [HW_ID_CH, HW_ID_EN])
def test_released_images_validate(hardware_id: int) -> None:
    """Check the real pvvx releases, when they are available locally."""
    directory = Path(os.environ[firmware.FIRMWARE_DIR_ENV])
    path = directory / FIRMWARE_NAMES[hardware_id]
    if not path.is_file():
        pytest.skip(f"{path} is not present")
    image = firmware.load(path)
    assert image.block_count > 1000
    assert len(image.data) % 16 == 0
    # Both released images fit the ordinary slot with room to spare, which is
    # why flashing one has never needed the extended area.
    assert len(image.data) < MAX_BLE_OTA_SIZE_EN
    # The terminator names the last block, so it is the one frame whose
    # contents depend on the whole image rather than on 16 bytes of it.
    last = image.block_count - 1
    assert ota.end_frame(image.block_count) == OTA_END_COMMAND + struct.pack(
        "<HH", last, ~last & 0xFFFF
    )
    assert ota.frame(0, image.block(0))[2:18] == image.data[:16]
