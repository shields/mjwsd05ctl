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

"""Tests for advertisement decoding.

The encrypted cases build their ciphertext the way the firmware does, written
out here from the C rather than by calling the decoder's own helpers, so that
the nonce layout and the presence or absence of associated data are actually
being checked.
"""

import json
import struct
from collections.abc import Callable
from typing import ClassVar, Self

import pytest
from bleak import AdvertisementData, BLEDevice, BlueZScannerArgs
from bleak.args.bluez import OrPattern
from bleak.assigned_numbers import AdvertisementDataType
from Crypto.Cipher import AES

from mjwsd05ctl import reader
from mjwsd05ctl.constants import ATC_SERVICE, BTHOME_SERVICE, MI_BEACON_SERVICE

ADDRESS = "A4:C1:38:11:22:33"
MAC_DISPLAY = bytes.fromhex("A4C138112233")
MAC_LE = MAC_DISPLAY[::-1]
BINDKEY = bytes(range(16))


def advertisement(
    uuid: str, payload: bytes, *, name: str = "ATC_112233", address: str = ADDRESS
) -> tuple[BLEDevice, AdvertisementData]:
    device = BLEDevice(address, name, None)
    data = AdvertisementData(
        local_name=name,
        manufacturer_data={},
        service_data={uuid: payload},
        service_uuids=[uuid],
        tx_power=None,
        rssi=-55,
        platform_data=(),
    )
    return device, data


def decode(uuid: str, payload: bytes, *, key: bytes | None = None) -> reader.Reading:
    device, data = advertisement(uuid, payload)
    keys = {ADDRESS: key} if key else {}
    result = reader.decode(device, data, keys)
    assert result is not None
    return result


def test_pvvx_plaintext() -> None:
    payload = struct.pack("<6shHHBBB", MAC_LE, 2137, 4512, 2980, 87, 42, 0x04)
    assert len(payload) == reader.PVVX_LEN
    got = decode(ATC_SERVICE, payload)
    assert got.format == "pvvx"
    assert got.values["temperature"] == 21.37
    assert got.values["humidity"] == 45.12
    assert got.values["battery_mv"] == 2980
    assert got.values["battery"] == 87
    assert got.values["counter"] == 42
    assert got.values["mac"] == ADDRESS
    assert got.rssi == -55
    assert got.name == "ATC_112233"
    assert not got.encrypted


def test_atc1441_plaintext_is_big_endian() -> None:
    payload = struct.pack(">6shBBHB", MAC_DISPLAY, 213, 45, 87, 2980, 42)
    assert len(payload) == reader.ATC1441_LEN
    got = decode(ATC_SERVICE, payload)
    assert got.format == "atc1441"
    assert got.values["temperature"] == 21.3
    assert got.values["humidity"] == 45
    assert got.values["battery_mv"] == 2980
    assert got.values["mac"] == ADDRESS


def test_negative_temperatures_survive_the_round_trip() -> None:
    payload = struct.pack("<6shHHBBB", MAC_LE, -1250, 8000, 2500, 40, 1, 0)
    got = decode(ATC_SERVICE, payload)
    assert got.values["temperature"] == -12.5


def test_bthome_plaintext_objects() -> None:
    payload = (
        bytes([0x40, 0x00, 7, 0x01, 91])
        + bytes([0x02])
        + struct.pack("<h", 2137)
        + bytes([0x03])
        + struct.pack("<H", 4512)
        + bytes([0x0C])
        + struct.pack("<H", 2980)
    )
    got = decode(BTHOME_SERVICE, payload)
    assert got.format == "bthome"
    assert got.values["packet_id"] == 7
    assert got.values["battery"] == 91
    assert got.values["temperature"] == 21.37
    assert got.values["humidity"] == 45.12
    assert got.values["voltage"] == 2.98


def test_bthome_repeated_objects_are_numbered_not_overwritten() -> None:
    payload = bytes([0x40])
    payload += bytes([0x02]) + struct.pack("<h", 100)
    payload += bytes([0x02]) + struct.pack("<h", 200)
    values = reader.decode_bthome(payload[1:])
    assert values["temperature"] == 1.0
    assert values["temperature_2"] == 2.0


def test_bthome_stops_at_an_object_it_does_not_know() -> None:
    payload = bytes([0x01, 50, 0x7F, 1, 2, 3])
    values = reader.decode_bthome(payload)
    assert values == {"battery": 50}


def test_bthome_variable_length_objects() -> None:
    payload = bytes([0x53, 5]) + b"hello" + bytes([0x01, 50])
    values = reader.decode_bthome(payload)
    assert values["text"] == "hello"
    assert values["battery"] == 50


def encrypt_bthome(plaintext: bytes, counter: int) -> bytes:
    """Build an encrypted BTHome payload as `bthome_encrypt` in the firmware does.

    Note there is no associated data, though the published BTHome format calls
    for `0x11`; the firmware passes NULL.
    """
    info = b"\x41"
    counter_bytes = struct.pack("<I", counter)
    nonce = MAC_DISPLAY + b"\xd2\xfc" + info + counter_bytes
    cipher = AES.new(BINDKEY, AES.MODE_CCM, nonce=nonce, mac_len=4)
    ciphertext, mic = cipher.encrypt_and_digest(plaintext)
    return info + ciphertext + counter_bytes + mic


def test_bthome_encrypted() -> None:
    plaintext = bytes([0x01, 91]) + bytes([0x02]) + struct.pack("<h", 2137)
    got = decode(BTHOME_SERVICE, encrypt_bthome(plaintext, 1234), key=BINDKEY)
    assert got.encrypted
    assert got.error is None
    assert got.values["battery"] == 91
    assert got.values["temperature"] == 21.37
    assert got.values["counter"] == 1234


def test_bthome_encrypted_without_a_key_says_so() -> None:
    got = decode(BTHOME_SERVICE, encrypt_bthome(bytes([0x01, 91]), 1))
    assert got.encrypted
    assert got.error == "no bind key known"
    assert got.values == {}


def test_bthome_encrypted_with_the_wrong_key_reports_the_failure() -> None:
    payload = encrypt_bthome(bytes([0x01, 91]), 1)
    got = decode(BTHOME_SERVICE, payload, key=bytes(16))
    assert got.error is not None
    assert "decryption" in got.error


def encrypt_atc_family(plaintext: bytes, counter: int) -> bytes:
    """Build a pvvx or ATC encrypted payload as `custom_beacon.c` does.

    The nonce covers the advertisement header, and the associated data is a
    single 0x11 byte, both unlike BTHome.
    """
    total = len(plaintext) + 4 + 1  # data, MIC, counter
    header = bytes([total + 4 - 1, 0x16, 0x1A, 0x18])
    nonce = MAC_LE + header + bytes([counter])
    cipher = AES.new(BINDKEY, AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(b"\x11")
    ciphertext, mic = cipher.encrypt_and_digest(plaintext)
    return bytes([counter]) + ciphertext + mic


def test_pvvx_encrypted() -> None:
    plaintext = struct.pack("<hHBB", 2137, 4512, 87, 0)
    payload = encrypt_atc_family(plaintext, 42)
    assert len(payload) == reader.PVVX_ENCRYPTED_LEN
    got = decode(ATC_SERVICE, payload, key=BINDKEY)
    assert got.format == "pvvx"
    assert got.encrypted
    assert got.error is None
    assert got.values["temperature"] == 21.37
    assert got.values["humidity"] == 45.12
    assert got.values["battery"] == 87
    assert got.values["counter"] == 42


def test_atc1441_encrypted_uses_half_degree_steps() -> None:
    # The firmware stores (centi °C + 25) / 50 + 80, so 21.5 °C is 123.
    plaintext = bytes([123, 90, 87 | 0x80])
    payload = encrypt_atc_family(plaintext, 7)
    assert len(payload) == reader.ATC1441_ENCRYPTED_LEN
    got = decode(ATC_SERVICE, payload, key=BINDKEY)
    assert got.format == "atc1441"
    assert got.values["temperature"] == 21.5
    assert got.values["humidity"] == 45.0
    assert got.values["battery"] == 87
    assert got.values["trigger"] is True


def test_atc1441_encrypted_trigger_bit_is_0x80() -> None:
    # custom_beacon.c ORs the trigger flag into the battery byte as 0x80
    # (`data.bat = measured_data.battery_level | (trg.flg.trigger_on ? 0x80 : 0)`),
    # not 0x40. 87 has bit 0x40 set on its own, so it must NOT be reported as
    # triggered; a battery with only 0x80 set must be.
    not_triggered = bytes([123, 90, 87])
    payload = encrypt_atc_family(not_triggered, 7)
    got = decode(ATC_SERVICE, payload, key=BINDKEY)
    assert got.values["battery"] == 87
    assert got.values["trigger"] is False

    triggered = bytes([123, 90, 0x80 | 5])
    payload = encrypt_atc_family(triggered, 7)
    got = decode(ATC_SERVICE, payload, key=BINDKEY)
    assert got.values["battery"] == 5
    assert got.values["trigger"] is True


def test_mi_beacon_plaintext_objects() -> None:
    control = (1 << 4) | (1 << 6)  # MAC included, objects included
    payload = struct.pack("<HHB", control, 0x055B, 9) + MAC_LE
    payload += struct.pack("<HB", 0x1004, 2) + struct.pack("<h", 213)
    payload += struct.pack("<HB", 0x100A, 1) + bytes([88])
    got = decode(MI_BEACON_SERVICE, payload)
    assert got.format == "mi"
    assert got.values["product_id"] == 0x055B
    assert got.values["mac"] == ADDRESS
    assert got.values["temperature"] == 21.3
    assert got.values["battery"] == 88


def test_mi_beacon_encrypted() -> None:
    control = (1 << 3) | (1 << 4) | (1 << 6)
    product_id = 0x055B
    frame = 9
    extended = bytes([1, 2, 3])
    plaintext = struct.pack("<HB", 0x1004, 2) + struct.pack("<h", 213)
    nonce = MAC_LE + struct.pack("<H", product_id) + bytes([frame]) + extended
    cipher = AES.new(BINDKEY, AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(b"\x11")
    ciphertext, mic = cipher.encrypt_and_digest(plaintext)
    payload = (
        struct.pack("<HHB", control, product_id, frame)
        + MAC_LE
        + ciphertext
        + extended
        + mic
    )
    got = decode(MI_BEACON_SERVICE, payload, key=BINDKEY)
    assert got.encrypted
    assert got.error is None
    assert got.values["temperature"] == 21.3


def test_bindkey_lookup_is_case_insensitive_to_the_device_address() -> None:
    # Bindkeys are always keyed by canonical uppercase address, but not every
    # backend reports the address that way.
    payload = encrypt_bthome(bytes([0x01, 91]), 1)
    device, data = advertisement(BTHOME_SERVICE, payload, address=ADDRESS.lower())
    got = reader.decode(device, data, {ADDRESS: BINDKEY})
    assert got is not None
    assert got.error is None
    assert got.values["battery"] == 91


def test_encryption_needs_a_real_address() -> None:
    # macOS hands out a per-host UUID instead of the hardware address.
    device = BLEDevice("6B29FC40-CA47-1067-B31D-00DD010662DA", "ATC_1", None)
    _, data = advertisement(BTHOME_SERVICE, encrypt_bthome(bytes([0x01, 91]), 1))
    got = reader.decode(device, data, {device.address: BINDKEY})
    assert got is not None
    assert got.error == "device address is not visible"


def test_encrypted_atc_family_accepts_a_dash_separated_mac() -> None:
    # 12 hex digits separated by dashes rather than colons, as some
    # platforms/tools report a hardware MAC; not to be confused with the
    # 36-character CoreBluetooth UUID, which also contains dashes.
    dashed_address = "A4-C1-38-11-22-33"
    plaintext = struct.pack("<hHBB", 2137, 4512, 87, 0)
    payload = encrypt_atc_family(plaintext, 42)
    device, data = advertisement(ATC_SERVICE, payload, address=dashed_address)
    got = reader.decode(device, data, {dashed_address: BINDKEY})
    assert got is not None
    assert got.error is None
    assert got.values["temperature"] == 21.37


def test_unrelated_advertisements_are_ignored() -> None:
    device = BLEDevice(ADDRESS, "Something else", None)
    data = AdvertisementData(
        local_name="Something else",
        manufacturer_data={},
        service_data={"0000180f-0000-1000-8000-00805f9b34fb": b"\x55"},
        service_uuids=[],
        tx_power=None,
        rssi=-70,
        platform_data=(),
    )
    assert reader.decode(device, data) is None


@pytest.mark.parametrize("length", [0, 1, 5, 9, 12, 20])
def test_odd_lengths_never_raise(length: int) -> None:
    payload = bytes(range(length))
    device, data = advertisement(ATC_SERVICE, payload)
    reader.decode(device, data, {ADDRESS: BINDKEY})


def test_readings_serialise_to_flat_json() -> None:
    payload = struct.pack("<6shHHBBB", MAC_LE, 2137, 4512, 2980, 87, 42, 0)
    got = decode(ATC_SERVICE, payload)
    parsed = json.loads(got.as_json())
    assert parsed["address"] == ADDRESS
    assert parsed["format"] == "pvvx"
    assert parsed["temperature"] == 21.37
    assert parsed["encrypted"] is False


def test_mibeacon_signal_object_does_not_clobber_the_advertisement_rssi() -> None:
    # MiBeacon object 0x1003 is the sensor's own notion of signal strength, and
    # must not be merged over the real RSSI bleak reports.
    control = 1 << 6
    payload = struct.pack("<HHB", control, 0x055B, 9)
    payload += struct.pack("<HB", 0x1003, 1) + bytes([166])
    got = decode(MI_BEACON_SERVICE, payload)
    assert got.rssi == -55
    assert got.as_dict()["rssi"] == -55
    assert got.values["mibeacon_rssi"] == 166


def test_a_present_but_empty_service_entry_is_not_mistaken_for_absent() -> None:
    device = BLEDevice(ADDRESS, "ATC_1", None)
    data = AdvertisementData(
        local_name="ATC_1",
        manufacturer_data={},
        service_data={BTHOME_SERVICE: b"", ATC_SERVICE: b"\x00" * reader.PVVX_LEN},
        service_uuids=[],
        tx_power=None,
        rssi=-60,
        platform_data=(),
    )
    # The empty BTHome entry decodes to nothing rather than falling through to
    # the ATC decoder and reporting the wrong format.
    assert reader.decode(device, data) is None


def test_truncated_bthome_text_stops_cleanly() -> None:
    # Declares five bytes of text but supplies two.
    assert reader.decode_bthome(bytes([0x53, 5]) + b"ab") == {}


def test_bthome_text_object_with_no_length_byte_stops_cleanly() -> None:
    # The object id is the last byte in the payload, so there is nowhere to
    # read a length from.
    assert reader.decode_bthome(bytes([0x53])) == {}


def test_bthome_stops_when_a_fixed_size_object_is_truncated() -> None:
    # Temperature (0x02) is two bytes wide; only one is supplied.
    assert reader.decode_bthome(bytes([0x02, 0x05])) == {}


def test_bthome_numbers_three_repeats_in_order() -> None:
    payload = bytes([0x02]) + struct.pack("<h", 100)
    payload += bytes([0x02]) + struct.pack("<h", 200)
    payload += bytes([0x02]) + struct.pack("<h", 300)
    values = reader.decode_bthome(payload)
    assert values["temperature"] == 1.0
    assert values["temperature_2"] == 2.0
    assert values["temperature_3"] == 3.0


def test_bthome_encrypted_payload_too_short_to_contain_a_mic() -> None:
    # Encrypted flag set, but far fewer bytes than the counter+MIC overhead.
    got = decode(BTHOME_SERVICE, bytes([0x01, 0, 0, 0]), key=BINDKEY)
    assert got.error == "truncated"


def test_bthome_encrypted_payload_at_exactly_the_minimum_length_decrypts() -> None:
    # 1 info byte + 4-byte counter + 4-byte MIC, with no encrypted object
    # bytes at all, is the shortest legitimate encrypted payload -- it must
    # not be mistaken for a truncated one.
    payload = encrypt_bthome(b"", 1)
    assert len(payload) == 1 + reader.BTHOME_ENCRYPTED_OVERHEAD
    got = decode(BTHOME_SERVICE, payload, key=BINDKEY)
    assert got.error is None
    assert got.values == {"counter": 1}


def test_as_dict_includes_only_the_fields_that_are_set() -> None:
    minimal = reader.Reading(ADDRESS, "pvvx", {"temperature": 21.0})
    assert minimal.as_dict() == {
        "address": ADDRESS,
        "format": "pvvx",
        "encrypted": False,
        "temperature": 21.0,
    }

    full = reader.Reading(
        ADDRESS,
        "pvvx",
        {},
        name="ATC_1",
        rssi=-42,
        encrypted=True,
        error="no bind key known",
    )
    assert full.as_dict() == {
        "address": ADDRESS,
        "format": "pvvx",
        "encrypted": True,
        "name": "ATC_1",
        "rssi": -42,
        "error": "no bind key known",
    }

    # rssi=0 is a real (if rare) reading, not the absence of one, and must
    # still appear in the dict.
    zero_rssi = reader.Reading(ADDRESS, "pvvx", {}, rssi=0)
    assert "rssi" in zero_rssi.as_dict()
    assert zero_rssi.as_dict()["rssi"] == 0


def test_encryption_reports_an_address_that_is_not_valid_hex() -> None:
    # Twelve characters after stripping separators, but "ZZ" is not hex.
    device = BLEDevice("AA:BB:CC:DD:EE:ZZ", "ATC_1", None)
    _, data = advertisement(BTHOME_SERVICE, encrypt_bthome(bytes([0x01, 91]), 1))
    got = reader.decode(device, data, {device.address: BINDKEY})
    assert got is not None
    assert got.error == "device address is not visible"


def test_pvvx_encrypted_without_a_key_says_so() -> None:
    plaintext = struct.pack("<hHBB", 2137, 4512, 87, 0)
    payload = encrypt_atc_family(plaintext, 42)
    got = decode(ATC_SERVICE, payload)
    assert got.format == "pvvx"
    assert got.encrypted
    assert got.error == "no bind key known"


def test_atc_encryption_needs_a_real_address() -> None:
    # macOS hands out a per-host UUID instead of the hardware address.
    device = BLEDevice("6B29FC40-CA47-1067-B31D-00DD010662DA", "ATC_1", None)
    plaintext = struct.pack("<hHBB", 2137, 4512, 87, 0)
    _, data = advertisement(ATC_SERVICE, encrypt_atc_family(plaintext, 42))
    got = reader.decode(device, data, {device.address: BINDKEY})
    assert got is not None
    assert got.error == "device address is not visible"


def test_pvvx_encrypted_with_the_wrong_key_reports_the_failure() -> None:
    plaintext = struct.pack("<hHBB", 2137, 4512, 87, 0)
    payload = encrypt_atc_family(plaintext, 42)
    got = decode(ATC_SERVICE, payload, key=bytes(16))
    assert got.error is not None
    assert "decryption" in got.error


def test_mi_beacon_stops_when_an_object_is_truncated() -> None:
    control = 1 << 6  # objects included
    payload = struct.pack("<HHB", control, 0x055B, 9)
    # Declares 5 bytes of value but supplies 2; the whole object is dropped.
    payload += struct.pack("<HB", 0x1004, 5) + bytes([1, 2])
    got = decode(MI_BEACON_SERVICE, payload)
    assert got.values == {"product_id": 0x055B, "counter": 9}


def test_mi_beacon_unknown_object_is_kept_as_hex_and_does_not_stop_decoding() -> None:
    control = 1 << 6
    payload = struct.pack("<HHB", control, 0x055B, 9)
    payload += struct.pack("<HB", 0x9999, 2) + bytes([0xAB, 0xCD])  # unrecognised id
    payload += struct.pack("<HB", 0x100A, 1) + bytes([50])  # battery, recognised
    got = decode(MI_BEACON_SERVICE, payload)
    assert got.values["object_9999"] == "abcd"
    assert got.values["battery"] == 50


def test_mi_beacon_humidity_object() -> None:
    control = 1 << 6
    payload = struct.pack("<HHB", control, 0x055B, 9)
    payload += struct.pack("<HB", 0x1006, 2) + struct.pack("<H", 512)
    got = decode(MI_BEACON_SERVICE, payload)
    assert got.values["humidity"] == 51.2


def test_mi_beacon_combined_temperature_humidity_object() -> None:
    control = 1 << 6
    payload = struct.pack("<HHB", control, 0x055B, 9)
    payload += struct.pack("<HB", 0x100D, 4) + struct.pack("<hH", 213, 512)
    got = decode(MI_BEACON_SERVICE, payload)
    assert got.values["temperature"] == 21.3
    assert got.values["humidity"] == 51.2


def test_mi_beacon_formaldehyde_object() -> None:
    control = 1 << 6
    payload = struct.pack("<HHB", control, 0x055B, 9)
    payload += struct.pack("<HB", 0x1010, 2) + struct.pack("<H", 1234)
    got = decode(MI_BEACON_SERVICE, payload)
    assert got.values["formaldehyde"] == 12.34


def test_mi_beacon_payload_too_short_is_ignored() -> None:
    device, data = advertisement(MI_BEACON_SERVICE, bytes(3))
    assert reader.decode(device, data) is None


def test_mi_beacon_capability_byte_is_skipped() -> None:
    # If the capability byte were not skipped, the parser would try to read
    # the battery object's header starting one byte too early.
    control = (1 << 5) | (1 << 6)  # capability byte present, objects present
    payload = struct.pack("<HHB", control, 0x055B, 9)
    payload += bytes([0x00])  # capability byte
    payload += struct.pack("<HB", 0x100A, 1) + bytes([50])  # battery
    got = decode(MI_BEACON_SERVICE, payload)
    assert got.values["battery"] == 50


def test_mi_beacon_without_object_flag_reports_only_the_header_fields() -> None:
    control = 0  # no MAC, no capability, no objects
    payload = struct.pack("<HHB", control, 0x055B, 9)
    got = decode(MI_BEACON_SERVICE, payload)
    assert got.format == "mi"
    assert got.values == {"product_id": 0x055B, "counter": 9}
    assert not got.encrypted


def test_mi_beacon_encrypted_without_a_key_says_so() -> None:
    control = (1 << 3) | (1 << 6)  # encrypted + objects, no MAC/capability
    payload = struct.pack("<HHB", control, 0x055B, 9)
    got = decode(MI_BEACON_SERVICE, payload)
    assert got.encrypted
    assert got.error == "no bind key known"
    assert got.values == {"product_id": 0x055B, "counter": 9}


def test_mi_beacon_encrypted_needs_a_real_address() -> None:
    control = (1 << 3) | (1 << 6)
    device = BLEDevice("6B29FC40-CA47-1067-B31D-00DD010662DA", "ATC_1", None)
    _, data = advertisement(MI_BEACON_SERVICE, struct.pack("<HHB", control, 0x055B, 9))
    got = reader.decode(device, data, {device.address: BINDKEY})
    assert got is not None
    assert got.error == "device address is not visible"


def test_mi_beacon_encrypted_payload_too_short_to_contain_a_mic() -> None:
    control = (1 << 3) | (1 << 6)
    # Only 6 bytes follow the header; the counter+MIC overhead alone is 7.
    payload = struct.pack("<HHB", control, 0x055B, 9) + bytes(6)
    got = decode(MI_BEACON_SERVICE, payload, key=BINDKEY)
    assert got.error == "truncated"


def test_mi_beacon_encrypted_with_the_wrong_key_reports_the_failure() -> None:
    control = (1 << 3) | (1 << 4) | (1 << 6)
    product_id = 0x055B
    frame = 9
    extended = bytes([1, 2, 3])
    plaintext = struct.pack("<HB", 0x1004, 2) + struct.pack("<h", 213)
    nonce = MAC_LE + struct.pack("<H", product_id) + bytes([frame]) + extended
    cipher = AES.new(BINDKEY, AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(b"\x11")
    ciphertext, mic = cipher.encrypt_and_digest(plaintext)
    payload = (
        struct.pack("<HHB", control, product_id, frame)
        + MAC_LE
        + ciphertext
        + extended
        + mic
    )
    got = decode(MI_BEACON_SERVICE, payload, key=bytes(16))
    assert got.error is not None
    assert "decryption" in got.error


def test_or_patterns_selects_the_three_service_data_uuids_we_decode() -> None:
    assert reader._or_patterns() == [
        OrPattern(0, AdvertisementDataType.SERVICE_DATA_UUID16, reader.BTHOME_UUID_LE),
        OrPattern(0, AdvertisementDataType.SERVICE_DATA_UUID16, reader.ATC_UUID_LE),
        OrPattern(
            0, AdvertisementDataType.SERVICE_DATA_UUID16, reader.MI_BEACON_UUID_LE
        ),
    ]


class FakeBleakScanner:
    """Stands in for `BleakScanner`.

    `feed` supplies the advertisements that `__aenter__` hands to the
    detection callback, the way discovering nearby devices would; `created`
    records every instance so a test can inspect how `Watcher` configured it.
    """

    feed: ClassVar[list[tuple[BLEDevice, AdvertisementData]]] = []
    created: ClassVar[list[FakeBleakScanner]] = []

    def __init__(
        self,
        *,
        detection_callback: Callable[[BLEDevice, AdvertisementData], None],
        scanning_mode: str,
        bluez: BlueZScannerArgs,
    ) -> None:
        self.detection_callback = detection_callback
        self.scanning_mode = scanning_mode
        self.bluez = bluez
        self.exited = False
        FakeBleakScanner.created.append(self)

    async def __aenter__(self) -> Self:
        for device, adv in FakeBleakScanner.feed:
            self.detection_callback(device, adv)
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        self.exited = True


@pytest.fixture
def fake_scanner(monkeypatch: pytest.MonkeyPatch) -> type[FakeBleakScanner]:
    FakeBleakScanner.feed = []
    FakeBleakScanner.created = []
    monkeypatch.setattr(reader, "BleakScanner", FakeBleakScanner)
    return FakeBleakScanner


WATCHER_ADDRESS_A = "A4:C1:38:00:00:01"
WATCHER_ADDRESS_B = "A4:C1:38:00:00:02"


def _pvvx_payload(counter: int = 42) -> bytes:
    return struct.pack("<6shHHBBB", MAC_LE, 2137, 4512, 2980, 87, counter, 0)


async def test_watcher_run_only_reports_addresses_on_the_allowlist(
    fake_scanner: type[FakeBleakScanner],
) -> None:
    payload = _pvvx_payload()
    fake_scanner.feed = [
        advertisement(ATC_SERVICE, payload, name="A", address=WATCHER_ADDRESS_A),
        advertisement(ATC_SERVICE, payload, name="B", address=WATCHER_ADDRESS_B),
    ]
    seen: list[reader.Reading] = []
    watcher = reader.Watcher(addresses=frozenset({WATCHER_ADDRESS_A}))
    await watcher.run(seen.append, duration=0)

    assert [r.address for r in seen] == [WATCHER_ADDRESS_A]
    scanner = fake_scanner.created[0]
    assert scanner.scanning_mode == "active"
    assert "or_patterns" not in scanner.bluez
    assert "adapter" not in scanner.bluez
    # A finite duration is what let `run` return at all.
    assert scanner.exited


async def test_watcher_run_reports_every_address_when_the_allowlist_is_empty(
    fake_scanner: type[FakeBleakScanner],
) -> None:
    unrelated = advertisement(
        "0000180f-0000-1000-8000-00805f9b34fb", b"\x55", address=WATCHER_ADDRESS_B
    )
    fake_scanner.feed = [
        advertisement(ATC_SERVICE, _pvvx_payload(), address=WATCHER_ADDRESS_A),
        unrelated,
    ]
    seen: list[reader.Reading] = []
    watcher = reader.Watcher()
    await watcher.run(seen.append, duration=0)

    # The unrelated advertisement decodes to nothing, so it never reaches the
    # callback even though nothing is filtering it out by address.
    assert [r.address for r in seen] == [WATCHER_ADDRESS_A]


async def test_watcher_run_uses_or_patterns_only_in_passive_mode(
    fake_scanner: type[FakeBleakScanner], monkeypatch: pytest.MonkeyPatch
) -> None:
    waits: list[None] = []

    class ImmediateEvent:
        async def wait(self) -> None:
            waits.append(None)

    # A `duration=None` watch waits on an `asyncio.Event` that nothing ever
    # sets, so it really would run forever; stand in for it instead of
    # sleeping for real.
    monkeypatch.setattr(reader.asyncio, "Event", ImmediateEvent)

    seen: list[reader.Reading] = []
    watcher = reader.Watcher(passive=True, adapter="hci1")
    await watcher.run(seen.append, duration=None)

    assert waits == [None]
    scanner = fake_scanner.created[0]
    assert scanner.scanning_mode == "passive"
    assert scanner.bluez["adapter"] == "hci1"
    assert scanner.bluez["or_patterns"] == reader._or_patterns()


async def test_watcher_run_drops_rebroadcasts_of_the_same_measurement(
    fake_scanner: type[FakeBleakScanner],
) -> None:
    # The firmware sends each measurement in several advertising events; the
    # counter is what tells a new measurement from a rebroadcast.
    fake_scanner.feed = [
        advertisement(ATC_SERVICE, _pvvx_payload(counter=42)),
        advertisement(ATC_SERVICE, _pvvx_payload(counter=42)),
        advertisement(ATC_SERVICE, _pvvx_payload(counter=43)),
    ]
    seen: list[reader.Reading] = []
    await reader.Watcher().run(seen.append, duration=0)

    assert [r.values["counter"] for r in seen] == [42, 43]


async def test_watcher_run_reports_rebroadcasts_when_deduplication_is_off(
    fake_scanner: type[FakeBleakScanner],
) -> None:
    fake_scanner.feed = [
        advertisement(ATC_SERVICE, _pvvx_payload()),
        advertisement(ATC_SERVICE, _pvvx_payload()),
    ]
    seen: list[reader.Reading] = []
    await reader.Watcher(deduplicate=False).run(seen.append, duration=0)

    assert [r.values["counter"] for r in seen] == [42, 42]


async def test_watcher_run_deduplicates_each_device_separately(
    fake_scanner: type[FakeBleakScanner],
) -> None:
    # A rebroadcast is still a rebroadcast when another device's reading
    # arrived in between; comparing against the last reading from anywhere
    # would let the third advertisement through.
    payload = _pvvx_payload()
    fake_scanner.feed = [
        advertisement(ATC_SERVICE, payload, address=WATCHER_ADDRESS_A),
        advertisement(ATC_SERVICE, payload, address=WATCHER_ADDRESS_B),
        advertisement(ATC_SERVICE, payload, address=WATCHER_ADDRESS_A),
    ]
    seen: list[reader.Reading] = []
    await reader.Watcher().run(seen.append, duration=0)

    assert [r.address for r in seen] == [WATCHER_ADDRESS_A, WATCHER_ADDRESS_B]


async def test_watcher_run_treats_a_format_change_as_a_new_reading(
    fake_scanner: type[FakeBleakScanner], monkeypatch: pytest.MonkeyPatch
) -> None:
    # No two real decoders produce the same values dict, so the format half
    # of the deduplication key is exercised with a fake decode: the same
    # values arriving under a new format are not a rebroadcast.
    readings = iter(
        [
            reader.Reading(ADDRESS, "pvvx", {"temperature": 21.5}),
            reader.Reading(ADDRESS, "atc1441", {"temperature": 21.5}),
        ]
    )
    monkeypatch.setattr(reader, "decode", lambda *_args: next(readings))
    fake_scanner.feed = [advertisement(ATC_SERVICE, _pvvx_payload())] * 2
    seen: list[reader.Reading] = []
    await reader.Watcher().run(seen.append, duration=0)

    assert [r.format for r in seen] == ["pvvx", "atc1441"]


async def test_watcher_run_deduplication_survives_a_callback_that_mutates(
    fake_scanner: type[FakeBleakScanner],
) -> None:
    # The callback is handed the reading's own values dict; deduplication
    # compares a snapshot, so mutating it must not let the rebroadcast in.
    fake_scanner.feed = [
        advertisement(ATC_SERVICE, _pvvx_payload()),
        advertisement(ATC_SERVICE, _pvvx_payload()),
    ]
    seen: list[reader.Reading] = []

    def enrich(reading: reader.Reading) -> None:
        seen.append(reading)
        reading.values["fahrenheit"] = 70.7

    await reader.Watcher().run(enrich, duration=0)

    assert len(seen) == 1


async def test_watcher_run_keeps_repeating_undecodable_readings(
    fake_scanner: type[FakeBleakScanner],
) -> None:
    # An encrypted beacon with no key known is reported every time it is
    # heard: the failure is still true, and there is no plaintext counter to
    # tell a rebroadcast from a new measurement anyway.
    payload = bytes([reader.BTHOME_ENCRYPTED_FLAG]) + bytes(12)
    fake_scanner.feed = [
        advertisement(BTHOME_SERVICE, payload),
        advertisement(BTHOME_SERVICE, payload),
    ]
    seen: list[reader.Reading] = []
    await reader.Watcher().run(seen.append, duration=0)

    assert [r.error for r in seen] == ["no bind key known", "no bind key known"]
