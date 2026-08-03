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

"""Decoding sensor advertisements.

Nothing here connects to a device: readings come from broadcasts, so any number
of sensors can be watched at once and none of them is disturbed. Four formats
are decoded, matching the four settings of `advertising_type`.

Encrypted beacons need the device's bind key and its Bluetooth address. The two
encrypted families disagree on the details, and the firmware is the authority
rather than any published specification: BTHome here uses *no* associated data,
where the BTHome specification calls for `0x11`, and the pvvx and ATC formats
use a reversed address in the nonce where BTHome uses display order.
"""

import asyncio
import json
import logging
import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from bleak import AdvertisementData, BleakScanner, BLEDevice, BlueZScannerArgs
from bleak.args.bluez import OrPattern
from bleak.assigned_numbers import AdvertisementDataType
from Crypto.Cipher import AES

from .constants import ATC_SERVICE, BTHOME_SERVICE, MI_BEACON_SERVICE

log = logging.getLogger(__name__)

type Value = float | int | str | bool
type ReadingCallback = Callable[["Reading"], None]

MIC_LEN = 4
BTHOME_COUNTER_LEN = 4
BTHOME_ENCRYPTED_OVERHEAD = BTHOME_COUNTER_LEN + MIC_LEN
BTHOME_ENCRYPTED_FLAG = 0x01
BTHOME_UUID_LE = b"\xd2\xfc"

# Lengths of the 0x181A service data payload, which is what tells the four
# pvvx and ATC variants apart.
PVVX_LEN = 15
ATC1441_LEN = 13
PVVX_ENCRYPTED_LEN = 11
ATC1441_ENCRYPTED_LEN = 8

# Reconstructed advertisement header, which the encrypted pvvx and ATC nonces
# cover but Bleak strips before handing us the service data.
AD_TYPE_SERVICE_DATA_16 = 0x16
ATC_UUID_LE = b"\x1a\x18"
MI_BEACON_UUID_LE = b"\x95\xfe"
ENCRYPTED_AAD = b"\x11"

MI_MIN_LEN = 5
MI_EXT_COUNTER_LEN = 3
MI_OBJECT_HEADER_LEN = 3
MI_TEMP_HUMIDITY_LEN = 4

ADDRESS_HEX_LEN = 12


@dataclass(frozen=True, slots=True)
class Reading:
    """One decoded advertisement."""

    address: str
    format: str
    values: dict[str, Value]
    name: str | None = None
    rssi: int | None = None
    encrypted: bool = False
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "address": self.address,
            "format": self.format,
            "encrypted": self.encrypted,
        }
        if self.name:
            payload["name"] = self.name
        if self.rssi is not None:
            payload["rssi"] = self.rssi
        if self.error:
            payload["error"] = self.error
        payload |= self.values
        return payload

    def as_json(self) -> str:
        return json.dumps(self.as_dict(), sort_keys=True)


def _address_bytes(address: str) -> bytes | None:
    """The address as six bytes in display order, if we have a real one.

    CoreBluetooth gives out a per-host UUID rather than the hardware address,
    which is enough to talk to a device but not to decrypt its broadcasts.
    """
    cleaned = address.replace(":", "").replace("-", "")
    if len(cleaned) != ADDRESS_HEX_LEN:
        return None
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        return None


def _undecodable(
    address: str, fmt: str, error: str, values: dict[str, Value] | None = None
) -> Reading:
    """An advertisement we recognise but cannot read, with the reason why."""
    return Reading(address, fmt, values or {}, encrypted=True, error=error)


def _decrypt(
    key: bytes, nonce: bytes, data: bytes, mic: bytes, aad: bytes | None
) -> bytes:
    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=MIC_LEN)
    if aad is not None:
        cipher.update(aad)
    return cipher.decrypt_and_verify(data, mic)


# BTHome object identifiers: name, byte width, signedness, and scale.
# https://bthome.io/format/ ; the firmware's own list is in src/bthome_beacon.h.
_BTHOME_OBJECTS: dict[int, tuple[str, int, bool, float]] = {
    0x00: ("packet_id", 1, False, 1),
    0x01: ("battery", 1, False, 1),
    0x02: ("temperature", 2, True, 0.01),
    0x03: ("humidity", 2, False, 0.01),
    0x04: ("pressure", 3, False, 0.01),
    0x05: ("illuminance", 3, False, 0.01),
    0x06: ("weight", 2, False, 0.01),
    0x08: ("dewpoint", 2, True, 0.01),
    0x09: ("count", 1, False, 1),
    0x0A: ("energy", 3, False, 0.001),
    0x0B: ("power", 3, False, 0.01),
    0x0C: ("voltage", 2, False, 0.001),
    0x0D: ("pm2_5", 2, False, 1),
    0x0E: ("pm10", 2, False, 1),
    0x0F: ("generic_boolean", 1, False, 1),
    0x10: ("switch", 1, False, 1),
    0x11: ("opened", 1, False, 1),
    0x12: ("co2", 2, False, 1),
    0x13: ("tvoc", 2, False, 1),
    0x14: ("moisture", 2, False, 0.01),
    0x15: ("low_battery", 1, False, 1),
    0x16: ("battery_charging", 1, False, 1),
    0x17: ("carbon_monoxide", 1, False, 1),
    0x18: ("cold", 1, False, 1),
    0x19: ("connectivity", 1, False, 1),
    0x1A: ("door", 1, False, 1),
    0x1B: ("garage_door", 1, False, 1),
    0x1C: ("gas", 1, False, 1),
    0x1D: ("heat", 1, False, 1),
    0x1E: ("light", 1, False, 1),
    0x1F: ("lock", 1, False, 1),
    0x20: ("moisture_detected", 1, False, 1),
    0x21: ("motion", 1, False, 1),
    0x22: ("moving", 1, False, 1),
    0x23: ("occupancy", 1, False, 1),
    0x24: ("plug", 1, False, 1),
    0x25: ("presence", 1, False, 1),
    0x26: ("problem", 1, False, 1),
    0x27: ("running", 1, False, 1),
    0x28: ("safety", 1, False, 1),
    0x29: ("smoke", 1, False, 1),
    0x2A: ("sound", 1, False, 1),
    0x2B: ("tamper", 1, False, 1),
    0x2C: ("vibration", 1, False, 1),
    0x2D: ("window", 1, False, 1),
    0x2E: ("humidity", 1, False, 1),
    0x2F: ("moisture", 1, False, 1),
    0x3A: ("button", 1, False, 1),
    0x3D: ("count", 2, False, 1),
    0x3E: ("count", 4, False, 1),
    0x3F: ("rotation", 2, True, 0.1),
    0x40: ("distance_mm", 2, False, 1),
    0x41: ("distance_m", 2, False, 0.1),
    0x42: ("duration", 3, False, 0.001),
    0x43: ("current", 2, False, 0.001),
    0x44: ("speed", 2, False, 0.01),
    0x45: ("temperature", 2, True, 0.1),
    0x46: ("uv_index", 1, False, 0.1),
    0x47: ("volume", 2, False, 0.1),
    0x48: ("volume", 2, False, 1),
    0x49: ("flow_rate", 2, False, 0.001),
    0x4A: ("voltage", 2, False, 0.1),
    0x4B: ("gas", 3, False, 0.001),
    0x4C: ("gas", 4, False, 0.001),
    0x4D: ("energy", 4, False, 0.001),
    0x4E: ("volume", 4, False, 0.001),
    0x4F: ("water", 4, False, 0.001),
    0x50: ("timestamp", 4, False, 1),
    0x51: ("acceleration", 2, False, 0.001),
    0x52: ("gyroscope", 2, False, 0.001),
    0x55: ("volume_storage", 4, False, 0.001),
    0x56: ("conductivity", 2, False, 1),
    0x57: ("temperature", 1, True, 1),
    0x58: ("temperature", 1, True, 0.35),
    0x59: ("count", 1, True, 1),
    0x5A: ("count", 2, True, 1),
    0x5B: ("count", 4, True, 1),
    0x5C: ("power", 4, True, 0.01),
    0x5D: ("current", 2, True, 0.001),
    0x5E: ("direction", 2, False, 0.01),
    0x5F: ("precipitation", 2, False, 1),
    0x60: ("channel", 1, True, 1),
}

# Variable-length objects, which carry their own size byte.
_BTHOME_TEXT = 0x53
_BTHOME_RAW = 0x54


def decode_bthome(payload: bytes) -> dict[str, Value]:
    """Walk a BTHome v2 object list."""
    values: dict[str, Value] = {}
    offset = 0
    while offset < len(payload):
        object_id = payload[offset]
        offset += 1
        if object_id in (_BTHOME_TEXT, _BTHOME_RAW):
            if offset >= len(payload):
                break
            size = payload[offset]
            offset += 1
            chunk = payload[offset : offset + size]
            if len(chunk) < size:
                break
            values["text" if object_id == _BTHOME_TEXT else "raw"] = (
                chunk.decode("utf-8", errors="replace")
                if object_id == _BTHOME_TEXT
                else chunk.hex()
            )
            offset += size
            continue

        entry = _BTHOME_OBJECTS.get(object_id)
        if entry is None:
            log.debug("unknown BTHome object %#04x; stopping", object_id)
            break
        name, size, signed, factor = entry
        chunk = payload[offset : offset + size]
        if len(chunk) < size:
            break
        offset += size
        raw = int.from_bytes(chunk, "little", signed=signed)
        values[_unique(values, name)] = round(raw * factor, 3) if factor != 1 else raw
    return values


def _unique(values: Mapping[str, Value], name: str) -> str:
    """BTHome allows repeats of an object; number them rather than overwrite."""
    if name not in values:
        return name
    index = 2
    while f"{name}_{index}" in values:
        index += 1
    return f"{name}_{index}"


def _decode_bthome_service(
    data: bytes, address: str, bindkey: bytes | None
) -> Reading | None:
    if not data:
        return None
    info = data[0]
    encrypted = bool(info & BTHOME_ENCRYPTED_FLAG)
    if not encrypted:
        return Reading(address, "bthome", decode_bthome(data[1:]))

    if bindkey is None:
        return _undecodable(address, "bthome", "no bind key known")
    mac = _address_bytes(address)
    if mac is None:
        return _undecodable(address, "bthome", "device address is not visible")
    if len(data) < 1 + BTHOME_ENCRYPTED_OVERHEAD:
        return _undecodable(address, "bthome", "truncated")

    ciphertext = data[1:-BTHOME_ENCRYPTED_OVERHEAD]
    counter = data[-BTHOME_ENCRYPTED_OVERHEAD:-MIC_LEN]
    mic = data[-MIC_LEN:]
    nonce = mac + BTHOME_UUID_LE + data[0:1] + counter
    try:
        plain = _decrypt(bindkey, nonce, ciphertext, mic, aad=None)
    except ValueError as exc:
        return _undecodable(address, "bthome", f"decryption: {exc}")
    values = decode_bthome(plain)
    values["counter"] = int.from_bytes(counter, "little")
    return Reading(address, "bthome", values, encrypted=True)


def _decode_pvvx(data: bytes) -> dict[str, Value]:
    mac, temperature, humidity, battery_mv, battery, counter, flags = struct.unpack(
        "<6shHHBBB", data
    )
    return {
        "mac": ":".join(f"{byte:02X}" for byte in reversed(mac)),
        "temperature": round(temperature * 0.01, 2),
        "humidity": round(humidity * 0.01, 2),
        "battery_mv": battery_mv,
        "battery": battery,
        "counter": counter,
        "flags": flags,
    }


def _decode_atc1441(data: bytes) -> dict[str, Value]:
    mac, temperature, humidity, battery, battery_mv, counter = struct.unpack(
        ">6shBBHB", data
    )
    return {
        "mac": ":".join(f"{byte:02X}" for byte in mac),
        "temperature": round(temperature * 0.1, 1),
        "humidity": humidity,
        "battery": battery,
        "battery_mv": battery_mv,
        "counter": counter,
    }


def _decode_encrypted_atc_family(
    data: bytes, address: str, bindkey: bytes | None, name: str
) -> Reading:
    """Decrypt a pvvx or ATC1441 encrypted beacon.

    The nonce covers the advertisement header that Bleak has already stripped,
    so it is rebuilt here: the total length, the service-data type, and the
    16-bit UUID.
    """
    if bindkey is None:
        return _undecodable(address, name, "no bind key known")
    mac = _address_bytes(address)
    if mac is None:
        return _undecodable(address, name, "device address is not visible")

    header = bytes([len(data) + 3, AD_TYPE_SERVICE_DATA_16]) + ATC_UUID_LE
    nonce = mac[::-1] + header + data[0:1]
    try:
        plain = _decrypt(
            bindkey, nonce, data[1:-MIC_LEN], data[-MIC_LEN:], ENCRYPTED_AAD
        )
    except ValueError as exc:
        return _undecodable(address, name, f"decryption: {exc}")

    values: dict[str, Value] = {"counter": data[0]}
    if name == "pvvx":
        temperature, humidity, battery, trigger = struct.unpack("<hHBB", plain)
        values |= {
            "temperature": round(temperature * 0.01, 2),
            "humidity": round(humidity * 0.01, 2),
            "battery": battery,
            "flags": trigger,
        }
    else:
        temperature, humidity, battery = struct.unpack("<BBB", plain)
        values |= {
            "temperature": round(temperature * 0.5 - 40.0, 1),
            "humidity": humidity * 0.5,
            "battery": battery & 0x7F,
            "trigger": bool(battery & 0x80),
        }
    return Reading(address, name, values, encrypted=True)


def _decode_atc_service(
    data: bytes, address: str, bindkey: bytes | None
) -> Reading | None:
    match len(data):
        case _ if len(data) == PVVX_LEN:
            return Reading(address, "pvvx", _decode_pvvx(data))
        case _ if len(data) == ATC1441_LEN:
            return Reading(address, "atc1441", _decode_atc1441(data))
        case _ if len(data) == PVVX_ENCRYPTED_LEN:
            return _decode_encrypted_atc_family(data, address, bindkey, "pvvx")
        case _ if len(data) == ATC1441_ENCRYPTED_LEN:
            return _decode_encrypted_atc_family(data, address, bindkey, "atc1441")
        case _:
            log.debug("unrecognised 0x181A payload of %d bytes", len(data))
            return None


# MiBeacon object identifiers, limited to what environmental sensors report.
_MI_OBJECTS: dict[int, tuple[str, str]] = {
    0x1002: ("sleep", "u8"),
    # Named to avoid colliding with Reading.rssi, the advertisement's own
    # signal strength: as_dict() merges `values` over the top-level fields.
    0x1003: ("mibeacon_rssi", "u8"),
    0x1004: ("temperature", "t10"),
    0x1006: ("humidity", "h10"),
    0x1007: ("illuminance", "u24"),
    0x1008: ("moisture", "u8"),
    0x1009: ("conductivity", "u16"),
    0x100A: ("battery", "u8"),
    0x100D: ("temperature_humidity", "th"),
    0x1010: ("formaldehyde", "u16_100"),
    0x1012: ("opened", "u8"),
    0x1013: ("consumable", "u8"),
    0x1014: ("moisture_detected", "u8"),
    0x1017: ("idle_time", "u32"),
    0x1018: ("light", "u8"),
    0x1019: ("door", "u8"),
}

_MI_FRCTRL_ENCRYPTED = 3
_MI_FRCTRL_MAC = 4
_MI_FRCTRL_CAPABILITY = 5
_MI_FRCTRL_OBJECT = 6


def _decode_mi_objects(payload: bytes) -> dict[str, Value]:
    values: dict[str, Value] = {}
    offset = 0
    while offset + 3 <= len(payload):
        object_id = int.from_bytes(payload[offset : offset + 2], "little")
        size = payload[offset + 2]
        chunk = payload[offset + MI_OBJECT_HEADER_LEN : offset + 3 + size]
        offset += MI_OBJECT_HEADER_LEN + size
        if len(chunk) < size:
            break
        entry = _MI_OBJECTS.get(object_id)
        if entry is None:
            values[f"object_{object_id:04x}"] = chunk.hex()
            continue
        name, kind = entry
        values |= _decode_mi_value(name, kind, chunk)
    return values


def _decode_mi_value(name: str, kind: str, chunk: bytes) -> dict[str, Value]:
    match kind:
        case "t10":
            return {name: round(int.from_bytes(chunk, "little", signed=True) * 0.1, 1)}
        case "h10":
            return {name: round(int.from_bytes(chunk, "little") * 0.1, 1)}
        case "th" if len(chunk) >= MI_TEMP_HUMIDITY_LEN:
            temperature, humidity = struct.unpack("<hH", chunk[:4])
            return {
                "temperature": round(temperature * 0.1, 1),
                "humidity": round(humidity * 0.1, 1),
            }
        case "u16_100":
            return {name: round(int.from_bytes(chunk, "little") * 0.01, 2)}
        case _:
            return {name: int.from_bytes(chunk, "little")}


def _decode_mi_service(
    data: bytes, address: str, bindkey: bytes | None
) -> Reading | None:
    """Decode a MiBeacon frame, as a device on stock firmware broadcasts."""
    if len(data) < MI_MIN_LEN:
        return None
    control, product_id = struct.unpack_from("<HH", data, 0)
    counter = data[4]
    offset = 5
    values: dict[str, Value] = {"product_id": product_id, "counter": counter}

    if control >> _MI_FRCTRL_MAC & 1:
        values["mac"] = ":".join(
            f"{byte:02X}" for byte in reversed(data[offset : offset + 6])
        )
        offset += 6
    if control >> _MI_FRCTRL_CAPABILITY & 1:
        offset += 1
    if not control >> _MI_FRCTRL_OBJECT & 1:
        return Reading(address, "mi", values)

    payload = data[offset:]
    if not control >> _MI_FRCTRL_ENCRYPTED & 1:
        return Reading(address, "mi", values | _decode_mi_objects(payload))

    if bindkey is None:
        return _undecodable(address, "mi", "no bind key known", values)
    mac = _address_bytes(address)
    if mac is None:
        return _undecodable(address, "mi", "device address is not visible", values)
    if len(payload) < MI_EXT_COUNTER_LEN + MIC_LEN:
        return _undecodable(address, "mi", "truncated", values)

    ciphertext = payload[: -(MI_EXT_COUNTER_LEN + MIC_LEN)]
    extended = payload[-(MI_EXT_COUNTER_LEN + MIC_LEN) : -MIC_LEN]
    mic = payload[-MIC_LEN:]
    nonce = mac[::-1] + data[2:4] + data[4:5] + extended
    try:
        plain = _decrypt(bindkey, nonce, ciphertext, mic, ENCRYPTED_AAD)
    except ValueError as exc:
        return _undecodable(address, "mi", f"decryption: {exc}", values)
    return Reading(address, "mi", values | _decode_mi_objects(plain), encrypted=True)


def decode(
    device: BLEDevice,
    advertisement: AdvertisementData,
    bindkeys: Mapping[str, bytes] | None = None,
) -> Reading | None:
    """Decode an advertisement, or return None if it is not one of ours."""
    keys = bindkeys or {}
    bindkey = keys.get(device.address.upper())
    service_data = advertisement.service_data

    reading: Reading | None = None
    if (payload := service_data.get(BTHOME_SERVICE)) is not None:
        reading = _decode_bthome_service(bytes(payload), device.address, bindkey)
    elif (payload := service_data.get(ATC_SERVICE)) is not None:
        reading = _decode_atc_service(bytes(payload), device.address, bindkey)
    elif (payload := service_data.get(MI_BEACON_SERVICE)) is not None:
        reading = _decode_mi_service(bytes(payload), device.address, bindkey)

    if reading is None:
        return None
    return replace(
        reading,
        name=advertisement.local_name or device.name,
        rssi=advertisement.rssi,
    )


@dataclass
class Watcher:
    """Scans continuously, decoding what it recognises."""

    bindkeys: Mapping[str, bytes] = field(default_factory=dict)
    adapter: str | None = None
    passive: bool = False
    addresses: frozenset[str] = frozenset()

    async def run(
        self, on_reading: ReadingCallback, *, duration: float | None = None
    ) -> None:
        """Watch until `duration` elapses, or forever if it is None."""

        def detected(device: BLEDevice, advertisement: AdvertisementData) -> None:
            if self.addresses and device.address.upper() not in self.addresses:
                return
            reading = decode(device, advertisement, self.bindkeys)
            if reading is not None:
                on_reading(reading)

        bluez = BlueZScannerArgs()
        if self.adapter:
            bluez["adapter"] = self.adapter
        if self.passive:
            # BlueZ refuses a passive scan without match rules, so name the
            # service data we know how to decode.
            bluez["or_patterns"] = _or_patterns()

        scanner = BleakScanner(
            detection_callback=detected,
            scanning_mode="passive" if self.passive else "active",
            bluez=bluez,
        )
        async with scanner:
            if duration is None:
                await asyncio.Event().wait()
            else:
                await asyncio.sleep(duration)


def _or_patterns() -> list[OrPattern | tuple[int, AdvertisementDataType, bytes]]:
    """Match rules selecting the service data we know how to decode."""
    return [
        OrPattern(0, AdvertisementDataType.SERVICE_DATA_UUID16, uuid)
        for uuid in (BTHOME_UUID_LE, ATC_UUID_LE, MI_BEACON_UUID_LE)
    ]
