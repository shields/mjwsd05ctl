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

"""Reading and writing the pvvx firmware's settings.

The layout is `cfg_t` from `src/app.h` for `DEVICE_MJWSD05MMC`. C allocates
bit-fields from the least significant bit, while `construct` reads them most
significant first, so each byte's fields appear here in the reverse of their
declaration order.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from construct import BitsInteger, BitStruct, Container, Flag, Int8ul, Int16ul, Struct

from .constants import (
    CONFIG_VERSION,
    CUSTOM_CHAR,
    MI_BINDKEY_LEN,
    MI_TOKEN_LEN,
    AdvertisingType,
    CommandId,
    ScreenType,
)
from .errors import ConfigError

if TYPE_CHECKING:
    from enum import IntEnum

    from .transport import Link

log = logging.getLogger(__name__)

RESPONSE_TIMEOUT = 10.0

CFG = Struct(
    "flg"
    / BitStruct(
        "lp_measures" / Flag,
        "tx_measures" / Flag,
        "time_am_pm" / Flag,
        "temp_F_or_C" / Flag,
        "x100" / Flag,
        "comfort_smiley" / Flag,
        "advertising_type" / BitsInteger(2),
    ),
    "flg2"
    / BitStruct(
        "screen_off" / Flag,
        "longrange" / Flag,
        "bt5phy" / Flag,
        "adv_flags" / Flag,
        "adv_crypto" / Flag,
        "screen_type" / BitsInteger(3),
    ),
    "flg3"
    / BitStruct(
        "not_day_of_week" / Flag,
        "date_ddmm" / Flag,
        "reserved" / BitsInteger(2),
        "adv_interval_delay" / BitsInteger(4),
    ),
    "event_adv_cnt" / Int8ul,
    "advertising_interval" / Int8ul,
    "measure_interval" / Int8ul,
    "rf_tx_power" / Int8ul,
    "connect_latency" / Int8ul,
    "min_step_time_update_lcd" / Int8ul,
    "hw_ver" / Int8ul,
    "averaging_measurements" / Int8ul,
)

CFG_SIZE = 11

# `dev_id_t` from src/cmd_parser.h.
DEV_ID = Struct(
    "pid" / Int8ul,
    "revision" / Int8ul,
    "hw_version" / Int16ul,
    "sw_version" / Int16ul,
    "dev_spec_data" / Int16ul,
    "services" / Int8ul[4],
)

# Advertising interval is counted in units of 62.5 ms, LCD update in 50 ms, and
# connection latency in 20 ms.
ADV_INTERVAL_MS = 62.5
LCD_STEP_MS = 50
CONNECT_LATENCY_MS = 20


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """One user-settable field, for validation and help text."""

    group: str | None
    help: str
    choices: type[IntEnum] | None = None
    boolean: bool = False
    minimum: int = 0
    maximum: int = 255
    read_only: bool = False
    unit: str = ""


FIELDS: dict[str, FieldSpec] = {
    "advertising_type": FieldSpec(
        "flg", "advertisement format", choices=AdvertisingType
    ),
    "comfort_smiley": FieldSpec("flg", "show the comfort indicator", boolean=True),
    "x100": FieldSpec("flg", "show values scaled by 100", boolean=True),
    "temp_F_or_C": FieldSpec(
        "flg", "display Fahrenheit instead of Celsius", boolean=True
    ),
    "time_am_pm": FieldSpec("flg", "12-hour clock", boolean=True),
    "tx_measures": FieldSpec(
        "flg", "notify every measurement while connected", boolean=True
    ),
    "lp_measures": FieldSpec("flg", "measure in low-power mode", boolean=True),
    "screen_type": FieldSpec("flg2", "what the second line shows", choices=ScreenType),
    "adv_crypto": FieldSpec("flg2", "encrypt advertisements", boolean=True),
    "adv_flags": FieldSpec("flg2", "include flags in advertisements", boolean=True),
    "bt5phy": FieldSpec("flg2", "allow Bluetooth 5 PHYs", boolean=True),
    "longrange": FieldSpec("flg2", "advertise on the coded PHY", boolean=True),
    "screen_off": FieldSpec("flg2", "turn the display off", boolean=True),
    "adv_interval_delay": FieldSpec(
        "flg3", "random advertising jitter", maximum=15, unit="× 0.625 ms"
    ),
    "date_ddmm": FieldSpec("flg3", "show the date as dd:mm", boolean=True),
    "not_day_of_week": FieldSpec("flg3", "hide the day of the week", boolean=True),
    "event_adv_cnt": FieldSpec(None, "advertisements sent per event", minimum=6),
    "advertising_interval": FieldSpec(
        None, "advertising interval", minimum=1, maximum=160, unit="× 62.5 ms"
    ),
    "measure_interval": FieldSpec(
        None, "measurements per advertisement", minimum=2, maximum=25
    ),
    "rf_tx_power": FieldSpec(None, "radio transmit power", minimum=1),
    "connect_latency": FieldSpec(None, "connection latency", unit="× 20 ms"),
    "min_step_time_update_lcd": FieldSpec(
        None, "shortest display refresh", minimum=10, unit="× 50 ms"
    ),
    "hw_ver": FieldSpec(None, "hardware version", read_only=True),
    "averaging_measurements": FieldSpec(None, "measurements to average, 0 to disable"),
}

_TRUE = frozenset({"1", "on", "true", "yes", "y"})
_FALSE = frozenset({"0", "off", "false", "no", "n"})


@dataclass
class Session:
    """A subscription to the pvvx config characteristic."""

    link: Link
    queue: asyncio.Queue[bytes] | None = field(init=False, default=None)

    async def open(self) -> None:
        if not self.link.has_characteristic(CUSTOM_CHAR):
            msg = (
                "device does not expose the pvvx config characteristic; "
                "it is probably still running stock firmware"
            )
            raise ConfigError(msg)
        self.queue = await self.link.subscribe(CUSTOM_CHAR)

    async def request(
        self,
        command: CommandId,
        payload: bytes = b"",
        *,
        expect: CommandId | None = None,
        timeout: float = RESPONSE_TIMEOUT,
    ) -> bytes:
        """Send a command and return the matching reply's payload.

        `expect` names the opcode the reply carries when it is not the one that
        was sent, which is the case for `CFG_DEF`.
        """
        if self.queue is None:
            msg = "Session.open() must be called before issuing commands"
            raise ConfigError(msg)
        wanted = command if expect is None else expect
        await self.link.write(CUSTOM_CHAR, bytes([command]) + payload)
        try:
            async with asyncio.timeout(timeout):
                while True:
                    response = await self.queue.get()
                    # Unrelated notifications, such as streamed measurements,
                    # share this characteristic.
                    if response and response[0] == wanted:
                        return response[1:]
        except TimeoutError:
            msg = f"device did not answer command {command.name} within {timeout:g}s"
            raise ConfigError(msg) from None

    async def read_config(self) -> Container[Any]:
        return _parse_config(await self.request(CommandId.CFG))

    async def write_config(self, cfg: Container[Any]) -> Container[Any]:
        """Write settings and return what the device reports afterwards.

        The device clamps out-of-range values, so the reply is the truth about
        what was actually applied.
        """
        return _parse_config(await self.request(CommandId.CFG, CFG.build(cfg)))

    async def reset_config(self) -> Container[Any]:
        """Restore factory settings and return them.

        The reply comes back tagged `CFG`, not `CFG_DEF`. The firmware answers
        both through `ble_send_cfg()`, which pushes a buffer whose opcode byte
        is only ever written by `test_config()` (`app.c`) — and `test_config()`
        runs on the reset path itself, stamping it back to `CMD_ID_CFG`. Waiting
        for a `CFG_DEF` reply would therefore time out every time.
        """
        return _parse_config(
            await self.request(CommandId.CFG_DEF, expect=CommandId.CFG)
        )

    async def device_id(self) -> Container[Any]:
        response = await self.request(CommandId.DEV_ID)
        return DEV_ID.parse(bytes([CommandId.DEV_ID]) + response)

    async def set_time(self, when: datetime | None = None) -> int:
        """Set the clock.

        The firmware displays its stored time directly, so it wants local time
        presented as if it were UTC, which is what the reference flasher sends.
        """
        moment = when or datetime.now(UTC)
        offset = moment.astimezone().utcoffset()
        shift = int(offset.total_seconds()) if offset else 0
        stamp = int(moment.timestamp()) + shift
        response = await self.request(CommandId.UTC_TIME, stamp.to_bytes(4, "little"))
        return int.from_bytes(response[:4], "little")

    async def get_bindkey(self) -> bytes | None:
        response = await self.request(CommandId.BKEY)
        if len(response) < MI_BINDKEY_LEN:
            return None
        return response[:MI_BINDKEY_LEN]

    async def set_bindkey(self, key: bytes) -> bytes | None:
        if len(key) != MI_BINDKEY_LEN:
            msg = f"bind key must be {MI_BINDKEY_LEN} bytes, got {len(key)}"
            raise ConfigError(msg)
        response = await self.request(CommandId.BKEY, key)
        if len(response) < MI_BINDKEY_LEN:
            return None
        return response[:MI_BINDKEY_LEN]

    async def set_mi_keys(self, token: bytes, bindkey: bytes) -> None:
        """Store the Xiaomi token and bind key so Mi Home can be restored."""
        if len(token) != MI_TOKEN_LEN or len(bindkey) != MI_BINDKEY_LEN:
            msg = "Mi keys must be a 12-byte token and a 16-byte bind key"
            raise ConfigError(msg)
        await self.link.write(
            CUSTOM_CHAR, bytes([CommandId.MI_TBIND]) + token + bindkey
        )

    async def reboot(self) -> None:
        """Ask the device to restart when we disconnect."""
        await self.link.write(CUSTOM_CHAR, bytes([CommandId.REBOOT]))


def _parse_config(response: bytes) -> Container[Any]:
    """Parse a config reply: a version byte, then `cfg_t`.

    The firmware sends one byte more than it fills, so trailing bytes are
    expected and ignored.
    """
    if len(response) < CFG_SIZE + 1:
        msg = f"config reply is only {len(response)} bytes"
        raise ConfigError(msg)
    version = response[0]
    if version != CONFIG_VERSION:
        log.warning(
            "device reports config version %#x, this tool knows %#x; "
            "fields may be misinterpreted",
            version,
            CONFIG_VERSION,
        )
    return CFG.parse(response[1 : 1 + CFG_SIZE])


def to_dict(cfg: Container[Any]) -> dict[str, int | bool | str]:
    """Flatten a parsed config into plain values, naming enum members."""
    result: dict[str, int | bool | str] = {}
    for name, spec in FIELDS.items():
        value = _get(cfg, name, spec)
        if spec.choices is not None:
            try:
                result[name] = spec.choices(value).name
            except ValueError:
                result[name] = value
        else:
            result[name] = value
    return result


def derived(cfg: Container[Any]) -> dict[str, float]:
    """Values the raw fields imply, in real units."""
    interval = cfg.advertising_interval * ADV_INTERVAL_MS
    return {
        "advertising_interval_ms": interval,
        "measurement_interval_ms": interval * cfg.measure_interval,
        "connection_latency_ms": (cfg.connect_latency + 1) * CONNECT_LATENCY_MS,
        "lcd_update_interval_ms": cfg.min_step_time_update_lcd * LCD_STEP_MS,
    }


def validate(settings: dict[str, str]) -> dict[str, int]:
    """Check names and values against the schema, needing no device.

    Kept separate from `apply` so a typo is reported before we go looking for
    hardware, rather than after connecting to it.
    """
    parsed: dict[str, int] = {}
    for name, raw in settings.items():
        spec = FIELDS.get(name)
        if spec is None:
            known = ", ".join(sorted(FIELDS))
            msg = f"unknown setting {name!r}; known settings are {known}"
            raise ConfigError(msg)
        if spec.read_only:
            msg = f"{name} is read-only"
            raise ConfigError(msg)
        parsed[name] = parse_value(name, spec, raw)
    return parsed


def apply(cfg: Container[Any], settings: dict[str, str]) -> Container[Any]:
    """Apply `name=value` settings to a parsed config."""
    for name, value in validate(settings).items():
        _set(cfg, name, FIELDS[name], value)
    return cfg


def parse_value(name: str, spec: FieldSpec, raw: str) -> int:
    """Turn a command-line string into the integer the firmware stores."""
    text = raw.strip()
    if spec.boolean:
        lowered = text.lower()
        if lowered in _TRUE:
            return 1
        if lowered in _FALSE:
            return 0
        msg = f"{name}: expected a yes/no value, got {raw!r}"
        raise ConfigError(msg)

    if spec.choices is not None:
        for member in spec.choices:
            if member.name.lower() == text.lower():
                return int(member)

    try:
        value = int(text, 0)
    except ValueError:
        if spec.choices is not None:
            names = ", ".join(member.name for member in spec.choices)
            msg = f"{name}: expected one of {names}, got {raw!r}"
        else:
            msg = f"{name}: expected a number, got {raw!r}"
        raise ConfigError(msg) from None

    if spec.choices is not None:
        if value not in {int(member) for member in spec.choices}:
            names = ", ".join(member.name for member in spec.choices)
            msg = f"{name}: expected one of {names}, got {raw!r}"
            raise ConfigError(msg)
        return value

    if not spec.minimum <= value <= spec.maximum:
        msg = f"{name}: {value} is outside {spec.minimum}..{spec.maximum}"
        raise ConfigError(msg)
    return value


def _get(cfg: Container[Any], name: str, spec: FieldSpec) -> int:
    group = cfg[spec.group] if spec.group else cfg
    return int(group[name])


def _set(cfg: Container[Any], name: str, spec: FieldSpec, value: int) -> None:
    group = cfg[spec.group] if spec.group else cfg
    group[name] = bool(value) if spec.boolean else value
