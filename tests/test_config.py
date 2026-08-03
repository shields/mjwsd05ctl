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

"""Tests for the `cfg_t` layout and the settings commands.

The expected bytes below are worked out from the C declaration in `src/app.h`,
where bit-fields are allocated from the least significant bit up. Getting this
backwards is the easiest possible mistake, so the bit positions are spelled out.
"""

import asyncio
import os
import time
from datetime import UTC, datetime
from typing import Any

import pytest

from mjwsd05ctl import config
from mjwsd05ctl.constants import CONFIG_VERSION, AdvertisingType, CommandId, ScreenType
from mjwsd05ctl.errors import ConfigError

# flg: advertising_type=3 at bits 0-1, comfort_smiley=1 at bit 2.
FLG = 0b0000_0111
# flg2: screen_type=1 at bits 0-2, adv_flags=1 at bit 4.
FLG2 = 0b0001_0001
# flg3: adv_interval_delay=5 at bits 0-3, date_ddmm=1 at bit 6.
FLG3 = 0b0100_0101

SAMPLE = bytes(
    [
        FLG,
        FLG2,
        FLG3,
        10,  # event_adv_cnt
        32,  # advertising_interval
        5,  # measure_interval
        191,  # rf_tx_power
        49,  # connect_latency
        16,  # min_step_time_update_lcd
        9,  # hw_ver
        60,  # averaging_measurements
    ]
)

# What `device_id()` sees after the opcode echo is stripped: revision,
# hw_version, sw_version, dev_spec_data (all Int16ul, little-endian), then 4
# service ids. `dev_id_t.pid` itself is never sent separately; the reader
# reconstructs it from the echoed opcode (DEV_ID == 0), so it always reads 0.
DEV_ID_REPLY = (
    bytes([7]) + b"\x34\x12" + b"\x08\x05" + b"\x02\x01" + bytes([10, 20, 30, 40])
)

# `scomfort_t` holding the firmware's own defaults (`def_cmf` in app.c): 21.00
# to 26.00 °C and 30.00 to 60.00 %, each a little-endian 16-bit count of
# hundredths. 2100 = 0x0834, 2600 = 0x0A28, 3000 = 0x0BB8, 6000 = 0x1770.
COMFORT_SAMPLE = bytes.fromhex("3408280ab80b7017")

# What DEV_MAC answers with: a length byte, the public address least
# significant byte first, then the two bytes that differ in the random static
# address. Written down those are A4:C1:38:11:22:33 and C0:44:55:11:22:33.
MAC_STORED = bytes.fromhex("33221138c1a45544")


def test_the_config_is_eleven_bytes() -> None:
    assert config.CFG.sizeof() == config.CFG_SIZE
    assert len(SAMPLE) == config.CFG_SIZE


def test_bit_fields_are_read_from_the_least_significant_bit() -> None:
    cfg = config.CFG.parse(SAMPLE)
    assert cfg.flg.advertising_type == AdvertisingType.BTHOME
    assert cfg.flg.comfort_smiley is True
    assert cfg.flg.x100 is False
    assert cfg.flg.temp_F_or_C is False
    assert cfg.flg.lp_measures is False

    assert cfg.flg2.screen_type == ScreenType.TEMPERATURE
    assert cfg.flg2.adv_flags is True
    assert cfg.flg2.adv_crypto is False
    assert cfg.flg2.screen_off is False

    assert cfg.flg3.adv_interval_delay == 5
    assert cfg.flg3.date_ddmm is True
    assert cfg.flg3.not_day_of_week is False

    assert cfg.advertising_interval == 32
    assert cfg.rf_tx_power == 191
    assert cfg.hw_ver == 9


def test_building_a_parsed_config_reproduces_the_bytes() -> None:
    assert config.CFG.build(config.CFG.parse(SAMPLE)) == SAMPLE


@pytest.mark.parametrize("byte", [0x00, 0xFF, 0x5A, 0xA5])
def test_every_bit_pattern_round_trips(byte: int) -> None:
    raw = bytes([byte]) * config.CFG_SIZE
    assert config.CFG.build(config.CFG.parse(raw)) == raw


def test_parse_config_tolerates_the_extra_byte_the_firmware_sends() -> None:
    # ble_send_cfg() pushes one byte more than it fills, so replies run long.
    reply = bytes([CONFIG_VERSION]) + SAMPLE + b"\x00"
    cfg = config._parse_config(reply)
    assert cfg.advertising_interval == 32


def test_parse_config_rejects_a_short_reply() -> None:
    with pytest.raises(ConfigError, match="only"):
        config._parse_config(bytes([CONFIG_VERSION]) + SAMPLE[:4])


def test_parse_config_rejects_a_reply_exactly_one_byte_short() -> None:
    # 1 version byte + 10 of the 11 cfg bytes is 11 bytes long: equal to
    # CFG_SIZE, one below the real minimum of CFG_SIZE + 1. A `< CFG_SIZE`
    # guard would let this slip through to CFG.parse() with too few bytes.
    with pytest.raises(ConfigError, match="only"):
        config._parse_config(bytes([CONFIG_VERSION]) + SAMPLE[:-1])


def test_parse_config_warns_about_an_unknown_version(
    caplog: pytest.LogCaptureFixture,
) -> None:
    config._parse_config(bytes([0x99]) + SAMPLE)
    assert "config version" in caplog.text


def test_derived_values_use_the_firmware_units() -> None:
    cfg = config.CFG.parse(SAMPLE)
    extra = config.derived(cfg)
    assert extra["advertising_interval_ms"] == 2000.0  # 32 × 62.5 ms
    assert extra["measurement_interval_ms"] == 10000.0  # × 5
    assert extra["connection_latency_ms"] == 1000  # (49 + 1) × 20 ms
    assert extra["lcd_update_interval_ms"] == 800  # 16 × 50 ms


def test_to_dict_names_enum_members() -> None:
    values = config.to_dict(config.CFG.parse(SAMPLE))
    assert values["advertising_type"] == "BTHOME"
    assert values["screen_type"] == "TEMPERATURE"
    assert values["comfort_smiley"] == 1
    assert values["hw_ver"] == 9


def test_to_dict_reports_the_raw_value_for_an_undefined_choice() -> None:
    # screen_type is a 3-bit field (0-7) but ScreenType only names 0-5, so the
    # firmware could still send a value with no matching enum member.
    raw = bytearray(SAMPLE)
    raw[1] = 0b0000_0110  # flg2: screen_type=6, adv_flags=0
    values = config.to_dict(config.CFG.parse(bytes(raw)))
    assert values["screen_type"] == 6


def test_apply_accepts_names_numbers_and_yes_no() -> None:
    cfg = config.CFG.parse(SAMPLE)
    config.apply(
        cfg,
        {
            "advertising_type": "pvvx",
            "screen_type": "3",
            "adv_crypto": "yes",
            "comfort_smiley": "off",
            "advertising_interval": "160",
        },
    )
    assert cfg.flg.advertising_type == AdvertisingType.PVVX
    assert cfg.flg2.screen_type == ScreenType.BATTERY_PERCENT
    assert cfg.flg2.adv_crypto is True
    assert cfg.flg.comfort_smiley is False
    assert cfg.advertising_interval == 160


def test_apply_rejects_unknown_and_read_only_settings() -> None:
    cfg = config.CFG.parse(SAMPLE)
    with pytest.raises(ConfigError, match="unknown setting"):
        config.apply(cfg, {"nonsense": "1"})
    with pytest.raises(ConfigError, match="read-only"):
        config.apply(cfg, {"hw_ver": "9"})


def test_apply_rejects_out_of_range_and_unparsable_values() -> None:
    cfg = config.CFG.parse(SAMPLE)
    with pytest.raises(ConfigError, match=r"outside 1\.\.160"):
        config.apply(cfg, {"advertising_interval": "200"})
    with pytest.raises(ConfigError, match="expected one of"):
        config.apply(cfg, {"advertising_type": "smoke signals"})
    with pytest.raises(ConfigError, match="yes/no"):
        config.apply(cfg, {"adv_crypto": "perhaps"})
    with pytest.raises(ConfigError, match="expected a number"):
        config.apply(cfg, {"advertising_interval": "soon"})


class FakeLink:
    """Enough of `transport.Link` to answer configuration commands."""

    def __init__(
        self,
        *,
        has_characteristic: bool = True,
        bindkey_missing: bool = False,
        mac_reply: bytes = bytes([len(MAC_STORED)]) + MAC_STORED,
    ) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.writes: list[bytes] = []
        self.silent = False
        self.mac_reply = mac_reply
        self._present = has_characteristic
        # Simulates a device with no Xiaomi bind key stored: BKEY replies come
        # back short, rather than the usual 16 bytes.
        self.bindkey_missing = bindkey_missing

    def has_characteristic(self, uuid: str) -> bool:
        del uuid
        return self._present

    async def subscribe(self, uuid: str) -> asyncio.Queue[bytes]:
        del uuid
        return self.queue

    async def write(
        self, uuid: str, data: bytes, *, response: bool | None = None
    ) -> None:
        del uuid, response
        self.writes.append(data)
        self.reply(data)

    def reply(self, request: bytes) -> None:
        if self.silent:
            return
        command = request[0]
        if command in (CommandId.CFG, CommandId.CFG_DEF):
            stored = request[1:] if len(request) > 1 else SAMPLE
            # Chatter on the same characteristic must not confuse the reader.
            self.queue.put_nowait(bytes([CommandId.MEASURE, 1, 2, 3]))
            # Both CFG and CFG_DEF are answered through ble_send_cfg(), whose
            # opcode byte is only ever written by test_config() (app.c); that
            # runs on the reset path too and stamps it back to CMD_ID_CFG
            # (cmd_parser.c / ble.h). A real device never echoes CFG_DEF back.
            self.queue.put_nowait(
                bytes([CommandId.CFG, CONFIG_VERSION]) + stored + b"\x00"
            )
        elif command == CommandId.UTC_TIME:
            self.queue.put_nowait(bytes([CommandId.UTC_TIME]) + request[1:5])
        elif command == CommandId.BKEY:
            key = request[1:17] if len(request) > 1 else bytes(range(16))
            reply_key = b"" if self.bindkey_missing else key
            self.queue.put_nowait(bytes([CommandId.BKEY]) + reply_key)
        elif command == CommandId.DEV_ID:
            self.queue.put_nowait(bytes([CommandId.DEV_ID]) + DEV_ID_REPLY)
        elif command == CommandId.COMFORT:
            # The firmware saves whatever it was sent and then reports the
            # band it now holds, which is that same value.
            stored = request[1:9] if len(request) > 1 else COMFORT_SAMPLE
            self.queue.put_nowait(bytes([CommandId.COMFORT]) + stored)
        elif command == CommandId.DEV_MAC:
            reply = self.mac_reply
            self.queue.put_nowait(bytes([CommandId.DEV_MAC]) + reply)


async def session(**kwargs: Any) -> tuple[config.Session, FakeLink]:
    link = FakeLink(**kwargs)
    ses = config.Session(link)  # ty: ignore[invalid-argument-type]
    await ses.open()
    return ses, link


async def test_reading_the_config_skips_unrelated_notifications() -> None:
    ses, link = await session()
    cfg = await ses.read_config()
    assert cfg.advertising_interval == 32
    assert link.writes == [bytes([CommandId.CFG])]


async def test_writing_the_config_sends_no_version_byte() -> None:
    ses, link = await session()
    cfg = await ses.read_config()
    config.apply(cfg, {"advertising_interval": "64"})
    written = await ses.write_config(cfg)
    # The request is the opcode followed by the eleven config bytes, with no
    # version byte; only replies carry one.
    assert len(link.writes[-1]) == config.CFG_SIZE + 1
    assert link.writes[-1][0] == CommandId.CFG
    assert written.advertising_interval == 64


async def test_setting_the_clock_sends_local_time_as_if_it_were_utc() -> None:
    # astimezone() with no argument converts to the *host's* configured zone,
    # not `when`'s own tzinfo, so pin the host to a fixed, DST-free offset to
    # make the expected stamp deterministic regardless of where tests run.
    original_tz = os.environ.get("TZ")
    os.environ["TZ"] = "Etc/GMT-5"  # POSIX sign is inverted: this is UTC+5
    time.tzset()
    try:
        ses, link = await session()
        moment = datetime(2024, 6, 15, 12, 30, 0, tzinfo=UTC)
        reported = await ses.set_time(moment)
    finally:
        if original_tz is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = original_tz
        time.tzset()

    request = link.writes[-1]
    assert request[0] == CommandId.UTC_TIME
    # 12:30 UTC is 17:30 at UTC+5; the firmware wants that wall-clock reading
    # sent as though it were itself a UTC timestamp.
    expected_stamp = int(datetime(2024, 6, 15, 17, 30, 0, tzinfo=UTC).timestamp())
    assert int.from_bytes(request[1:5], "little") == expected_stamp
    assert reported == expected_stamp


async def test_bind_key_round_trips() -> None:
    ses, _ = await session()
    key = bytes(range(16, 32))
    assert await ses.set_bindkey(key) == key


async def test_bind_key_of_the_wrong_length_is_refused() -> None:
    ses, _ = await session()
    with pytest.raises(ConfigError, match="16 bytes"):
        await ses.set_bindkey(b"short")


async def test_get_bindkey_returns_the_stored_key() -> None:
    ses, link = await session()
    assert await ses.get_bindkey() == bytes(range(16))
    assert link.writes == [bytes([CommandId.BKEY])]


async def test_get_bindkey_returns_none_when_the_device_has_none_stored() -> None:
    ses, _ = await session(bindkey_missing=True)
    assert await ses.get_bindkey() is None


async def test_set_bindkey_returns_none_when_the_device_does_not_echo_it_back() -> None:
    ses, _ = await session(bindkey_missing=True)
    assert await ses.set_bindkey(bytes(range(16, 32))) is None


async def test_reset_config_asks_for_factory_defaults() -> None:
    # The device answers a CFG_DEF request tagged CFG (see reset_config's
    # docstring), so this only passes if reset_config() actually waits for
    # that tag rather than the CFG_DEF it sent.
    ses, link = await session()
    cfg = await ses.reset_config()
    assert link.writes == [bytes([CommandId.CFG_DEF])]
    assert cfg.advertising_interval == 32


async def test_request_expect_waits_for_the_named_opcode_not_the_sent_one() -> None:
    # Pins the contract behind reset_config(): `expect=` is what request()
    # matches replies against, and a reply tagged with the *sent* opcode
    # (what a naive implementation, or the firmware, does NOT do for CFG_DEF)
    # must still be ignored.
    ses, link = await session()
    link.silent = True
    link.queue.put_nowait(bytes([CommandId.CFG_DEF, 0xAA]))  # wrong tag: ignored
    link.queue.put_nowait(bytes([CommandId.CFG, 0xBB]))  # matches `expect`
    response = await ses.request(CommandId.CFG_DEF, expect=CommandId.CFG)
    assert response == bytes([0xBB])


async def test_device_id_reconstructs_the_dev_id_t_layout() -> None:
    ses, link = await session()
    info = await ses.device_id()
    assert link.writes == [bytes([CommandId.DEV_ID])]
    # pid is never sent as data; it is filled in from the echoed opcode, which
    # for the DEV_ID command is always 0.
    assert info.pid == CommandId.DEV_ID
    assert info.revision == 7
    assert info.hw_version == 0x1234
    assert info.sw_version == 0x0508
    assert info.dev_spec_data == 0x0102
    assert list(info.services) == [10, 20, 30, 40]


async def test_set_mi_keys_writes_the_token_and_bind_key_in_one_command() -> None:
    ses, link = await session()
    token = bytes(range(12))
    bindkey = bytes(range(16, 32))
    await ses.set_mi_keys(token, bindkey)
    assert link.writes[-1] == bytes([CommandId.MI_TBIND]) + token + bindkey


async def test_set_mi_keys_rejects_a_token_or_bindkey_of_the_wrong_length() -> None:
    ses, _ = await session()
    with pytest.raises(ConfigError, match="12-byte token and a 16-byte bind key"):
        await ses.set_mi_keys(b"short", bytes(range(16)))
    with pytest.raises(ConfigError, match="12-byte token and a 16-byte bind key"):
        await ses.set_mi_keys(bytes(range(12)), b"short")


async def test_comfort_reads_the_band_the_firmware_ships_with() -> None:
    ses, link = await session()
    zone = await ses.comfort()
    # A bare opcode is a read: the firmware only overwrites the band when the
    # request carries one, so this must send no payload.
    assert link.writes == [bytes([CommandId.COMFORT])]
    assert zone.temperature_min == 2100
    assert zone.temperature_max == 2600
    assert zone.humidity_min == 3000
    assert zone.humidity_max == 6000
    assert config.comfort_to_dict(zone) == {
        "temperature_min": 21.0,
        "temperature_max": 26.0,
        "humidity_min": 30.0,
        "humidity_max": 60.0,
    }


async def test_writing_the_comfort_band_sends_eight_little_endian_values() -> None:
    ses, link = await session()
    zone = await ses.comfort()
    config.apply_comfort(zone, {"temperature_min": "-5.5", "humidity_max": "62.25"})
    written = await ses.write_comfort(zone)

    request = link.writes[-1]
    assert request[0] == CommandId.COMFORT
    assert len(request) == config.COMFORT_SIZE + 1
    # -5.50 °C is -550, which is 0xFDDA as a signed 16-bit little-endian value;
    # 62.25 % is 6225 = 0x1851. Getting the signedness wrong shows up here.
    assert request[1:3] == bytes.fromhex("dafd")
    assert request[7:9] == bytes.fromhex("5118")
    assert written.temperature_min == -550
    assert written.humidity_max == 6225


def test_a_temperature_below_freezing_survives_the_round_trip() -> None:
    # Humidity is unsigned in the C, temperature is not; parsing both the same
    # way turns a cold room into 655 °C.
    zone = config.COMFORT.parse(bytes.fromhex("dafd280ab80b7017"))
    assert zone.temperature_min == -550
    assert config.comfort_to_dict(zone)["temperature_min"] == -5.5


def test_a_humidity_with_its_top_bit_set_is_not_read_as_negative() -> None:
    # `scomfort_t.h` is `u16`, and the firmware stores whatever it is sent, so
    # a value above 327.67 % is representable. Read as signed it would come
    # back negative, which is the mirror image of the bug above and invisible
    # for the 0..100 % values anyone would actually set.
    zone = config.COMFORT.parse(bytes.fromhex("3408280a0080ffff"))
    assert zone.humidity_min == 0x8000
    assert zone.humidity_max == 0xFFFF
    assert config.comfort_to_dict(zone)["humidity_max"] == 655.35


def test_a_short_comfort_reply_is_rejected() -> None:
    with pytest.raises(ConfigError, match="only 4 bytes"):
        config._parse_comfort(COMFORT_SAMPLE[:4])


def test_comfort_limits_are_rejected_before_touching_hardware() -> None:
    with pytest.raises(ConfigError, match="unknown comfort limit"):
        config.validate_comfort({"tempurature_min": "20"})
    with pytest.raises(ConfigError, match="expected a number"):
        config.validate_comfort({"temperature_min": "chilly"})
    with pytest.raises(ConfigError, match="outside"):
        config.validate_comfort({"temperature_min": "400"})
    with pytest.raises(ConfigError, match="outside"):
        config.validate_comfort({"humidity_min": "-1"})


def test_comfort_values_are_stored_as_hundredths() -> None:
    assert config.validate_comfort({"temperature_min": "20.5"}) == {
        "temperature_min": 2050
    }
    # Rounded, not truncated: 20.999 must not become 20.99.
    assert config.validate_comfort({"temperature_max": "20.999"}) == {
        "temperature_max": 2100
    }


def test_a_band_whose_floor_is_above_its_ceiling_is_refused() -> None:
    # Only one edge is being set, so the check has to look at the band as a
    # whole after the change, not at the value on its own.
    zone = config.COMFORT.parse(COMFORT_SAMPLE)
    with pytest.raises(ConfigError, match="no reading can satisfy"):
        config.apply_comfort(zone, {"temperature_min": "30"})

    zone = config.COMFORT.parse(COMFORT_SAMPLE)
    with pytest.raises(ConfigError, match="no reading can satisfy"):
        config.apply_comfort(zone, {"humidity_max": "10"})

    zone = config.COMFORT.parse(COMFORT_SAMPLE)
    assert config.apply_comfort(zone, {"temperature_min": "20"}).temperature_min == 2000


async def test_the_mac_address_is_reported_the_way_it_is_written_down() -> None:
    ses, link = await session()
    addresses = await ses.mac_address()
    assert link.writes == [bytes([CommandId.DEV_MAC])]
    # Flash holds the address least significant byte first.
    assert addresses.public == "A4:C1:38:11:22:33"
    # The random static address keeps the public address's first three bytes,
    # takes the two the device generated, and always ends 0xC0.
    assert addresses.random_static == "C0:44:55:11:22:33"


@pytest.mark.parametrize(
    "reply",
    [
        bytes([8]) + MAC_STORED[:5],  # the eight bytes were not all sent
        # One byte short of a whole reply. The two random static bytes are the
        # last thing in it, so a `<` guard here reads past the end instead of
        # refusing, and the boundary is the only place that shows.
        bytes([8]) + MAC_STORED[:7],
        bytes([6]) + MAC_STORED,  # a length that is not what we can parse
    ],
)
async def test_an_unusable_mac_reply_is_refused_rather_than_guessed(
    reply: bytes,
) -> None:
    ses, _ = await session(mac_reply=reply)
    with pytest.raises(ConfigError, match="DEV_MAC"):
        await ses.mac_address()


def test_the_software_version_is_read_out_of_the_low_byte_as_bcd() -> None:
    # VERSION in app_config.h is 0x58 for firmware 5.8, and only the low byte
    # of sw_version carries it; anything above it must not leak into the name.
    identity = config.DEV_ID.parse(
        bytes([CommandId.DEV_ID, 0])
        + b"\x0c\x00"  # hw_version 12
        + b"\x58\x01"  # sw_version 0x0158
        + b"\x00\x00"
        + bytes(4)
    )
    assert identity.sw_version == 0x0158
    assert config.software_version(identity) == "5.8"


async def test_reboot_writes_the_reboot_command() -> None:
    ses, link = await session()
    await ses.reboot()
    assert link.writes[-1] == bytes([CommandId.REBOOT])


async def test_opening_without_the_characteristic_explains_why() -> None:
    with pytest.raises(ConfigError, match="stock firmware"):
        await session(has_characteristic=False)


async def test_a_silent_device_times_out_rather_than_hanging() -> None:
    ses, link = await session()
    link.silent = True
    with pytest.raises(ConfigError, match="did not answer"):
        await ses.request(CommandId.CFG, timeout=0.05)


def test_a_number_outside_an_enum_is_rejected_before_touching_hardware() -> None:
    # Caught by validate(), not left to fail inside construct after connecting.
    with pytest.raises(ConfigError, match="expected one of"):
        config.validate({"advertising_type": "99"})
    assert config.validate({"advertising_type": "3"}) == {"advertising_type": 3}


def test_measure_interval_is_bounded_by_the_firmwares_real_limits() -> None:
    # 2..25 measurements per advertisement is the device's own range, not a
    # value this test should recompute from the FieldSpec.
    assert config.validate({"measure_interval": "2"}) == {"measure_interval": 2}
    assert config.validate({"measure_interval": "25"}) == {"measure_interval": 25}
    with pytest.raises(ConfigError, match=r"outside 2\.\.25"):
        config.validate({"measure_interval": "1"})
    with pytest.raises(ConfigError, match=r"outside 2\.\.25"):
        config.validate({"measure_interval": "26"})


def test_rf_tx_power_rejects_zero() -> None:
    assert config.validate({"rf_tx_power": "1"}) == {"rf_tx_power": 1}
    with pytest.raises(ConfigError, match=r"outside 1\.\.255"):
        config.validate({"rf_tx_power": "0"})


def test_min_step_time_update_lcd_is_bounded_below() -> None:
    assert config.validate({"min_step_time_update_lcd": "10"}) == {
        "min_step_time_update_lcd": 10
    }
    with pytest.raises(ConfigError, match=r"outside 10\.\.255"):
        config.validate({"min_step_time_update_lcd": "9"})


async def test_commands_before_open_are_a_clear_error() -> None:
    ses = config.Session(FakeLink())  # ty: ignore[invalid-argument-type]
    with pytest.raises(ConfigError, match="open"):
        await ses.request(CommandId.CFG)
