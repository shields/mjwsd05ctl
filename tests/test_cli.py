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

import argparse
import contextlib
import json
import logging
import sys
from collections.abc import AsyncIterator, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Self

import pytest
from bleak import AdvertisementData, BLEDevice

from mjwsd05ctl import cli, config
from mjwsd05ctl.constants import (
    CUSTOM_SERVICE,
    HW_ID_CH,
    HW_ID_EN,
    MI_AUTH_SERVICE,
    OTA_SERVICE,
)
from mjwsd05ctl.errors import ConfigError, Error
from mjwsd05ctl.firmware import FirmwareImage
from mjwsd05ctl.keystore import normalise
from mjwsd05ctl.miauth import MiKeys
from mjwsd05ctl.reader import Reading
from mjwsd05ctl.transport import DeviceInfo


@pytest.mark.parametrize(
    "command",
    ["scan", "info", "activate", "flash", "bootstrap", "config", "read"],
)
def test_every_subcommand_parses(command: str) -> None:
    args = cli.build_parser().parse_args([command])
    assert args.command == command
    assert callable(args.handler)


def test_a_command_is_required() -> None:
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args([])


def test_settings_accumulate() -> None:
    args = cli.build_parser().parse_args(
        ["config", "--set", "adv_crypto=yes", "--set", "advertising_interval=64"]
    )
    assert cli._parse_settings(args.set) == {
        "adv_crypto": "yes",
        "advertising_interval": "64",
    }


def test_a_setting_without_a_value_is_rejected() -> None:
    with pytest.raises(Error, match="expected NAME=VALUE"):
        cli._parse_settings(["adv_crypto"])


def test_a_setting_may_contain_an_equals_sign_in_its_value() -> None:
    assert cli._parse_settings(["name=a=b"]) == {"name": "a=b"}


def test_a_setting_name_is_stripped_of_surrounding_whitespace() -> None:
    # A user might introduce stray whitespace via shell quoting or copy-paste;
    # the name must still match a real field, e.g. "adv_crypto" not " adv_crypto".
    assert cli._parse_settings([" adv_crypto =yes"]) == {"adv_crypto": "yes"}


def test_field_descriptions_cover_every_setting() -> None:
    for name, spec in config.FIELDS.items():
        described = cli._describe_field(spec)
        assert described, f"{name} has no description"


def test_field_descriptions_name_the_choices() -> None:
    assert "BTHOME" in cli._describe_field(config.FIELDS["advertising_type"])
    assert cli._describe_field(config.FIELDS["adv_crypto"]) == "yes/no"
    assert "1..160" in cli._describe_field(config.FIELDS["advertising_interval"])


def test_listing_the_fields_needs_no_device(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["config", "--fields"]) == 0
    printed = capsys.readouterr().out
    assert "advertising_type" in printed
    assert "hardware version" in printed


def test_expected_failures_print_a_plain_message(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def boom(args: argparse.Namespace) -> int:
        del args
        msg = "no device in range"
        raise Error(msg)

    monkeypatch.setattr(cli, "cmd_scan", boom)
    assert cli.main(["scan"]) == 1
    assert "mjwsd05ctl: no device in range" in capsys.readouterr().err


def test_scan_rows_render_without_a_reading() -> None:
    row = cli.ScanRow(address="A4:C1:38:11:22:33", name=None, rssi=None, reading=None)
    assert "A4:C1:38:11:22:33" in row.as_line()
    assert row.as_dict()["format"] is None


def test_bad_setting_names_are_caught_before_touching_hardware(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # No Bluetooth adapter is opened, so this must fail on the name alone.
    assert cli.main(["config", "--set", "nope=1"]) == 1
    assert "unknown setting" in capsys.readouterr().err


def test_bad_setting_values_are_caught_before_touching_hardware(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["config", "--set", "advertising_interval=999"]) == 1
    assert "outside" in capsys.readouterr().err


def test_verbose_leaves_bleaks_own_logger_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []
    monkeypatch.setattr(logging.getLogger("bleak"), "setLevel", calls.append)
    assert cli.main(["--verbose", "config", "--fields"]) == 0
    assert calls == []


def test_non_verbose_quiets_bleaks_own_logger(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr(logging.getLogger("bleak"), "setLevel", calls.append)
    assert cli.main(["config", "--fields"]) == 0
    assert calls == [logging.WARNING]


def test_a_keyboard_interrupt_during_a_command_exits_130(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def interrupted(args: argparse.Namespace) -> int:
        del args
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "cmd_scan", interrupted)
    assert cli.main(["scan"]) == 130


def test_reboot_wait_is_long_enough_for_the_device_to_come_back() -> None:
    # Every bootstrap test monkeypatches this to 0.0 so it can run fast, which
    # means nothing else exercises the real production value; pin it directly.
    assert cli.REBOOT_WAIT == 8.0


# --- Fakes for the collaborators `cli` reaches for by name -----------------
#
# `cli` binds these with `from .transport import connect, scan` and
# `from . import config as config_module` (and similarly for reader, ota,
# firmware, Keystore, MiAuth, Publisher), so patching `cli.<name>` replaces
# what the command handlers see without touching the real modules or
# hardware.

KEYS = MiKeys(
    token=bytes(range(12)), bindkey=bytes(range(16, 32)), device_id=b"did-abc123"
)


def seen(
    address: str, name: str | None, rssi: int
) -> tuple[BLEDevice, AdvertisementData]:
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


@dataclass
class FakeLink:
    """Enough of `transport.Link` for the command handlers under test."""

    address: str = "A4:C1:38:11:22:33"
    services: frozenset[str] = frozenset()
    info: DeviceInfo = field(default_factory=lambda: DeviceInfo(None, None, None))

    def has_service(self, uuid: str) -> bool:
        return uuid in self.services

    async def device_info(self) -> DeviceInfo:
        return self.info


class FakeConnect:
    """Replaces `connect`, handing out prepared links in order."""

    def __init__(self, *links: FakeLink) -> None:
        self._links = iter(links)
        self.calls: list[tuple[str | None, str | None]] = []

    @contextlib.asynccontextmanager
    async def __call__(
        self, target: str | None = None, *, adapter: str | None = None
    ) -> AsyncIterator[FakeLink]:
        self.calls.append((target, adapter))
        yield next(self._links)


class FakeScan:
    """Replaces `scan`, returning a fixed list of discoveries."""

    def __init__(self, pairs: Sequence[tuple[BLEDevice, AdvertisementData]]) -> None:
        self.pairs = list(pairs)
        self.calls: list[tuple[str | None, float, bool]] = []

    async def __call__(
        self,
        *,
        adapter: str | None = None,
        timeout: float = 10.0,
        all_devices: bool = False,
    ) -> list[tuple[BLEDevice, AdvertisementData]]:
        self.calls.append((adapter, timeout, all_devices))
        return self.pairs


def make_reader_module(
    decoded: dict[str, Reading | None] | None = None,
    watcher_readings: Sequence[Reading] = (),
) -> SimpleNamespace:
    """Stand in for `reader`: canned decodes, and a watcher that replays readings."""
    resolved = decoded or {}
    watchers: list[Any] = []

    def decode(
        device: BLEDevice, advertisement: AdvertisementData, bindkeys: Any = None
    ) -> Reading | None:
        del advertisement, bindkeys
        return resolved.get(device.address)

    class FakeWatcher:
        def __init__(self, **kwargs: Any) -> None:
            self.kwargs = kwargs
            self.duration: float | None = None
            watchers.append(self)

        async def run(
            self,
            on_reading: Callable[[Reading], None],
            *,
            duration: float | None = None,
        ) -> None:
            self.duration = duration
            for reading in watcher_readings:
                on_reading(reading)

    return SimpleNamespace(decode=decode, Watcher=FakeWatcher, watchers=watchers)


class FakePublisher:
    """Stands in for `mqtt.Publisher`, recording what would have been sent."""

    def __init__(self, url: str, topic_prefix: str) -> None:
        self.url = url
        self.topic_prefix = topic_prefix
        self.entered = False
        self.exited = False
        self.published: list[Reading] = []

    def __enter__(self) -> Self:
        self.entered = True
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.exited = True

    def publish(self, reading: Reading) -> None:
        self.published.append(reading)


def make_publisher_factory() -> tuple[
    Callable[[str, str], FakePublisher], list[FakePublisher]
]:
    created: list[FakePublisher] = []

    def factory(url: str, topic_prefix: str) -> FakePublisher:
        publisher = FakePublisher(url, topic_prefix)
        created.append(publisher)
        return publisher

    return factory, created


class FakeMiAuth:
    """Stands in for `MiAuth`, handing back fixed keys instead of registering."""

    def __init__(self, keys: MiKeys, link: Any) -> None:
        self.keys = keys
        self.link = link
        self.opened = False
        self.activated = False
        self.logged_in_with: bytes | None = None

    async def open(self) -> None:
        self.opened = True

    async def activate(self) -> MiKeys:
        self.activated = True
        return self.keys

    async def login(self, token: bytes) -> None:
        self.logged_in_with = token


def make_miauth(keys: MiKeys) -> tuple[Callable[[Any], FakeMiAuth], list[FakeMiAuth]]:
    instances: list[FakeMiAuth] = []

    def factory(link: Any) -> FakeMiAuth:
        instance = FakeMiAuth(keys, link)
        instances.append(instance)
        return instance

    return factory, instances


class _FakeStore:
    def __init__(self, saved: dict[str, MiKeys]) -> None:
        self._saved = saved

    def get(self, address: str) -> MiKeys | None:
        return self._saved.get(normalise(address))

    def put(self, address: str, keys: MiKeys) -> None:
        self._saved[normalise(address)] = keys


class FakeKeystore:
    """Stands in for `Keystore`, keeping keys in memory instead of on disk."""

    def __init__(self) -> None:
        self.saved: dict[str, MiKeys] = {}
        self.opened_with: list[Path | None] = []

    def open(self, path: Path | None = None) -> _FakeStore:
        self.opened_with.append(path)
        return _FakeStore(self.saved)


class FakeOTAModule:
    """Stands in for `ota`, recording the image it was asked to install."""

    def __init__(self) -> None:
        self.calls: list[tuple[Any, Any]] = []

    async def update(
        self,
        link: Any,
        image: Any,
        progress: Callable[[int, int], None] | None = None,
    ) -> None:
        self.calls.append((link, image))
        if progress is not None:
            progress(4, 8)


class FakeFirmwareModule:
    """Stands in for `firmware`, handing back one fixed image."""

    def __init__(self, image: FirmwareImage) -> None:
        self.image = image
        self.calls: list[tuple[int, Path | None]] = []

    def resolve(self, hardware_id: int, path: Path | None = None) -> FirmwareImage:
        self.calls.append((hardware_id, path))
        return self.image


def make_config_module(
    cfg: dict[str, Any], *, set_time_error: Error | None = None
) -> SimpleNamespace:
    """Stand in for `config`: an in-memory settings dict behind a fake session."""
    sessions: list[Any] = []

    class FakeConfigSession:
        def __init__(self, link: Any) -> None:
            self.link = link
            self.cfg = dict(cfg)
            self.opened = False
            self.reset_called = False
            self.written: list[dict[str, Any]] = []
            self.time_requested = False
            self.bindkey_writes: list[bytes] = []
            self.mi_keys_writes: list[tuple[bytes, bytes]] = []
            sessions.append(self)

        async def open(self) -> None:
            self.opened = True

        async def read_config(self) -> dict[str, Any]:
            return dict(self.cfg)

        async def reset_config(self) -> dict[str, Any]:
            self.reset_called = True
            self.cfg = {**self.cfg, "advertising_interval": 1}
            return dict(self.cfg)

        async def write_config(self, updated: dict[str, Any]) -> dict[str, Any]:
            self.written.append(dict(updated))
            self.cfg = dict(updated)
            return dict(self.cfg)

        async def set_time(self) -> int:
            self.time_requested = True
            if set_time_error is not None:
                raise set_time_error
            return 1_700_000_000

        async def set_bindkey(self, key: bytes) -> bytes:
            self.bindkey_writes.append(key)
            return key

        async def set_mi_keys(self, token: bytes, bindkey: bytes) -> None:
            self.mi_keys_writes.append((token, bindkey))

    def to_dict(current: dict[str, Any]) -> dict[str, Any]:
        return dict(current)

    def derived(current: dict[str, Any]) -> dict[str, float]:
        return {"advertising_interval_ms": current["advertising_interval"] * 62.5}

    def apply(current: dict[str, Any], settings: dict[str, str]) -> dict[str, Any]:
        # Mutates in place and returns it, like the real `config.apply`, since
        # `cmd_bootstrap` calls this only for the side effect and ignores the
        # return value.
        for name, value in settings.items():
            try:
                current[name] = int(value)
            except ValueError:
                current[name] = value
        return current

    def validate(settings: dict[str, str]) -> dict[str, str]:
        return dict(settings)

    return SimpleNamespace(
        Session=FakeConfigSession,
        sessions=sessions,
        to_dict=to_dict,
        derived=derived,
        apply=apply,
        validate=validate,
    )


# --- scan --------------------------------------------------------------


def test_scan_lists_devices_and_decoded_readings_as_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    with_reading, adv_with_reading = seen("A4:C1:38:00:00:01", "ATC_112233", -80)
    without_reading, adv_without_reading = seen("A4:C1:38:00:00:02", "ATC_445566", -90)
    fake_scan = FakeScan(
        [(with_reading, adv_with_reading), (without_reading, adv_without_reading)]
    )
    monkeypatch.setattr(cli, "scan", fake_scan)
    reading = Reading(with_reading.address, "pvvx", {"temperature": 21.5})
    monkeypatch.setattr(
        cli, "reader", make_reader_module(decoded={with_reading.address: reading})
    )

    assert cli.main(["--keys", str(tmp_path / "keys.json"), "scan"]) == 0

    assert fake_scan.calls == [(None, 10.0, False)]
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    assert lines[0] == (
        "A4:C1:38:00:00:01   -80 dBm  ATC_112233       pvvx     temperature=21.5"
    )
    assert without_reading.address in lines[1]
    assert "   ?" not in lines[0]  # it has a real rssi, unlike the row below
    assert "?" not in lines[0].split()[3]  # its format column is not empty either


def test_scan_explains_when_nothing_is_found(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "scan", FakeScan([]))
    monkeypatch.setattr(cli, "reader", make_reader_module())
    assert cli.main(["--keys", str(tmp_path / "keys.json"), "scan"]) == 0
    out = capsys.readouterr().out
    assert "No devices found" in out
    assert "both buttons" in out


def test_scan_json_reports_every_field(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    device, advertisement = seen("A4:C1:38:00:00:03", "ATC_778899", -55)
    monkeypatch.setattr(cli, "scan", FakeScan([(device, advertisement)]))
    reading = Reading(device.address, "bthome", {"humidity": 55})
    monkeypatch.setattr(
        cli, "reader", make_reader_module(decoded={device.address: reading})
    )

    assert cli.main(["--json", "--keys", str(tmp_path / "keys.json"), "scan"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload == [
        {
            "address": device.address,
            "name": "ATC_778899",
            "rssi": -55,
            "format": "bthome",
            "values": {"humidity": 55},
        }
    ]


def test_scan_all_asks_for_every_device_not_just_thermometers(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fake_scan = FakeScan([])
    monkeypatch.setattr(cli, "scan", fake_scan)
    monkeypatch.setattr(cli, "reader", make_reader_module())
    assert cli.main(["--keys", str(tmp_path / "keys.json"), "scan", "--all"]) == 0
    capsys.readouterr()
    assert fake_scan.calls == [(None, 10.0, True)]


def test_scan_prefers_the_name_from_this_advertisement_over_the_os_cache(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # bleak's BLEDevice.name is the OS's cached name from a previous sighting;
    # AdvertisementData.local_name is what was actually broadcast in *this*
    # packet. After a rename (e.g. activation strips the MHO-/ATC_ prefix) the
    # cache can be stale, so the freshly broadcast name must win.
    device = BLEDevice("A4:C1:38:00:00:04", "stale-cached-name", None)
    advertisement = AdvertisementData(
        local_name="ATC_998877",
        manufacturer_data={},
        service_data={},
        service_uuids=[],
        tx_power=None,
        rssi=-70,
        platform_data=(),
    )
    monkeypatch.setattr(cli, "scan", FakeScan([(device, advertisement)]))
    monkeypatch.setattr(cli, "reader", make_reader_module())

    assert cli.main(["--keys", str(tmp_path / "keys.json"), "scan"]) == 0

    out = capsys.readouterr().out
    assert "ATC_998877" in out
    assert "stale-cached-name" not in out


# --- info ----------------------------------------------------------------


def test_info_shows_settings_from_custom_firmware_as_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    info = DeviceInfo(
        firmware_revision="0005-pvvx", hardware_revision="1.0", software_revision="5.8"
    )
    link = FakeLink(
        address="A4:C1:38:00:00:09",
        services=frozenset({CUSTOM_SERVICE, OTA_SERVICE}),
        info=info,
    )
    monkeypatch.setattr(cli, "connect", FakeConnect(link))
    monkeypatch.setattr(
        cli,
        "config_module",
        make_config_module({"z_field": 1, "advertising_interval": 32}),
    )

    assert cli.main(["info"]) == 0

    out = capsys.readouterr().out
    assert "custom_firmware: True" in out
    assert "stock_firmware: False" in out
    assert "ota: True" in out
    assert "config:" in out
    assert "  advertising_interval: 32" in out
    assert "derived:" in out
    assert "  advertising_interval_ms: 2000.0" in out
    # Settings are listed alphabetically, not in whatever order the device
    # (or a dict) happens to return them.
    assert out.index("advertising_interval:") < out.index("z_field:")


def test_info_json_includes_config_and_derived_for_custom_firmware(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    info = DeviceInfo(
        firmware_revision="0005-pvvx", hardware_revision=None, software_revision=None
    )
    link = FakeLink(services=frozenset({CUSTOM_SERVICE}), info=info)
    monkeypatch.setattr(cli, "connect", FakeConnect(link))
    monkeypatch.setattr(
        cli, "config_module", make_config_module({"advertising_interval": 32})
    )

    assert cli.main(["--json", "info"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["hardware_id"] == HW_ID_EN  # firmware revision starts with "0005"
    assert payload["config"] == {"advertising_interval": 32}
    assert payload["derived"] == {"advertising_interval_ms": 2000.0}


def test_info_omits_config_for_stock_firmware(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    info = DeviceInfo(
        firmware_revision=None, hardware_revision=None, software_revision=None
    )
    link = FakeLink(services=frozenset({MI_AUTH_SERVICE}), info=info)
    monkeypatch.setattr(cli, "connect", FakeConnect(link))
    fake_config = make_config_module({"advertising_interval": 32})
    monkeypatch.setattr(cli, "config_module", fake_config)

    assert cli.main(["info"]) == 0

    out = capsys.readouterr().out
    assert "stock_firmware: True" in out
    assert "hardware_id" in out
    assert str(HW_ID_CH) in out
    assert "config:" not in out
    assert fake_config.sessions == []


# --- activate --------------------------------------------------------------


def test_activate_registers_and_saves_keys_as_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    link = FakeLink(address="a4:c1:38:00:00:09", services=frozenset({MI_AUTH_SERVICE}))
    monkeypatch.setattr(cli, "connect", FakeConnect(link))
    factory, _ = make_miauth(KEYS)
    monkeypatch.setattr(cli, "MiAuth", factory)
    fake_keystore = FakeKeystore()
    monkeypatch.setattr(cli, "Keystore", fake_keystore)
    keys_path = tmp_path / "keys.json"

    assert cli.main(["--keys", str(keys_path), "activate"]) == 0

    out = capsys.readouterr().out
    assert f"Token:    {KEYS.token.hex()}" in out
    assert f"Bind key: {KEYS.bindkey.hex()}" in out
    assert fake_keystore.saved[normalise(link.address)] == KEYS
    # `--keys` must reach `Keystore.open`, not just get parsed and dropped.
    assert fake_keystore.opened_with == [keys_path]


def test_activate_json_reports_the_normalised_address(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    link = FakeLink(address="a4:c1:38:00:00:09", services=frozenset({MI_AUTH_SERVICE}))
    monkeypatch.setattr(cli, "connect", FakeConnect(link))
    factory, _ = make_miauth(KEYS)
    monkeypatch.setattr(cli, "MiAuth", factory)
    monkeypatch.setattr(cli, "Keystore", FakeKeystore())

    assert cli.main(["--json", "activate"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "address": normalise(link.address),
        "token": KEYS.token.hex(),
        "bindkey": KEYS.bindkey.hex(),
        "device_id": KEYS.device_id.hex(),
    }


def test_activate_refuses_a_device_with_no_xiaomi_service(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    link = FakeLink(services=frozenset())
    monkeypatch.setattr(cli, "connect", FakeConnect(link))

    assert cli.main(["activate"]) == 1

    assert "does not offer the Xiaomi authentication service" in capsys.readouterr().err


# --- flash -------------------------------------------------------------


def test_flash_command_skips_activation_when_asked(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    info = DeviceInfo(
        firmware_revision=None, hardware_revision=None, software_revision=None
    )
    link = FakeLink(services=frozenset({MI_AUTH_SERVICE}), info=info)
    monkeypatch.setattr(cli, "connect", FakeConnect(link))
    fake_ota = FakeOTAModule()
    monkeypatch.setattr(cli, "ota", fake_ota)
    image = FirmwareImage(name="fw.bin", data=b"\x00" * 16)
    fake_firmware = FakeFirmwareModule(image)
    monkeypatch.setattr(cli, "firmware", fake_firmware)
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)

    assert cli.main(["flash", "--skip-activation"]) == 0

    assert fake_ota.calls == [(link, image)]
    assert fake_firmware.calls == [(HW_ID_CH, None)]
    assert capsys.readouterr().err == "\rFlashing:  50% (4/8 blocks)\n"


def test_flash_logs_in_with_saved_keys_before_updating(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    link = FakeLink(services=frozenset({MI_AUTH_SERVICE}))
    monkeypatch.setattr(cli, "connect", FakeConnect(link))
    fake_keystore = FakeKeystore()
    fake_keystore.saved[normalise(link.address)] = KEYS
    monkeypatch.setattr(cli, "Keystore", fake_keystore)
    factory, instances = make_miauth(KEYS)
    monkeypatch.setattr(cli, "MiAuth", factory)
    fake_ota = FakeOTAModule()
    monkeypatch.setattr(cli, "ota", fake_ota)
    image = FirmwareImage(name="fw.bin", data=b"\x00" * 16)
    monkeypatch.setattr(cli, "firmware", FakeFirmwareModule(image))
    keys_path = tmp_path / "keys.json"

    assert cli.main(["--keys", str(keys_path), "flash"]) == 0

    assert instances[0].opened is True
    assert instances[0].logged_in_with == KEYS.token
    assert fake_ota.calls == [(link, image)]
    assert capsys.readouterr().err == ""  # stderr is not a tty under capsys
    # `--keys` must reach `Keystore.open`, not just get parsed and dropped.
    assert fake_keystore.opened_with == [keys_path]


async def test_flash_refuses_to_run_without_saved_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    link = FakeLink(services=frozenset({MI_AUTH_SERVICE}))
    monkeypatch.setattr(cli, "Keystore", FakeKeystore())
    args = argparse.Namespace(keys=None, firmware=None)

    with pytest.raises(Error, match="no saved Xiaomi keys"):
        await cli.flash(link, args, login_first=True)  # ty: ignore[invalid-argument-type]


def test_flash_does_not_attempt_a_login_on_a_device_already_running_custom_firmware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `login_first` defaults True (no `--skip-activation`), but a device that
    # only offers CUSTOM_SERVICE has no Xiaomi auth service to log in to; the
    # gate must check for MI_AUTH_SERVICE too, not just `login_first`.
    info = DeviceInfo(
        firmware_revision=None, hardware_revision=None, software_revision=None
    )
    link = FakeLink(services=frozenset({CUSTOM_SERVICE}), info=info)
    monkeypatch.setattr(cli, "connect", FakeConnect(link))
    fake_keystore = FakeKeystore()
    monkeypatch.setattr(cli, "Keystore", fake_keystore)
    factory, instances = make_miauth(KEYS)
    monkeypatch.setattr(cli, "MiAuth", factory)
    fake_ota = FakeOTAModule()
    monkeypatch.setattr(cli, "ota", fake_ota)
    image = FirmwareImage(name="fw.bin", data=b"\x00" * 16)
    monkeypatch.setattr(cli, "firmware", FakeFirmwareModule(image))

    assert cli.main(["flash"]) == 0

    assert instances == []  # no MiAuth was ever constructed
    assert fake_keystore.opened_with == []  # no Keystore was opened either
    assert fake_ota.calls == [(link, image)]  # the update still ran


# --- bootstrap -----------------------------------------------------------


def test_bootstrap_activates_flashes_and_configures_a_fresh_device(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setattr(cli, "REBOOT_WAIT", 0.0)
    sleeps: list[float] = []

    async def fake_sleep(delay: float) -> None:
        sleeps.append(delay)

    monkeypatch.setattr(cli.asyncio, "sleep", fake_sleep)

    stock_link = FakeLink(
        address="A4:C1:38:00:00:09", services=frozenset({MI_AUTH_SERVICE})
    )
    custom_link = FakeLink(
        address=stock_link.address, services=frozenset({CUSTOM_SERVICE})
    )
    fake_connect = FakeConnect(stock_link, custom_link)
    monkeypatch.setattr(cli, "connect", fake_connect)
    fake_keystore = FakeKeystore()
    monkeypatch.setattr(cli, "Keystore", fake_keystore)
    factory, instances = make_miauth(KEYS)
    monkeypatch.setattr(cli, "MiAuth", factory)
    fake_ota = FakeOTAModule()
    monkeypatch.setattr(cli, "ota", fake_ota)
    image = FirmwareImage(name="fw.bin", data=b"\x00" * 16)
    monkeypatch.setattr(cli, "firmware", FakeFirmwareModule(image))
    fake_config = make_config_module(
        {"advertising_type": "PVVX", "advertising_interval": 32}
    )
    monkeypatch.setattr(cli, "config_module", fake_config)
    keys_path = tmp_path / "keys.json"

    assert cli.main(["--keys", str(keys_path), "bootstrap"]) == 0

    assert instances[0].activated is True
    assert fake_keystore.saved[normalise(stock_link.address)] == KEYS
    assert fake_ota.calls == [(stock_link, image)]
    session = fake_config.sessions[0]
    assert session.written[0]["advertising_type"] == "BTHOME"
    assert session.bindkey_writes == [KEYS.bindkey]
    assert session.mi_keys_writes == [(KEYS.token, KEYS.bindkey)]
    assert sleeps == [0.0]
    # `--keys` must reach `Keystore.open`, not just get parsed and dropped.
    assert fake_keystore.opened_with == [keys_path]

    out = capsys.readouterr().out
    assert "Bootstrapped. Current settings:" in out
    assert "advertising_type" in out


def test_bootstrap_skips_activation_for_a_device_already_on_custom_firmware(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(cli, "REBOOT_WAIT", 0.0)

    async def fake_sleep(delay: float) -> None:
        del delay

    monkeypatch.setattr(cli.asyncio, "sleep", fake_sleep)

    link = FakeLink(address="A4:C1:38:00:00:10", services=frozenset({CUSTOM_SERVICE}))
    second_link = FakeLink(address=link.address, services=frozenset({CUSTOM_SERVICE}))
    monkeypatch.setattr(cli, "connect", FakeConnect(link, second_link))
    fake_keystore = FakeKeystore()
    monkeypatch.setattr(cli, "Keystore", fake_keystore)
    fake_ota = FakeOTAModule()
    monkeypatch.setattr(cli, "ota", fake_ota)
    image = FirmwareImage(name="fw.bin", data=b"\x00" * 16)
    monkeypatch.setattr(cli, "firmware", FakeFirmwareModule(image))
    fake_config = make_config_module(
        {"advertising_type": "PVVX", "advertising_interval": 32}
    )
    monkeypatch.setattr(cli, "config_module", fake_config)

    with caplog.at_level(logging.INFO, logger="mjwsd05ctl"):
        assert cli.main(["--json", "bootstrap"]) == 0

    assert "skipping activation" in caplog.text
    assert fake_keystore.saved == {}
    session = fake_config.sessions[0]
    assert session.bindkey_writes == []
    assert session.mi_keys_writes == []
    payload = json.loads(capsys.readouterr().out)
    assert payload["advertising_type"] == "BTHOME"


def test_bootstrap_no_configure_stops_after_flashing(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    link = FakeLink(services=frozenset({MI_AUTH_SERVICE}))
    fake_connect = FakeConnect(link)
    monkeypatch.setattr(cli, "connect", fake_connect)
    monkeypatch.setattr(cli, "Keystore", FakeKeystore())
    factory, _ = make_miauth(KEYS)
    monkeypatch.setattr(cli, "MiAuth", factory)
    monkeypatch.setattr(cli, "ota", FakeOTAModule())
    image = FirmwareImage(name="fw.bin", data=b"\x00" * 16)
    monkeypatch.setattr(cli, "firmware", FakeFirmwareModule(image))
    fake_config = make_config_module({"advertising_interval": 32})
    monkeypatch.setattr(cli, "config_module", fake_config)

    assert cli.main(["bootstrap", "--no-configure"]) == 0

    assert len(fake_connect.calls) == 1
    assert fake_config.sessions == []
    assert "Bootstrapped" not in capsys.readouterr().out


def test_bootstrap_tolerates_a_device_that_refuses_to_set_the_clock(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "REBOOT_WAIT", 0.0)

    async def fake_sleep(delay: float) -> None:
        del delay

    monkeypatch.setattr(cli.asyncio, "sleep", fake_sleep)

    link = FakeLink(services=frozenset({CUSTOM_SERVICE}))
    second_link = FakeLink(services=frozenset({CUSTOM_SERVICE}))
    monkeypatch.setattr(cli, "connect", FakeConnect(link, second_link))
    monkeypatch.setattr(cli, "Keystore", FakeKeystore())
    monkeypatch.setattr(cli, "ota", FakeOTAModule())
    image = FirmwareImage(name="fw.bin", data=b"\x00" * 16)
    monkeypatch.setattr(cli, "firmware", FakeFirmwareModule(image))
    fake_config = make_config_module(
        {"advertising_type": "PVVX", "advertising_interval": 32},
        set_time_error=ConfigError("clock refused"),
    )
    monkeypatch.setattr(cli, "config_module", fake_config)

    assert cli.main(["bootstrap"]) == 0

    session = fake_config.sessions[0]
    assert session.time_requested is True
    assert "Bootstrapped" in capsys.readouterr().out


# --- config ----------------------------------------------------------------


def test_config_shows_current_settings_as_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "connect", FakeConnect(FakeLink()))
    fake_config = make_config_module({"advertising_interval": 32})
    monkeypatch.setattr(cli, "config_module", fake_config)

    assert cli.main(["config"]) == 0

    out = capsys.readouterr().out
    assert "advertising_interval       32" in out
    assert "advertising_interval_ms    2000" in out
    session = fake_config.sessions[0]
    assert session.reset_called is False
    assert session.written == []


def test_config_json_reports_config_and_derived_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "connect", FakeConnect(FakeLink()))
    monkeypatch.setattr(
        cli, "config_module", make_config_module({"advertising_interval": 32})
    )

    assert cli.main(["--json", "config"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "config": {"advertising_interval": 32},
        "derived": {"advertising_interval_ms": 2000.0},
    }


def test_config_reset_restores_factory_settings(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "connect", FakeConnect(FakeLink()))
    fake_config = make_config_module({"advertising_interval": 32})
    monkeypatch.setattr(cli, "config_module", fake_config)

    assert cli.main(["--json", "config", "--reset"]) == 0

    assert fake_config.sessions[0].reset_called is True
    payload = json.loads(capsys.readouterr().out)
    assert payload["config"]["advertising_interval"] == 1


def test_config_set_changes_a_setting(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "connect", FakeConnect(FakeLink()))
    fake_config = make_config_module({"advertising_interval": 32})
    monkeypatch.setattr(cli, "config_module", fake_config)

    assert cli.main(["--json", "config", "--set", "advertising_interval=64"]) == 0

    assert fake_config.sessions[0].written == [{"advertising_interval": 64}]
    payload = json.loads(capsys.readouterr().out)
    assert payload["config"]["advertising_interval"] == 64


def test_config_set_time_updates_the_clock(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(cli, "connect", FakeConnect(FakeLink()))
    fake_config = make_config_module({"advertising_interval": 32})
    monkeypatch.setattr(cli, "config_module", fake_config)

    with caplog.at_level(logging.INFO, logger="mjwsd05ctl"):
        assert cli.main(["config", "--set-time"]) == 0

    assert fake_config.sessions[0].time_requested is True
    assert "clock set; device now reports 1700000000" in caplog.text
    capsys.readouterr()


def test_config_set_bindkey_writes_the_saved_bind_key(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
) -> None:
    link = FakeLink(address="A4:C1:38:00:00:11")
    monkeypatch.setattr(cli, "connect", FakeConnect(link))
    fake_keystore = FakeKeystore()
    fake_keystore.saved[normalise(link.address)] = KEYS
    monkeypatch.setattr(cli, "Keystore", fake_keystore)
    fake_config = make_config_module({"advertising_interval": 32})
    monkeypatch.setattr(cli, "config_module", fake_config)
    keys_path = tmp_path / "keys.json"

    with caplog.at_level(logging.INFO, logger="mjwsd05ctl"):
        assert cli.main(["--keys", str(keys_path), "config", "--set-bindkey"]) == 0

    assert fake_config.sessions[0].bindkey_writes == [KEYS.bindkey]
    assert "bind key written" in caplog.text
    # `--keys` must reach `Keystore.open`, not just get parsed and dropped.
    assert fake_keystore.opened_with == [keys_path]
    capsys.readouterr()


def test_config_set_bindkey_without_saved_keys_is_an_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "connect", FakeConnect(FakeLink()))
    monkeypatch.setattr(cli, "Keystore", FakeKeystore())
    monkeypatch.setattr(
        cli, "config_module", make_config_module({"advertising_interval": 32})
    )

    assert cli.main(["config", "--set-bindkey"]) == 1

    assert "no saved Xiaomi keys for this device" in capsys.readouterr().err


# --- read --------------------------------------------------------------


def test_format_pads_the_type_column_and_appends_errors() -> None:
    ok = Reading("A4:C1:38:00:00:01", "pvvx", {"temperature": 21.5})
    assert cli._format(ok) == "A4:C1:38:00:00:01 pvvx     temperature=21.5"
    bad = Reading("A4:C1:38:00:00:02", "mi", {}, error="decryption: no key")
    assert cli._format(bad) == "A4:C1:38:00:00:02 mi        [decryption: no key]"


def test_read_prints_decoded_lines_as_text(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    ok = Reading("A4:C1:38:00:00:01", "pvvx", {"temperature": 21.5})
    bad = Reading("A4:C1:38:00:00:02", "mi", {}, error="decryption: no key")
    fake_reader = make_reader_module(watcher_readings=[ok, bad])
    monkeypatch.setattr(cli, "reader", fake_reader)

    assert (
        cli.main(["--keys", str(tmp_path / "keys.json"), "read", "--duration", "0"])
        == 0
    )

    lines = capsys.readouterr().out.splitlines()
    assert lines == [cli._format(ok), cli._format(bad)]
    watcher = fake_reader.watchers[0]
    assert watcher.duration == 0.0
    assert watcher.kwargs["passive"] is False
    assert watcher.kwargs["addresses"] == frozenset()


def test_read_passes_passive_and_normalised_addresses_to_the_watcher(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    fake_reader = make_reader_module()
    monkeypatch.setattr(cli, "reader", fake_reader)

    assert (
        cli.main(
            [
                "--keys",
                str(tmp_path / "keys.json"),
                "read",
                "--passive",
                "--address",
                "a4:c1:38:00:00:01",
                "--address",
                "a4:c1:38:00:00:02",
                "--duration",
                "0",
            ]
        )
        == 0
    )

    capsys.readouterr()
    watcher = fake_reader.watchers[0]
    assert watcher.kwargs["passive"] is True
    assert watcher.kwargs["addresses"] == {"A4:C1:38:00:00:01", "A4:C1:38:00:00:02"}


def test_read_prints_decoded_readings_as_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    reading = Reading("A4:C1:38:00:00:01", "bthome", {"humidity": 55}, rssi=-60)
    monkeypatch.setattr(cli, "reader", make_reader_module(watcher_readings=[reading]))

    assert cli.main(["--json", "--keys", str(tmp_path / "keys.json"), "read"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload == json.loads(reading.as_json())


def test_read_publishes_each_reading_to_mqtt(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    reading = Reading("A4:C1:38:00:00:01", "pvvx", {"temperature": 21.5})
    monkeypatch.setattr(cli, "reader", make_reader_module(watcher_readings=[reading]))
    publisher_factory, publishers = make_publisher_factory()
    monkeypatch.setattr(cli, "Publisher", publisher_factory)

    assert (
        cli.main(
            [
                "--keys",
                str(tmp_path / "keys.json"),
                "read",
                "--mqtt",
                "test.example:1883",
            ]
        )
        == 0
    )

    capsys.readouterr()
    publisher = publishers[0]
    assert publisher.url == "test.example:1883"
    assert publisher.topic_prefix == "mjwsd05ctl"
    assert publisher.entered is True
    assert publisher.exited is True
    assert publisher.published == [reading]


def test_progress_reports_percentage_when_stderr_is_a_terminal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys.stderr, "isatty", lambda: True)
    cli._progress(3, 10)
    assert capsys.readouterr().err == "\rFlashing:  30% (3/10 blocks)"


def test_progress_stays_silent_when_stderr_is_not_a_terminal(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys.stderr, "isatty", lambda: False)
    cli._progress(3, 10)
    assert capsys.readouterr().err == ""
