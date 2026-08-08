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

"""The `mjwsd05ctl` command."""

import argparse
import asyncio
import contextlib
import functools
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from bleak import BleakError
from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm

from . import config as config_module
from . import firmware, ota, reader
from .constants import (
    CUSTOM_SERVICE,
    MI_AUTH_CONTROL_CHAR,
    OTA_SERVICE,
    AdvertisingType,
)
from .errors import Error, TransportError
from .keystore import Keystore, bindkeys, normalise
from .miauth import MiAuth, MiKeys
from .mqtt import Publisher
from .transport import Link, connect, scan

if TYPE_CHECKING:
    from collections.abc import Sequence
    from contextlib import AbstractAsyncContextManager

log = logging.getLogger("mjwsd05ctl")

# A device reboots into its new firmware after an update and needs a moment
# before it will accept a connection again.
REBOOT_WAIT = 8.0
# The freshly booted firmware advertises every five seconds by default, so a
# single ten-second scan misses it often enough to need more than one look.
RECONNECT_ATTEMPTS = 4


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
        stream=sys.stderr,
    )
    if not args.verbose:
        logging.getLogger("bleak").setLevel(logging.WARNING)

    try:
        return asyncio.run(args.handler(args))
    except (Error, BleakError) as exc:
        # Expected failures get a plain message; a traceback would only be noise.
        # BleakError covers what the platform's own stack refuses, such as
        # Bluetooth being switched off or permission being denied.
        print(f"mjwsd05ctl: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mjwsd05ctl",
        description="Activate, flash, configure, and read a Xiaomi MJWSD05MMC.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="log every packet")
    parser.add_argument("--adapter", help="Bluetooth adapter to use, such as hci0")
    parser.add_argument("--keys", type=Path, help="path to the Xiaomi key store")
    parser.add_argument("--json", action="store_true", help="emit JSON, not text")
    parser.add_argument(
        "--pin",
        action="store_true",
        help="bond with the device, which is needed only once a PIN code has "
        "been set on it; the code is collected by whatever Bluetooth agent the "
        "system has registered, such as bluetoothctl, not by this tool",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def device_args(sub: argparse.ArgumentParser) -> None:
        sub.add_argument(
            "--address", help="device address; omit to use the closest one found"
        )

    scan_parser = subparsers.add_parser("scan", help="list nearby devices")
    scan_parser.add_argument("--timeout", type=float, default=10.0)
    scan_parser.add_argument(
        "--all", action="store_true", help="include devices that are not thermometers"
    )
    scan_parser.set_defaults(handler=cmd_scan)

    info_parser = subparsers.add_parser("info", help="show what a device reports")
    device_args(info_parser)
    info_parser.set_defaults(handler=cmd_info)

    activate_parser = subparsers.add_parser(
        "activate", help="register with the device and save its Xiaomi keys"
    )
    device_args(activate_parser)
    activate_parser.set_defaults(handler=cmd_activate)

    flash_parser = subparsers.add_parser("flash", help="install firmware")
    device_args(flash_parser)
    flash_parser.add_argument("--firmware", type=Path, help="image to install")
    flash_parser.add_argument(
        "--skip-activation",
        action="store_true",
        help="do not log in first, even on stock firmware",
    )
    flash_parser.set_defaults(handler=cmd_flash)

    bootstrap_parser = subparsers.add_parser(
        "bootstrap", help="activate, flash, and configure a factory-fresh device"
    )
    device_args(bootstrap_parser)
    bootstrap_parser.add_argument("--firmware", type=Path)
    bootstrap_parser.add_argument(
        "--no-configure", action="store_true", help="stop after flashing"
    )
    bootstrap_parser.set_defaults(handler=cmd_bootstrap)

    config_parser = subparsers.add_parser("config", help="show or change settings")
    device_args(config_parser)
    config_parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="change a setting; may be repeated",
    )
    config_parser.add_argument(
        "--reset", action="store_true", help="restore factory settings"
    )
    config_parser.add_argument(
        "--set-time", action="store_true", help="set the clock from this host"
    )
    config_parser.add_argument(
        "--set-bindkey",
        action="store_true",
        help="write the saved Xiaomi bind key, enabling encrypted advertising",
    )
    config_parser.add_argument(
        "--fields", action="store_true", help="list the settings and exit"
    )
    config_parser.set_defaults(handler=cmd_config)

    comfort_parser = subparsers.add_parser(
        "comfort", help="show or set the band the display's smiley reflects"
    )
    device_args(comfort_parser)
    comfort_parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="change a limit, such as temperature_min=20.5; may be repeated",
    )
    comfort_parser.set_defaults(handler=cmd_comfort)

    reboot_parser = subparsers.add_parser("reboot", help="restart the device")
    device_args(reboot_parser)
    reboot_parser.set_defaults(handler=cmd_reboot)

    read_parser = subparsers.add_parser("read", help="decode advertisements")
    read_parser.add_argument(
        "--address", action="append", default=[], help="only this device; repeatable"
    )
    read_parser.add_argument(
        "--duration", type=float, help="stop after this many seconds"
    )
    read_parser.add_argument(
        "--passive",
        action="store_true",
        help="passive scanning, which needs BlueZ and a recent kernel",
    )
    read_parser.add_argument(
        "--duplicates",
        action="store_true",
        help="report every advertisement, not one per measurement",
    )
    read_parser.add_argument("--mqtt", help="broker URL to publish to")
    read_parser.add_argument("--topic-prefix", default="mjwsd05ctl")
    read_parser.set_defaults(handler=cmd_read)

    return parser


def open_link(
    args: argparse.Namespace, address: str | None = None
) -> AbstractAsyncContextManager[Link]:
    """Connect to the device this invocation is about.

    Every command goes through here so that `--pin` reaches all of them; a call
    site that connected on its own would silently ignore it.
    """
    return connect(
        args.address if address is None else address,
        adapter=args.adapter,
        pair=args.pin,
    )


async def cmd_scan(args: argparse.Namespace) -> int:
    found = await scan(adapter=args.adapter, timeout=args.timeout, all_devices=args.all)
    keys = bindkeys(args.keys)
    rows = [
        ScanRow(
            address=device.address,
            name=advertisement.local_name or device.name,
            rssi=advertisement.rssi,
            reading=reader.decode(device, advertisement, keys),
        )
        for device, advertisement in found
    ]

    if args.json:
        print(json.dumps([row.as_dict() for row in rows], indent=2, sort_keys=True))
    elif not rows:
        print("No devices found. Hold both buttons to wake a sleeping device.")
    else:
        for row in rows:
            print(row.as_line())
    return 0


@dataclass(frozen=True, slots=True)
class ScanRow:
    """One device seen while scanning."""

    address: str
    name: str | None
    rssi: int | None
    reading: reader.Reading | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "name": self.name,
            "rssi": self.rssi,
            "format": self.reading.format if self.reading else None,
            "values": self.reading.values if self.reading else {},
        }

    def as_line(self) -> str:
        values = self.reading.values if self.reading else {}
        summary = " ".join(f"{name}={value}" for name, value in values.items())
        fmt = self.reading.format if self.reading else ""
        rssi = f"{self.rssi:>4}" if self.rssi is not None else "   ?"
        return f"{self.address}  {rssi} dBm  {self.name or '?':<16} {fmt:<8} {summary}"


def has_mi_auth(link: Link) -> bool:
    """Whether the stock firmware's Xiaomi authentication is on offer.

    The FE95 service's presence cannot answer this: the pvvx firmware keeps a
    bare declaration of the same service, with no characteristics in it, so
    only the control characteristic tells stock firmware apart.
    """
    return link.has_characteristic(MI_AUTH_CONTROL_CHAR)


async def cmd_info(args: argparse.Namespace) -> int:
    async with open_link(args) as link:
        info = await link.device_info()
        report: dict[str, Any] = {
            "address": link.address,
            "firmware_revision": info.firmware_revision,
            "hardware_revision": info.hardware_revision,
            "software_revision": info.software_revision,
            "hardware_id": info.hardware_id,
            "stock_firmware": has_mi_auth(link),
            "custom_firmware": link.has_service(CUSTOM_SERVICE),
            "ota": link.has_service(OTA_SERVICE),
        }
        if link.has_service(CUSTOM_SERVICE):
            session = config_module.Session(link)
            await session.open()
            addresses = await session.mac_address()
            # The address the connection came in on is a per-host UUID on macOS,
            # so the one the device reports is not redundant with it.
            report["mac_address"] = addresses.public
            report["random_mac_address"] = addresses.random_static
            identity = await session.device_id()
            report["firmware_version"] = config_module.software_version(identity)
            report["bindkey_stored"] = await session.get_bindkey() is not None
            cfg = await session.read_config()
            report["config"] = config_module.to_dict(cfg)
            report["derived"] = config_module.derived(cfg)
            report["comfort"] = config_module.comfort_to_dict(await session.comfort())

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for key, value in report.items():
            if isinstance(value, dict):
                print(f"{key}:")
                for name, item in sorted(value.items()):
                    print(f"  {name}: {item}")
            else:
                print(f"{key}: {value}")
    return 0


async def cmd_activate(args: argparse.Namespace) -> int:
    async with open_link(args) as link:
        keys = await activate(link)
        store = Keystore.open(args.keys)
        store.put(link.address, keys)
        payload = {
            "address": normalise(link.address),
            "token": keys.token.hex(),
            "bindkey": keys.bindkey.hex(),
            "device_id": keys.device_id.hex(),
        }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Token:    {payload['token']}")
        print(f"Bind key: {payload['bindkey']}")
    return 0


async def activate(link: Link) -> MiKeys:
    if not has_mi_auth(link):
        msg = (
            "device does not offer the Xiaomi authentication characteristics; "
            "it is not running stock firmware"
        )
        raise Error(msg)
    auth = MiAuth(link)
    await auth.open()
    return await auth.activate()


async def cmd_flash(args: argparse.Namespace) -> int:
    async with open_link(args) as link:
        await flash(link, args, login_first=not args.skip_activation)
    return 0


async def flash(link: Link, args: argparse.Namespace, *, login_first: bool) -> None:
    """Install firmware, logging in first if the device is still stock."""
    if login_first and has_mi_auth(link):
        store = Keystore.open(args.keys)
        known = store.get(link.address)
        if known is None:
            msg = (
                "no saved Xiaomi keys for this device; "
                "run `mjwsd05ctl activate` first, or use `bootstrap`"
            )
            raise Error(msg)
        auth = MiAuth(link)
        await auth.open()
        await auth.login(known.token)

    info = await link.device_info()
    image = firmware.resolve(info.hardware_id, args.firmware)
    # `disable=None` shows the bar only when stderr is a terminal. The log
    # lines `ota` emits share that stream, so they must be redirected through
    # the bar or they splice into its carriage-return redraws.
    with (
        logging_redirect_tqdm(),
        tqdm(desc="Flashing", unit="block", disable=None) as bar,
    ):
        await ota.update(
            link,
            image,
            hardware_id=info.hardware_id,
            progress=functools.partial(_progress, bar),
        )


def _progress(bar: tqdm, done: int, total: int) -> None:
    bar.total = total
    bar.update(done - bar.n)


async def cmd_bootstrap(args: argparse.Namespace) -> int:
    keys: MiKeys | None = None
    async with open_link(args) as link:
        address = link.address
        if link.has_service(CUSTOM_SERVICE):
            log.info("device already runs custom firmware; skipping activation")
        else:
            keys = await activate(link)
            Keystore.open(args.keys).put(address, keys)
        await flash(link, args, login_first=False)

    if args.no_configure:
        return 0

    log.info("waiting for the device to restart")
    await asyncio.sleep(REBOOT_WAIT)

    attempt = 0
    while True:
        attempt += 1
        try:
            report = await _bootstrap_configure(args, address, keys)
            break
        except TransportError as exc:
            if attempt == RECONNECT_ATTEMPTS:
                raise
            log.warning("reconnect %d/%d failed: %s", attempt, RECONNECT_ATTEMPTS, exc)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print("Bootstrapped. Current settings:")
        for name, value in report.items():
            print(f"  {name}: {value}")
    return 0


async def _bootstrap_configure(
    args: argparse.Namespace, address: str, keys: MiKeys | None
) -> dict[str, int | bool | str]:
    """One attempt at bootstrap's post-reboot configuration pass."""
    async with open_link(args, address) as link:
        session = config_module.Session(link)
        await session.open()
        cfg = await session.read_config()
        config_module.apply(cfg, {"advertising_type": AdvertisingType.BTHOME.name})
        cfg = await session.write_config(cfg)
        with contextlib.suppress(Error):
            await session.set_time()
        if keys is not None:
            await session.set_bindkey(keys.bindkey)
            await session.set_mi_keys(keys.token, keys.bindkey)
        return config_module.to_dict(cfg)


async def cmd_config(args: argparse.Namespace) -> int:
    if args.fields:
        for name, spec in config_module.FIELDS.items():
            kind = _describe_field(spec)
            suffix = " (read-only)" if spec.read_only else ""
            print(f"{name:<26} {kind:<28} {spec.help}{suffix}")
        return 0

    settings = _parse_settings(args.set)
    config_module.validate(settings)
    async with open_link(args) as link:
        session = config_module.Session(link)
        await session.open()

        cfg = (
            await session.reset_config() if args.reset else await session.read_config()
        )
        if settings:
            cfg = await session.write_config(config_module.apply(cfg, settings))
        if args.set_time:
            stamp = await session.set_time()
            log.info("clock set; device now reports %d", stamp)
        if args.set_bindkey:
            known = Keystore.open(args.keys).get(link.address)
            if known is None:
                msg = "no saved Xiaomi keys for this device"
                raise Error(msg)
            await session.set_bindkey(known.bindkey)
            log.info("bind key written")

        report = config_module.to_dict(cfg)
        extra = config_module.derived(cfg)

    if args.json:
        print(
            json.dumps({"config": report, "derived": extra}, indent=2, sort_keys=True)
        )
    else:
        for name, value in report.items():
            print(f"{name:<26} {value}")
        for name, value in extra.items():
            print(f"{name:<26} {value:g}")
    return 0


async def cmd_comfort(args: argparse.Namespace) -> int:
    settings = _parse_settings(args.set)
    config_module.validate_comfort(settings)
    async with open_link(args) as link:
        session = config_module.Session(link)
        await session.open()
        zone = await session.comfort()
        if settings:
            zone = await session.write_comfort(
                config_module.apply_comfort(zone, settings)
            )
        report = config_module.comfort_to_dict(zone)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(
            f"Comfortable between {report['temperature_min']:g} and "
            f"{report['temperature_max']:g} °C, {report['humidity_min']:g} and "
            f"{report['humidity_max']:g} %"
        )
    return 0


async def cmd_reboot(args: argparse.Namespace) -> int:
    async with open_link(args) as link:
        address = link.address
        session = config_module.Session(link)
        await session.open()
        await session.reboot()

    # The firmware restarts on disconnect, not on the command itself, so this
    # is only true once the connection above has been closed.
    if args.json:
        print(
            json.dumps(
                {"address": address, "restarting": True}, indent=2, sort_keys=True
            )
        )
    else:
        print("Device is restarting.")
    return 0


def _describe_field(spec: config_module.FieldSpec) -> str:
    if spec.boolean:
        return "yes/no"
    if spec.choices is not None:
        return "|".join(member.name for member in spec.choices)
    span = f"{spec.minimum}..{spec.maximum}"
    return f"{span} {spec.unit}".strip()


def _parse_settings(items: Sequence[str]) -> dict[str, str]:
    settings: dict[str, str] = {}
    for item in items:
        name, separator, value = item.partition("=")
        if not separator:
            msg = f"expected NAME=VALUE, got {item!r}"
            raise Error(msg)
        settings[name.strip()] = value
    return settings


async def cmd_read(args: argparse.Namespace) -> int:
    publisher = Publisher(args.mqtt, args.topic_prefix) if args.mqtt else None
    watcher = reader.Watcher(
        bindkeys=bindkeys(args.keys),
        adapter=args.adapter,
        passive=args.passive,
        addresses=frozenset(normalise(a) for a in args.address),
        deduplicate=not args.duplicates,
    )

    def emit(reading: reader.Reading) -> None:
        print(reading.as_json() if args.json else _format(reading), flush=True)
        if publisher is not None:
            publisher.publish(reading)

    with contextlib.ExitStack() as stack:
        if publisher is not None:
            stack.enter_context(publisher)
        await watcher.run(emit, duration=args.duration)
    return 0


def _format(reading: reader.Reading) -> str:
    body = " ".join(f"{name}={value}" for name, value in reading.values.items())
    suffix = f" [{reading.error}]" if reading.error else ""
    return f"{reading.address} {reading.format:<8} {body}{suffix}"


if __name__ == "__main__":
    sys.exit(main())
