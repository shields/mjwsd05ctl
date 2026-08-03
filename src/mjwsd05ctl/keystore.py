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

"""Persistence for per-device Xiaomi keys.

Losing the token means losing the ability to restore the device to Mi Home, and
losing the bind key means encrypted advertisements become undecodable, so both
are written out as soon as registration produces them.
"""

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from .errors import Error
from .miauth import MiKeys

log = logging.getLogger(__name__)

ENV_VAR = "MJWSD05CTL_KEYS"

# Keys are secrets: the file is owner-only, and so is the directory holding it.
FILE_MODE = 0o600
DIR_MODE = 0o700


def default_path() -> Path:
    if override := os.environ.get(ENV_VAR):
        return Path(override)
    config = os.environ.get("XDG_CONFIG_HOME")
    base = Path(config) if config else Path.home() / ".config"
    return base / "mjwsd05ctl" / "keys.json"


def normalise(address: str) -> str:
    return address.strip().upper()


@dataclass(frozen=True, slots=True)
class Keystore:
    """A JSON file mapping device address to its Xiaomi keys."""

    path: Path

    @classmethod
    def open(cls, path: Path | None = None) -> Keystore:
        return cls(path or default_path())

    def load(self) -> dict[str, MiKeys]:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            msg = f"cannot read key store {self.path}: {exc}"
            raise Error(msg) from exc

        keys = {}
        for address, entry in raw.items():
            try:
                keys[normalise(address)] = MiKeys(
                    token=bytes.fromhex(entry["token"]),
                    bindkey=bytes.fromhex(entry["bindkey"]),
                    device_id=bytes.fromhex(entry.get("device_id", "")),
                )
            except (KeyError, TypeError, ValueError, Error) as exc:
                log.warning("ignoring unusable key store entry %s: %s", address, exc)
        return keys

    def get(self, address: str) -> MiKeys | None:
        return self.load().get(normalise(address))

    def put(self, address: str, keys: MiKeys) -> None:
        entries = self.load()
        entries[normalise(address)] = keys
        self._write(entries)
        log.info("saved Xiaomi keys for %s to %s", normalise(address), self.path)

    def _write(self, entries: dict[str, MiKeys]) -> None:
        payload = {
            address: {
                "token": keys.token.hex(),
                "bindkey": keys.bindkey.hex(),
                "device_id": keys.device_id.hex(),
            }
            for address, keys in sorted(entries.items())
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=DIR_MODE)
            # `mkdir`'s mode is ignored for a directory that already exists, and
            # O_CREAT likewise leaves an existing file's permissions alone, so
            # both are set explicitly rather than trusted to file creation.
            self.path.parent.chmod(DIR_MODE)
            descriptor = os.open(
                self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, FILE_MODE
            )
            os.fchmod(descriptor, FILE_MODE)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
        except OSError as exc:
            msg = f"cannot write key store {self.path}: {exc}"
            raise Error(msg) from exc


def bindkeys(path: Path | None = None) -> dict[str, bytes]:
    """Every known bind key, for decoding encrypted advertisements."""
    return {
        address: keys.bindkey for address, keys in Keystore.open(path).load().items()
    }
